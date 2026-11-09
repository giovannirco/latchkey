# SPDX-License-Identifier: GPL-3.0-or-later
"""The lock's operation log, the unlock alerts and the lock clock over the USB serial console, against the owner's
TTLock lock held by the ESP32-S3. The checks that need no lock run on any board.

Log entries carry what the lock recorded, and passcode entries record the code typed, so the suite asserts on the
entry shape, the record numbers and the record types only, and never prints an entry. Reading the log changes
nothing on the lock. The unlock test restores the bolt's starting state. The time-zone test changes the
board's time zone for a few minutes and puts the one it found back, so the lock clock is set twice.
"""

from __future__ import annotations

import re
import sys
import time
from collections import Counter
from typing import Any

import pytest
from board import prepare, stored, wait_idle
from latchkey_cli import Console
from owner import hide

DOCUMENTATION_MAC = "00:00:5E:00:53:99"
LOCK_TIMEOUT_S = 90.0
CLOCK_WAIT_S = 240.0
ENTRY_KEYS = {"seq", "time", "type", "battery"}
SHOWN_SLOTS = 16
APP_UNLOCK = 1
APP_LOCK = 26
TOLERANCE_S = 120
TEST_ZONE = "CET-1CEST,M3.5.0,M10.5.0/3"
READ_LINE = re.compile(r"read (\d+) new log records of ")
CLOCK_LINE = re.compile(r"(set|corrected) the clock of \S+ \(offset (-?\d+) s\): (\w+)")
REPLY_ID = re.compile(r"unlock reply: record yes, uid \d+, record id (\d+)")
LOGGED_ID = re.compile(r"log record (\d+) type 1 uid \d+ record id (\d+)")


def code_of(console: Console, method: str, params: dict[str, Any]) -> str | None:
    return console.request(method, params, timeout=LOCK_TIMEOUT_S).get("error", {}).get("code")


def frames(console: Console) -> int:
    return console.call("system.info")["ble"]["frames"]


def fetch(console: Console, mac: str, **params: Any) -> dict[str, Any]:
    return console.call("lock.log.fetch", {"lock": mac, **params}, timeout=LOCK_TIMEOUT_S)


def check_page(page: dict[str, Any]) -> None:
    assert set(page) == {"entries", "last", "more"}
    assert isinstance(page["last"], int) and isinstance(page["more"], bool)
    seqs = [entry["seq"] for entry in page["entries"]]
    assert seqs == sorted(set(seqs))
    for entry in page["entries"]:
        assert set(entry) == ENTRY_KEYS
        assert isinstance(entry["seq"], int) and isinstance(entry["type"], int)
        assert entry["time"] is None or isinstance(entry["time"], int)
        assert 0 <= entry["battery"] <= 100
    if seqs:
        assert page["last"] == seqs[-1]


def alerts(console: Console, mac: str) -> list[dict[str, Any]]:
    return [
        event["data"] for event in console.events if event["event"] == "lock.alert" and event["data"]["lock"] == mac
    ]


def wait_line(console: Console, pattern: re.Pattern[str], since: int, timeout: float) -> re.Match[str]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        for line in console.lines[since:]:
            found = pattern.search(line)
            if found:
                return found
        console.wait_event(lambda _: False, 2.0)
    pytest.fail(f"no console line matched {pattern.pattern!r} within {timeout:.0f} s")


@pytest.fixture(scope="module")
def board(console: Console) -> dict[str, Any]:
    info = prepare(console)
    for tag in ("locks", "lock_log"):
        assert console.call("system.log.set", {"tag": tag, "level": "debug"}) == {}
    return info


@pytest.fixture
def held(console: Console, board: dict[str, Any], lock_mac: str) -> dict[str, Any]:
    lock = stored(console, lock_mac)
    if lock is None:
        pytest.skip("this board holds no keys for the lock")
    return hide(lock)


def test_log_fetch_checks_its_params_without_touching_the_lock(console: Console, board: dict[str, Any]) -> None:
    wait_idle(console)
    before = frames(console)
    assert code_of(console, "lock.log.fetch", {}) == "invalid_argument"
    assert code_of(console, "lock.log.fetch", {"lock": "not-a-mac"}) == "invalid_argument"
    assert code_of(console, "lock.log.fetch", {"lock": DOCUMENTATION_MAC}) == "not_paired"
    for since in (-1, 1.5, "3", 65535, True):
        assert code_of(console, "lock.log.fetch", {"lock": DOCUMENTATION_MAC, "since": since}) == "invalid_argument"
    assert frames(console) == before


def test_the_log_shows_the_newest_entries_then_only_newer_ones(
    console: Console, held: dict[str, Any], lock_mac: str
) -> None:
    page = fetch(console, lock_mac)
    check_page(page)
    assert page["entries"], "the owner's lock has a log"
    assert len(page["entries"]) <= SHOWN_SLOTS + 8
    newer = fetch(console, lock_mac, since=page["last"])
    check_page(newer)
    assert all(entry["seq"] > page["last"] for entry in newer["entries"])
    assert newer["last"] >= page["last"]
    if page["last"] > 2 * SHOWN_SLOTS:
        since = page["last"] - 2 * SHOWN_SLOTS
        older = fetch(console, lock_mac, since=since)
        check_page(older)
        assert older["entries"] and all(since < entry["seq"] <= since + SHOWN_SLOTS for entry in older["entries"])
        assert older["more"]
    types = Counter(entry["type"] for entry in page["entries"])
    print(
        f"log: newest {len(page['entries'])} entries up to record {page['last']}, types {dict(types)}", file=sys.stderr
    )


def test_recent_alerts_are_readable_and_a_zero_acknowledgement_keeps_them(
    console: Console, held: dict[str, Any], lock_mac: str
) -> None:
    before = console.call("lock.alerts.list", {"lock": lock_mac})
    assert set(before) == {"alerts", "warnings"}
    ids = [alert["id"] for alert in before["alerts"]]
    assert ids == sorted(set(ids), reverse=True)
    assert all(isinstance(warning, str) for warning in before["warnings"])
    assert console.call("lock.alerts.ack", {"lock": lock_mac, "through": 0}) == before
    assert stored(console, lock_mac)["alertCount"] == len(ids)
    for through in (-1, 1.5, True, "1", 2**32):
        assert code_of(console, "lock.alerts.ack", {"lock": lock_mac, "through": through}) == "invalid_argument"
    assert console.call("lock.alerts.list", {"lock": lock_mac}) == before


def test_an_unlock_by_the_board_raises_no_alert(console: Console, held: dict[str, Any], lock_mac: str) -> None:
    initial = console.call("lock.status", {"lock": lock_mac}, timeout=LOCK_TIMEOUT_S)["state"]
    assert initial in {"locked", "unlocked"}
    before = fetch(console, lock_mac)
    console.events.clear()
    seen = len(console.lines)
    started = time.time()
    try:
        assert console.call("lock.unlock", {"lock": lock_mac}, timeout=LOCK_TIMEOUT_S)["state"] == "unlocked"
    finally:
        if initial == "locked":
            assert console.call("lock.lock", {"lock": lock_mac}, timeout=LOCK_TIMEOUT_S)["state"] == initial
    ended = time.time()
    wait_line(console, READ_LINE, seen, 60.0)
    after = fetch(console, lock_mac, since=before["last"])
    check_page(after)
    unlocks = [entry for entry in after["entries"] if entry["type"] == APP_UNLOCK]
    assert len(unlocks) == 1, [entry["type"] for entry in after["entries"]]
    assert started - TOLERANCE_S <= unlocks[0]["time"] <= ended + TOLERANCE_S
    assert alerts(console, lock_mac) == []
    replied = [found.group(1) for line in console.lines[seen:] if (found := REPLY_ID.search(line))]
    logged = [found.group(2) for line in console.lines[seen:] if (found := LOGGED_ID.search(line))]
    assert replied and replied == logged[:1]
    print(
        f"unlock: log entry {unlocks[0]['time'] - int(started):+d} s from the request, "
        f"{len(after['entries'])} new entries {[entry['type'] for entry in after['entries']]}; record id in the reply "
        f"{'equals' if replied and replied == logged[:1] else 'differs from'} the logged one; reply id minus the "
        f"request time: {int(replied[0]) - int(started) if replied else None} s",
        file=sys.stderr,
    )


def test_a_time_zone_change_sets_the_lock_clock_after_reading_its_log(
    console: Console, held: dict[str, Any], lock_mac: str
) -> None:
    found = console.call("system.timezone.get")["tz"]
    seen = len(console.lines)
    changed = False
    try:
        assert console.call("system.timezone.set", {"tz": TEST_ZONE})["tz"] == TEST_ZONE
        changed = True
        offset = console.call("system.timezone.get")["utcOffset"]
        clock = wait_line(console, CLOCK_LINE, seen, CLOCK_WAIT_S)
        assert (clock.group(1), int(clock.group(2)), clock.group(3)) == ("set", offset, "ok")
        lines = console.lines[seen:]
        read = next(i for i, line in enumerate(lines) if READ_LINE.search(line))
        assert read < next(i for i, line in enumerate(lines) if CLOCK_LINE.search(line))
    finally:
        if changed:
            back = len(console.lines)
            assert console.call("system.timezone.set", {"tz": found})["tz"] == found
            restored = wait_line(console, CLOCK_LINE, back, CLOCK_WAIT_S)
            assert restored.group(3) == "ok"
    assert console.call("system.timezone.get")["tz"] == found
