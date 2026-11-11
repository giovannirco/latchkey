# SPDX-License-Identifier: GPL-3.0-or-later
"""Lock settings over the USB serial console, which counts as presence at the board, against the owner's TTLock
lock held by the ESP32-S3. The checks that need no lock run on any board.

The lock belongs to its owner: the tests that change auto-lock, sound or passage mode run only with
--allow-lock-writes, and put every setting back exactly as it was read, in a finally block that retries a few times
and fails naming what it left on the lock. The suite never clears the passage schedule and deletes only the window it
added. It sends no SWITCH write (reset button, privacy lock, tamper alert) to the owner's lock: every write must refuse
before sending a frame.
"""

from __future__ import annotations

import re
import sys
import time
from collections.abc import Callable, Iterator
from typing import Any

import pytest
from board import prepare, stored, wait_idle
from latchkey_cli import Console, ConsoleTimeout, LatchkeyError
from owner import hide

DOCUMENTATION_MAC = "00:00:5E:00:53:99"
LOCK_TIMEOUT_S = 90.0
CLEANUP_ATTEMPTS = 3
CLOCK = re.compile(r"([01][0-9]|2[0-3]):[0-5][0-9]")
SWITCHES = {
    "reset_button": "lock.resetButton",
    "privacy_lock": "lock.privacyLock",
    "tamper_alert": "lock.tamperAlert",
}
LOCK_METHODS: dict[str, dict[str, Any]] = {
    "lock.autolock.get": {},
    "lock.autolock.set": {"seconds": 5},
    "lock.passage.list": {},
    "lock.passage.add": {"type": "weekly", "days": [3], "start": "03:17", "end": "03:41"},
    "lock.passage.delete": {"type": "weekly", "day": 3, "start": "03:17", "end": "03:41"},
    "lock.passage.clear": {},
    "lock.sound.get": {},
    "lock.sound.set": {"enabled": True, "volume": 3},
    "lock.resetButton.get": {},
    "lock.resetButton.set": {"enabled": True},
    "lock.privacyLock.get": {},
    "lock.privacyLock.set": {"enabled": False},
    "lock.tamperAlert.get": {},
    "lock.tamperAlert.set": {"enabled": False},
}
BAD_PARAMS: list[tuple[str, dict[str, Any]]] = [
    ("lock.autolock.set", {}),
    ("lock.autolock.set", {"seconds": -1}),
    ("lock.autolock.set", {"seconds": 1.5}),
    ("lock.autolock.set", {"seconds": "5"}),
    ("lock.autolock.set", {"seconds": 65536}),
    ("lock.passage.add", {}),
    ("lock.passage.add", {"type": "weekly", "days": [], "start": "03:17", "end": "03:41"}),
    ("lock.passage.add", {"type": "weekly", "days": [8], "start": "03:17", "end": "03:41"}),
    ("lock.passage.add", {"type": "weekly", "days": ["1"], "start": "03:17", "end": "03:41"}),
    ("lock.passage.add", {"type": "weekly", "days": [1], "start": "3:17", "end": "03:41"}),
    ("lock.passage.add", {"type": "weekly", "days": [1], "start": "03:41", "end": "03:17"}),
    ("lock.passage.add", {"type": "weekly", "days": [1], "start": "03:17", "end": "03:17"}),
    ("lock.passage.add", {"type": "monthly", "days": [1], "start": "03:17", "end": "03:41"}),
    ("lock.passage.add", {"type": "daily", "days": [1], "start": "03:17", "end": "03:41"}),
    ("lock.passage.delete", {}),
    ("lock.passage.delete", {"type": "weekly", "day": 8, "start": "03:17", "end": "03:41"}),
    ("lock.passage.delete", {"type": "monthly", "day": 0, "start": "03:17", "end": "03:41"}),
    ("lock.passage.delete", {"type": "weekly", "day": 1, "start": "24:00", "end": "03:41"}),
    ("lock.sound.set", {}),
    ("lock.sound.set", {"enabled": "yes"}),
    ("lock.sound.set", {"enabled": True, "volume": 0}),
    ("lock.sound.set", {"enabled": True, "volume": 6}),
    ("lock.sound.set", {"enabled": True, "volume": 2.5}),
    ("lock.resetButton.set", {}),
    ("lock.resetButton.set", {"enabled": 1}),
    ("lock.privacyLock.set", {}),
    ("lock.privacyLock.set", {"enabled": "false"}),
    ("lock.tamperAlert.set", {}),
    ("lock.tamperAlert.set", {"enabled": None}),
]


def code_of(console: Console, method: str, params: dict[str, Any]) -> str | None:
    return console.request(method, params, timeout=LOCK_TIMEOUT_S).get("error", {}).get("code")


def frames(console: Console) -> int:
    return console.call("system.info")["ble"]["frames"]


def call(console: Console, method: str, mac: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    return console.call(method, {"lock": mac, **(params or {})}, timeout=LOCK_TIMEOUT_S)


def features_of(console: Console, mac: str) -> set[str]:
    return set(call(console, "lock.features", mac)["features"])


def put_back(console: Console, left: str, restore: Callable[[], bool]) -> None:
    problems: list[str] = []
    for _ in range(CLEANUP_ATTEMPTS):
        try:
            if restore():
                return
            problems.append("still there after the attempt")
        except (LatchkeyError, ConsoleTimeout) as error:
            problems.append(str(error))
        try:
            wait_idle(console)
        except ConsoleTimeout as error:
            problems.append(str(error))
    pytest.fail(f"left on the lock after {CLEANUP_ATTEMPTS} attempts: {left} ({'; '.join(problems)})")


def check_passage_mode(mode: dict[str, Any]) -> None:
    keys = {"type", "day", "start", "end"} | ({"month"} if mode["type"] == "monthly" else set())
    assert set(mode) == keys, mode
    assert mode["type"] in ("weekly", "monthly", "other")
    assert isinstance(mode["day"], int)
    assert CLOCK.fullmatch(mode["start"]) or mode["type"] == "other"
    assert CLOCK.fullmatch(mode["end"]) or mode["type"] == "other"


@pytest.fixture(scope="module")
def board(console: Console) -> dict[str, Any]:
    return prepare(console)


@pytest.fixture
def held(console: Console, board: dict[str, Any], lock_mac: str) -> dict[str, Any]:
    lock = stored(console, lock_mac)
    if lock is None:
        pytest.skip("this board holds no keys for the lock")
    return hide(lock)


@pytest.fixture
def writable(allow_lock_writes: bool) -> None:
    if not allow_lock_writes:
        pytest.skip("pass --allow-lock-writes to change the lock's settings and put them back")


@pytest.fixture(scope="module")
def found(console: Console, board: dict[str, Any], lock_mac: str) -> Iterator[dict[str, Any]]:
    readings: dict[str, Any] = {}
    yield readings
    if stored(console, lock_mac) is None or not readings:
        return
    now = {
        "autolock": call(console, "lock.autolock.get", lock_mac)["seconds"] if "autolock" in readings else None,
        "sound": call(console, "lock.sound.get", lock_mac) if "sound" in readings else None,
        "passage": call(console, "lock.passage.list", lock_mac)["modes"] if "passage" in readings else None,
        "switches": {
            feature: call(console, f"{prefix}.get", lock_mac)["enabled"]
            for feature, prefix in SWITCHES.items()
            if feature in readings.get("switches", {})
        },
    }
    assert now["autolock"] == readings.get("autolock", {}).get("seconds")
    assert now["sound"] == readings.get("sound")
    assert now["passage"] == readings.get("passage")
    assert now["switches"] == readings.get("switches", {})


def test_settings_methods_check_their_params_without_touching_the_lock(
    console: Console, board: dict[str, Any]
) -> None:
    wait_idle(console)
    before = frames(console)
    for method, params in LOCK_METHODS.items():
        assert code_of(console, method, {}) == "invalid_argument", method
        assert code_of(console, method, {"lock": "not-a-mac", **params}) == "invalid_argument", method
        assert code_of(console, method, {"lock": DOCUMENTATION_MAC, **params}) == "not_paired", method
    for method, params in BAD_PARAMS:
        assert code_of(console, method, {"lock": DOCUMENTATION_MAC, **params}) == "invalid_argument", (method, params)
    assert frames(console) == before


def test_every_reported_setting_reads(
    console: Console, held: dict[str, Any], lock_mac: str, found: dict[str, Any]
) -> None:
    features = features_of(console, lock_mac)
    read: list[str] = []
    if "auto_lock" in features:
        autolock = call(console, "lock.autolock.get", lock_mac)
        assert set(autolock) == {"seconds", "min", "max"}
        assert isinstance(autolock["seconds"], int) and autolock["seconds"] >= 0
        assert autolock["min"] is None or isinstance(autolock["min"], int)
        assert autolock["max"] is None or isinstance(autolock["max"], int)
        found["autolock"] = autolock
        read.append(f"auto-lock {autolock}")
    if "passage_mode" in features:
        modes = call(console, "lock.passage.list", lock_mac)["modes"]
        for mode in modes:
            check_passage_mode(mode)
        found["passage"] = modes
        read.append(f"passage {len(modes)} windows")
    if "audio_management" in features:
        sound = call(console, "lock.sound.get", lock_mac)
        assert set(sound) == {"enabled", "volume", "levels"}
        assert isinstance(sound["enabled"], bool)
        assert sound["volume"] is None or 1 <= sound["volume"] <= 5
        assert sound["levels"] == 5
        found["sound"] = sound
        read.append(f"sound {sound}")
    found["switches"] = {}
    for feature, prefix in SWITCHES.items():
        if feature in features:
            switch = call(console, f"{prefix}.get", lock_mac)
            assert set(switch) == {"enabled"} and isinstance(switch["enabled"], bool)
            found["switches"][feature] = switch["enabled"]
    read.append(f"switches {found['switches']}")
    print("settings read: " + "; ".join(read), file=sys.stderr)
    assert read


def test_the_reset_button_is_on(console: Console, held: dict[str, Any], lock_mac: str) -> None:
    if "reset_button" not in features_of(console, lock_mac):
        pytest.skip("the lock does not report reset_button")
    assert call(console, "lock.resetButton.get", lock_mac) == {"enabled": True}


def test_the_reset_button_is_not_turned_off_without_a_key_backup(
    console: Console, held: dict[str, Any], lock_mac: str
) -> None:
    if "reset_button" not in features_of(console, lock_mac):
        pytest.skip("the lock does not report reset_button")
    wait_idle(console)
    before = frames(console)
    started = time.monotonic()
    reply = console.request("lock.resetButton.set", {"lock": lock_mac, "enabled": False}, timeout=LOCK_TIMEOUT_S)
    expected = "unverified" if held["backedUp"] else "backup_required"
    assert reply["error"]["code"] == expected
    if not held["backedUp"]:
        assert "keys.export" in reply["error"]["message"]
    assert time.monotonic() - started < 5.0
    assert frames(console) == before


def test_unverified_switch_writes_send_no_frames(
    console: Console, held: dict[str, Any], lock_mac: str
) -> None:
    features = features_of(console, lock_mac)
    wait_idle(console)
    before = frames(console)
    for feature, prefix in SWITCHES.items():
        if feature not in features:
            continue
        for enabled in (True, False):
            missing_backup = feature == "reset_button" and not enabled and not held["backedUp"]
            expected = "backup_required" if missing_backup else "unverified"
            assert code_of(console, f"{prefix}.set", {"lock": lock_mac, "enabled": enabled}) == expected
    assert frames(console) == before


def test_auto_lock_changes_and_comes_back(
    console: Console, writable: None, held: dict[str, Any], lock_mac: str
) -> None:
    if "auto_lock" not in features_of(console, lock_mac):
        pytest.skip("the lock does not report auto_lock")
    found = call(console, "lock.autolock.get", lock_mac)
    other = (found["min"] or 1) if found["seconds"] == 0 else 0
    try:
        changed = call(console, "lock.autolock.set", lock_mac, {"seconds": other})
        assert changed == {**found, "seconds": other}
        assert call(console, "lock.autolock.get", lock_mac) == changed
        if found["max"] is not None:
            too_long = {"lock": lock_mac, "seconds": found["max"] + 1}
            assert code_of(console, "lock.autolock.set", too_long) == "invalid_argument"
    finally:

        def restore() -> bool:
            call(console, "lock.autolock.set", lock_mac, {"seconds": found["seconds"]})
            return call(console, "lock.autolock.get", lock_mac) == found

        put_back(console, f"auto-lock {other} s instead of {found['seconds']} s", restore)


def test_sound_changes_and_comes_back(
    console: Console, writable: None, held: dict[str, Any], lock_mac: str
) -> None:
    if "audio_management" not in features_of(console, lock_mac):
        pytest.skip("the lock does not report audio_management")
    found = call(console, "lock.sound.get", lock_mac)
    restore = {"enabled": found["enabled"]} | ({"volume": found["volume"]} if found["volume"] else {})
    try:
        quiet = call(console, "lock.sound.set", lock_mac, {"enabled": not found["enabled"]})
        assert quiet["enabled"] is (not found["enabled"])
        if found["volume"]:
            level = 2 if found["volume"] != 2 else 4
            louder = call(console, "lock.sound.set", lock_mac, {"enabled": True, "volume": level})
            assert (louder["enabled"], louder["volume"]) == (True, level)
    finally:

        def put_sound_back() -> bool:
            call(console, "lock.sound.set", lock_mac, restore)
            return call(console, "lock.sound.get", lock_mac) == found

        put_back(console, f"sound changed from {found}", put_sound_back)


def test_a_passage_window_is_added_and_deleted(
    console: Console, writable: None, held: dict[str, Any], lock_mac: str
) -> None:
    if "passage_mode" not in features_of(console, lock_mac):
        pytest.skip("the lock does not report passage_mode")
    found = call(console, "lock.passage.list", lock_mac)["modes"]
    today = time.gmtime(console.call("system.info")["time"]["utc"] + console.call("system.timezone.get")["utcOffset"])
    day = (today.tm_wday + 3) % 7 + 1
    window = {"type": "weekly", "day": day, "start": "03:17", "end": "03:41"}
    assert window not in found
    try:
        params = {"type": "weekly", "days": [day], "start": window["start"], "end": window["end"]}
        added = call(console, "lock.passage.add", lock_mac, params)["modes"]
        assert sorted(map(str, added)) == sorted(map(str, [*found, window]))
        assert call(console, "lock.passage.list", lock_mac)["modes"] == added
        print(f"passage window added for weekday {day} (1 = Monday), listed as {window}", file=sys.stderr)
    finally:

        def remove_window() -> bool:
            if window in call(console, "lock.passage.list", lock_mac)["modes"]:
                call(console, "lock.passage.delete", lock_mac, window)
            return window not in call(console, "lock.passage.list", lock_mac)["modes"]

        put_back(console, f"passage window {window}", remove_window)
    assert call(console, "lock.passage.list", lock_mac)["modes"] == found
    gone = code_of(console, "lock.passage.delete", {"lock": lock_mac, **window})
    assert gone == "invalid_argument"
