# SPDX-License-Identifier: GPL-3.0-or-later
"""locks.* and lock.* over the USB serial console, against the owner's TTLock lock.

The ESP32-S3 is the board that holds the lock. It pairs it once, only while it holds no keys for it,
and keeps it paired afterwards; any other board only scans. A factory-fresh lock advertises for about
15 s after a touch on its keypad: with --touch-file <path>, the pairing test writes the UTC time into
that file while it waits (up to 10 minutes) for the lock to wake, and deletes it once pairing starts.
lock.factoryReset runs only with --allow-lock-reset.
"""

from __future__ import annotations

import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from latchkey_cli import Console

PAIRING_CHIP = "esp32s3"
PAIR_WAIT_S = 600
LOCK_TIMEOUT_S = 90.0
LOCK_NAME = "Bench lock"
DOCUMENTATION_MAC = "00:00:5E:00:53:99"
SCAN_SECONDS = 15
ADVERT_WATCH_S = 60
ADVERT_SAMPLE_S = 5
MAX_ADVERT_GAP_S = 20
IDLE_TIMEOUT_S = 45.0
SUMMARY_KEYS = {
    "id",
    "mac",
    "name",
    "model",
    "state",
    "battery",
    "rssi",
    "lastSeen",
    "lastEvent",
    "hardened",
    "backedUp",
    "pairComplete",
}
INFO_KEYS = {"mac", "model", "hardware", "firmware", "manufactureDate", "protocol"}
STATES = {"locked", "unlocked"}
FEATURE_NAMES = {
    "passcode",
    "ic",
    "finger_print",
    "wrist_band",
    "auto_lock",
    "passcode_with_delete_function",
    "firmware_setting",
    "modify_passcode_function",
    "manual_lock",
    "password_display_or_hide",
    "gateway_unlock",
    "freeze_lock",
    "cyclic_password",
    "magnetometer",
    "config_gateway_unlock",
    "audio_management",
    "nb_lock",
    "get_admin_code",
    "hotel_lock",
    "lock_no_clock_chip",
    "can_not_click_unlock",
    "passage_mode",
    "passage_mode_and_auto_lock_and_can_close",
    "wireless_keyboard",
    "lamp",
    "tamper_alert",
    "reset_button",
    "privacy_lock",
    "dead_lock",
    "cyclic_ic_or_finger_print",
    "unlock_direction",
    "finger_vein",
    "telink_chip",
    "nb_activate_configuration",
    "cyclic_passcode_can_recovery",
    "wireless_key_fob",
    "accessory_battery",
}


def error_code(console: Console, method: str, params: dict[str, Any] | None = None) -> str | None:
    reply = console.request(method, params, timeout=LOCK_TIMEOUT_S)
    return reply.get("error", {}).get("code")


def stored(console: Console, mac: str) -> dict[str, Any] | None:
    return next((lock for lock in console.call("locks.list")["locks"] if lock["id"] == mac), None)


def events_for(console: Console, name: str, mac: str) -> list[dict[str, Any]]:
    return [event["data"] for event in console.events if event["event"] == name and event["data"].get("lock") == mac]


def prepare(console: Console) -> dict[str, Any]:
    info = console.wait_ready()
    assert console.call("system.time.set", {"utc": int(time.time())}) == {}
    assert console.call("system.log.set", {"tag": "ble", "level": "debug"}) == {}
    console.wait_info(lambda state: state["ble"]["ready"], 15.0, "the Bluetooth host to sync")
    return info


def wait_idle(console: Console) -> dict[str, Any]:
    return console.wait_info(lambda state: not state["ble"]["connected"], IDLE_TIMEOUT_S, "the lock link to close")


def utc_stamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class TouchRequest:
    def __init__(self, path: Path | None) -> None:
        self.path = path

    def open(self) -> None:
        if self.path is None:
            print("touch the lock's keypad now: waiting for it to advertise", file=sys.stderr, flush=True)
            return
        self.path.write_text(utc_stamp() + "\n", encoding="utf-8")

    def close(self) -> None:
        if self.path is not None:
            self.path.unlink(missing_ok=True)


@pytest.fixture(scope="module")
def board(console: Console) -> dict[str, Any]:
    return prepare(console)


@pytest.fixture
def held(console: Console, board: dict[str, Any], lock_mac: str) -> dict[str, Any]:
    lock = stored(console, lock_mac)
    if lock is None:
        pytest.skip("this board holds no keys for the lock")
    return lock


def test_lock_params_are_checked(console: Console, board: dict[str, Any]) -> None:
    assert error_code(console, "lock.status", {}) == "invalid_argument"
    assert error_code(console, "lock.status", {"lock": "not-a-mac"}) == "invalid_argument"
    assert error_code(console, "lock.status", {"lock": DOCUMENTATION_MAC}) == "not_paired"
    assert error_code(console, "lock.unlock", {"lock": DOCUMENTATION_MAC}) == "not_paired"
    assert error_code(console, "lock.features", {"lock": DOCUMENTATION_MAC}) == "not_paired"
    assert error_code(console, "locks.forget", {"lock": DOCUMENTATION_MAC}) == "not_paired"
    assert error_code(console, "locks.rename", {"lock": DOCUMENTATION_MAC, "name": "x"}) == "not_paired"
    assert error_code(console, "locks.pair", {"name": "x"}) == "invalid_argument"
    assert error_code(console, "locks.pair", {"mac": DOCUMENTATION_MAC, "wait": 0}) == "invalid_argument"
    assert error_code(console, "locks.scan", {"seconds": 31}) == "invalid_argument"
    assert error_code(console, "locks.scan", {"seconds": "ten"}) == "invalid_argument"


def test_pairs_the_factory_fresh_lock(
    console: Console, board: dict[str, Any], lock_mac: str, touch_file: Path | None
) -> None:
    if board["chip"] != PAIRING_CHIP:
        pytest.skip("only the ESP32-S3 pairs the lock")
    if stored(console, lock_mac) is not None:
        pytest.skip("the board already holds the lock")
    console.events.clear()
    touch = TouchRequest(touch_file)

    def on_event(event: dict[str, Any]) -> None:
        if event["event"] == "scan.result" and event["data"].get("mac") == lock_mac:
            touch.close()

    touch.open()
    try:
        params = {"mac": lock_mac, "name": LOCK_NAME, "wait": PAIR_WAIT_S}
        result = console.call("locks.pair", params, timeout=PAIR_WAIT_S + 180.0, on_event=on_event)
    finally:
        touch.close()
    lock = result["lock"]
    assert set(lock) == SUMMARY_KEYS
    same = lock["id"] == lock_mac and lock["mac"] == lock_mac
    assert same, "pairing returned another lock"
    assert lock["name"] == LOCK_NAME
    assert lock["hardened"] is False
    assert lock["pairComplete"] is True
    adverts = [event["data"] for event in console.events if event["event"] == "scan.result"]
    target = [data for data in adverts if data.get("mac") == lock_mac]
    assert target, "the pairing wait did not report the lock's advert"
    assert target[0]["paired"] is False
    assert stored(console, lock_mac) is not None


def test_status_comes_first_after_pairing(console: Console, held: dict[str, Any], lock_mac: str) -> None:
    status = console.call("lock.status", {"lock": lock_mac}, timeout=LOCK_TIMEOUT_S)
    assert status["state"] in STATES
    assert 0 <= status["battery"] <= 100
    assert isinstance(status["adminPasscodeConfirmed"], bool)
    assert status["pairComplete"] is True


def test_info_reports_the_device(console: Console, held: dict[str, Any], lock_mac: str) -> None:
    info = console.call("lock.info", {"lock": lock_mac}, timeout=LOCK_TIMEOUT_S)
    assert set(info) == INFO_KEYS
    same = info["mac"] == lock_mac
    assert same, "lock.info returned another lock"
    assert isinstance(info["model"], str) and info["model"]
    assert all(isinstance(info[key], str) for key in ("hardware", "firmware", "manufactureDate", "protocol"))


def test_features_are_named(console: Console, held: dict[str, Any], lock_mac: str) -> None:
    features = console.call("lock.features", {"lock": lock_mac}, timeout=LOCK_TIMEOUT_S)["features"]
    assert features
    assert len(set(features)) == len(features)
    assert set(features) <= FEATURE_NAMES


def test_unlock_then_lock_emit_events(console: Console, held: dict[str, Any], lock_mac: str) -> None:
    console.events.clear()
    unlocked = console.call("lock.unlock", {"lock": lock_mac}, timeout=LOCK_TIMEOUT_S)
    assert unlocked["state"] == "unlocked"
    assert 0 <= unlocked["battery"] <= 100
    events = events_for(console, "lock.event", lock_mac)
    assert any(event["action"] == "unlock" and event["method"] == "app" for event in events)
    assert all(event["time"] > 0 for event in events)
    assert any(state["state"] == "unlocked" for state in events_for(console, "lock.state", lock_mac))
    console.events.clear()
    locked = console.call("lock.lock", {"lock": lock_mac}, timeout=LOCK_TIMEOUT_S)
    assert locked["state"] == "locked"
    events = events_for(console, "lock.event", lock_mac)
    assert any(event["action"] == "lock" and event["method"] == "app" for event in events)
    assert any(state["state"] == "locked" for state in events_for(console, "lock.state", lock_mac))


def test_two_requests_in_flight_run_in_order(console: Console, held: dict[str, Any], lock_mac: str) -> None:
    console.reply_ids.clear()
    first = console.start("lock.unlock", {"lock": lock_mac})
    second = console.start("lock.lock", {"lock": lock_mac})
    later = console.finish(second, LOCK_TIMEOUT_S * 2)
    earlier = console.finish(first, LOCK_TIMEOUT_S)
    assert earlier["result"]["state"] == "unlocked"
    assert later["result"]["state"] == "locked"
    assert console.reply_ids.index(first) < console.reply_ids.index(second)


def test_time_sync_sets_the_lock_clock(console: Console, held: dict[str, Any], lock_mac: str) -> None:
    result = console.call("lock.time.sync", {"lock": lock_mac}, timeout=LOCK_TIMEOUT_S)
    assert abs(result["time"] - time.time()) <= 10


def test_list_and_rename(console: Console, held: dict[str, Any], lock_mac: str) -> None:
    assert set(held) == SUMMARY_KEYS
    assert held["state"] in STATES | {"unknown"}
    renamed = console.call("locks.rename", {"lock": lock_mac, "name": "  Desk lock  "})["lock"]
    assert renamed["name"] == "Desk lock"
    assert stored(console, lock_mac)["name"] == "Desk lock"
    assert error_code(console, "locks.rename", {"lock": lock_mac, "name": "   "}) == "invalid_argument"
    assert error_code(console, "locks.rename", {"lock": lock_mac, "name": "x" * 33}) == "invalid_argument"
    assert console.call("locks.rename", {"lock": lock_mac, "name": LOCK_NAME})["lock"]["name"] == LOCK_NAME


def test_audit_targets_the_lock(console: Console, held: dict[str, Any], lock_mac: str) -> None:
    assert console.call("locks.rename", {"lock": lock_mac, "name": held["name"]})["lock"]["name"] == held["name"]
    assert error_code(console, "locks.rename", {"lock": lock_mac, "name": ""}) == "invalid_argument"
    entries = console.call("audit.list", {"limit": 50})["entries"]
    assert [entry["result"] for entry in entries[:2]] == ["invalid_argument", "ok"]
    assert all(entry["method"] == "locks.rename" for entry in entries[:2])
    operated = [
        entry for entry in entries if entry["method"] in ("lock.unlock", "lock.lock") and entry["result"] == "ok"
    ]
    operations = entries[:2] + operated
    targeted = all(entry["target"] == lock_mac for entry in operations)
    assert targeted, "a lock operation was audited without the lock as its target"


def test_keys_survive_a_reboot(console: Console, held: dict[str, Any], lock_mac: str) -> None:
    console.call_and_wait_restart("system.reboot")
    prepare(console)
    after = stored(console, lock_mac)
    assert after is not None
    assert after["name"] == held["name"]
    status = console.call("lock.status", {"lock": lock_mac}, timeout=LOCK_TIMEOUT_S)
    assert status["state"] in STATES


def test_scan_reports_the_lock(console: Console, board: dict[str, Any], lock_mac: str) -> None:
    wait_idle(console)
    console.events.clear()
    holds = stored(console, lock_mac) is not None
    assert console.call("locks.scan", {"seconds": SCAN_SECONDS}, timeout=LOCK_TIMEOUT_S) == {"seconds": SCAN_SECONDS}
    found = console.wait_event(
        lambda event: event["event"] == "scan.result" and event["data"].get("mac") == lock_mac, SCAN_SECONDS + 5.0
    )
    assert found is not None, "the scan did not see the lock"
    data = found["data"]
    assert set(data) <= {"mac", "name", "rssi", "paired", "lock"}
    assert -110 < data["rssi"] < 0
    assert data["paired"] is True
    reported_as_held = data.get("lock") == lock_mac
    assert reported_as_held == holds


def test_paired_lock_keeps_advertising_untouched(console: Console, held: dict[str, Any], lock_mac: str) -> None:
    wait_idle(console)
    started = time.time()
    samples: list[int] = []
    while time.time() - started < ADVERT_WATCH_S:
        time.sleep(ADVERT_SAMPLE_S)
        seen = stored(console, lock_mac)["lastSeen"]
        if seen is not None:
            samples.append(seen)
    print(f"lastSeen offsets (s): {[round(seen - started) for seen in samples]}", file=sys.stderr)
    fresh = sorted({seen for seen in samples if seen >= started})
    assert len(fresh) >= 3, "the lock was seen fewer than 3 times in 60 s"
    gaps = [later - earlier for earlier, later in zip([int(started)] + fresh, fresh + [int(time.time())])]
    assert max(gaps) <= MAX_ADVERT_GAP_S


def test_heap_holds_with_bluetooth_up(console: Console, board: dict[str, Any]) -> None:
    info = console.call("system.info")
    heap = info["heap"]
    print(f"heap free={heap['free']} min_free={heap['min_free']} largest={heap['largest_block']}", file=sys.stderr)
    assert info["ble"]["ready"] is True
    assert heap["min_free"] > 40_000
    assert heap["largest_block"] > 20_000


def test_every_lock_reply_passed_crc(console: Console, held: dict[str, Any]) -> None:
    ble = console.call("system.info")["ble"]
    assert ble["frames"] > 0
    assert ble["bad_crc"] == 0


def test_board_reset_refuses_while_the_lock_is_stored(console: Console, held: dict[str, Any], lock_mac: str) -> None:
    started = time.monotonic()
    uptime = console.call("system.info")["uptime_ms"]
    assert error_code(console, "system.factoryReset", {}) == "locks_paired"
    assert error_code(console, "system.factoryReset", {"force": False}) == "locks_paired"
    elapsed_ms = (time.monotonic() - started) * 1000.0
    grown = console.call("system.info")["uptime_ms"] - uptime
    assert grown >= elapsed_ms - 1000.0, "the board restarted"
    assert stored(console, lock_mac) is not None


def test_lock_factory_reset_forgets_the_lock(
    console: Console, held: dict[str, Any], lock_mac: str, allow_lock_reset: bool
) -> None:
    if not allow_lock_reset:
        pytest.skip("pass --allow-lock-reset to factory-reset the lock")
    assert console.call("lock.factoryReset", {"lock": lock_mac}, timeout=LOCK_TIMEOUT_S) == {}
    assert stored(console, lock_mac) is None
