# SPDX-License-Identifier: GPL-3.0-or-later
"""system.* and audit.list over the USB serial console of a real board.

Each test builds its own state through the fresh, claimed and online fixtures, so any subset runs alone.
"""

from __future__ import annotations

import json
import re
import time
from datetime import datetime, timezone
from typing import Any
from zoneinfo import ZoneInfo

from board import error_code, is_json_object, set_clock
from latchkey_cli import Console
from owner import claim_secret, holds_no_secret, setup_params, wifi_params

BOARDS = {"esp32": ("esp32-devkit", 0), "esp32s3": ("esp32s3-atom", 41)}
AUDIT_CAPACITY = 200
MIN_UTC = 1704067200
SYNC_TOLERANCE_S = 10
NVS_HEADROOM_ENTRIES = 500
CET = "CET-1CEST,M3.5.0,M10.5.0/3"
CLOCK_TOLERANCE_S = 5


def audit_entries(console: Console) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    before = None
    while True:
        params: dict[str, Any] = {"limit": 50}
        if before is not None:
            params["before"] = before
        page = console.call("audit.list", params)
        entries += page["entries"]
        assert page["more"] is (page["next"] is not None)
        before = page["next"]
        if before is None:
            return entries


def paris_offset() -> int:
    return int(datetime.now(timezone.utc).astimezone(ZoneInfo("Europe/Paris")).utcoffset().total_seconds())


def assert_local_time(info: dict[str, Any], tz: str, offset: int) -> None:
    assert info["timezone"] == tz
    local = datetime.fromisoformat(info["localTime"])
    assert local.utcoffset().total_seconds() == offset
    assert abs(local.timestamp() - info["time"]["utc"]) <= CLOCK_TOLERANCE_S


def test_info_reports_identity(console: Console) -> None:
    info = console.wait_ready()
    assert info["chip"] in BOARDS
    board, button = BOARDS[info["chip"]]
    assert info["board"] == board
    assert info["button"]["gpio"] == button
    assert info["firmware"] == "0.1.0"
    assert re.fullmatch(r"\d+\.\d+\.\d+", info["idf"])
    assert 0 < info["heap"]["minFree"] <= info["heap"]["free"]
    assert 0 < info["heap"]["largestBlock"] <= info["heap"]["free"]
    assert isinstance(info["uptime"], int) and info["uptime"] >= 0


def test_info_reports_a_fresh_board(console: Console, fresh: list[str]) -> None:
    info = console.call("system.info")
    assert info["heap"]["free"] > 50_000
    assert info["claimed"] is False
    assert info["wifi"] == {"configured": False, "connected": False, "ssid": None, "ip": None, "rssi": None}
    assert info["time"] == {"utc": None, "synced": False}
    assert info["timezone"] == "UTC0"
    assert info["localTime"] is None
    assert info["certFingerprint"] is None


def test_bluetooth_comes_up_idle(console: Console, fresh: list[str]) -> None:
    info = console.wait_info(lambda state: state["ble"]["ready"], 15.0, "the Bluetooth host to sync")
    assert info["ble"]["connected"] is False
    assert info["ble"]["scanning"] is False
    assert info["ble"]["badCrc"] == 0
    assert console.call("locks.list") == {"locks": []}


def test_factory_reset_takes_force_as_a_boolean(console: Console, fresh: list[str]) -> None:
    started = time.monotonic()
    uptime = console.call("system.info")["uptime"]
    assert error_code(console, "system.factoryReset", {"force": "yes"}) == "invalid_argument"
    assert error_code(console, "system.factoryReset", {"force": 1}) == "invalid_argument"
    elapsed = time.monotonic() - started
    grown = console.call("system.info")["uptime"] - uptime
    assert grown >= elapsed - 2.0, "the board restarted"


def test_log_lines_start_with_hash(fresh: list[str]) -> None:
    banners = [i for i, line in enumerate(fresh) if line.startswith("# latchkey 0.1.0 board=")]
    assert banners, "the boot banner was not seen after the restart"
    after = [line for line in fresh[banners[-1] :] if line]
    unprefixed = [line for line in after if not line.startswith("#") and not is_json_object(line)]
    assert unprefixed == []
    assert sum(line.startswith("# ") for line in after) >= 5


def test_rejects_malformed_requests(console: Console, fresh: list[str]) -> None:
    assert console.request_raw("this is not json")["error"]["code"] == "bad_request"
    assert console.request_raw('["system.info"]')["error"]["code"] == "bad_request"
    assert console.request_raw("x" * 3000)["error"]["code"] == "bad_request"
    assert console.request_raw('{"id":null,"method":7}')["error"]["code"] == "bad_request"
    reply = console.request_raw('{"id":null,"method":"system.info","params":[1]}')
    assert reply["error"]["code"] == "invalid_argument"
    assert error_code(console, "no.such.method") == "unknown_method"
    assert error_code(console, "system.time.set", {"utc": "soon"}) == "invalid_argument"
    assert error_code(console, "system.setup", {"password": "long enough password"}) == "invalid_argument"
    assert console.call("system.info")["claimed"] is False


def test_rejects_deep_nesting_and_keeps_answering(console: Console) -> None:
    started = time.monotonic()
    uptime = console.call("system.info")["uptime"]
    assert console.request_raw("[" * 1500)["error"]["code"] == "bad_request"
    nine_deep = '{"id":null,"method":"system.info","params":' + '{"a":' * 7 + "{}" + "}" * 7 + "}"
    assert console.request_raw(nine_deep)["error"]["code"] == "bad_request"
    eight_deep = '{"id":null,"method":"system.info","params":' + '{"a":' * 6 + "{}" + "}" * 6 + "}"
    assert console.request_raw(eight_deep)["result"]["chip"] in BOARDS
    elapsed = time.monotonic() - started
    grown = console.call("system.info")["uptime"] - uptime
    assert grown >= elapsed - 2.0, "the board restarted"


def test_string_ids_are_echoed(console: Console) -> None:
    reply = console.request_raw('{"id":"abc","method":"system.info"}', reply_id="abc")
    assert reply["result"]["chip"] in BOARDS


def test_time_set_marks_clock_synced(console: Console, fresh: list[str]) -> None:
    assert console.call("system.info")["time"]["synced"] is False
    assert error_code(console, "system.time.set", {"utc": MIN_UTC - 1}) == "invalid_argument"
    assert error_code(console, "system.time.set", {"utc": 1.5e9 + 0.5}) == "invalid_argument"
    now = int(time.time())
    assert console.call("system.time.set", {"utc": now}) == {}
    info = console.call("system.info")
    assert info["time"]["synced"] is True
    assert abs(info["time"]["utc"] - now) <= 5


def test_setup_returns_otpauth_once(
    console: Console, fresh: list[str], secrets: dict[str, Any], board_settings: dict[str, Any]
) -> None:
    board = console.call("system.info")["board"]
    short = {**setup_params(secrets, board_settings), "password": "short"}
    assert error_code(console, "system.setup", short) == "invalid_argument"
    bad_ip = {
        "wifi": {**wifi_params(secrets, board_settings), "ip": "300.1.2.3"},
        "password": secrets["owner_password"],
    }
    assert error_code(console, "system.setup", bad_ip) == "invalid_argument"
    claim_secret(console, secrets, board_settings, board)
    assert error_code(console, "system.setup", setup_params(secrets, board_settings)) == "already_claimed"
    info = console.call("system.info")
    assert info["claimed"] is True
    assert info["wifi"]["configured"] is True


def test_time_zone_sets_the_local_time(console: Console, fresh: list[str]) -> None:
    assert console.call("system.timezone.get") == {"tz": "UTC0", "utcOffset": None}
    set_clock(console)
    assert console.call("system.timezone.get") == {"tz": "UTC0", "utcOffset": 0}
    assert_local_time(console.call("system.info"), "UTC0", 0)
    assert console.call("system.timezone.set", {"tz": "BRT3"}) == {"tz": "BRT3", "utcOffset": -10800}
    assert_local_time(console.call("system.info"), "BRT3", -10800)
    assert console.call("system.timezone.set", {"tz": CET}) == {"tz": CET, "utcOffset": paris_offset()}
    assert_local_time(console.call("system.info"), CET, paris_offset())
    for bad in ("garbage", "CET-1CEST", "BRT3 ", "", 5, None):
        assert error_code(console, "system.timezone.set", {"tz": bad}) == "invalid_argument"
    assert error_code(console, "system.timezone.set", {}) == "invalid_argument"
    assert console.call("system.timezone.get")["tz"] == CET
    info = console.call_and_wait_restart("system.reboot")
    assert info["timezone"] == CET
    assert info["localTime"] is None
    assert console.call("system.timezone.get") == {"tz": CET, "utcOffset": None}
    set_clock(console)
    assert console.call("system.timezone.get") == {"tz": CET, "utcOffset": paris_offset()}


def test_audit_lists_actions_without_secrets(
    console: Console, fresh: list[str], secrets: dict[str, Any], board_settings: dict[str, Any]
) -> None:
    assert error_code(console, "system.time.set", {"utc": MIN_UTC - 1}) == "invalid_argument"
    assert console.call("system.time.set", {"utc": int(time.time())}) == {}
    short = {**setup_params(secrets, board_settings), "password": "short"}
    assert error_code(console, "system.setup", short) == "invalid_argument"
    claim_secret(console, secrets, board_settings, console.call("system.info")["board"])
    assert error_code(console, "system.setup", setup_params(secrets, board_settings)) == "already_claimed"
    entries = audit_entries(console)
    actions = [(entry["method"], entry["result"]) for entry in reversed(entries)]
    assert actions == [
        ("system.factoryReset", "ok"),
        ("system.time.set", "invalid_argument"),
        ("system.time.set", "ok"),
        ("system.setup", "invalid_argument"),
        ("system.setup", "ok"),
        ("system.setup", "already_claimed"),
    ]
    assert {entry["source"] for entry in entries} == {"serial"}
    assert all(set(entry) == {"seq", "time", "source", "method", "target", "result"} for entry in entries)
    seqs = [entry["seq"] for entry in entries]
    assert seqs == sorted(seqs, reverse=True)
    assert entries[0]["time"] >= MIN_UTC
    clean = holds_no_secret(json.dumps(entries), secrets)
    assert clean, "an audit entry contains a secret"
    appended = [event["data"] for event in console.events if event.get("event") == "audit.appended"]
    assert [(data["method"], data["result"]) for data in appended] == actions
    clean_events = holds_no_secret(json.dumps(console.events), secrets)
    assert clean_events, "an event contains a secret"


def test_joins_wifi_with_static_ip_after_reboot(
    console: Console, claimed: bytes, secrets: dict[str, Any], board_settings: dict[str, Any]
) -> None:
    console.call_and_wait_restart("system.reboot")
    info = console.wait_info(lambda state: state["wifi"]["connected"], 45.0, "wifi to connect")
    same_ssid = info["wifi"]["ssid"] == secrets["wifi_ssid"]
    assert same_ssid, "board joined a different SSID"
    same_ip = info["wifi"]["ip"] == board_settings["static_ip"]
    assert same_ip, "board does not use its static IP"
    assert -100 < info["wifi"]["rssi"] < 0
    assert info["claimed"] is True
    output = "\n".join(line for line in console.lines if not is_json_object(line))
    clean = holds_no_secret(output, secrets)
    assert clean, "the console printed a secret"


def test_sntp_syncs_after_joining(console: Console, online: dict[str, Any]) -> None:
    info = console.wait_info(lambda state: state["time"]["synced"], 60.0, "SNTP to sync")
    assert abs(info["time"]["utc"] - time.time()) <= SYNC_TOLERANCE_S


def test_wifi_set_validates_and_reconnects(
    console: Console, online: dict[str, Any], secrets: dict[str, Any], board_settings: dict[str, Any]
) -> None:
    params = wifi_params(secrets, board_settings)
    assert error_code(console, "system.wifi.set", {**params, "netmask": "255.0.255.0"}) == "invalid_argument"
    assert error_code(console, "system.wifi.set", {**params, "ssid": ""}) == "invalid_argument"
    assert error_code(console, "system.wifi.set", {**params, "password": "short"}) == "invalid_argument"
    assert console.call("system.wifi.set", params) == {}
    info = console.wait_info(lambda state: state["wifi"]["connected"], 45.0, "wifi to reconnect")
    same_ip = info["wifi"]["ip"] == board_settings["static_ip"]
    assert same_ip, "board does not use its static IP"


def test_audit_keeps_the_last_200_entries(console: Console, fresh: list[str]) -> None:
    now = int(time.time())
    for _ in range(AUDIT_CAPACITY + 5):
        assert console.call("system.time.set", {"utc": now}) == {}
    entries = audit_entries(console)
    assert len(entries) == AUDIT_CAPACITY
    seqs = [entry["seq"] for entry in entries]
    assert seqs == list(range(seqs[0], seqs[0] - AUDIT_CAPACITY, -1))
    assert all(entry["method"] == "system.time.set" for entry in entries)
    first_page = console.call("audit.list", {"limit": 3})
    assert [entry["seq"] for entry in first_page["entries"]] == seqs[:3]
    assert first_page["next"] == seqs[2]
    assert first_page["more"] is True
    assert [entry["seq"] for entry in console.call("audit.list")["entries"]] == seqs[:50]
    assert error_code(console, "audit.list", {"limit": 0}) == "invalid_argument"
    assert error_code(console, "audit.list", {"limit": 51}) == "invalid_argument"
    nvs = console.call("system.info")["nvs"]
    assert nvs["availableEntries"] >= NVS_HEADROOM_ENTRIES


def certificate(console: Console, what: str) -> str:
    return console.wait_info(lambda state: state["certFingerprint"] is not None, 60.0, what)["certFingerprint"]


def test_factory_reset_unclaims_and_a_new_claim_gets_a_new_secret_and_certificate(
    console: Console, claimed: bytes, secrets: dict[str, Any], board_settings: dict[str, Any]
) -> None:
    first = certificate(console, "the HTTPS certificate")
    info = console.call_and_wait_restart("system.factoryReset")
    assert info["claimed"] is False
    assert info["wifi"]["configured"] is False
    assert info["certFingerprint"] is None
    assert [entry["method"] for entry in audit_entries(console)] == ["system.factoryReset"]
    second = claim_secret(console, secrets, board_settings, info["board"])
    different = second != claimed
    assert different, "a new claim reused the previous TOTP secret"
    assert certificate(console, "a new HTTPS certificate") != first
