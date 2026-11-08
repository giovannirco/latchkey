# SPDX-License-Identifier: GPL-3.0-or-later
"""system.* and audit.list over the USB serial console of a real board."""

from __future__ import annotations

import base64
import json
import re
import time
from typing import Any

import pytest
from latchkey_cli import Console

OTPAUTH = re.compile(
    r"otpauth://totp/Latchkey:(?P<board>[a-z0-9-]+)\?secret=(?P<secret>[A-Z2-7]{32})"
    r"&issuer=Latchkey&algorithm=SHA1&digits=6&period=30"
)
BOARDS = {"esp32": ("esp32-devkit", 0), "esp32s3": ("esp32s3-atom", 41)}
AUDIT_CAPACITY = 200
MIN_UTC = 1704067200
SYNC_TOLERANCE_S = 10
NVS_HEADROOM_ENTRIES = 500
claims: list[bytes] = []


def wifi_params(secrets: dict[str, Any], board: dict[str, Any]) -> dict[str, Any]:
    return {
        "ssid": secrets["wifi_ssid"],
        "password": secrets["wifi_password"],
        "ip": board["static_ip"],
        "gateway": secrets["gateway"],
        "netmask": secrets["netmask"],
        "dns": secrets["dns"],
    }


def setup_params(secrets: dict[str, Any], board: dict[str, Any]) -> dict[str, Any]:
    return {"wifi": wifi_params(secrets, board), "password": secrets["owner_password"]}


def error_code(console: Console, method: str, params: dict[str, Any] | None = None) -> str | None:
    reply = console.request(method, params, timeout=30.0)
    return reply.get("error", {}).get("code")


def claim_secret(console: Console, secrets: dict[str, Any], board: dict[str, Any], expected_board: str) -> bytes:
    result = console.call("system.setup", setup_params(secrets, board), timeout=30.0)
    only_otpauth = set(result) == {"otpauth"}
    assert only_otpauth, "system.setup returned more than the otpauth URI"
    match = OTPAUTH.fullmatch(result["otpauth"])
    shaped = match is not None
    assert shaped, "otpauth URI does not have the expected shape"
    assert match["board"] == expected_board
    secret = base64.b32decode(match["secret"])
    length = len(secret)
    assert length == 20
    nonzero = any(secret)
    assert nonzero, "TOTP secret is all zeros"
    return secret


def holds_no_secret(text: str, secrets: dict[str, Any]) -> bool:
    needles = [secrets["owner_password"], secrets["wifi_password"]]
    needles += [base64.b32encode(secret).decode() for secret in claims]
    return not any(needle in text for needle in needles)


def audit_entries(console: Console) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    before = None
    while True:
        params: dict[str, Any] = {"limit": 50}
        if before is not None:
            params["before"] = before
        page = console.call("audit.list", params)
        entries += page["entries"]
        before = page["next"]
        if before is None:
            return entries


@pytest.fixture(scope="module")
def fresh(console: Console) -> list[str]:
    console.wait_ready()
    console.lines.clear()
    console.events.clear()
    console.call_and_wait_restart("system.factoryReset")
    return list(console.lines)


def test_info_reports_identity(console: Console, fresh: list[str]) -> None:
    info = console.call("system.info")
    assert info["chip"] in BOARDS
    board, button = BOARDS[info["chip"]]
    assert info["board"] == board
    assert info["firmware"] == "0.1.0"
    assert re.fullmatch(r"\d+\.\d+\.\d+", info["idf"])
    assert info["heap"]["free"] > 50_000
    assert 0 < info["heap"]["min_free"] <= info["heap"]["free"]
    assert info["uptime_ms"] > 0
    assert info["claimed"] is False
    assert info["wifi"] == {"configured": False, "connected": False, "ssid": None, "ip": None, "rssi": None}
    assert info["button"]["gpio"] == button
    assert info["time_synced"] is False
    assert info["utc"] is None


def is_json_object(line: str) -> bool:
    try:
        return isinstance(json.loads(line), dict)
    except ValueError:
        return False


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
    assert reply["error"]["code"] == "invalid_params"
    assert error_code(console, "no.such.method") == "unknown_method"
    assert error_code(console, "system.time.set", {"utc": "soon"}) == "invalid_params"
    assert error_code(console, "system.setup", {"password": "long enough password"}) == "invalid_params"
    assert console.call("system.info")["claimed"] is False


def test_string_ids_are_echoed(console: Console, fresh: list[str]) -> None:
    reply = console.request_raw('{"id":"abc","method":"system.info"}', reply_id="abc")
    assert reply["result"]["chip"] in BOARDS


def test_time_set_marks_clock_synced(console: Console, fresh: list[str]) -> None:
    assert console.call("system.info")["time_synced"] is False
    assert error_code(console, "system.time.set", {"utc": MIN_UTC - 1}) == "invalid_params"
    assert error_code(console, "system.time.set", {"utc": 1.5e9 + 0.5}) == "invalid_params"
    now = int(time.time())
    assert console.call("system.time.set", {"utc": now}) == {}
    info = console.call("system.info")
    assert info["time_synced"] is True
    assert abs(info["utc"] - now) <= 5


def test_setup_returns_otpauth_once(
    console: Console, fresh: list[str], secrets: dict[str, Any], board_settings: dict[str, Any]
) -> None:
    board = console.call("system.info")["board"]
    assert error_code(console, "system.setup", {**setup_params(secrets, board_settings), "password": "short"}) == (
        "invalid_params"
    )
    bad_ip = {
        "wifi": {**wifi_params(secrets, board_settings), "ip": "300.1.2.3"},
        "password": secrets["owner_password"],
    }
    assert error_code(console, "system.setup", bad_ip) == "invalid_params"
    claims.append(claim_secret(console, secrets, board_settings, board))
    assert error_code(console, "system.setup", setup_params(secrets, board_settings)) == "already_claimed"
    info = console.call("system.info")
    assert info["claimed"] is True
    assert info["wifi"]["configured"] is True


def test_audit_lists_actions_without_secrets(console: Console, fresh: list[str], secrets: dict[str, Any]) -> None:
    entries = audit_entries(console)
    actions = [(entry["method"], entry["result"]) for entry in reversed(entries)]
    assert actions == [
        ("system.factoryReset", "ok"),
        ("system.time.set", "invalid_params"),
        ("system.setup", "invalid_params"),
        ("system.time.set", "invalid_params"),
        ("system.time.set", "invalid_params"),
        ("system.time.set", "ok"),
        ("system.setup", "invalid_params"),
        ("system.setup", "invalid_params"),
        ("system.setup", "ok"),
        ("system.setup", "already_claimed"),
    ]
    assert {entry["origin"] for entry in entries} == {"serial"}
    assert all(set(entry) == {"seq", "utc", "origin", "method", "target", "result"} for entry in entries)
    seqs = [entry["seq"] for entry in entries]
    assert seqs == sorted(seqs, reverse=True)
    assert entries[0]["utc"] >= MIN_UTC
    clean = holds_no_secret(json.dumps(entries), secrets)
    assert clean, "an audit entry contains a secret"
    appended = [event["data"] for event in console.events if event.get("event") == "audit.appended"]
    assert [(data["method"], data["result"]) for data in appended][-2:] == [
        ("system.setup", "ok"),
        ("system.setup", "already_claimed"),
    ]
    clean_events = holds_no_secret(json.dumps(console.events), secrets)
    assert clean_events, "an event contains a secret"


def test_joins_wifi_with_static_ip_after_reboot(
    console: Console, fresh: list[str], secrets: dict[str, Any], board_settings: dict[str, Any]
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


def test_sntp_syncs_after_joining(console: Console, fresh: list[str]) -> None:
    info = console.wait_info(lambda state: state["time_synced"], 60.0, "SNTP to sync")
    assert abs(info["utc"] - time.time()) <= SYNC_TOLERANCE_S


def test_wifi_set_validates_and_reconnects(
    console: Console, fresh: list[str], secrets: dict[str, Any], board_settings: dict[str, Any]
) -> None:
    params = wifi_params(secrets, board_settings)
    assert error_code(console, "system.wifi.set", {**params, "netmask": "255.0.255.0"}) == "invalid_params"
    assert error_code(console, "system.wifi.set", {**params, "ssid": ""}) == "invalid_params"
    assert error_code(console, "system.wifi.set", {**params, "password": "short"}) == "invalid_params"
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
    assert error_code(console, "audit.list", {"limit": 0}) == "invalid_params"
    assert error_code(console, "audit.list", {"limit": 51}) == "invalid_params"
    nvs = console.call("system.info")["nvs"]
    assert nvs["available_entries"] >= NVS_HEADROOM_ENTRIES


def test_factory_reset_unclaims_and_a_new_claim_gets_a_new_secret(
    console: Console, fresh: list[str], secrets: dict[str, Any], board_settings: dict[str, Any]
) -> None:
    info = console.call_and_wait_restart("system.factoryReset")
    assert info["claimed"] is False
    assert info["wifi"]["configured"] is False
    assert [entry["method"] for entry in audit_entries(console)] == ["system.factoryReset"]
    claims.append(claim_secret(console, secrets, board_settings, info["board"]))
    different = claims[-1] != claims[-2]
    assert different, "a new claim reused the previous TOTP secret"
