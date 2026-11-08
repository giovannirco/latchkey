# SPDX-License-Identifier: GPL-3.0-or-later
"""auth.* and parameter errors over the USB serial console of a real board.

Serial logins pass dryRun: they run every check of a web login, the rate limit included, and open no
session. The owner fixture claims the board on a Wi-Fi network that does not exist, so the clock stays
unset until a test sets it with system.time.set.
"""

from __future__ import annotations

import json
import time
from typing import Any

import pytest
from board import error_code, is_json_object, set_clock
from latchkey_cli import Console
from owner import Private, claim_secret, holds_no_secret, otpauth_secret, totp_code

OFFLINE_WIFI = {"ssid": "latchkey-hil-offline", "password": "not-a-real-network"}
LOGIN_TIMEOUT_S = 30.0
FREE_FAILURES = 4
FIRST_WAIT_S = 30
OTHER_PASSWORD = Private("another owner password")
WRONG_PASSWORD = Private("not the owner password")
DOCUMENTATION_MAC = "00:00:5E:00:53:99"


@pytest.fixture
def owner(console: Console, fresh: list[str], secrets: dict[str, Any], board_settings: dict[str, Any]) -> bytes:
    return claim_secret(console, secrets, board_settings, console.call("system.info")["board"], OFFLINE_WIFI)


def login(console: Console, password: str, code: str) -> dict[str, Any]:
    params = {"password": password, "totp": code, "dryRun": True}
    return console.request("auth.login", params, timeout=LOGIN_TIMEOUT_S)


def outcome(reply: dict[str, Any]) -> Any:
    return reply["error"]["code"] if "error" in reply else reply.get("result")


def test_login_needs_the_password_and_a_fresh_code(console: Console, owner: bytes, secrets: dict[str, Any]) -> None:
    now = set_clock(console)
    password = secrets["owner_password"]
    current = totp_code(owner, now)
    assert outcome(login(console, password, current)) == {"ok": True}
    assert outcome(login(console, password, current)) == "unauthorized"
    assert outcome(login(console, password, totp_code(owner, now, 10))) == "unauthorized"
    following = totp_code(owner, now, 1)
    assert outcome(login(console, WRONG_PASSWORD, following)) == "unauthorized"
    assert outcome(login(console, password, following)) == {"ok": True}
    entries = console.call("audit.list", {"limit": 5})["entries"]
    assert [(entry["method"], entry["origin"], entry["result"]) for entry in reversed(entries)] == [
        ("auth.login", "serial", "ok"),
        ("auth.login", "serial", "unauthorized"),
        ("auth.login", "serial", "unauthorized"),
        ("auth.login", "serial", "unauthorized"),
        ("auth.login", "serial", "ok"),
    ]


def test_malformed_logins_are_refused_without_counting(console: Console, owner: bytes, secrets: dict[str, Any]) -> None:
    now = set_clock(console)
    password = secrets["owner_password"]
    code = totp_code(owner, now)
    malformed = [
        {"password": password, "totp": code},
        {"password": password, "totp": code, "dryRun": False},
        {"password": password, "totp": code, "dryRun": "yes"},
        {"password": password, "totp": code[:5], "dryRun": True},
        {"password": password, "totp": int(code), "dryRun": True},
        {"totp": code, "dryRun": True},
        {"password": "", "totp": code, "dryRun": True},
    ]
    for params in malformed:
        reply = console.request("auth.login", params, timeout=LOGIN_TIMEOUT_S)
        assert outcome(reply) == "invalid_argument"
    assert outcome(login(console, password, code)) == {"ok": True}


def test_codes_wait_for_the_clock(console: Console, owner: bytes, secrets: dict[str, Any]) -> None:
    assert console.call("system.info")["time_synced"] is False
    password = secrets["owner_password"]
    assert outcome(login(console, password, totp_code(owner, time.time()))) == "time_unsynced"
    now = set_clock(console)
    assert outcome(login(console, password, totp_code(owner, now))) == {"ok": True}


def test_five_failures_start_a_wait_that_a_reboot_keeps(
    console: Console, owner: bytes, secrets: dict[str, Any]
) -> None:
    now = set_clock(console)
    password = secrets["owner_password"]
    for _ in range(FREE_FAILURES + 1):
        assert outcome(login(console, password, totp_code(owner, now, 10))) == "unauthorized"
    blocked = login(console, password, totp_code(owner, now))
    assert outcome(blocked) == "rate_limited"
    assert 0 < blocked["error"]["retryAfter"] <= FIRST_WAIT_S
    console.call_and_wait_restart("system.reboot")
    rebooted = login(console, password, totp_code(owner, time.time()))
    assert outcome(rebooted) == "rate_limited"
    assert 0 < rebooted["error"]["retryAfter"] <= FIRST_WAIT_S
    time.sleep(rebooted["error"]["retryAfter"] + 1)
    now = set_clock(console)
    assert outcome(login(console, password, totp_code(owner, now))) == {"ok": True}
    assert outcome(login(console, password, totp_code(owner, now, 10))) == "unauthorized"
    entries = console.call("audit.list", {"limit": 50})["entries"]
    results = [entry["result"] for entry in entries if entry["method"] == "auth.login"]
    assert results == ["unauthorized", "ok"] + ["unauthorized"] * (FREE_FAILURES + 1)


def test_change_password_needs_the_current_one(console: Console, owner: bytes, secrets: dict[str, Any]) -> None:
    now = set_clock(console)
    password = secrets["owner_password"]
    wrong = {"current": WRONG_PASSWORD, "new": OTHER_PASSWORD}
    assert error_code(console, "auth.changePassword", wrong) == "invalid_argument"
    assert error_code(console, "auth.changePassword", {"current": password, "new": "too short"}) == "invalid_argument"
    assert error_code(console, "auth.changePassword", {"current": password}) == "invalid_argument"
    changed = console.call("auth.changePassword", {"current": password, "new": OTHER_PASSWORD}, LOGIN_TIMEOUT_S)
    assert changed == {}
    code = totp_code(owner, now)
    assert outcome(login(console, password, code)) == "unauthorized"
    assert outcome(login(console, OTHER_PASSWORD, code)) == {"ok": True}


def test_rotating_the_totp_secret_retires_the_old_one(console: Console, owner: bytes, secrets: dict[str, Any]) -> None:
    now = set_clock(console)
    password = secrets["owner_password"]
    result = console.call("auth.rotateTotp", timeout=LOGIN_TIMEOUT_S)
    only_otpauth = set(result) == {"otpauth"}
    assert only_otpauth, "auth.rotateTotp returned more than the otpauth URI"
    rotated = otpauth_secret(result["otpauth"], console.call("system.info")["board"])
    different = rotated != owner
    assert different, "auth.rotateTotp kept the old secret"
    assert outcome(login(console, password, totp_code(owner, now))) == "unauthorized"
    assert outcome(login(console, password, totp_code(rotated, now))) == {"ok": True}


def test_serial_has_no_session_of_its_own(console: Console, owner: bytes) -> None:
    assert console.call("auth.sessions") == {"sessions": []}
    assert error_code(console, "auth.revoke", {"id": "1"}) == "invalid_argument"
    assert error_code(console, "auth.revoke", {"id": 1}) == "invalid_argument"
    assert error_code(console, "auth.revoke", {}) == "invalid_argument"
    assert console.call("auth.logout", {"all": True}) == {}
    assert error_code(console, "auth.logout", {}) == "invalid_argument"
    assert error_code(console, "auth.logout", {"all": "yes"}) == "invalid_argument"


def test_bad_parameters_answer_invalid_argument_everywhere(console: Console, fresh: list[str]) -> None:
    cases = [
        ("system.time.set", {"utc": "soon"}),
        ("system.time.set", {}),
        ("system.wifi.set", {"ssid": ""}),
        ("system.setup", {"password": "long enough password"}),
        ("system.factoryReset", {"force": "yes"}),
        ("system.log.set", {"tag": "rpc"}),
        ("system.timezone.set", {"tz": "garbage"}),
        ("audit.list", {"limit": 0}),
        ("audit.list", {"before": "x"}),
        ("auth.changePassword", {"current": "x"}),
        ("auth.revoke", {}),
        ("lock.status", {}),
        ("lock.status", {"lock": "not-a-mac"}),
        ("locks.scan", {"seconds": 31}),
        ("locks.pair", {"mac": DOCUMENTATION_MAC, "wait": 0}),
        ("locks.rename", {"lock": DOCUMENTATION_MAC, "name": ""}),
    ]
    codes = [(method, error_code(console, method, params)) for method, params in cases]
    assert codes == [(method, "invalid_argument") for method, _ in cases]
    reply = console.request_raw('{"id":null,"method":"system.info","params":[1]}')
    assert reply["error"]["code"] == "invalid_argument"
    assert console.call("system.info")["claimed"] is False


def test_no_secret_reaches_the_console(console: Console, owner: bytes, secrets: dict[str, Any]) -> None:
    now = set_clock(console)
    password = secrets["owner_password"]
    assert outcome(login(console, password, totp_code(owner, now))) == {"ok": True}
    assert outcome(login(console, WRONG_PASSWORD, totp_code(owner, now, 1))) == "unauthorized"
    changed = console.call("auth.changePassword", {"current": password, "new": OTHER_PASSWORD}, LOGIN_TIMEOUT_S)
    assert changed == {}
    rotated = console.call("auth.rotateTotp", timeout=LOGIN_TIMEOUT_S)["otpauth"]
    otpauth_secret(rotated, console.call("system.info")["board"])
    extra = (OTHER_PASSWORD, WRONG_PASSWORD)
    output = "\n".join(line for line in console.lines if not is_json_object(line))
    clean_output = holds_no_secret(output, secrets, extra)
    assert clean_output, "the console printed a secret"
    clean_events = holds_no_secret(json.dumps(console.events), secrets, extra)
    assert clean_events, "an event contains a secret"
    entries = console.call("audit.list", {"limit": 50})["entries"]
    clean_audit = holds_no_secret(json.dumps(entries), secrets, extra)
    assert clean_audit, "an audit entry contains a secret"
