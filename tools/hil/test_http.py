# SPDX-License-Identifier: GPL-3.0-or-later
"""HTTPS, the port-80 redirect, the session cookie, CSRF checks, WebSocket events, web jobs and the button
confirmation, against a real board through a relay host on its network (relay.py).

Skipped without the hil_relay key in secrets.local.json. The board must be claimed on the real Wi-Fi: the
suite claims it only when it is not and holds neither lock keys nor an owner login. A board whose entry in
secrets.local.json has a totp_uri belongs to its owner: the suite computes codes from that URI and never
rotates, changes or resets anything there. Any other board gets a fresh TOTP secret from auth.rotateTotp over
the USB console (physical presence), kept in memory only. Nobody may press the board button while the
confirmation test runs.
"""

from __future__ import annotations

import base64
import gzip
import json
import re
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import build_web
import pytest
from board import is_json_object
from latchkey_cli import Console
from owner import Private, claim_secret, holds_no_secret, otpauth_secret, totp_code
from relay import Relay, body, header, headers, json_body

WEB_DIR = Path(__file__).resolve().parents[2] / "web"
DOCUMENTATION_MAC = "00:00:5E:00:53:99"
FOREIGN_ORIGIN = "https://attacker.example"
OTHER_PASSWORD = Private("another owner password")
STATES = {"locked", "unlocked"}
CONFIRM_TIMEOUT_MS = 30000
SESSION_COOKIE = re.compile(r"lk_session=([0-9a-f]{64}); Path=/; Secure; HttpOnly; SameSite=Strict")
CLEARED_COOKIE = "lk_session=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict"
AUDIT_KEYS = {"seq", "time", "source", "method", "target", "result"}
MIN_FREE_HEAP = 30_000
TOTP_STEP_S = 30
SAFE_STEP_WINDOW = (2.0, 24.0)
LOCK_JOB_S = 150
VALUE_HEAVY_REQUESTS = 12
STALLED_HANDSHAKE_LIMIT_MS = 7000
SECURITY_HEADERS = ("content-security-policy", "x-frame-options", "referrer-policy", "x-content-type-options")
seen_tokens: list[str] = []


class Codes:
    """Hands out TOTP codes for strictly increasing steps, away from step boundaries."""

    def __init__(self, secret: bytes) -> None:
        self.secret = secret
        self.last: int | None = None

    def next(self) -> str:
        while True:
            position = time.time() % TOTP_STEP_S
            if not SAFE_STEP_WINDOW[0] <= position <= SAFE_STEP_WINDOW[1]:
                time.sleep((SAFE_STEP_WINDOW[0] - position) % TOTP_STEP_S + 0.1)
                continue
            current = int(time.time()) // TOTP_STEP_S
            step = current - 1 if self.last is None else max(self.last + 1, current - 1)
            if step <= current + 1:
                self.last = step
                return totp_code(self.secret, step * TOTP_STEP_S)
            time.sleep(TOTP_STEP_S - position + SAFE_STEP_WINDOW[0])


@dataclass
class Login:
    cookie: str
    set_cookie: str
    reply: dict[str, Any]


def rpc_step(method: str, params: dict[str, Any] | None = None, cookie: str | None = None, **extra: Any) -> dict:
    request_headers = {"Content-Type": "application/json", **extra.pop("headers", {})}
    if cookie is not None:
        request_headers["Cookie"] = cookie
    payload = json.dumps({"id": 1, "method": method, "params": params or {}})
    return {"type": "http", "method": "POST", "path": "/api/rpc", "headers": request_headers, "body": payload, **extra}


def session_cookie(set_cookie: str) -> str:
    match = SESSION_COOKIE.fullmatch(set_cookie)
    shaped = match is not None
    assert shaped, "Set-Cookie does not have the expected value and attributes"
    seen_tokens.append(Private(match.group(1)))
    return Private(f"lk_session={match.group(1)}")


def rpc(relay: Relay, method: str, params: dict[str, Any] | None = None, cookie: str | None = None) -> dict:
    result = relay.step(rpc_step(method, params, cookie), timeout_s=60)
    assert result.get("status") == 200, result.get("error")
    return json_body(result)


def login(relay: Relay, codes: Codes, secrets: dict[str, Any], password: str | None = None) -> Login:
    params = {"password": password or secrets["owner_password"], "totp": codes.next()}
    result = relay.step(rpc_step("auth.login", params), timeout_s=60)
    assert result.get("status") == 200, result.get("error")
    set_cookies = headers(result, "set-cookie")
    assert len(set_cookies) == 1
    return Login(session_cookie(set_cookies[0]), set_cookies[0], json_body(result))


def last_audit_seq(console: Console) -> int:
    entries = console.call("audit.list", {"limit": 1})["entries"]
    return entries[0]["seq"] if entries else 0


def events_named(result: dict[str, Any], name: str) -> list[dict[str, Any]]:
    return [event.get("data", {}) for event in result.get("events", []) if event.get("event") == name]


def der_items(data: bytes, offset: int, end: int) -> list[tuple[int, int, int]]:
    items = []
    while offset < end:
        tag = data[offset]
        size = data[offset + 1]
        start = offset + 2
        if size & 0x80:
            count = size & 0x7F
            size = int.from_bytes(data[start : start + count], "big")
            start += count
        items.append((tag, start, start + size))
        offset = start + size
    return items


def validity(der: bytes) -> tuple[str, str]:
    _, start, end = der_items(der, 0, len(der))[0]
    _, start, end = der_items(der, start, end)[0]
    fields = der_items(der, start, end)
    window = fields[4] if fields[0][0] == 0xA0 else fields[3]
    times = der_items(der, window[1], window[2])
    texts = [der[begin:finish].decode() for _, begin, finish in times]
    return tuple("20" + text if tag == 0x17 else text for (tag, _, _), text in zip(times, texts))


def secure_headers_present(result: dict[str, Any], policy: str) -> bool:
    expected = {
        "content-security-policy": policy,
        "x-frame-options": "DENY",
        "referrer-policy": "no-referrer",
        "x-content-type-options": "nosniff",
        "cache-control": "no-store",
    }
    return all(header(result, name) == value for name, value in expected.items())


@pytest.fixture(scope="module")
def relay(secrets: dict[str, Any], board_settings: dict[str, Any]) -> Relay:
    settings = secrets.get("hil_relay")
    if not settings:
        pytest.skip("secrets.local.json has no hil_relay")
    return Relay(list(settings["command"]), int(settings.get("timeout_s", 150)), board_settings["static_ip"])


@pytest.fixture(scope="module")
def origin(board_settings: dict[str, Any]) -> str:
    return Private(f"https://{board_settings['static_ip']}")


@pytest.fixture(scope="module")
def codes(console: Console, relay: Relay, secrets: dict[str, Any], board_settings: dict[str, Any]) -> Codes:
    info = console.wait_ready()
    owned = board_settings.get("totp_uri")
    online = info["claimed"] and info["wifi"]["connected"] and info["wifi"]["ssid"] == secrets["wifi_ssid"]
    if not online:
        if owned or console.call("locks.list")["locks"]:
            pytest.fail("the board is not online on the real Wi-Fi and holds lock keys or the owner's login")
        console.call_and_wait_restart("system.factoryReset")
        claim_secret(console, secrets, board_settings, info["board"])
        console.wait_info(lambda state: state["wifi"]["connected"], 60.0, "wifi to connect")
    console.wait_info(lambda state: state["time"]["synced"], 90.0, "SNTP to sync")
    console.wait_info(lambda state: state["certFingerprint"] is not None, 60.0, "the HTTPS certificate")
    if owned:
        return Codes(otpauth_secret(owned, info["board"]))
    rotated = console.call("auth.rotateTotp", timeout=30.0)
    return Codes(otpauth_secret(rotated["otpauth"], info["board"]))


@pytest.fixture(scope="module")
def session(relay: Relay, codes: Codes, secrets: dict[str, Any]) -> Login:
    return login(relay, codes, secrets)


def test_the_certificate_has_no_expiry_date(relay: Relay, codes: Codes) -> None:
    page = relay.step({"type": "http", "path": "/"})
    assert page.get("status") == 200, page.get("error")
    assert validity(base64.b64decode(page["certificate_b64"])) == ("20240101000000Z", "99991231235959Z")


def test_https_answers_with_the_board_certificate(console: Console, relay: Relay, codes: Codes) -> None:
    expected = console.call("system.info")["certFingerprint"]
    assert re.fullmatch(r"([0-9A-F]{2}:){31}[0-9A-F]{2}", expected)
    page = relay.step({"type": "http", "path": "/"})
    assert page.get("status") == 200, page.get("error")
    assert page["fingerprint"] == expected
    html = gzip.decompress(body(page)).decode()
    assert "<title>Latchkey</title>" in html
    assert 'http-equiv="Content-Security-Policy"' in html


def test_port_80_only_redirects_to_https(relay: Relay, origin: str) -> None:
    policy = build_web.header_policy(WEB_DIR)
    for path in ("/", "/api/rpc"):
        redirect = relay.step({"type": "http", "tls": False, "path": path})
        assert redirect.get("status") == 301, redirect.get("error")
        same = header(redirect, "location") == f"{origin}/"
        assert same, "the redirect does not point at the board's HTTPS root"
        assert secure_headers_present(redirect, policy)


def test_every_response_carries_the_security_headers(relay: Relay, codes: Codes, session: Login) -> None:
    policy = build_web.header_policy(WEB_DIR)
    assert "frame-ancestors 'none'" in policy
    page, api, missing, wrong_method, foreign, plain, large, no_upgrade = relay.run(
        [
            {"type": "http", "path": "/"},
            rpc_step("system.info"),
            {"type": "http", "path": "/no/such/page"},
            {"type": "http", "method": "POST", "path": "/", "body": ""},
            rpc_step("system.info", cookie=session.cookie, headers={"Origin": FOREIGN_ORIGIN}),
            rpc_step("system.info", cookie=session.cookie, headers={"Content-Type": "text/plain"}),
            rpc_step("system.info", {"pad": "x" * 9000}, session.cookie),
            {"type": "http", "path": "/api/events", "headers": {"Cookie": session.cookie}},
        ]
    )
    for result in (page, api, missing, wrong_method, foreign, plain, large, no_upgrade):
        assert secure_headers_present(result, policy)
    for result in (api, missing, wrong_method, foreign, plain, large, no_upgrade):
        assert header(result, "content-type") == "application/json"
    assert [result["status"] for result in (foreign, plain, large, no_upgrade)] == [403, 415, 413, 426]
    assert header(no_upgrade, "upgrade") == "websocket"
    assert json_body(no_upgrade)["error"]["code"] == "upgrade_required"
    assert header(page, "content-encoding") == "gzip"
    assert header(page, "content-type").startswith("text/html")
    assert header(api, "content-type") == "application/json"
    assert missing["status"] == 404
    assert json_body(missing) == {"id": None, "error": {"code": "not_found", "message": "no such page"}}
    assert wrong_method["status"] == 405
    assert json_body(wrong_method)["error"]["code"] == "method_not_allowed"


def test_login_sets_a_strict_session_cookie(session: Login) -> None:
    result = session.reply["result"]
    assert result["idleTimeout"] == 900
    assert isinstance(result["session"]["id"], str)
    reply = json.dumps(session.reply)
    clean = all(token not in reply for token in seen_tokens) and "lk_session" not in reply
    assert clean, "the login reply carries the session token"


def test_rpc_needs_a_session(console: Console, relay: Relay, codes: Codes) -> None:
    before = last_audit_seq(console)
    for method, params in (("system.info", {}), ("locks.rename", {"lock": DOCUMENTATION_MAC, "name": "x"})):
        reply = rpc(relay, method, params)
        assert reply["error"]["code"] == "unauthorized"
    bogus = Private("lk_session=" + "0" * 64)
    assert rpc(relay, "system.info", {}, bogus)["error"]["code"] == "unauthorized"
    assert last_audit_seq(console) == before


def test_rpc_with_the_session_answers(console: Console, relay: Relay, session: Login) -> None:
    info = rpc(relay, "system.info", {}, session.cookie)["result"]
    assert isinstance(info["uptime"], int) and info["uptime"] > 0
    assert 0 < info["heap"]["minFree"] <= info["heap"]["free"]
    assert info["time"]["synced"] is True
    assert abs(info["time"]["utc"] - time.time()) <= 10
    assert info["certFingerprint"] == console.call("system.info")["certFingerprint"]
    assert info["wifi"]["connected"] is True
    assert {"timezone", "localTime"} <= set(info)
    sessions = rpc(relay, "auth.sessions", {}, session.cookie)["result"]["sessions"]
    current = [entry for entry in sessions if entry["current"]]
    assert len(current) == 1
    assert current[0]["origin"] == "web"
    assert current[0]["id"] == session.reply["result"]["session"]["id"]


def test_cross_origin_and_other_content_types_are_refused(relay: Relay, session: Login, origin: str) -> None:
    foreign, plain, own, large = relay.run(
        [
            rpc_step("system.info", cookie=session.cookie, headers={"Origin": FOREIGN_ORIGIN}),
            rpc_step("system.info", cookie=session.cookie, headers={"Content-Type": "text/plain"}),
            rpc_step("system.info", cookie=session.cookie, headers={"Origin": origin}),
            rpc_step("system.info", {"pad": "x" * 9000}, session.cookie),
        ]
    )
    assert foreign["status"] == 403
    assert json_body(foreign) == {"id": None, "error": {"code": "forbidden", "message": "cross-origin request refused"}}
    assert plain["status"] == 415
    assert json_body(plain)["error"]["code"] == "invalid_argument"
    assert own["status"] == 200
    assert "result" in json_body(own)
    assert large["status"] == 413
    assert json_body(large)["error"]["code"] == "invalid_argument"


def test_serial_only_methods_are_forbidden_from_the_web(relay: Relay, session: Login) -> None:
    for method, params in (
        ("system.time.set", {"utc": int(time.time())}),
        ("system.setup", {}),
        ("system.log.set", {"tag": "rpc", "level": "info"}),
        ("lock.adminPasscode.raw", {"lock": DOCUMENTATION_MAC}),
    ):
        assert rpc(relay, method, params, session.cookie)["error"]["code"] == "forbidden"


def test_events_need_a_session(relay: Relay, session: Login, origin: str) -> None:
    bare, bogus, foreign = relay.run(
        [
            {"type": "ws", "path": "/api/events", "headers": {"Origin": origin}},
            {"type": "ws", "path": "/api/events", "headers": {"Origin": origin, "Cookie": "lk_session=" + "1" * 64}},
            {"type": "ws", "path": "/api/events", "headers": {"Origin": FOREIGN_ORIGIN, "Cookie": session.cookie}},
        ]
    )
    for result in (bare, bogus, foreign):
        assert result.get("status") is None
        assert result.get("closed") is True
        assert result.get("error") == "closed by the board"


def test_host_and_origin_must_name_the_board(relay: Relay, session: Login, origin: str) -> None:
    rebind = "rebind.attacker.example"
    default_port, foreign_host, foreign_events = relay.run(
        [
            rpc_step("system.info", cookie=session.cookie, headers={"Origin": f"{origin}:443"}),
            rpc_step("system.info", cookie=session.cookie, headers={"Host": rebind}),
            {"type": "ws", "path": "/api/events", "headers": {"Host": rebind, "Cookie": session.cookie}},
        ]
    )
    assert "result" in json_body(default_port)
    assert foreign_host["status"] == 403
    assert json_body(foreign_host)["error"]["code"] == "forbidden"
    assert foreign_events.get("closed") is True
    assert foreign_events.get("status") is None


def test_events_arrive_with_the_session(relay: Relay, session: Login, origin: str) -> None:
    started = time.time()
    result = relay.step(
        {
            "type": "ws",
            "path": "/api/events",
            "headers": {"Origin": origin, "Cookie": session.cookie},
            "steps": [rpc_step("locks.rename", {"lock": DOCUMENTATION_MAC, "name": "Bench"}, session.cookie)],
            "until": {"event": "audit.appended"},
            "collect_s": 10,
        }
    )
    assert result.get("status") == 101, result.get("error")
    assert json_body(result["steps"][0])["error"]["code"] == "not_paired"
    appended = [data for data in events_named(result, "audit.appended") if data["method"] == "locks.rename"]
    assert len(appended) == 1
    entry = appended[0]
    assert set(entry) == AUDIT_KEYS
    assert (entry["source"], entry["target"], entry["result"]) == ("web", DOCUMENTATION_MAC, "not_paired")
    assert abs(entry["time"] - started) <= 15


def job_run(relay: Relay, session: Login, origin: str, method: str, params: dict[str, Any], wait_s: int) -> dict:
    result = relay.step(
        {
            "type": "ws",
            "path": "/api/events",
            "headers": {"Origin": origin, "Cookie": session.cookie},
            "steps": [rpc_step(method, params, session.cookie)],
            "until": {"event": "job.done", "job_from": 0},
            "collect_s": wait_s,
        },
        timeout_s=wait_s + 60,
    )
    assert result.get("status") == 101, result.get("error")
    return result


def job_outcome(result: dict[str, Any]) -> dict[str, Any]:
    reply = json_body(result["steps"][0])
    job = reply["result"]["job"]
    assert isinstance(job, str) and job
    done = [data for data in events_named(result, "job.done") if data.get("job") == job]
    assert len(done) == 1, "no job.done for the job"
    return done[0]


def test_lock_methods_reply_with_a_job_and_report_job_done(relay: Relay, session: Login, origin: str) -> None:
    missing = job_outcome(job_run(relay, session, origin, "lock.status", {"lock": DOCUMENTATION_MAC}, 30))
    assert missing["error"]["code"] == "not_paired"
    assert "result" not in missing
    scan = job_outcome(job_run(relay, session, origin, "locks.scan", {"seconds": 3}, 30))
    assert scan["result"] == {"seconds": 3}


def test_a_held_lock_answers_a_job_over_https(
    console: Console, relay: Relay, session: Login, origin: str, lock_mac: str
) -> None:
    if not any(lock["id"] == lock_mac for lock in console.call("locks.list")["locks"]):
        pytest.skip("this board holds no keys for the lock")
    status = job_outcome(job_run(relay, session, origin, "lock.status", {"lock": lock_mac}, LOCK_JOB_S))
    assert status["result"]["state"] in STATES
    synced = job_outcome(job_run(relay, session, origin, "lock.time.sync", {"lock": lock_mac}, LOCK_JOB_S))
    assert abs(synced["result"]["time"] - time.time()) <= 15


def test_a_held_lock_lists_its_passcodes_over_https(
    console: Console, relay: Relay, session: Login, origin: str, lock_mac: str
) -> None:
    if not any(lock["id"] == lock_mac for lock in console.call("locks.list")["locks"]):
        pytest.skip("this board holds no keys for the lock")
    listed = job_outcome(job_run(relay, session, origin, "lock.passcodes.list", {"lock": lock_mac}, LOCK_JOB_S))
    entries = listed["result"]["passcodes"]
    assert isinstance(entries, list)
    assert all("code" not in entry for entry in entries)


def test_button_methods_wait_for_the_board_button(console: Console, relay: Relay, session: Login, origin: str) -> None:
    result = job_run(relay, session, origin, "locks.pair", {"mac": DOCUMENTATION_MAC, "name": "Bench"}, 45)
    required = events_named(result, "confirm.required")
    assert required == [{"action": "locks.pair", "timeoutMs": CONFIRM_TIMEOUT_MS}]
    assert events_named(result, "confirm.result") == [{"action": "locks.pair", "confirmed": False}]
    outcome = job_outcome(result)
    assert outcome["error"]["code"] == "confirm_timeout"
    names = [event["event"] for event in result["events"]]
    assert names.index("confirm.required") < names.index("confirm.result") < names.index("job.done")
    entry = console.call("audit.list", {"limit": 5})["entries"][0]
    assert (entry["method"], entry["source"], entry["result"]) == ("locks.pair", "web", "confirm_timeout")


def test_button_methods_check_their_parameters_before_the_press(
    console: Console, relay: Relay, session: Login, origin: str
) -> None:
    unknown = job_run(relay, session, origin, "lock.factoryReset", {"lock": DOCUMENTATION_MAC}, 20)
    assert job_outcome(unknown)["error"]["code"] == "not_paired"
    malformed = job_run(relay, session, origin, "locks.pair", {"mac": "not-a-mac"}, 20)
    assert job_outcome(malformed)["error"]["code"] == "invalid_argument"
    for result in (unknown, malformed):
        assert events_named(result, "confirm.required") == []
    entries = console.call("audit.list", {"limit": 5})["entries"]
    reset = next(entry for entry in entries if entry["method"] == "lock.factoryReset")
    assert (reset["source"], reset["target"], reset["result"]) == ("web", DOCUMENTATION_MAC, "not_paired")


def test_admin_passcode_methods_check_the_lock_before_the_press(relay: Relay, session: Login, origin: str) -> None:
    for method in ("lock.adminPasscode.get", "lock.adminPasscode.set"):
        result = job_run(relay, session, origin, method, {"lock": DOCUMENTATION_MAC}, 20)
        assert job_outcome(result)["error"]["code"] == "not_paired"
        assert events_named(result, "confirm.required") == []
    chosen = job_run(relay, session, origin, "lock.adminPasscode.set", {"lock": DOCUMENTATION_MAC, "code": "12"}, 20)
    pairing = job_run(relay, session, origin, "locks.pair", {"mac": DOCUMENTATION_MAC, "adminPasscode": "12a4"}, 20)
    for result in (chosen, pairing):
        assert job_outcome(result)["error"]["code"] == "invalid_argument"
        assert events_named(result, "confirm.required") == []


def test_the_reset_button_switch_is_checked_before_the_press(
    console: Console, relay: Relay, session: Login, origin: str, lock_mac: str
) -> None:
    unknown = job_run(relay, session, origin, "lock.resetButton.set", {"lock": DOCUMENTATION_MAC, "enabled": True}, 20)
    assert job_outcome(unknown)["error"]["code"] == "not_paired"
    assert events_named(unknown, "confirm.required") == []
    if not any(lock["id"] == lock_mac for lock in console.call("locks.list")["locks"]):
        pytest.skip("this board holds no keys for the lock")
    if "reset_button" not in console.call("lock.features", {"lock": lock_mac}, timeout=60.0)["features"]:
        pytest.skip("the lock does not report reset_button")
    off = job_run(relay, session, origin, "lock.resetButton.set", {"lock": lock_mac, "enabled": False}, 20)
    assert job_outcome(off)["error"]["code"] == "backup_required"
    assert events_named(off, "confirm.required") == []
    on = job_run(relay, session, origin, "lock.resetButton.set", {"lock": lock_mac, "enabled": True}, 45)
    assert events_named(on, "confirm.required") == []
    assert job_outcome(on)["error"]["code"] == "unverified"


def test_ending_the_session_ends_its_button_wait(
    relay: Relay, codes: Codes, secrets: dict[str, Any], session: Login, origin: str
) -> None:
    other = login(relay, codes, secrets)
    pair = rpc_step("locks.pair", {"mac": DOCUMENTATION_MAC, "name": "Bench"}, other.cookie)
    result = relay.step(
        {
            "type": "ws",
            "path": "/api/events",
            "headers": {"Origin": origin, "Cookie": session.cookie},
            "steps": [
                pair,
                pair,
                {"type": "sleep", "seconds": 2},
                rpc_step("auth.revoke", {"id": other.reply["result"]["session"]["id"]}, session.cookie),
            ],
            "until": {"event": "audit.appended", "match": {"method": "locks.pair", "result": "unauthorized"}},
            "collect_s": 25,
        },
        timeout_s=90,
    )
    assert result.get("status") == 101, result.get("error")
    first, second, _, revoke = result["steps"]
    assert isinstance(json_body(first)["result"]["job"], str)
    assert json_body(second)["error"]["code"] == "busy"
    assert json_body(revoke) == {"id": 1, "result": {}}
    assert events_named(result, "confirm.required") == [{"action": "locks.pair", "timeoutMs": CONFIRM_TIMEOUT_MS}]
    assert events_named(result, "confirm.result") == [{"action": "locks.pair", "confirmed": False}]
    ended = [
        event
        for event in result["events"]
        if event.get("event") == "audit.appended" and event["data"].get("result") == "unauthorized"
    ]
    assert len(ended) == 1
    assert ended[0]["data"]["method"] == "locks.pair"
    assert ended[0]["at_ms"] - revoke["started_ms"] < 10_000


def test_revoking_a_session_closes_its_event_socket(
    console: Console, relay: Relay, codes: Codes, secrets: dict[str, Any], session: Login, origin: str
) -> None:
    other = login(relay, codes, secrets)
    web = relay.step(
        {
            "type": "ws",
            "path": "/api/events",
            "headers": {"Origin": origin, "Cookie": other.cookie},
            "steps": [rpc_step("auth.revoke", {"id": other.reply["result"]["session"]["id"]}, session.cookie)],
            "collect_s": 8,
        }
    )
    assert web.get("status") == 101, web.get("error")
    assert web["closed"] is True
    third = login(relay, codes, secrets)
    holder: dict[str, Any] = {}

    def hold() -> None:
        holder["result"] = relay.step(
            {
                "type": "ws",
                "path": "/api/events",
                "headers": {"Origin": origin, "Cookie": third.cookie},
                "steps": [{"type": "sleep", "seconds": 25}],
                "collect_s": 0,
            },
            timeout_s=90,
        )

    thread = threading.Thread(target=hold)
    thread.start()
    time.sleep(12)
    assert console.call("auth.revoke", {"id": third.reply["result"]["session"]["id"]}) == {}
    thread.join()
    serial = holder["result"]
    assert serial.get("status") == 101, serial.get("error")
    assert serial["closed"] is True
    assert serial["closed_after_ms"] < 24_000


def test_logout_clears_the_cookie_and_closes_the_events(
    relay: Relay, codes: Codes, secrets: dict[str, Any], origin: str
) -> None:
    other = login(relay, codes, secrets)
    result = relay.step(
        {
            "type": "ws",
            "path": "/api/events",
            "headers": {"Origin": origin, "Cookie": other.cookie},
            "steps": [rpc_step("auth.logout", {}, other.cookie)],
            "collect_s": 5,
        }
    )
    assert result.get("status") == 101, result.get("error")
    logout = result["steps"][0]
    assert json_body(logout) == {"id": 1, "result": {}}
    assert headers(logout, "set-cookie") == [CLEARED_COOKIE]
    assert result["closed"] is True
    assert rpc(relay, "system.info", {}, other.cookie)["error"]["code"] == "unauthorized"


def test_revoking_the_own_session_ends_it(relay: Relay, codes: Codes, secrets: dict[str, Any]) -> None:
    other = login(relay, codes, secrets)
    own = other.reply["result"]["session"]["id"]
    revoked = relay.step(rpc_step("auth.revoke", {"id": own}, other.cookie))
    assert json_body(revoked) == {"id": 1, "result": {}}
    assert headers(revoked, "set-cookie") == [CLEARED_COOKIE]
    assert rpc(relay, "system.info", {}, other.cookie)["error"]["code"] == "unauthorized"


def test_a_password_change_keeps_only_the_callers_session(
    console: Console,
    relay: Relay,
    codes: Codes,
    session: Login,
    secrets: dict[str, Any],
    board_settings: dict[str, Any],
) -> None:
    if board_settings.get("totp_uri"):
        pytest.skip("the owner holds this board's login: no password change here")
    password = secrets["owner_password"]
    other = login(relay, codes, secrets)
    changed = False
    try:
        reply = rpc(relay, "auth.changePassword", {"current": password, "new": OTHER_PASSWORD}, session.cookie)
        changed = reply == {"id": 1, "result": {}}
        assert changed
        assert rpc(relay, "system.info", {}, other.cookie)["error"]["code"] == "unauthorized"
        assert "result" in rpc(relay, "system.info", {}, session.cookie)
        back = rpc(relay, "auth.changePassword", {"current": OTHER_PASSWORD, "new": password}, session.cookie)
        assert back == {"id": 1, "result": {}}
        changed = False
    finally:
        if changed:
            console.call("auth.changePassword", {"current": OTHER_PASSWORD, "new": password}, timeout=30.0)
    assert "result" in rpc(relay, "system.info", {}, session.cookie)


def test_a_value_heavy_request_is_refused_before_parsing(console: Console, relay: Relay, codes: Codes) -> None:
    payload = "[" + ",".join("0" for _ in range(4095)) + "]"
    assert len(payload) <= 8192
    heavy = {
        "type": "http",
        "method": "POST",
        "path": "/api/rpc",
        "headers": {"Content-Type": "application/json"},
        "body": payload,
    }
    results = relay.run([heavy] * VALUE_HEAVY_REQUESTS, timeout_s=150)
    for result in results:
        assert result.get("status") == 200, result.get("error")
        assert json_body(result)["error"] == {"code": "bad_request", "message": "request has too many values"}
    heap = console.call("system.info")["heap"]
    print(f"after {VALUE_HEAVY_REQUESTS} value-heavy requests: heap {heap}", file=sys.stderr)
    assert heap["minFree"] >= MIN_FREE_HEAP
    serial = console.request_raw("[" + ",".join("0" for _ in range(1000)) + "]")
    assert serial["error"] == {"code": "bad_request", "message": "request has too many values"}


def test_a_stalled_handshake_is_dropped_within_seconds(relay: Relay, codes: Codes) -> None:
    result = relay.step({"type": "stall", "timeout_s": 30}, timeout_s=90)
    assert result.get("closed") is True, result.get("error")
    assert result["closed_after_ms"] <= STALLED_HANDSHAKE_LIMIT_MS


def test_heap_holds_with_one_tls_session_and_events(relay: Relay, session: Login, origin: str) -> None:
    result = relay.step(
        {
            "type": "ws",
            "path": "/api/events",
            "headers": {"Origin": origin, "Cookie": session.cookie},
            "steps": [
                rpc_step("locks.scan", {"seconds": 10}, session.cookie),
                {"type": "sleep", "seconds": 4},
                rpc_step("system.info", {}, session.cookie),
            ],
            "collect_s": 1,
        },
        timeout_s=90,
    )
    assert result.get("status") == 101, result.get("error")
    info = json_body(result["steps"][2])["result"]
    heap = info["heap"]
    print(
        f"heap free={heap['free']} minFree={heap['minFree']} largestBlock={heap['largestBlock']} "
        f"stackFree={info['stackFree']}",
        file=sys.stderr,
    )
    assert info["ble"]["ready"] is True
    assert heap["minFree"] >= MIN_FREE_HEAP
    assert heap["largestBlock"] > 16_384


def test_no_secret_reaches_the_console_or_the_audit(console: Console, secrets: dict[str, Any]) -> None:
    assert seen_tokens, "the suite saw no session token"
    extra = tuple(seen_tokens) + (OTHER_PASSWORD,)
    output = "\n".join(line for line in console.lines if not is_json_object(line))
    clean_output = holds_no_secret(output, secrets, extra)
    assert clean_output, "the console printed a secret or a session token"
    clean_events = holds_no_secret(json.dumps(console.events), secrets, extra)
    assert clean_events, "a console event carries a secret or a session token"
    assert [event for event in console.events if event.get("event") == "job.done"] == []
    entries = console.call("audit.list", {"limit": 50})["entries"]
    clean_audit = holds_no_secret(json.dumps(entries), secrets, extra)
    assert clean_audit, "an audit entry contains a secret or a session token"
