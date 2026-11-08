# SPDX-License-Identifier: GPL-3.0-or-later
"""Firmware updates over POST /api/ota, sent from this machine straight to the board's HTTPS address.

The images come from this worktree's builds: build the esp32 and esp32s3 envs (and esp32-rollback-test for the
rollback test) and flash the board with its own env over USB first. The board is claimed and put on the real Wi-Fi
when it is not and holds neither lock keys nor an owner login. A board whose entry in secrets.local.json has a
totp_uri belongs to its owner: the suite signs in with codes from that URI and changes nothing there. Any other board
gets a fresh TOTP secret from auth.rotateTotp over the USB console.

Nobody may press the board button while the refusal and timeout tests run. The update tests need a press: with
--button-file <path> they write the UTC time into that file while they wait, up to 10 minutes, and delete it when the
wait ends, pressed or not. Meanwhile they upload the image again and again, each upload waiting 30 s for the button.
Without a press a test skips, and so does every later test that needs one. The rollback test runs on the classic
ESP32 only: the esp32-rollback-test image names a button pin the chip does not have, so it aborts at boot and the
bootloader returns to the image that ran before.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import re
import socket
import struct
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest
from board import is_json_object, stored
from latchkey_cli import Console, ConsoleTimeout
from owner import Codes, Private, holds_no_secret, prepare_web_login
from relay import headers, json_body, private_cookies
from relay_runner import WS_GUID, EventReader, fingerprint, masked_frame, read_head, run_step, tls_context

BUILD_DIR = Path(__file__).resolve().parents[2] / ".pio" / "build"
OTHER_CHIP = {"esp32": "esp32s3", "esp32s3": "esp32"}
SLOT_BYTES = {"esp32": 0x1E0000, "esp32s3": 0x300000}
ROLLBACK_CHIP = "esp32"
ROLLBACK_ENV = "esp32-rollback-test"
OCTET_STREAM = "application/octet-stream"
FOREIGN_ORIGIN = "https://attacker.example"
REBOUND_HOST = "rebind.attacker.example"
SESSION_COOKIE = re.compile(r"lk_session=([0-9a-f]{64}); Path=/; Secure; HttpOnly; SameSite=Strict")
UPLOAD_LOG = re.compile(r"\d+ bytes received in \d+ ms, heap min free (?P<minFree>\d+), worker stack free \d+")
MIN_IMAGE_BYTES = 64 * 1024
DECLARED_BYTES = 1_000_000
HEAD_BYTES = 4096
PREFIX_BYTES = 512
VERSION_FIELD = slice(48, 80)
ELF_SHA_FIELD = slice(176, 208)
CONFIRM_REQUIRED = {"action": "ota", "timeoutMs": 30000}
CONFIRM_WAIT_S = 30
WINDOW_OPEN_S = 10.0
OUTCOME_S = 45.0
BUTTON_WAIT_S = 600
BUSY_RETRY_S = 2.0
SCAN_SECONDS = 25
LOGIN_ATTEMPTS = 3
REQUEST_TIMEOUT_S = 30
UPLOAD_TIMEOUT_S = 120
RESTART_S = 120.0
RESTART_SLACK_S = 5
KEPT_S = 150.0
ONLINE_S = 90.0
LOCK_JOB_S = 150
MIN_FREE_HEAP = 30_000
STATES = {"locked", "unlocked"}
MQTT_SETTINGS = ("enabled", "host", "port", "username", "prefix", "passwordSet")
LOCK_RECORD = ("id", "name", "model", "hardened", "backedUp", "pairComplete")
CREDENTIAL_LISTS = (
    ("lock.passcodes.list", "passcodes"),
    ("lock.fingerprints.list", "fingerprints"),
    ("lock.cards.list", "cards"),
)
seen_tokens: list[str] = []
upload_heap: list[int] = []


@dataclass(frozen=True)
class Target:
    chip: str
    host: str
    origin: str
    fingerprint: str

    def connect(self, timeout: float) -> http.client.HTTPSConnection:
        connection = http.client.HTTPSConnection(self.host, 443, timeout=timeout, context=tls_context())
        connection.connect()
        same = fingerprint(connection.sock.getpeercert(binary_form=True)) == self.fingerprint
        assert same, "the board answered with another certificate"
        return connection

    def step(self, step: dict[str, Any]) -> dict[str, Any]:
        result = private_cookies(run_step(self.host, step))
        same = result.get("fingerprint", self.fingerprint) == self.fingerprint
        assert same, "the board answered with another certificate"
        return result


@dataclass
class Reply:
    status: int
    body: dict[str, Any]


class Events:
    def __init__(self, reader: EventReader) -> None:
        self.reader = reader

    def mark(self) -> int:
        return len(self.reader.events)

    def named(self, name: str, since: int = 0) -> list[dict[str, Any]]:
        return [event.get("data", {}) for event in self.reader.events[since:] if event.get("event") == name]

    def wait(self, since: int, name: str, timeout: float) -> dict[str, Any] | None:
        found = self.named(name, since)
        if not found and self.reader.drain(timeout, lambda event: event.get("event") == name):
            found = self.named(name, since)
        return found[0] if found else None

    def collect(self, seconds: float) -> None:
        self.reader.drain(seconds, lambda event: False)


class ButtonRequest:
    """Asks for a press of the board button through the marker file and remembers a wait nobody answered."""

    def __init__(self, path: Path | None, chip: str) -> None:
        self.path = path
        self.chip = chip
        self.unanswered = False

    def open(self, purpose: str) -> None:
        if self.path is None:
            print(f"press the {self.chip} board button now ({purpose})", file=sys.stderr, flush=True)
            return
        self.path.write_text(f"{utc_stamp()}\n{self.chip}: press the board button ({purpose})\n", encoding="utf-8")

    def close(self) -> None:
        if self.path is not None:
            self.path.unlink(missing_ok=True)


def utc_stamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def firmware(env: str) -> bytes:
    path = BUILD_DIR / env / "firmware.bin"
    if not path.is_file():
        pytest.fail(f".pio/build/{env}/firmware.bin is missing: build the {env} env first")
    return path.read_bytes()


def image_version(image: bytes) -> str:
    return image[VERSION_FIELD].split(b"\0", 1)[0].decode()


def elf_sha256(image: bytes) -> str:
    return image[ELF_SHA_FIELD].hex()


def with_version(image: bytes, version: str) -> bytes:
    field = version.encode().ljust(VERSION_FIELD.stop - VERSION_FIELD.start, b"\0")
    return image[: VERSION_FIELD.start] + field + image[VERSION_FIELD.stop :]


def rpc_step(target: Target, method: str, params: dict[str, Any] | None = None, cookie: str | None = None) -> dict:
    request_headers = {"Content-Type": "application/json", "Origin": target.origin}
    if cookie is not None:
        request_headers["Cookie"] = cookie
    payload = json.dumps({"id": 1, "method": method, "params": params or {}})
    return {
        "type": "http",
        "method": "POST",
        "path": "/api/rpc",
        "headers": request_headers,
        "body": payload,
        "timeout_s": REQUEST_TIMEOUT_S,
    }


def login(target: Target, codes: Codes, password: str) -> str:
    """Signs in over HTTPS; a code from a step an earlier run already used is refused, so the next one follows."""
    for _ in range(LOGIN_ATTEMPTS):
        result = target.step(rpc_step(target, "auth.login", {"password": password, "totp": codes.next()}))
        assert result.get("status") == 200, result.get("error")
        reply = json_body(result)
        if "error" in reply:
            assert reply["error"]["code"] == "unauthorized", reply["error"]
            continue
        set_cookies = headers(result, "set-cookie")
        assert len(set_cookies) == 1
        match = SESSION_COOKIE.fullmatch(set_cookies[0])
        shaped = match is not None
        assert shaped, "Set-Cookie does not have the expected value and attributes"
        seen_tokens.append(Private(match.group(1)))
        return Private(f"lk_session={match.group(1)}")
    pytest.fail(f"auth.login refused {LOGIN_ATTEMPTS} codes in a row")


def lock_job(target: Target, cookie: str, method: str, params: dict[str, Any]) -> dict[str, Any]:
    result = target.step(
        {
            "type": "ws",
            "path": "/api/events",
            "headers": {"Origin": target.origin, "Cookie": cookie},
            "steps": [rpc_step(target, method, params, cookie)],
            "until": {"event": "job.done", "job_from": 0},
            "collect_s": LOCK_JOB_S,
        }
    )
    assert result.get("status") == 101, result.get("error")
    job = json_body(result["steps"][0])["result"]["job"]
    done = [
        event["data"]
        for event in result["events"]
        if event.get("event") == "job.done" and event["data"].get("job") == job
    ]
    assert len(done) == 1, "no job.done for the job"
    return done[0]


@contextmanager
def event_stream(target: Target, cookie: str) -> Iterator[Events]:
    sock = tls_context().wrap_socket(socket.create_connection((target.host, 443), timeout=REQUEST_TIMEOUT_S))
    try:
        same = fingerprint(sock.getpeercert(binary_form=True)) == target.fingerprint
        assert same, "the board answered with another certificate"
        key = base64.b64encode(os.urandom(16)).decode()
        request = [
            "GET /api/events HTTP/1.1",
            f"Host: {target.host}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {key}",
            "Sec-WebSocket-Version: 13",
            f"Origin: {target.origin}",
            f"Cookie: {cookie}",
        ]
        sock.sendall(("\r\n".join(request) + "\r\n\r\n").encode())
        head = read_head(sock).decode("latin-1").split("\r\n")
        fields = [line.split(":", 1) for line in head[1:] if ":" in line]
        accepted = {name.strip().lower(): value.strip() for name, value in fields}
        expected = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
        opened = head[0].split(" ")[1] == "101" and accepted.get("sec-websocket-accept") == expected
        assert opened, "the board did not open the event socket"
        events = Events(EventReader(sock))
        events.collect(0.5)
        yield events
        if not events.reader.closed:
            sock.sendall(masked_frame(0x8, struct.pack("!H", 1000)))
    finally:
        sock.close()


def upload_headers(target: Target, cookie: str | None = None, changes: dict[str, str | None] | None = None) -> dict:
    chosen = {"Origin": target.origin, "Content-Type": OCTET_STREAM, "Cookie": cookie, **(changes or {})}
    return {name: value for name, value in chosen.items() if value is not None}


def open_upload(target: Target, length: int, request_headers: dict[str, str]) -> http.client.HTTPSConnection:
    connection = target.connect(UPLOAD_TIMEOUT_S)
    connection.putrequest("POST", "/api/ota", skip_host="Host" in request_headers, skip_accept_encoding=True)
    for name, value in {**request_headers, "Content-Length": str(length)}.items():
        connection.putheader(name, value)
    connection.endheaders()
    return connection


def finish(connection: http.client.HTTPSConnection) -> Reply:
    try:
        response = connection.getresponse()
        return Reply(response.status, json.loads(response.read()))
    finally:
        connection.close()


def refusal(target: Target, length: int, request_headers: dict[str, str]) -> Reply:
    connection = open_upload(target, length, request_headers)
    connection.send(bytes(min(length, PREFIX_BYTES)))
    return finish(connection)


def upload(target: Target, image: bytes, request_headers: dict[str, str]) -> Reply:
    connection = open_upload(target, len(image), request_headers)
    connection.send(image)
    return finish(connection)


def attempt_install(target: Target, image: bytes, cookie: str, events: Events) -> Reply:
    assert not events.reader.closed, "the board closed the event socket"
    mark = events.mark()
    connection = open_upload(target, len(image), upload_headers(target, cookie))
    connection.send(image[:HEAD_BYTES])
    if events.wait(mark, "confirm.required", WINDOW_OPEN_S) is not None:
        outcome = events.wait(mark, "confirm.result", OUTCOME_S)
        assert outcome is not None, "the board announced a button wait and never its outcome"
        if outcome["confirmed"]:
            connection.send(image[HEAD_BYTES:])
    return finish(connection)


def install_with_press(
    target: Target, image: bytes, cookie: str, events: Events, button: ButtonRequest, purpose: str
) -> Reply:
    if button.unanswered:
        pytest.skip("nobody pressed the board button during an earlier wait")
    deadline = time.monotonic() + BUTTON_WAIT_S
    button.open(purpose)
    try:
        while time.monotonic() < deadline:
            reply = attempt_install(target, image, cookie, events)
            code = reply.body.get("error", {}).get("code")
            if code == "busy":
                time.sleep(BUSY_RETRY_S)
            elif code != "confirm_timeout":
                return reply
    finally:
        button.close()
    button.unanswered = True
    pytest.skip(f"nobody pressed the board button within {BUTTON_WAIT_S // 60} minutes")


def ota_status(console: Console) -> dict[str, Any]:
    return console.call("system.ota.status")


def last_audit_seq(console: Console) -> int:
    entries = console.call("audit.list", {"limit": 1})["entries"]
    return entries[0]["seq"] if entries else 0


def ota_audit_since(console: Console, seq: int) -> list[tuple[str, str, str]]:
    entries = console.call("audit.list", {"limit": 50})["entries"]
    fresh = [entry for entry in reversed(entries) if entry["seq"] > seq and entry["method"] == "ota"]
    return [(entry["source"], entry["target"], entry["result"]) for entry in fresh]


def board_state(console: Console) -> dict[str, Any]:
    info = console.call("system.info")
    mqtt = console.call("mqtt.get")
    locks = console.call("locks.list")["locks"]
    return {
        "claimed": info["claimed"],
        "certFingerprint": info["certFingerprint"],
        "timezone": info["timezone"],
        "wifi": {key: info["wifi"][key] for key in ("configured", "ssid", "ip")},
        "mqtt": {key: mqtt[key] for key in MQTT_SETTINGS},
        "locks": [{key: lock[key] for key in LOCK_RECORD} for lock in locks],
    }


def credential_counts(console: Console, lock: str) -> dict[str, int]:
    return {key: len(console.call(method, {"lock": lock}, timeout=LOCK_JOB_S)[key]) for method, key in CREDENTIAL_LISTS}


def uptime_mark(console: Console) -> tuple[int, float]:
    return console.call("system.info")["uptime"], time.monotonic()


def wait_for_restart(console: Console, mark: tuple[int, float]) -> dict[str, Any]:
    uptime, since = mark
    deadline = time.monotonic() + RESTART_S
    while time.monotonic() < deadline:
        try:
            info = console.call("system.info", timeout=2.0)
        except ConsoleTimeout:
            continue
        if info["uptime"] + RESTART_SLACK_S < uptime + (time.monotonic() - since):
            return info
        time.sleep(1.0)
    pytest.fail(f"the board did not restart within {RESTART_S:.0f} s")


def wait_for_state(console: Console, state: str) -> dict[str, Any]:
    deadline = time.monotonic() + KEPT_S
    while True:
        status = ota_status(console)
        if status["running"]["state"] == state:
            return status
        if time.monotonic() > deadline:
            pytest.fail(f"the running image is still {status['running']['state']} after {KEPT_S:.0f} s")
        time.sleep(2.0)


def wait_online(console: Console) -> None:
    console.wait_info(lambda info: info["wifi"]["connected"] and info["time"]["synced"], ONLINE_S, "Wi-Fi and SNTP")


@pytest.fixture(scope="module")
def codes(console: Console, secrets: dict[str, Any], board_settings: dict[str, Any]) -> Codes:
    return prepare_web_login(console, secrets, board_settings)


@pytest.fixture(scope="module")
def target(console: Console, codes: Codes, board_settings: dict[str, Any]) -> Target:
    info = console.call("system.info")
    host = board_settings["static_ip"]
    return Target(info["chip"], host, Private(f"https://{host}"), info["certFingerprint"])


@pytest.fixture(scope="module")
def session(target: Target, codes: Codes, secrets: dict[str, Any]) -> str:
    return login(target, codes, secrets["owner_password"])


@pytest.fixture(scope="module")
def own_image(console: Console, target: Target) -> bytes:
    image = firmware(target.chip)
    same = ota_status(console)["running"]["elfSha256"] == elf_sha256(image)
    assert same, f"the board does not run .pio/build/{target.chip}/firmware.bin: upload it over USB first"
    return image


@pytest.fixture(scope="module")
def button(button_file: Path | None, target: Target) -> ButtonRequest:
    return ButtonRequest(button_file, target.chip)


def test_an_upload_needs_a_session(console: Console, target: Target) -> None:
    seq = last_audit_seq(console)
    bare = refusal(target, DECLARED_BYTES, upload_headers(target))
    bogus = refusal(target, DECLARED_BYTES, upload_headers(target, Private("lk_session=" + "0" * 64)))
    refused = Reply(401, {"id": None, "error": {"code": "unauthorized", "message": "sign in first"}})
    assert bare == refused
    assert bogus == refused
    assert ota_audit_since(console, seq) == []


def test_an_upload_from_another_origin_is_refused(console: Console, target: Target, session: str) -> None:
    seq = last_audit_seq(console)
    foreign = refusal(target, DECLARED_BYTES, upload_headers(target, session, {"Origin": FOREIGN_ORIGIN}))
    rebound = refusal(target, DECLARED_BYTES, upload_headers(target, session, {"Host": REBOUND_HOST}))
    refused = Reply(403, {"id": None, "error": {"code": "forbidden", "message": "cross-origin request refused"}})
    assert foreign == refused
    assert rebound == refused
    assert ota_audit_since(console, seq) == []


def test_an_upload_must_be_an_octet_stream_that_fits_the_slot(console: Console, target: Target, session: str) -> None:
    seq = last_audit_seq(console)
    plain = refusal(target, DECLARED_BYTES, upload_headers(target, session, {"Content-Type": "text/plain"}))
    untyped = refusal(target, DECLARED_BYTES, upload_headers(target, session, {"Content-Type": None}))
    small = refusal(target, MIN_IMAGE_BYTES - 1, upload_headers(target, session))
    large = refusal(target, SLOT_BYTES[target.chip] + 1, upload_headers(target, session))
    wrong_type = {"code": "invalid_argument", "message": "send the image as application/octet-stream"}
    assert plain == Reply(415, {"id": None, "error": wrong_type})
    assert untyped == Reply(415, {"id": None, "error": wrong_type})
    too_small = {"code": "invalid_argument", "message": "the file is too small to be firmware"}
    assert small == Reply(400, {"id": None, "error": too_small})
    slot = SLOT_BYTES[target.chip]
    too_large = {"code": "invalid_argument", "message": f"the image is larger than the {slot}-byte app slot"}
    assert large == Reply(413, {"id": None, "error": too_large})
    assert ota_audit_since(console, seq) == [("web", "", "invalid_argument")] * 4


def test_an_image_for_the_other_chip_is_refused_before_the_button(
    console: Console, target: Target, session: str, own_image: bytes
) -> None:
    other = OTHER_CHIP[target.chip]
    foreign = firmware(other)[:MIN_IMAGE_BYTES]
    before = ota_status(console)
    seq = last_audit_seq(console)
    with event_stream(target, session) as events:
        reply = upload(target, foreign, upload_headers(target, session))
        events.collect(1.0)
        prompts = events.named("confirm.required")
    message = f"this image is for the {other}, and this board is an {target.chip}"
    assert reply == Reply(400, {"id": None, "error": {"code": "invalid_argument", "message": message}})
    assert prompts == []
    assert ota_audit_since(console, seq) == [("web", "", "invalid_argument")]
    assert ota_status(console) == before


def test_without_a_press_the_upload_times_out_and_leaves_the_other_slot(
    console: Console, target: Target, session: str, own_image: bytes
) -> None:
    marker = f"hil-{os.urandom(6).hex()}"
    image = with_version(own_image, marker)
    before = ota_status(console)
    seq = last_audit_seq(console)
    idle = console.call("system.info")
    presses = idle["button"]["presses"]
    scan = console.start("locks.scan", {"seconds": SCAN_SECONDS})
    with event_stream(target, session) as events:
        started = time.monotonic()
        reply = upload(target, image, upload_headers(target, session))
        waited = time.monotonic() - started
        events.collect(1.0)
        prompts = events.named("confirm.required")
        outcomes = events.named("confirm.result")
    assert console.finish(scan, timeout=60.0)["result"] == {"seconds": SCAN_SECONDS}
    info = console.call("system.info")
    heap = info["heap"]
    upload_heap.append(heap["minFree"])
    print(
        f"{target.chip}: a {len(image)}-byte upload with no press answered after {waited:.1f} s with a scan, "
        f"TLS and the event socket; heap before free={idle['heap']['free']} minFree={idle['heap']['minFree']}, "
        f"after free={heap['free']} minFree={heap['minFree']} largestBlock={heap['largestBlock']}, "
        f"webJobs stack free={info['stackFree']['webJobs']}",
        file=sys.stderr,
    )
    timeout = {"code": "confirm_timeout", "message": "the button was not pressed within 30 s"}
    assert reply == Reply(403, {"id": None, "error": timeout})
    assert prompts == [CONFIRM_REQUIRED]
    assert outcomes == [{"action": "ota", "confirmed": False}]
    assert waited >= CONFIRM_WAIT_S
    assert info["button"]["presses"] == presses
    assert info["ble"]["ready"] is True
    assert ota_status(console) == before
    assert ota_audit_since(console, seq) == [("web", marker, "confirm_timeout")]


def test_a_pressed_update_restarts_into_the_image_and_keeps_the_board(
    console: Console,
    target: Target,
    codes: Codes,
    secrets: dict[str, Any],
    own_image: bytes,
    button: ButtonRequest,
    lock_mac: str,
) -> None:
    before = ota_status(console)
    assert before["running"]["state"] != "pending_verify", "the board is still checking its last update"
    state = board_state(console)
    held = stored(console, lock_mac) is not None
    counts = credential_counts(console, lock_mac) if held else None
    seq = last_audit_seq(console)
    cookie = login(target, codes, secrets["owner_password"])
    mark = uptime_mark(console)
    seen = len(console.lines)
    with event_stream(target, cookie) as events:
        reply = install_with_press(target, own_image, cookie, events, button, "update")
    assert reply == Reply(200, {"result": {"bytes": len(own_image), "rebooting": True}})
    wait_for_restart(console, mark)
    started = ota_status(console)
    version = image_version(own_image)
    new_image = {"slot": before["other"]["slot"], "version": version, "elfSha256": elf_sha256(own_image)}
    assert started["running"] == {**new_image, "state": "pending_verify"}
    assert started["boot"] == new_image["slot"]
    kept = wait_for_state(console, "valid")
    assert kept["running"] == {**new_image, "state": "valid"}
    assert kept["other"] == before["running"]
    uploaded = [UPLOAD_LOG.search(line) for line in console.lines[seen:] if UPLOAD_LOG.search(line)]
    if uploaded:
        upload_heap.append(int(uploaded[-1].group("minFree")))
    print(f"{target.chip}: {uploaded[-1].group(0) if uploaded else 'no upload log line was read'}", file=sys.stderr)
    assert any("passed its first-boot check and is kept" in line for line in console.lines[seen:])
    wait_online(console)
    same = board_state(console) == state
    assert same, "the update changed the board's settings, certificate or locks"
    audit = ota_audit_since(console, seq)
    assert audit[-1] == ("web", version, "ok")
    assert set(audit[:-1]) <= {("web", version, "confirm_timeout")}
    again = login(target, codes, secrets["owner_password"])
    if held:
        status = lock_job(target, again, "lock.status", {"lock": lock_mac})
        assert status["result"]["state"] in STATES
        same_counts = credential_counts(console, lock_mac) == counts
        assert same_counts, "the lock's credential lists changed across the update"


def test_an_image_that_fails_its_first_boot_is_rolled_back(
    console: Console,
    target: Target,
    codes: Codes,
    secrets: dict[str, Any],
    own_image: bytes,
    button: ButtonRequest,
) -> None:
    if target.chip != ROLLBACK_CHIP:
        pytest.skip("the rollback runs on the classic ESP32, which holds no lock")
    failing = firmware(ROLLBACK_ENV)
    before = ota_status(console)
    assert before["running"]["state"] != "pending_verify", "the board is still checking its last update"
    state = board_state(console)
    seq = last_audit_seq(console)
    cookie = login(target, codes, secrets["owner_password"])
    mark = uptime_mark(console)
    seen = len(console.lines)
    with event_stream(target, cookie) as events:
        reply = install_with_press(target, failing, cookie, events, button, "rollback")
    assert reply == Reply(200, {"result": {"bytes": len(failing), "rebooting": True}})
    wait_for_restart(console, mark)
    status = ota_status(console)
    assert status["running"] == before["running"]
    assert status["boot"] == before["running"]["slot"]
    rejected = {"slot": before["other"]["slot"], "version": image_version(failing), "elfSha256": elf_sha256(failing)}
    assert status["other"] == {**rejected, "state": "aborted"}
    assert any("ESP_ERROR_CHECK failed" in line for line in console.lines[seen:])
    wait_online(console)
    same = board_state(console) == state
    assert same, "the rollback changed the board's settings, certificate or locks"
    assert ota_audit_since(console, seq)[-1] == ("web", image_version(failing), "ok")
    login(target, codes, secrets["owner_password"])


def test_the_heap_keeps_30_kb_free_through_an_upload(target: Target) -> None:
    assert upload_heap, "no upload measured the heap"
    lowest = min(upload_heap)
    print(f"{target.chip}: lowest minimum free heap through the uploads: {lowest}", file=sys.stderr)
    assert lowest >= MIN_FREE_HEAP


def test_no_secret_reaches_the_console(console: Console, secrets: dict[str, Any]) -> None:
    assert seen_tokens, "the suite saw no session token"
    output = "\n".join(line for line in console.lines if not is_json_object(line))
    clean_output = holds_no_secret(output, secrets, tuple(seen_tokens))
    assert clean_output, "the console printed a secret or a session token"
    clean_events = holds_no_secret(json.dumps(console.events), secrets, tuple(seen_tokens))
    assert clean_events, "a console event carries a secret or a session token"
