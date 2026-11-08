# SPDX-License-Identifier: GPL-3.0-or-later
"""The board's recent log lines (system.logs) and remote shipping over syslog (RFC 5424), on a real board.

Over the USB serial console. A board whose entry in secrets.local.json has a totp_uri belongs to its owner: the
suite changes nothing there but its remote-logging settings, which it puts back. On any other board it also runs
the Wi-Fi and authenticator paths whose secrets must never reach the log.

The shipping tests need hil_relay (a host on the boards' network, see relay.py) and hil_syslog {host, port}: the
address of that relay host as the board reaches it and a free port there. They run a listener on the relay host
for under a minute, and skip with a message when either key is missing or the board cannot reach the listener.
"""

from __future__ import annotations

import base64
import json
import re
import threading
import time
from typing import Any

import pytest
from board import error_code
from latchkey_cli import Console
from owner import Private, holds_no_secret, otpauth_secret, wifi_params
from relay import Relay

LEVELS = ("error", "warn", "info", "debug", "verbose")
RING_BYTES = {"esp32": 6144, "esp32s3": 32768}
CLOCK_MARKER = "clock set over serial, utc {}"
LISTEN_S = 60
LISTENER_STARTUP_S = 8.0
CONNECT_WAIT_S = 20.0
DELIVERY_WAIT_S = 4.0
APP_NAME = "latchkey-hil"
SYSLOG_LINE = re.compile(
    r"<(?P<pri>\d{1,3})>1 (?P<time>-|\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z) (?P<host>\S+) (?P<app>\S+) - "
    r"(?P<msgid>\S+) \[meta sequenceId=\"(?P<seq>\d+)\" sysUpTime=\"(?P<up>\d+)\"\] (?P<msg>.*)",
    re.DOTALL,
)
SECRET_SHAPES = re.compile(r"otpauth://|secret=|lk_session=|[0-9A-Fa-f]{32}", re.IGNORECASE)
seen_secrets: list[str] = []


def all_lines(console: Console, **params: Any) -> list[dict[str, Any]]:
    lines: list[dict[str, Any]] = []
    since = 0
    while True:
        page = console.call("system.logs", {**params, "since": since})
        lines += page["lines"]
        since = page["next"]
        if not page["more"]:
            return lines


def mark_clock(console: Console) -> str:
    utc = int(time.time())
    assert console.call("system.time.set", {"utc": utc}) == {}
    return CLOCK_MARKER.format(utc)


def has_marker(lines: list[dict[str, Any]], marker: str) -> bool:
    return any(line["tag"] == "clock" and line["message"] == marker for line in lines)


def known_secrets(secrets: dict[str, Any]) -> tuple[str, ...]:
    extra = [*seen_secrets]
    mqtt = secrets.get("mqtt") or {}
    if mqtt.get("password"):
        extra.append(mqtt["password"])
    return tuple(extra)


@pytest.fixture(scope="module")
def owned(board_settings: dict[str, Any]) -> bool:
    return bool(board_settings.get("totp_uri"))


@pytest.fixture(scope="module")
def chip(console: Console) -> str:
    return console.wait_ready()["chip"]


def test_info_reports_the_ring_and_remote_logging(console: Console, chip: str) -> None:
    info = console.call("system.info")
    ring = info["logs"]
    assert set(ring) == {"lines", "capacity", "withheld"}
    assert ring["capacity"] == RING_BYTES[chip]
    assert ring["lines"] > 0
    assert set(info["syslog"]) == {"enabled", "connected", "sent", "dropped", "errors"}
    assert "syslog" in info["stackFree"]


def test_recent_lines_hold_a_known_action(console: Console) -> None:
    before = console.call("system.logs", {"limit": 1})["next"]
    started = time.time()
    marker = mark_clock(console)
    page = console.call("system.logs", {"since": before})
    lines = page["lines"]
    assert has_marker(lines, marker)
    line = next(line for line in lines if line["message"] == marker)
    assert set(line) == {"seq", "uptimeMs", "utcMs", "level", "tag", "message"}
    assert line["level"] == "info"
    assert line["seq"] > before
    assert page["next"] >= line["seq"]
    assert page["missed"] == 0
    uptime_ms = console.call("system.info")["uptime"] * 1000
    assert 0 < line["uptimeMs"] <= uptime_ms + 1000
    assert abs(line["utcMs"] / 1000 - started) <= 5
    seqs = [entry["seq"] for entry in lines]
    assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs)


def test_the_newest_lines_come_without_since(console: Console) -> None:
    marker = mark_clock(console)
    page = console.call("system.logs", {"limit": 5})
    assert 1 <= len(page["lines"]) <= 5
    assert has_marker(page["lines"], marker)
    assert page["more"] is False
    assert page["next"] == page["lines"][-1]["seq"]


def test_a_level_keeps_only_that_level_and_worse(console: Console) -> None:
    marker = mark_clock(console)
    for level in LEVELS:
        lines = all_lines(console, level=level)
        allowed = set(LEVELS[: LEVELS.index(level) + 1])
        assert {line["level"] for line in lines} <= allowed
        assert has_marker(lines, marker) is (level in ("info", "debug", "verbose"))


def test_paging_follows_the_sequence(console: Console) -> None:
    mark_clock(console)
    mark_clock(console)
    first = console.call("system.logs", {"limit": 2})
    oldest = first["lines"][0]["seq"]
    page = console.call("system.logs", {"since": oldest - 1, "limit": 1})
    assert [line["seq"] for line in page["lines"]] == [oldest]
    assert page["more"] is True
    assert page["next"] == oldest
    newest = console.call("system.logs", {"limit": 1})["next"]
    ahead = console.call("system.logs", {"since": newest + 1000})
    assert ahead["lines"] == [] and ahead["more"] is False
    assert ahead["next"] >= newest
    held = all_lines(console)
    if held[0]["seq"] > 1:
        assert console.call("system.logs", {"since": 0, "limit": 1})["missed"] >= held[0]["seq"] - 1


def test_bad_parameters_are_refused(console: Console) -> None:
    for params in (
        {"since": -1},
        {"since": "1"},
        {"since": 1.5},
        {"level": "loud"},
        {"level": 3},
        {"limit": 0},
        {"limit": 101},
        {"limit": "5"},
    ):
        assert error_code(console, "system.logs", params) == "invalid_argument", params


def test_no_secret_reaches_the_ring(
    console: Console, owned: bool, secrets: dict[str, Any], board_settings: dict[str, Any]
) -> None:
    info = console.call("system.info")
    if owned:
        otpauth_secret(board_settings["totp_uri"], info["board"])
    else:
        if info["claimed"] and info["wifi"]["ssid"] == secrets["wifi_ssid"]:
            assert console.call("system.wifi.set", wifi_params(secrets, board_settings)) == {}
            console.wait_info(lambda state: state["wifi"]["connected"], 45.0, "Wi-Fi to reconnect")
        if info["claimed"]:
            rotated = console.call("auth.rotateTotp", timeout=30.0)["otpauth"]
            seen_secrets.append(Private(rotated))
            otpauth_secret(rotated, info["board"])
    text = json.dumps(all_lines(console))
    clean = holds_no_secret(text, secrets, known_secrets(secrets))
    assert clean, "a log line holds a secret"
    shaped = SECRET_SHAPES.search(text) is None
    assert shaped, "a log line has the shape of a secret"
    assert console.call("system.info")["logs"]["withheld"] == 0


def test_syslog_settings_are_checked_and_audited(console: Console, owned: bool) -> None:
    original = console.call("system.syslog.get")
    assert set(original) == {
        "enabled",
        "host",
        "port",
        "transport",
        "appName",
        "level",
        "connected",
        "sent",
        "dropped",
        "errors",
    }
    refused = (
        ()
        if owned
        else (
            {},
            {"enabled": "yes"},
            {"enabled": True},
            {"enabled": True, "host": "a b"},
            {"enabled": False, "host": ".example.net"},
            {"enabled": False, "host": "x" * 65},
            {"enabled": False, "port": 0},
            {"enabled": False, "port": 65536},
            {"enabled": False, "transport": "quic"},
            {"enabled": False, "appName": "a b"},
            {"enabled": False, "appName": "a" * 49},
            {"enabled": False, "level": "loud"},
        )
    )
    try:
        for params in refused:
            assert error_code(console, "system.syslog.set", params) == "invalid_argument", sorted(params)
        view = console.call(
            "system.syslog.set",
            {"enabled": False, "host": "logs.example.net", "port": 6514, "transport": "tcp", "level": "warn"},
        )
        assert view["enabled"] is False
        assert (view["host"], view["port"], view["transport"], view["appName"], view["level"]) == (
            "logs.example.net",
            6514,
            "tcp",
            "latchkey",
            "warn",
        )
        assert console.call("system.syslog.get")["host"] == "logs.example.net"
        defaults = console.call("system.syslog.set", {"enabled": False})
        assert (defaults["host"], defaults["port"], defaults["transport"], defaults["level"]) == (
            "",
            514,
            "udp",
            "info",
        )
        entries = console.call("audit.list", {"limit": 20})["entries"]
        recent = [entry["result"] for entry in entries if entry["method"] == "system.syslog.set"]
        assert recent[:3] == ["ok", "ok", "ok" if owned else "invalid_argument"]
    finally:
        restore(console, original)


def restore(console: Console, original: dict[str, Any]) -> None:
    keys = ("enabled", "host", "port", "transport", "appName", "level")
    console.call("system.syslog.set", {key: original[key] for key in keys})


@pytest.fixture(scope="module")
def listener(secrets: dict[str, Any], board_settings: dict[str, Any]) -> tuple[Relay, dict[str, Any]]:
    relay_settings = secrets.get("hil_relay")
    target = secrets.get("hil_syslog")
    if not relay_settings or not target:
        pytest.skip("secrets.local.json needs hil_relay and hil_syslog {host, port} to test remote logging")
    relay = Relay(
        list(relay_settings["command"]), int(relay_settings.get("timeout_s", 150)), board_settings["static_ip"]
    )
    return relay, {"host": Private(target["host"]), "port": int(target["port"])}


def listen(relay: Relay, port: int, results: list[dict[str, Any]]) -> threading.Thread:
    def run() -> None:
        try:
            results.append(relay.step({"type": "syslog", "port": port, "seconds": LISTEN_S}, timeout_s=LISTEN_S + 30))
        except Exception as err:
            results.append({"error": type(err).__name__})

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


def wait_connected(console: Console) -> bool:
    deadline = time.monotonic() + CONNECT_WAIT_S
    while time.monotonic() < deadline:
        if console.call("system.syslog.get")["connected"]:
            return True
        time.sleep(1.0)
    return False


def octet_frames(stream: bytes) -> list[bytes] | None:
    frames: list[bytes] = []
    position = 0
    while position < len(stream):
        space = stream.find(b" ", position)
        if space < 0 or not stream[position:space].isdigit():
            return None
        start = space + 1
        end = start + int(stream[position:space])
        if end > len(stream):
            return None
        frames.append(stream[start:end])
        position = end
    return frames


def parse_messages(raw: list[bytes]) -> list[re.Match[str] | None]:
    return [SYSLOG_LINE.fullmatch(item.decode("utf-8")) for item in raw]


def test_syslog_ships_framed_lines_over_tcp_and_udp(
    console: Console,
    listener: tuple[Relay, dict[str, Any]],
    secrets: dict[str, Any],
    board_settings: dict[str, Any],
) -> None:
    relay, target = listener
    board = console.call("system.info")["board"]
    original = console.call("system.syslog.get")
    results: list[dict[str, Any]] = []
    thread = listen(relay, target["port"], results)
    settings = {"enabled": True, "host": target["host"], "port": target["port"], "appName": APP_NAME, "level": "info"}
    try:
        time.sleep(LISTENER_STARTUP_S)
        console.call("system.syslog.set", {**settings, "transport": "tcp"})
        connected = wait_connected(console)
        tcp_marker = mark_clock(console) if connected else None
        time.sleep(DELIVERY_WAIT_S)
        console.call("system.syslog.set", {**settings, "transport": "udp"})
        udp_marker = mark_clock(console)
        time.sleep(DELIVERY_WAIT_S)
        shipped = console.call("system.syslog.get")
    finally:
        restore(console, original)
    thread.join(LISTEN_S + 60)
    assert results, "the listener on the relay host did not report"
    outcome = results[0]
    assert "error" not in outcome, f"the listener failed: {outcome.get('error')}"
    streams = [base64.b64decode(item) for item in outcome["streams_b64"]]
    datagrams = [base64.b64decode(item) for item in outcome["datagrams_b64"]]
    if not connected and not streams and not datagrams:
        pytest.skip("the board cannot reach the listener on the relay host: its network blocks that port")
    assert connected, "the board did not connect over TCP, but the listener heard from it"
    assert shipped["sent"] > 0
    frames = [frame for stream in streams for frame in (octet_frames(stream) or [b"<unframed>"])]
    tcp = parse_messages(frames)
    udp = parse_messages(datagrams)
    assert tcp and all(tcp), "a TCP frame is not an RFC 5424 message with octet counting"
    assert udp and all(udp), "a UDP datagram is not an RFC 5424 message"
    for messages in (tcp, udp):
        assert {found["host"] for found in messages} == {board}
        assert {found["app"] for found in messages} == {APP_NAME}
        seqs = [int(found["seq"]) for found in messages]
        assert seqs == sorted(seqs) and len(set(seqs)) == len(seqs)
        assert all(found["time"] != "-" for found in messages[-3:])
    assert any(found["msgid"] == "clock" and found["msg"] == tcp_marker for found in tcp)
    assert any(found["msgid"] == "clock" and found["msg"] == udp_marker for found in udp)
    marker_pri = {found["pri"] for found in tcp + udp if found["msgid"] == "clock"}
    assert marker_pri == {"134"}
    text = "\n".join(item.decode("utf-8") for item in frames + datagrams)
    clean = holds_no_secret(text, secrets, known_secrets(secrets))
    assert clean, "a shipped line holds a secret"
    shaped = SECRET_SHAPES.search(text) is None
    assert shaped, "a shipped line has the shape of a secret"


def test_an_unreachable_collector_costs_counted_errors_not_lines(console: Console) -> None:
    original = console.call("system.syslog.get")
    before = console.call("system.logs", {"limit": 1})["next"]
    try:
        console.call("system.syslog.set", {"enabled": True, "host": "192.0.2.1", "port": 9, "transport": "tcp"})
        time.sleep(15.0)
        mark_clock(console)
        view = console.call("system.syslog.get")
        assert view["connected"] is False
        assert view["errors"] >= 1
    finally:
        restore(console, original)
    warnings = [
        line
        for line in all_lines(console)
        if line["seq"] > before and line["tag"] == "syslog" and line["level"] == "warn"
    ]
    assert len(warnings) == 1
