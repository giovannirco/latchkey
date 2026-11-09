# SPDX-License-Identifier: GPL-3.0-or-later
"""Mock of the Latchkey board API, for building and testing the web UI without a board.

    python3 tools/mock_api.py [--port 8765] [--host 127.0.0.1] [--web-dir web] [--verbose]

Open http://127.0.0.1:8765/ and sign in with password "owner-pass" and authenticator code "123456".

Served like the firmware serves them:

- GET /             the page bundled by tools/build_web.py (gzip), rebuilt on every request;
- POST /api/rpc     {"id", "method", "params"} -> {"id", "result"} or {"id", "error": {"code", "message"}};
- GET /api/events   WebSocket (RFC 6455, text frames) carrying {"event", "data"};
- POST /api/ota     a firmware image as application/octet-stream, installed after the board button.

The session is an HttpOnly, SameSite=Strict cookie set by auth.login. /api/rpc only accepts
application/json and refuses a foreign Origin. A method that needs the board's button emits
confirm.required, then confirm.result after 2 s (pressed) unless a test asks for a timeout.
As on the board, the lock methods (locks.scan, locks.pair, lock.status, lock.info, lock.features,
lock.unlock, lock.lock, lock.time.sync, lock.factoryReset, lock.passcodes.*, lock.fingerprints.*,
lock.cards.*, lock.adminPasscode.*, lock.autolock.*, lock.passage.*, lock.sound.*, lock.resetButton.*,
lock.privacyLock.*, lock.tamperAlert.*, lock.log.fetch) and the button-gated auth.rotateTotp and
system.factoryReset run as jobs: the reply is {"job": id} and the outcome arrives as a job.done event
{"job", "result"} or {"job", "error"}, sent only to the sockets of the session that asked.

lock.log.fetch answers {"entries", "last", "more"}: without "since" the newest 16 entries, with "since"
up to 16 entries after that record number, with "more" when others follow. The board reads the log in the
background and sends lock.alert {"lock", "method", "time", "seq", "type"} for an unlock from an app it
did not make, or a forced opening; tests emit one with the emit hook. Switch writes refuse with
unverified before any radio traffic or board-button wait. Turning the reset button off refuses first
with backup_required, with or without a key backup.

lock.alerts.list answers {alerts, warnings}; lock.alerts.ack {lock, through} acknowledges displayed
ids without removing later arrivals. An alert's kind is unexpected_unlock, or a stored warning:
watch_state_unreadable (the log cursor was lost) or alerts_unreadable (the stored alerts could not be
read, so the board started a new list). These two methods do not use Bluetooth or run as jobs.
locks.list includes alertCount and warnings; system.info includes warnings grouped by lock.

Test hooks used by tools/ui-tests/:

- POST /__mock/control  {"reset": true} restores the demo state; other keys: "confirm" ("auto" or
  "never"), "confirmDelayMs", "confirmTimeoutMs", "latencyMs", "jobReplyDelayMs", "timeSynced",
  "expireSessions", "dropSockets" (closes every event socket), "setLock" {"id", fields} (changes a
  lock without an event), "failNext" {"method", "code", "message"}, "warnNext" {"method", "warning"}
  (adds a warning to the next result), "delay" {"method", "ms"} (holds the next reply), "scanExtra"
  [devices], "emit" [{"event", "data"}], "logLines" [{"level", "tag", "message"}] (adds lines to the
  board's log);
- GET /__mock/calls     every RPC since the last reset, with secret parameters replaced by "***";
- GET /__mock/health    readiness probe.

system.logs pages through the board's recent log lines, oldest first: {since?, level?, limit?} gives up
to limit (1 to 100) lines after the sequence number since, or the newest ones without it, at that level
or a more severe one (error, warn, info, debug, verbose); each line is {seq, uptimeMs, utcMs (null until
the clock is set), level, tag, message}. The result is {lines, more, next, missed}: pass next as since to
continue, more says lines that match follow, missed counts lines the board overwrote after since. The
board may return fewer than limit lines when they are long. system.syslog.get/set read and change the
remote logging settings {enabled, host, port, transport (udp or tcp), appName, level} and report
{connected, sent, dropped, errors}; system.info carries logs {lines, capacity, withheld} and syslog
{enabled, connected, sent, dropped, errors}.

Results may carry a "warning" the UI must show, as on the board: a name the board could not store,
a pairing whose offline-code seeds were lost, or an easy passcode (a run or one repeated digit). Like
the board, the methods that would store more names answer "storage_full" once its storage is down to
what it keeps for pairing and the audit log, and the lists answer "too_large" when it lacks the memory
to render them; failNext produces both.

All state is in memory. Addresses are documentation values (RFC 5737 IPv4, RFC 7042 MAC).
"""

from __future__ import annotations

import argparse
import base64
import copy
import gzip
import hashlib
import hmac
import json
import math
import queue
import re
import secrets
import select
import socket
import struct
import sys
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from http.cookies import CookieError, SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Callable, Iterator
from urllib.parse import urlsplit

sys.dont_write_bytecode = True
import build_web  # noqa: E402

SESSION_COOKIE = "lk_session"
MOCK_PASSWORD = "owner-pass"
MOCK_TOTP = "123456"
IDLE_TIMEOUT_S = 900
LOGIN_FAILURES_BEFORE_BACKOFF = 5
LOGIN_BACKOFF_S = 30
QUEUE_WAIT_S = 60
MAX_BODY = 64 * 1024
OTA_SLOT_BYTES = 0x1E0000
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
SYSLOG_COUNTERS = ("enabled", "connected", "sent", "dropped", "errors")
SECRET_PARAMS = {"password", "totp", "passphrase", "code", "current", "new", "backup", "adminPasscode"}
FRONT_DOOR = "00:00:5E:00:53:01"
SHED = "00:00:5E:00:53:02"
CERT_FINGERPRINT = ":".join(f"{byte:02X}" for byte in hashlib.sha256(b"latchkey mock certificate").digest())
FULL_FEATURES = [
    "passcode",
    "ic",
    "finger_print",
    "auto_lock",
    "passcode_with_delete_function",
    "modify_passcode_function",
    "manual_lock",
    "cyclic_password",
    "audio_management",
    "get_admin_code",
    "passage_mode",
    "reset_button",
    "privacy_lock",
    "tamper_alert",
    "config_gateway_unlock",
    "cyclic_ic_or_finger_print",
]
BASIC_FEATURES = ["passcode", "auto_lock", "manual_lock"]
PASSCODE_TYPES = ("permanent", "timed", "one_time", "cyclic")
HARDEN_STEPS = ("admin_passcode", "passcodes", "reset_button", "time")
ADMIN_PASSCODE_DIGITS = 7
IN_USE = "that code is already in use on the lock"
EASY_CODE_WARNING = (
    "this code is easy to guess; use 7 to 9 digits that are not a run or one repeated digit, since the lock "
    "opens whenever the code appears among the digits typed"
)
HHMM = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
HOST_NAME = re.compile(r"^[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]+)*$")
HOST_MESSAGE = "host must be a host name or an IPv4 address of at most 64 characters"
HA_ID = re.compile(r"^[A-Za-z0-9_-]+$")
WIFI_MESSAGE = "wifi needs ssid, password, ip, gateway, netmask and dns"
LOG_LEVELS = ("error", "warn", "info", "debug", "verbose")
LEVEL_MESSAGE = "level is error, warn, info, debug or verbose"
LOG_RING_BYTES = 16384
LOG_RING_LINES = 230
LOG_PAGE_LINES = 100
LOG_APP_UNLOCK = 1
LOG_PASSCODE_UNLOCK = 4
LOG_WRONG_PASSCODE = 7
LOG_POWER_ON = 14
LOG_CARD_UNLOCK = 17
LOG_FINGERPRINT_UNLOCK = 20
LOG_APP_LOCK = 26
LOG_KEY_UNLOCK = 27
LOG_SHOWN = 16
LOG_LAST_SLOT = 65534


class RpcError(Exception):
    def __init__(self, code: str, message: str, **extra: Any) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.extra = extra

    def to_json(self) -> dict[str, Any]:
        return {"code": self.code, "message": self.message, **self.extra}


@dataclass
class Config:
    confirm: str = "auto"
    confirm_delay_ms: int = 2000
    confirm_timeout_ms: int = 30000
    latency_ms: int = 150
    job_reply_delay_ms: int = 0
    time_synced: bool = True


@dataclass
class Context:
    token: str | None
    cookies: list[str] = field(default_factory=list)
    target: str | None = None


@dataclass(frozen=True)
class Method:
    handler: Callable[..., dict[str, Any]]
    session: bool
    feature: str | None
    audited: bool
    job: bool


METHODS: dict[str, Method] = {}


def rpc(
    name: str, *, session: bool = True, feature: str | None = None, audited: bool = True, job: bool = False
) -> Callable:
    def register(handler: Callable[..., dict[str, Any]]) -> Callable[..., dict[str, Any]]:
        METHODS[name] = Method(handler, session, feature, audited, job)
        return handler

    return register


def now() -> int:
    return int(time.time())


def is_easy_code(code: str) -> bool:
    steps = {int(b) - int(a) for a, b in zip(code, code[1:])}
    return len(steps) == 1 and steps <= {-1, 0, 1}


def random_digits(count: int) -> str:
    return "".join(str(secrets.randbelow(10)) for _ in range(count))


def new_id(prefix: str) -> str:
    return f"{prefix}-{secrets.token_hex(4)}"


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "***" if key in SECRET_PARAMS and item not in (None, "") else redact(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item) for item in value]
    return value


def invalid(message: str) -> RpcError:
    return RpcError("invalid_argument", message)


def parse_ipv4(value: Any) -> int | None:
    if not isinstance(value, str):
        return None
    octets = value.split(".")
    if len(octets) != 4 or any(not octet.isdigit() or len(octet) > 3 or octet != str(int(octet)) for octet in octets):
        return None
    numbers = [int(octet) for octet in octets]
    return None if max(numbers) > 255 else int.from_bytes(bytes(numbers), "big")


def is_static_ipv4(address: int, gateway: int, netmask: int) -> bool:
    prefix = bin(netmask).count("1")
    if netmask != (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF or not 1 <= prefix <= 30:
        return False
    host_bits = ~netmask & 0xFFFFFFFF
    hosts = all(value & host_bits not in (0, host_bits) for value in (address, gateway))
    return hosts and address != gateway and address & netmask == gateway & netmask


def is_app_name(value: str) -> bool:
    return 1 <= len(value) <= 48 and all(33 <= ord(c) <= 126 for c in value)


def text_param(params: dict, key: str, *, max_len: int, required: bool = False) -> str:
    value = params.get(key)
    if value is None:
        value = ""
    if not isinstance(value, str):
        raise invalid(f"{key} must be a string")
    value = value.strip()
    if required and not value:
        raise invalid(f"{key} is required")
    if len(value) > max_len:
        raise invalid(f"{key} is longer than {max_len} characters")
    return value


def int_param(
    params: dict, key: str, *, default: int | None = None, lo: int | None = None, hi: int | None = None
) -> int | None:
    value = params.get(key, default)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise invalid(f"{key} must be an integer")
    if (lo is not None and value < lo) or (hi is not None and value > hi):
        raise invalid(f"{key} must be between {lo} and {hi}")
    return value


def bool_param(params: dict, key: str) -> bool:
    value = params.get(key)
    if not isinstance(value, bool):
        raise invalid(f"{key} must be true or false")
    return value


def digits_param(value: Any, *, lo: int = 4, hi: int = 9) -> str:
    if not isinstance(value, str) or not value.isdigit() or not lo <= len(value) <= hi:
        raise invalid(f"a passcode is {lo} to {hi} digits")
    return value


def hhmm_param(value: Any, key: str) -> str:
    if not isinstance(value, str) or not HHMM.match(value):
        raise invalid(f"{key} must be HH:MM")
    return value


def validity_param(value: Any, *, required: bool) -> dict[str, int] | None:
    if value is None:
        if required:
            raise invalid("this needs a validity window")
        return None
    if not isinstance(value, dict):
        raise invalid("validity must be an object with start and end")
    start = int_param(value, "start", lo=0)
    end = int_param(value, "end", lo=0)
    if start is None or end is None:
        raise invalid("validity needs start and end (UTC seconds)")
    if end <= start:
        raise invalid("the end of the validity window must be after its start")
    return {"start": start, "end": end}


def cycle_param(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise invalid("cycle must be an object with days, start and end")
    days = value.get("days")
    if (
        not isinstance(days, list)
        or not days
        or any(isinstance(d, bool) or not isinstance(d, int) or not 1 <= d <= 7 for d in days)
    ):
        raise invalid("cycle.days lists weekdays 1 (Monday) to 7 (Sunday)")
    start = hhmm_param(value.get("start"), "cycle.start")
    end = hhmm_param(value.get("end"), "cycle.end")
    if end <= start:
        raise invalid("the daily window must end after it starts")
    return {"days": sorted(set(days)), "start": start, "end": end}


def passcode(
    kind: str, name: str, validity: dict[str, int] | None, *, managed: bool = True, code: str | None = None
) -> dict:
    return {
        "id": new_id("pc"),
        "type": kind,
        "code": code or random_digits(6),
        "name": name,
        "validity": validity,
        "managed": managed,
    }


def public_passcode(entry: dict) -> dict:
    return {key: entry[key] for key in ("id", "type", "name", "validity", "cycle", "managed") if key in entry}


def summary(lock: dict) -> dict:
    keys = ("id", "mac", "name", "model", "state", "battery", "rssi", "lastSeen", "lastEvent", "hardened", "backedUp")
    result = {key: copy.deepcopy(lock[key]) for key in keys}
    result["alertCount"] = len(lock["alerts"])
    result["warnings"] = list(lock["warnings"])
    if any(alert["kind"] == "alerts_unreadable" for alert in lock["alerts"]):
        result["warnings"].append(
            "The stored alerts could not be read and were cleared; alerts raised before then are lost."
        )
    if any(alert["kind"] == "watch_state_unreadable" for alert in lock["alerts"]):
        result["warnings"].append(
            "The saved operation-log cursor could not be read. Monitoring restarted; some events may have been missed."
        )
    return result


def advert_name(lock: dict) -> str:
    return f"{lock['model']}_{lock['mac'][-5:].replace(':', '')}"


def demo_log(stamp: int, entries: list[tuple[int, int, int]]) -> list[dict]:
    return [
        {"seq": seq, "time": stamp - age, "type": kind, "battery": battery}
        for seq, (age, kind, battery) in enumerate(entries, start=1)
    ]


def demo_locks() -> list[dict]:
    stamp = now()
    day = 86400
    front = {
        "id": FRONT_DOOR,
        "mac": FRONT_DOOR,
        "name": "Front door",
        "model": "LK-MOCK-1",
        "hardware": "1.4",
        "firmware": "6.0.2.240117",
        "manufactureDate": "2024-01-17",
        "protocol": "3.1",
        "features": list(FULL_FEATURES),
        "state": "locked",
        "battery": 87,
        "rssi": -61,
        "lastSeen": stamp - 12,
        "lastEvent": {"action": "lock", "method": "auto", "time": stamp - 600},
        "hardened": True,
        "backedUp": True,
        "autolock": {"seconds": 5, "min": 1, "max": 900},
        "sound": {"enabled": True, "volume": 3},
        "resetButton": False,
        "privacyLock": False,
        "tamperAlert": True,
        "adminPasscode": random_digits(8),
        "passcodes": [
            passcode("permanent", "Family", None),
            passcode("timed", "Cleaner", {"start": stamp - day, "end": stamp + 30 * day}),
        ],
        "fingerprints": [{"id": "1", "name": "Owner right index", "validity": None}],
        "cards": [{"id": "3141592653", "name": "Spare card", "validity": None}],
        "passage": [{"type": "weekly", "day": 0, "start": "08:00", "end": "09:00"}],
        "log": demo_log(
            stamp,
            [
                (2 * day, LOG_POWER_ON, 91),
                (2 * day - 300, LOG_APP_UNLOCK, 91),
                (2 * day - 280, LOG_APP_LOCK, 91),
                (day + 4000, LOG_PASSCODE_UNLOCK, 90),
                (day, LOG_WRONG_PASSCODE, 89),
                (day - 60, LOG_FINGERPRINT_UNLOCK, 89),
                (7200, LOG_CARD_UNLOCK, 88),
                (600, LOG_APP_LOCK, 87),
            ],
        ),
    }
    shed = {
        "id": SHED,
        "mac": SHED,
        "name": "Shed",
        "model": "LK-MOCK-2",
        "hardware": "1.0",
        "firmware": "5.1.0.210901",
        "manufactureDate": "2021-09-01",
        "protocol": "3.0",
        "features": list(BASIC_FEATURES),
        "state": "unlocked",
        "battery": 34,
        "rssi": -77,
        "lastSeen": stamp - 95,
        "lastEvent": {"action": "unlock", "method": "passcode", "time": stamp - 3600},
        "hardened": False,
        "backedUp": False,
        "autolock": {"seconds": 0, "min": 5, "max": 120},
        "sound": None,
        "resetButton": None,
        "privacyLock": None,
        "tamperAlert": None,
        "adminPasscode": "123456",
        "passcodes": [passcode("one_time", "Delivery", {"start": stamp, "end": stamp + 6 * 3600})],
        "fingerprints": [],
        "cards": [],
        "passage": [],
        "log": demo_log(
            stamp, [(5 * day, LOG_POWER_ON, 40), (3600, LOG_PASSCODE_UNLOCK, 34), (3000, LOG_KEY_UNLOCK, 34)]
        ),
    }
    for lock in (front, shed):
        lock.update(alerts=[], alertNext=1, warnings=[])
    return [front, shed]


def demo_nearby() -> list[dict]:
    return [
        {"mac": "00:00:5E:00:53:21", "name": "LK-MOCK-NEW", "rssi": -52, "paired": False},
        {"mac": "00:00:5E:00:53:22", "name": "LK-MOCK-OTHER", "rssi": -80, "paired": True},
    ]


def new_lock(mac: str, name: str, admin_passcode: str) -> dict:
    stamp = now()
    return {
        "id": mac,
        "mac": mac,
        "name": name,
        "model": "LK-MOCK-1",
        "hardware": "1.4",
        "firmware": "6.0.2.240117",
        "manufactureDate": "2025-03-02",
        "protocol": "3.1",
        "features": list(FULL_FEATURES),
        "state": "locked",
        "battery": 100,
        "rssi": -52,
        "lastSeen": stamp,
        "lastEvent": None,
        "hardened": False,
        "backedUp": False,
        "autolock": {"seconds": 0, "min": 1, "max": 900},
        "sound": {"enabled": True, "volume": 5},
        "resetButton": True,
        "privacyLock": False,
        "tamperAlert": False,
        "adminPasscode": admin_passcode,
        "passcodes": [passcode("permanent", "", None, managed=False, code="123456")],
        "fingerprints": [],
        "cards": [],
        "passage": [],
        "log": demo_log(stamp, [(5, LOG_POWER_ON, 100)]),
        "alerts": [],
        "alertNext": 1,
        "warnings": [],
    }


class EventHub:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._clients: dict[int, tuple[str | None, queue.Queue]] = {}
        self._next = 0

    def subscribe(self, token: str | None) -> tuple[int, queue.Queue]:
        with self._lock:
            self._next += 1
            inbox: queue.Queue = queue.Queue()
            self._clients[self._next] = (token, inbox)
            return self._next, inbox

    def unsubscribe(self, client: int) -> None:
        with self._lock:
            self._clients.pop(client, None)

    def publish(self, event: str, data: Any, tokens: set[str | None] | None = None) -> None:
        message = json.dumps({"event": event, "data": data})
        with self._lock:
            for token, inbox in self._clients.values():
                if tokens is None or token in tokens:
                    inbox.put(message)

    def disconnect(self, tokens: set[str | None] | None = None) -> None:
        with self._lock:
            for token, inbox in self._clients.values():
                if tokens is None or token in tokens:
                    inbox.put(None)


class Mock:
    def __init__(self) -> None:
        self.lock = threading.RLock()
        self.radio_lock = threading.Lock()
        self.events = EventHub()
        self.started = time.time()
        self.generation = 0
        self.timers: list[threading.Timer] = []
        self.reset()

    def later(self, seconds: float, action: Callable[[], None]) -> None:
        timer = threading.Timer(seconds, action)
        timer.daemon = True
        with self.lock:
            self.timers.append(timer)
        timer.start()

    def reset(self) -> None:
        with self.lock:
            for timer in self.timers:
                timer.cancel()
            self.timers = []
            self.generation += 1
            self.config = Config()
            self.password = MOCK_PASSWORD
            self.sessions: dict[str, float] = {}
            self.failures = 0
            self.blocked_until = 0.0
            self.fail_next: dict[str, RpcError] = {}
            self.warn_next: dict[str, str] = {}
            self.delay_next: dict[str, float] = {}
            self.calls: list[dict] = []
            self.audit: list[dict] = []
            self.locks: dict[str, dict] = {lock["id"]: lock for lock in demo_locks()}
            self.nearby = demo_nearby()
            self.backups: dict[str, dict] = {lock_id: copy.deepcopy(lock) for lock_id, lock in self.locks.items()}
            self.wifi = {
                "configured": True,
                "connected": True,
                "ssid": "lab-iot",
                "ip": "192.0.2.10",
                "gateway": "192.0.2.1",
                "netmask": "255.255.255.0",
                "dns": "192.0.2.53",
                "rssi": -58,
            }
            self.syslog = {
                "enabled": False,
                "host": "",
                "port": 514,
                "transport": "udp",
                "appName": "latchkey",
                "level": "info",
            }
            self.logs: list[dict] = []
            self.log_seq = 0
            self._seed_logs()
            self.mqtt = {
                "enabled": False,
                "host": "",
                "port": 1883,
                "username": "",
                "password": "",
                "prefix": "homeassistant",
            }
            self._seed_audit()
        self.events.disconnect()

    def _seed_logs(self) -> None:
        synced = int(self.started) + 3
        for uptime_ms, level, tag, message in (
            (120, "info", "", "latchkey 0.1.0 board=esp32s3-atom chip=esp32s3 idf=v6.1.0"),
            (380, "info", "certs", f"HTTPS certificate SHA-256 {CERT_FINGERPRINT}"),
            (2100, "info", "wifi", "connected, ip 192.0.2.10"),
            (2950, "info", "clock", f"SNTP synced, utc {synced}"),
            (3400, "info", "lock", "2 lock(s) stored"),
            (64000, "warn", "wifi", "disconnected, reason 8"),
            (66100, "info", "wifi", "connected, ip 192.0.2.10"),
            (66200, "info", "http", "HTTPS on port 443, redirect on port 80"),
        ):
            self.append_line(level, tag, message, uptime_ms)

    def append_line(self, level: str, tag: str, message: str, uptime_ms: int | None = None) -> None:
        with self.lock:
            self.log_seq += 1
            elapsed = uptime_ms if uptime_ms is not None else int((time.time() - self.started) * 1000)
            self.logs.append({"seq": self.log_seq, "uptimeMs": elapsed, "level": level, "tag": tag, "message": message})
            del self.logs[:-LOG_RING_LINES]

    def _log_view(self, line: dict) -> dict:
        utc = int(self.started * 1000) + line["uptimeMs"] if self.config.time_synced else None
        return {**line, "utcMs": utc}

    def _seed_audit(self) -> None:
        stamp = now()
        day = 86400
        for age, source, method, target, result in (
            (3 * day, "serial", "system.setup", None, "ok"),
            (3 * day - 60, "web", "auth.login", None, "ok"),
            (3 * day - 120, "web", "locks.pair", FRONT_DOOR, "ok"),
            (3 * day - 180, "web", "keys.export", FRONT_DOOR, "ok"),
            (3 * day - 240, "web", "lock.harden", FRONT_DOOR, "ok"),
            (day, "web", "locks.pair", SHED, "ok"),
            (3600, "web", "auth.login", None, "unauthorized"),
        ):
            entry = {
                "seq": len(self.audit) + 1,
                "time": stamp - age,
                "source": source,
                "method": method,
                "result": result,
            }
            if target:
                entry["target"] = target
            self.audit.append(entry)

    def emit(self, event: str, data: Any, generation: int | None = None, tokens: set[str | None] | None = None) -> None:
        if generation is not None and generation != self.generation:
            return
        if event == "lock.alert":
            with self.lock:
                lock = self.locks[data["lock"]]
                alert = {"kind": "unexpected_unlock", **{key: data[key] for key in ("time", "method", "seq", "type")}}
                if any(all(held[key] == value for key, value in alert.items()) for held in lock["alerts"]):
                    return
                lock["alerts"].append({"id": lock["alertNext"], **alert})
                lock["alertNext"] += 1
                lock["alerts"] = lock["alerts"][-8:]
        self.events.publish(event, data, tokens)

    def wait(self, seconds: float, generation: int) -> bool:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if generation != self.generation:
                return False
            time.sleep(min(0.05, max(0.0, deadline - time.monotonic())))
        return generation == self.generation

    @contextmanager
    def radio(self, extra_s: float = 0.0) -> Iterator[int]:
        generation = self.generation
        if not self.radio_lock.acquire(timeout=QUEUE_WAIT_S):
            raise RpcError("busy", f"waited {QUEUE_WAIT_S} s in the lock queue")
        try:
            if not self.wait(self.config.latency_ms / 1000 + extra_s, generation):
                raise RpcError("disconnected", "the mock was reset")
            yield generation
        finally:
            self.radio_lock.release()

    def confirm(self, action: str) -> None:
        generation = self.generation
        config = self.config
        self.emit("confirm.required", {"action": action, "timeoutMs": config.confirm_timeout_ms}, generation)
        if config.confirm == "auto" and config.confirm_delay_ms < config.confirm_timeout_ms:
            if not self.wait(config.confirm_delay_ms / 1000, generation):
                raise RpcError("confirm_timeout", "the mock was reset")
            self.emit("confirm.result", {"action": action, "confirmed": True}, generation)
            return
        if self.wait(config.confirm_timeout_ms / 1000, generation):
            self.emit("confirm.result", {"action": action, "confirmed": False}, generation)
        raise RpcError("confirm_timeout", f"the button was not pressed within {config.confirm_timeout_ms / 1000:g} s")

    def session_valid(self, token: str | None) -> bool:
        if not token:
            return False
        with self.lock:
            seen = self.sessions.get(token)
            if seen is None:
                return False
            if time.time() - seen > IDLE_TIMEOUT_S:
                del self.sessions[token]
                return False
            self.sessions[token] = time.time()
            return True

    def get_lock(self, params: dict) -> dict:
        lock_id = params.get("lock")
        if not isinstance(lock_id, str) or not lock_id:
            raise invalid("lock is required")
        with self.lock:
            lock = self.locks.get(lock_id)
        if lock is None:
            raise RpcError("not_paired", f"no paired lock {lock_id}")
        return lock

    def append_audit(self, method: str, ctx: Context, params: dict, result: str) -> None:
        with self.lock:
            entry = {"seq": len(self.audit) + 1, "time": now(), "source": "web", "method": method, "result": result}
            target = ctx.target or params.get("lock")
            if isinstance(target, str) and target:
                entry["target"] = target
            self.audit.append(entry)
        self.emit("audit.appended", entry)

    def append_log(self, lock: dict, kind: int) -> None:
        seq = lock["log"][-1]["seq"] + 1 if lock["log"] else 1
        lock["log"].append({"seq": seq, "time": now(), "type": kind, "battery": lock["battery"]})

    def dispatch(self, name: str, params: Any, ctx: Context) -> dict[str, Any]:
        with self.lock:
            self.calls.append({"method": name, "params": redact(params) if isinstance(params, dict) else params})
        method = METHODS.get(name)
        if method is None:
            raise RpcError("unknown_method", f"no method {name}")
        if not isinstance(params, dict):
            raise invalid("params must be an object")
        if method.session and not self.session_valid(ctx.token):
            raise RpcError("unauthorized", "sign in first")
        generation = self.generation
        try:
            with self.lock:
                injected = self.fail_next.pop(name, None)
                delay = self.delay_next.pop(name, 0.0)
            if delay and not self.wait(delay, generation):
                raise RpcError("disconnected", "the mock was reset")
            if injected:
                raise injected
            if method.feature:
                lock = self.get_lock(params)
                if method.feature not in lock["features"]:
                    raise RpcError("unsupported", f"the lock does not report {method.feature}")
            if method.job:
                return self._start_job(name, method, ctx, params)
            result = self._warned(name, method.handler(self, ctx, params))
        except RpcError as err:
            if method.audited and generation == self.generation:
                self.append_audit(name, ctx, params, err.code)
            raise
        if method.audited and generation == self.generation:
            self.append_audit(name, ctx, params, "ok")
        return result

    def _warned(self, name: str, result: dict[str, Any]) -> dict[str, Any]:
        with self.lock:
            warning = self.warn_next.pop(name, None)
        if warning:
            result = {**result, "warning": f"{result['warning']}; {warning}" if result.get("warning") else warning}
        return result

    def _start_job(self, name: str, method: Method, ctx: Context, params: dict) -> dict[str, Any]:
        job = new_id("job")
        generation = self.generation

        def run() -> None:
            try:
                result = self._warned(name, method.handler(self, ctx, params))
            except RpcError as err:
                if generation == self.generation:
                    if method.audited:
                        self.append_audit(name, ctx, params, err.code)
                    self.emit("job.done", {"job": job, "error": err.to_json()}, generation, {ctx.token})
                return
            if generation == self.generation:
                if method.audited:
                    self.append_audit(name, ctx, params, "ok")
                self.emit("job.done", {"job": job, "result": result}, generation, {ctx.token})

        threading.Thread(target=run, daemon=True).start()
        if self.config.job_reply_delay_ms:
            self.wait(self.config.job_reply_delay_ms / 1000, generation)
        return {"job": job}

    def control(self, body: dict) -> None:
        if body.get("reset"):
            self.reset()
        with self.lock:
            config = self.config
            if "confirm" in body:
                if body["confirm"] not in ("auto", "never"):
                    raise invalid("confirm is auto or never")
                config.confirm = body["confirm"]
            config.confirm_delay_ms = int(body.get("confirmDelayMs", config.confirm_delay_ms))
            config.confirm_timeout_ms = int(body.get("confirmTimeoutMs", config.confirm_timeout_ms))
            config.latency_ms = int(body.get("latencyMs", config.latency_ms))
            config.job_reply_delay_ms = int(body.get("jobReplyDelayMs", config.job_reply_delay_ms))
            if "delay" in body:
                self.delay_next[body["delay"]["method"]] = int(body["delay"]["ms"]) / 1000
            if "timeSynced" in body:
                config.time_synced = bool(body["timeSynced"])
            if "warnNext" in body:
                self.warn_next[body["warnNext"]["method"]] = body["warnNext"]["warning"]
            if "failNext" in body:
                failure = body["failNext"]
                self.fail_next[failure["method"]] = RpcError(failure["code"], failure.get("message", failure["code"]))
            if "scanExtra" in body:
                self.nearby.extend(dict(device) for device in body["scanExtra"])
            for line in body.get("logLines", []):
                self.append_line(line.get("level", "info"), line.get("tag", ""), line["message"])
            if "setLock" in body:
                changes = dict(body["setLock"])
                self.locks[changes.pop("id")].update(changes)
            if body.get("expireSessions"):
                self.sessions.clear()
        if body.get("expireSessions") or body.get("dropSockets"):
            self.events.disconnect()
        for item in body.get("emit", []):
            self.emit(item["event"], item["data"])

    @rpc("system.info", audited=False)
    def system_info(self, ctx: Context, params: dict) -> dict:
        synced = self.config.time_synced
        with self.lock:
            warnings = [
                {"lock": lock["id"], "warnings": summary(lock)["warnings"]}
                for lock in self.locks.values()
                if summary(lock)["warnings"]
            ]
        return {
            "firmware": "0.1.0",
            "board": "esp32s3-atom",
            "chip": "esp32s3",
            "idf": "v6.1.0",
            "uptime": int(time.time() - self.started),
            "heap": {"free": 151552, "minFree": 98304},
            "time": {"utc": now() if synced else 0, "synced": synced},
            "timezone": "UTC0",
            "localTime": time.strftime("%Y-%m-%dT%H:%M:%S+00:00", time.gmtime()) if synced else None,
            "wifi": dict(self.wifi),
            "certFingerprint": CERT_FINGERPRINT,
            "warnings": warnings,
            "logs": {"lines": len(self.logs), "capacity": LOG_RING_BYTES, "withheld": 0},
            "syslog": {key: value for key, value in self._syslog_view().items() if key in SYSLOG_COUNTERS},
        }

    @rpc("system.setup", session=False, audited=False)
    def system_setup(self, ctx: Context, params: dict) -> dict:
        raise RpcError("unsupported", "system.setup is only available over USB serial")

    @rpc("system.wifi.set")
    def system_wifi_set(self, ctx: Context, params: dict) -> dict:
        ssid = params.get("ssid")
        password = params.get("password")
        addresses = {key: parse_ipv4(params.get(key)) for key in ("ip", "gateway", "netmask", "dns")}
        valid = (
            isinstance(ssid, str)
            and 1 <= len(ssid.encode()) <= 32
            and isinstance(password, str)
            and (password == "" or 8 <= len(password.encode()) <= 63)
            and None not in addresses.values()
            and addresses["dns"] != 0
            and is_static_ipv4(addresses["ip"], addresses["gateway"], addresses["netmask"])
        )
        if not valid:
            raise invalid(WIFI_MESSAGE)
        with self.lock:
            self.wifi.update({"configured": True, "ssid": ssid})
            self.wifi.update({key: params[key] for key in addresses})
        return {}

    @rpc("system.logs", audited=False)
    def system_logs(self, ctx: Context, params: dict) -> dict:
        since = params.get("since")
        if since is not None and (isinstance(since, bool) or not isinstance(since, int) or not 0 <= since < 2**32):
            raise invalid("since must be the sequence number of a log line")
        level = params.get("level", "verbose")
        if level is None:
            level = "verbose"
        if level not in LOG_LEVELS:
            raise invalid(LEVEL_MESSAGE)
        limit = params.get("limit", LOG_PAGE_LINES)
        if limit is None:
            limit = LOG_PAGE_LINES
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= LOG_PAGE_LINES:
            raise invalid("limit must be 1 to 100")
        allowed = LOG_LEVELS[: LOG_LEVELS.index(level) + 1]
        with self.lock:
            held = [dict(line) for line in self.logs]
            newest = self.log_seq
        matching = [line for line in held if line["level"] in allowed]
        if since is None:
            window, more = matching[-limit:], False
        else:
            later = [line for line in matching if line["seq"] > since]
            window, more = later[:limit], len(later) > limit
        oldest = held[0]["seq"] if held else newest + 1
        return {
            "lines": [self._log_view(line) for line in window],
            "more": more,
            "next": window[-1]["seq"] if more else newest,
            "missed": max(0, oldest - since - 1) if since is not None else 0,
        }

    def _syslog_view(self) -> dict:
        on = self.syslog["enabled"]
        return {**self.syslog, "connected": on, "sent": 0, "dropped": 0, "errors": 0}

    @rpc("system.syslog.get", audited=False)
    def system_syslog_get(self, ctx: Context, params: dict) -> dict:
        return self._syslog_view()

    @rpc("system.syslog.set")
    def system_syslog_set(self, ctx: Context, params: dict) -> dict:
        enabled = params.get("enabled")
        if not isinstance(enabled, bool):
            raise invalid("enabled must be true or false")
        host = params.get("host") or ""
        if not isinstance(host, str):
            raise invalid(HOST_MESSAGE)
        host = host.strip(" ")
        if host and (len(host) > 64 or not HOST_NAME.match(host)):
            raise invalid(HOST_MESSAGE)
        if enabled and not host:
            raise invalid("host is required to turn remote logging on")
        port = params.get("port")
        if port is None:
            port = 514
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise invalid("port must be 1 to 65535")
        transport = params.get("transport") or "udp"
        if transport not in ("udp", "tcp"):
            raise invalid("transport is udp or tcp")
        app_name = params.get("appName") or ""
        if not isinstance(app_name, str) or (app_name.strip(" ") and not is_app_name(app_name.strip(" "))):
            raise invalid("appName must be 1 to 48 printable ASCII characters without spaces")
        level = params.get("level") or "info"
        if level not in LOG_LEVELS:
            raise invalid(LEVEL_MESSAGE)
        with self.lock:
            self.syslog = {
                "enabled": enabled,
                "host": host,
                "port": port,
                "transport": transport,
                "appName": app_name.strip(" ") or "latchkey",
                "level": level,
            }
        return self._syslog_view()

    @rpc("system.reboot")
    def system_reboot(self, ctx: Context, params: dict) -> dict:
        self.later(0.3, self.events.disconnect)
        return {"rebooting": True}

    @rpc("system.factoryReset", job=True)
    def system_factory_reset(self, ctx: Context, params: dict) -> dict:
        self.confirm("system.factoryReset")
        self.later(0.3, self.reset)
        return {"rebooting": True}

    @rpc("auth.login", session=False)
    def auth_login(self, ctx: Context, params: dict) -> dict:
        with self.lock:
            wait = self.blocked_until - time.time()
        if wait > 0:
            seconds = math.ceil(wait)
            raise RpcError("rate_limited", f"too many failed sign-ins; try again in {seconds} s", retryAfter=seconds)
        if not self.config.time_synced:
            raise RpcError("time_unsynced", "the board clock is not set, so codes cannot be checked")
        password = params.get("password")
        code = params.get("totp")
        if not isinstance(password, str) or not isinstance(code, str):
            raise invalid("password and totp are required")
        good = hmac.compare_digest(password.encode(), self.password.encode())
        good &= hmac.compare_digest(code.encode(), MOCK_TOTP.encode())
        with self.lock:
            if not good:
                self.failures += 1
                if self.failures >= LOGIN_FAILURES_BEFORE_BACKOFF:
                    self.failures = 0
                    self.blocked_until = time.time() + LOGIN_BACKOFF_S
                raise RpcError("unauthorized", "wrong password or code")
            self.failures = 0
            token = secrets.token_urlsafe(32)
            self.sessions[token] = time.time()
        ctx.cookies.append(f"{SESSION_COOKIE}={token}; Path=/; HttpOnly; SameSite=Strict")
        return {"idleTimeout": IDLE_TIMEOUT_S}

    @rpc("auth.logout", session=False)
    def auth_logout(self, ctx: Context, params: dict) -> dict:
        with self.lock:
            if params.get("all") is True and self.session_valid(ctx.token):
                ended: set[str | None] = set(self.sessions)
                self.sessions.clear()
            else:
                ended = {ctx.token}
                self.sessions.pop(ctx.token or "", None)
        self.events.disconnect(ended)
        ctx.cookies.append(f"{SESSION_COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict")
        return {}

    @rpc("auth.changePassword")
    def auth_change_password(self, ctx: Context, params: dict) -> dict:
        current = params.get("current")
        new = params.get("new")
        if not isinstance(current, str) or not isinstance(new, str):
            raise invalid("current and new are required")
        if not hmac.compare_digest(current.encode(), self.password.encode()):
            raise invalid("the current password is wrong")
        if not 12 <= len(new) <= 128:
            raise invalid("the new password needs 12 to 128 characters")
        with self.lock:
            self.password = new
            ended = {token for token in self.sessions if token != ctx.token}
            for token in ended:
                del self.sessions[token]
        self.events.disconnect(ended)
        return {}

    @rpc("auth.rotateTotp", job=True)
    def auth_rotate_totp(self, ctx: Context, params: dict) -> dict:
        self.confirm("auth.rotateTotp")
        secret = base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")
        return {
            "otpauth": f"otpauth://totp/Latchkey:owner?secret={secret}&issuer=Latchkey&algorithm=SHA1&digits=6&period=30"
        }

    @rpc("locks.scan", audited=False, job=True)
    def locks_scan(self, ctx: Context, params: dict) -> dict:
        seconds = int_param(params, "seconds", default=10, lo=1, hi=30)
        generation = self.generation
        with self.lock:
            found = [dict(device) for device in self.nearby]
            found += [
                {
                    "mac": lock["mac"],
                    "name": advert_name(lock),
                    "rssi": lock["rssi"],
                    "paired": True,
                    "lock": lock["id"],
                }
                for lock in self.locks.values()
            ]

        def stream() -> None:
            for device in found:
                if not self.wait(0.2, generation):
                    return
                self.emit("scan.result", device, generation)

        threading.Thread(target=stream, daemon=True).start()
        return {"seconds": seconds}

    @rpc("locks.list", audited=False)
    def locks_list(self, ctx: Context, params: dict) -> dict:
        with self.lock:
            return {"locks": [summary(lock) for lock in self.locks.values()]}

    @rpc("locks.rename")
    def locks_rename(self, ctx: Context, params: dict) -> dict:
        lock = self.get_lock(params)
        lock["name"] = text_param(params, "name", max_len=32, required=True)
        return {"lock": summary(lock)}

    @rpc("locks.forget")
    def locks_forget(self, ctx: Context, params: dict) -> dict:
        lock = self.get_lock(params)
        with self.lock:
            self.backups.setdefault(lock["id"], copy.deepcopy(lock))
            del self.locks[lock["id"]]
        return {}

    @rpc("locks.pair", job=True)
    def locks_pair(self, ctx: Context, params: dict) -> dict:
        mac = text_param(params, "mac", max_len=17, required=True).upper()
        name = text_param(params, "name", max_len=32) or "New lock"
        ctx.target = mac
        chosen = params.get("adminPasscode")
        admin_passcode = random_digits(ADMIN_PASSCODE_DIGITS) if chosen in (None, "") else digits_param(chosen)
        with self.lock:
            device = next((item for item in self.nearby if item["mac"].upper() == mac), None)
        if device is None:
            raise RpcError("timeout", "no lock with that address answered")
        if device["paired"]:
            raise RpcError("lock_error", "the lock is already paired to other keys; factory-reset it first")
        self.confirm("locks.pair")
        with self.radio(extra_s=1.0):
            lock = new_lock(mac, name, admin_passcode)
            with self.lock:
                self.locks[mac] = lock
                self.nearby = [item for item in self.nearby if item["mac"].upper() != mac]
        self.emit("lock.state", {"lock": mac, "state": lock["state"], "battery": lock["battery"]})
        return {"lock": summary(lock)}

    @rpc("lock.status", audited=False, job=True)
    def lock_status(self, ctx: Context, params: dict) -> dict:
        lock = self.get_lock(params)
        with self.radio():
            lock["lastSeen"] = now()
        return {"state": lock["state"], "battery": lock["battery"]}

    @rpc("lock.info", audited=False, job=True)
    def lock_info(self, ctx: Context, params: dict) -> dict:
        lock = self.get_lock(params)
        return {key: lock[key] for key in ("mac", "model", "hardware", "firmware", "manufactureDate", "protocol")}

    @rpc("lock.features", audited=False, job=True)
    def lock_features(self, ctx: Context, params: dict) -> dict:
        return {"features": list(self.get_lock(params)["features"])}

    def _operate(self, params: dict, action: str) -> dict:
        lock = self.get_lock(params)
        with self.radio():
            lock["state"] = "unlocked" if action == "unlock" else "locked"
            event = {"action": action, "method": "app", "time": now()}
            lock["lastEvent"] = event
            lock["lastSeen"] = now()
            self.append_log(lock, LOG_APP_UNLOCK if action == "unlock" else LOG_APP_LOCK)
        self.emit("lock.state", {"lock": lock["id"], "state": lock["state"], "battery": lock["battery"]})
        self.emit("lock.event", {"lock": lock["id"], **event})
        return {"state": lock["state"], "battery": lock["battery"]}

    @rpc("lock.unlock", job=True)
    def lock_unlock(self, ctx: Context, params: dict) -> dict:
        return self._operate(params, "unlock")

    @rpc("lock.lock", job=True)
    def lock_lock(self, ctx: Context, params: dict) -> dict:
        return self._operate(params, "lock")

    @rpc("lock.time.sync", job=True)
    def lock_time_sync(self, ctx: Context, params: dict) -> dict:
        self.get_lock(params)
        if not self.config.time_synced:
            raise RpcError("time_unsynced", "the board clock is not set yet")
        with self.radio():
            pass
        return {"time": now()}

    @rpc("lock.autolock.get", feature="auto_lock", audited=False, job=True)
    def lock_autolock_get(self, ctx: Context, params: dict) -> dict:
        lock = self.get_lock(params)
        with self.radio():
            return dict(lock["autolock"])

    @rpc("lock.autolock.set", feature="auto_lock", job=True)
    def lock_autolock_set(self, ctx: Context, params: dict) -> dict:
        lock = self.get_lock(params)
        setting = lock["autolock"]
        seconds = int_param(params, "seconds", lo=0, hi=setting["max"])
        if seconds is None or (seconds and seconds < setting["min"]):
            raise invalid(f"auto-lock is 0 (off) or {setting['min']} to {setting['max']} s")
        with self.radio():
            setting["seconds"] = seconds
        return dict(setting)

    @rpc("lock.passage.list", feature="passage_mode", audited=False, job=True)
    def lock_passage_list(self, ctx: Context, params: dict) -> dict:
        lock = self.get_lock(params)
        with self.radio():
            return {"modes": copy.deepcopy(lock["passage"])}

    def _passage_entry(self, params: dict, day: Any) -> dict:
        if params.get("type", "weekly") != "weekly":
            raise invalid("only weekly passage windows can be added")
        if isinstance(day, bool) or not isinstance(day, int) or not 0 <= day <= 7:
            raise invalid("day is 0 (every day) or 1 (Monday) to 7 (Sunday)")
        start = hhmm_param(params.get("start"), "start")
        end = hhmm_param(params.get("end"), "end")
        if end <= start:
            raise invalid("the passage window must end after it starts")
        return {"type": "weekly", "day": day, "start": start, "end": end}

    def _listed_entry(self, params: dict) -> dict:
        kind = params.get("type")
        day = params.get("day")
        if kind not in ("weekly", "monthly"):
            raise invalid("type is weekly or monthly")
        low, high = (0, 7) if kind == "weekly" else (1, 31)
        if isinstance(day, bool) or not isinstance(day, int) or not low <= day <= high:
            raise invalid(f"day is {low} to {high} for a {kind} passage mode")
        entry = {"type": kind, "day": day}
        if kind == "monthly":
            entry["month"] = int_param(params, "month", default=0, lo=0, hi=12)
        entry["start"] = hhmm_param(params.get("start"), "start")
        entry["end"] = hhmm_param(params.get("end"), "end")
        return entry

    @rpc("lock.passage.add", feature="passage_mode", job=True)
    def lock_passage_add(self, ctx: Context, params: dict) -> dict:
        lock = self.get_lock(params)
        days = params.get("days")
        if not isinstance(days, list) or not days:
            raise invalid("days lists 0 (every day) or weekdays 1 to 7")
        entries = [self._passage_entry(params, day) for day in days]
        with self.radio():
            for entry in entries:
                if entry not in lock["passage"]:
                    lock["passage"].append(entry)
        return {"modes": copy.deepcopy(lock["passage"])}

    @rpc("lock.passage.delete", feature="passage_mode", job=True)
    def lock_passage_delete(self, ctx: Context, params: dict) -> dict:
        lock = self.get_lock(params)
        entry = self._listed_entry(params)
        if entry not in lock["passage"]:
            raise invalid("no such passage mode on the lock")
        with self.radio():
            lock["passage"].remove(entry)
        return {"modes": copy.deepcopy(lock["passage"])}

    @rpc("lock.passage.clear", feature="passage_mode", job=True)
    def lock_passage_clear(self, ctx: Context, params: dict) -> dict:
        lock = self.get_lock(params)
        with self.radio():
            lock["passage"] = []
        return {"modes": []}

    def _find(self, lock: dict, collection: str, item_id: Any) -> dict:
        if not isinstance(item_id, str):
            raise invalid("id is required")
        entry = next((item for item in lock[collection] if item["id"] == item_id), None)
        if entry is None:
            raise invalid(f"no such entry {item_id}")
        return entry

    @rpc("lock.passcodes.list", feature="passcode", audited=False, job=True)
    def lock_passcodes_list(self, ctx: Context, params: dict) -> dict:
        lock = self.get_lock(params)
        with self.radio():
            return {"passcodes": [public_passcode(entry) for entry in lock["passcodes"]]}

    @rpc("lock.passcodes.add", feature="passcode", job=True)
    def lock_passcodes_add(self, ctx: Context, params: dict) -> dict:
        lock = self.get_lock(params)
        kind = params.get("type")
        if kind not in PASSCODE_TYPES:
            raise invalid(f"type is one of {', '.join(PASSCODE_TYPES)}")
        supplied = params.get("code")
        code = random_digits(6) if supplied in (None, "") else digits_param(supplied)
        name = text_param(params, "name", max_len=24)
        if kind == "cyclic":
            raise RpcError("unsupported", "this board cannot add cyclic passcodes yet")
        validity = None if kind == "permanent" else validity_param(params.get("validity"), required=True)
        entry = passcode(kind, name, validity, code=code)
        if code == lock["adminPasscode"] or any(item["code"] == code for item in lock["passcodes"]):
            raise RpcError("lock_error", IN_USE)
        with self.radio():
            lock["passcodes"].append(entry)
        result: dict[str, Any] = {"passcode": {**public_passcode(entry), "code": code}}
        if is_easy_code(code):
            result["warning"] = EASY_CODE_WARNING
        return result

    @rpc("lock.passcodes.update", feature="modify_passcode_function", job=True)
    def lock_passcodes_update(self, ctx: Context, params: dict) -> dict:
        lock = self.get_lock(params)
        entry = self._find(lock, "passcodes", params.get("id"))
        changes: dict[str, Any] = {}
        if params.get("code") not in (None, ""):
            changes["code"] = digits_param(params["code"])
            taken = any(item["code"] == changes["code"] and item is not entry for item in lock["passcodes"])
            if taken or changes["code"] == lock["adminPasscode"]:
                raise RpcError("lock_error", IN_USE)
            if changes["code"] != entry["code"]:
                changes["id"] = new_id("pc")
        if "name" in params:
            changes["name"] = text_param(params, "name", max_len=24)
        if "validity" in params and entry["type"] != "permanent":
            changes["validity"] = validity_param(params["validity"], required=True)
        with self.radio():
            entry.update(changes)
        result: dict[str, Any] = {"passcode": public_passcode(entry)}
        if "code" in changes and is_easy_code(changes["code"]):
            result["warning"] = EASY_CODE_WARNING
        return result

    @rpc("lock.passcodes.delete", feature="passcode", job=True)
    def lock_passcodes_delete(self, ctx: Context, params: dict) -> dict:
        lock = self.get_lock(params)
        entry = self._find(lock, "passcodes", params.get("id"))
        with self.radio():
            lock["passcodes"].remove(entry)
        return {}

    @rpc("lock.passcodes.clear", feature="passcode", job=True)
    def lock_passcodes_clear(self, ctx: Context, params: dict) -> dict:
        lock = self.get_lock(params)
        with self.radio():
            lock["passcodes"] = []
        return {}

    def _credentials(self, params: dict, collection: str) -> dict:
        lock = self.get_lock(params)
        with self.radio():
            return {collection: copy.deepcopy(lock[collection])}

    def _enroll(self, params: dict, collection: str, kind: str, scans: int) -> dict:
        lock = self.get_lock(params)
        name = text_param(params, "name", max_len=24)
        validity = validity_param(params.get("validity"), required=False)
        progress = {"lock": lock["id"], "kind": kind}
        with self.radio() as generation:
            self.emit("enroll.progress", {**progress, "stage": "waiting", "scans": 0, "total": scans}, generation)
            for scan in range(1, scans + 1):
                if not self.wait(0.6, generation):
                    raise RpcError("disconnected", "the mock was reset")
                self.emit(
                    "enroll.progress", {**progress, "stage": "progress", "scans": scan, "total": scans}, generation
                )
            if not self.wait(0.5, generation):
                raise RpcError("disconnected", "the mock was reset")
            if kind == "fingerprint":
                item_id = str(max((int(item["id"]) for item in lock[collection]), default=0) + 1)
            else:
                item_id = str(1_000_000_000 + secrets.randbelow(3_000_000_000))
            entry = {"id": item_id, "name": name, "validity": validity}
            lock[collection].append(entry)
            self.emit("enroll.progress", {**progress, "stage": "added", "id": item_id}, generation)
        return {kind: dict(entry)}

    def _set_validity(self, params: dict, collection: str) -> dict:
        lock = self.get_lock(params)
        entry = self._find(lock, collection, params.get("id"))
        validity = validity_param(params.get("validity"), required=False)
        cycle = None if params.get("cycle") is None else cycle_param(params["cycle"])
        if cycle is not None and "cyclic_ic_or_finger_print" not in lock["features"]:
            raise RpcError("unsupported", "the lock does not report cyclic_ic_or_finger_print")
        with self.radio():
            entry["validity"] = validity
            if cycle is None:
                entry.pop("cycle", None)
            else:
                entry["cycle"] = cycle
        return dict(entry)

    def _delete(self, params: dict, collection: str) -> dict:
        lock = self.get_lock(params)
        entry = self._find(lock, collection, params.get("id"))
        with self.radio():
            lock[collection].remove(entry)
        return {}

    def _clear(self, params: dict, collection: str) -> dict:
        lock = self.get_lock(params)
        with self.radio():
            lock[collection] = []
        return {}

    @rpc("lock.fingerprints.list", feature="finger_print", audited=False, job=True)
    def lock_fingerprints_list(self, ctx: Context, params: dict) -> dict:
        return self._credentials(params, "fingerprints")

    @rpc("lock.fingerprints.enroll", feature="finger_print", job=True)
    def lock_fingerprints_enroll(self, ctx: Context, params: dict) -> dict:
        return self._enroll(params, "fingerprints", "fingerprint", 4)

    @rpc("lock.fingerprints.setValidity", feature="finger_print", job=True)
    def lock_fingerprints_set_validity(self, ctx: Context, params: dict) -> dict:
        return {"fingerprint": self._set_validity(params, "fingerprints")}

    @rpc("lock.fingerprints.delete", feature="finger_print", job=True)
    def lock_fingerprints_delete(self, ctx: Context, params: dict) -> dict:
        return self._delete(params, "fingerprints")

    @rpc("lock.fingerprints.clear", feature="finger_print", job=True)
    def lock_fingerprints_clear(self, ctx: Context, params: dict) -> dict:
        return self._clear(params, "fingerprints")

    @rpc("lock.cards.list", feature="ic", audited=False, job=True)
    def lock_cards_list(self, ctx: Context, params: dict) -> dict:
        return self._credentials(params, "cards")

    @rpc("lock.cards.enroll", feature="ic", job=True)
    def lock_cards_enroll(self, ctx: Context, params: dict) -> dict:
        return self._enroll(params, "cards", "card", 1)

    @rpc("lock.cards.setValidity", feature="ic", job=True)
    def lock_cards_set_validity(self, ctx: Context, params: dict) -> dict:
        return {"card": self._set_validity(params, "cards")}

    @rpc("lock.cards.delete", feature="ic", job=True)
    def lock_cards_delete(self, ctx: Context, params: dict) -> dict:
        return self._delete(params, "cards")

    @rpc("lock.cards.clear", feature="ic", job=True)
    def lock_cards_clear(self, ctx: Context, params: dict) -> dict:
        return self._clear(params, "cards")

    @rpc("lock.log.fetch", audited=False, job=True)
    def lock_log_fetch(self, ctx: Context, params: dict) -> dict:
        lock = self.get_lock(params)
        since = int_param(params, "since", lo=0, hi=LOG_LAST_SLOT)
        with self.radio():
            if since is None:
                entries = [dict(entry) for entry in lock["log"][-LOG_SHOWN:]]
                more = False
            else:
                newer = [dict(entry) for entry in lock["log"] if entry["seq"] > since]
                entries = newer[:LOG_SHOWN]
                more = len(newer) > LOG_SHOWN
        last = entries[-1]["seq"] if entries else (since or 0)
        return {"entries": entries, "last": last, "more": more}

    @rpc("lock.sound.get", feature="audio_management", audited=False, job=True)
    def lock_sound_get(self, ctx: Context, params: dict) -> dict:
        lock = self.get_lock(params)
        with self.radio():
            return {**lock["sound"], "levels": 5}

    @rpc("lock.sound.set", feature="audio_management", job=True)
    def lock_sound_set(self, ctx: Context, params: dict) -> dict:
        lock = self.get_lock(params)
        enabled = bool_param(params, "enabled")
        volume = int_param(params, "volume", default=lock["sound"]["volume"], lo=1, hi=5)
        with self.radio():
            lock["sound"] = {"enabled": enabled, "volume": volume}
        return {**lock["sound"], "levels": 5}

    @rpc("lock.alerts.list", audited=False)
    def lock_alerts_list(self, ctx: Context, params: dict) -> dict:
        lock = self.get_lock(params)
        with self.lock:
            return {"alerts": copy.deepcopy(list(reversed(lock["alerts"]))), "warnings": summary(lock)["warnings"]}

    @rpc("lock.alerts.ack")
    def lock_alerts_ack(self, ctx: Context, params: dict) -> dict:
        through = int_param(params, "through", lo=0, hi=2**32 - 1)
        if through is None:
            raise invalid("through must be an alert id")
        lock = self.get_lock(params)
        with self.lock:
            if through >= lock["alertNext"]:
                raise invalid("through must identify an alert already issued for this lock")
            lock["alerts"] = [alert for alert in lock["alerts"] if alert["id"] > through]
            count = len(lock["alerts"])
        self.emit("lock.alerts.changed", {"lock": lock["id"], "alertCount": count})
        return self.lock_alerts_list(ctx, params)

    @rpc("lock.resetButton.get", feature="reset_button", audited=False, job=True)
    def lock_reset_button_get(self, ctx: Context, params: dict) -> dict:
        lock = self.get_lock(params)
        with self.radio():
            return {"enabled": lock["resetButton"]}

    @rpc("lock.resetButton.set", feature="reset_button", job=True)
    def lock_reset_button_set(self, ctx: Context, params: dict) -> dict:
        lock = self.get_lock(params)
        enabled = bool_param(params, "enabled")
        if not enabled:
            raise RpcError(
                "backup_required", "export this lock's keys with keys.export before turning its reset button off"
            )
        raise RpcError("unverified", "switch writes are not yet verified on this lock")

    def _switch(self, params: dict, key: str, *, write: bool) -> dict:
        lock = self.get_lock(params)
        if write:
            bool_param(params, "enabled")
            raise RpcError("unverified", "switch writes are not yet verified on this lock")
        with self.radio():
            return {"enabled": lock[key]}

    @rpc("lock.privacyLock.get", feature="privacy_lock", audited=False, job=True)
    def lock_privacy_lock_get(self, ctx: Context, params: dict) -> dict:
        return self._switch(params, "privacyLock", write=False)

    @rpc("lock.privacyLock.set", feature="privacy_lock", job=True)
    def lock_privacy_lock_set(self, ctx: Context, params: dict) -> dict:
        return self._switch(params, "privacyLock", write=True)

    @rpc("lock.tamperAlert.get", feature="tamper_alert", audited=False, job=True)
    def lock_tamper_alert_get(self, ctx: Context, params: dict) -> dict:
        return self._switch(params, "tamperAlert", write=False)

    @rpc("lock.tamperAlert.set", feature="tamper_alert", job=True)
    def lock_tamper_alert_set(self, ctx: Context, params: dict) -> dict:
        return self._switch(params, "tamperAlert", write=True)

    @rpc("lock.adminPasscode.set", feature="passcode", job=True)
    def lock_admin_passcode_set(self, ctx: Context, params: dict) -> dict:
        lock = self.get_lock(params)
        supplied = params.get("code")
        generated = supplied in (None, "")
        code = random_digits(ADMIN_PASSCODE_DIGITS) if generated else digits_param(supplied)
        self.confirm("lock.adminPasscode.set")
        if any(item["code"] == code for item in lock["passcodes"]):
            raise RpcError("lock_error", IN_USE)
        with self.radio():
            lock["adminPasscode"] = code
        if generated:
            return {"code": code}
        return {"warning": EASY_CODE_WARNING} if is_easy_code(code) else {}

    @rpc("lock.adminPasscode.get", job=True)
    def lock_admin_passcode_get(self, ctx: Context, params: dict) -> dict:
        lock = self.get_lock(params)
        self.confirm("lock.adminPasscode.get")
        if "get_admin_code" not in lock["features"]:
            return {"code": lock["adminPasscode"], "source": "board"}
        with self.radio():
            return {"code": lock["adminPasscode"], "source": "lock", "matchesBoard": True}

    def _harden_step(self, lock: dict, step: str) -> dict:
        if step == "admin_passcode":
            lock["adminPasscode"] = random_digits(8)
            return {"step": step, "ok": True}
        if step == "passcodes":
            unknown = [entry for entry in lock["passcodes"] if not entry["managed"]]
            lock["passcodes"] = [entry for entry in lock["passcodes"] if entry["managed"]]
            return {"step": step, "ok": True, "detail": f"{len(unknown)} removed"}
        if step == "reset_button":
            if "reset_button" not in lock["features"]:
                return {"step": step, "ok": True, "skipped": True, "detail": "the lock has no reset button switch"}
            lock["resetButton"] = False
            return {"step": step, "ok": True}
        return {"step": step, "ok": True}

    @rpc("lock.harden")
    def lock_harden(self, ctx: Context, params: dict) -> dict:
        lock = self.get_lock(params)
        if not lock["backedUp"]:
            raise RpcError("backup_required", "export this lock's keys with keys.export before hardening it")
        if not self.config.time_synced:
            raise RpcError("time_unsynced", "the board clock is not set yet")
        self.confirm("lock.harden")
        steps = []
        with self.radio() as generation:
            for step in HARDEN_STEPS:
                if not self.wait(0.25, generation):
                    raise RpcError("disconnected", "the mock was reset")
                result = self._harden_step(lock, step)
                steps.append(result)
                self.emit("harden.step", {"lock": lock["id"], **result}, generation)
            lock["hardened"] = True
        return {"steps": steps}

    @rpc("lock.factoryReset", job=True)
    def lock_factory_reset(self, ctx: Context, params: dict) -> dict:
        lock = self.get_lock(params)
        self.confirm("lock.factoryReset")
        with self.radio(extra_s=0.5):
            with self.lock:
                del self.locks[lock["id"]]
                self.nearby.append(
                    {"mac": lock["mac"], "name": advert_name(lock), "rssi": lock["rssi"], "paired": False}
                )
        return {}

    @rpc("keys.export")
    def keys_export(self, ctx: Context, params: dict) -> dict:
        passphrase = params.get("passphrase")
        if not isinstance(passphrase, str) or not 12 <= len(passphrase) <= 128:
            raise invalid("the passphrase needs 12 to 128 characters")
        if params.get("lock") is not None:
            ids = [self.get_lock(params)["id"]]
        else:
            with self.lock:
                ids = list(self.locks)
        if not ids:
            raise invalid("there are no locks to export")
        self.confirm("keys.export")
        salt = secrets.token_bytes(16)
        check = hmac.new(passphrase.encode(), salt, "sha256").digest()[:16]
        blob = b"LKB1" + salt + check + json.dumps(ids).encode()
        with self.lock:
            for lock_id in ids:
                self.locks[lock_id]["backedUp"] = True
                self.backups[lock_id] = copy.deepcopy(self.locks[lock_id])
        return {"backup": base64.b64encode(blob).decode(), "locks": ids}

    @rpc("keys.import")
    def keys_import(self, ctx: Context, params: dict) -> dict:
        passphrase = params.get("passphrase")
        backup = params.get("backup")
        if not isinstance(passphrase, str) or not isinstance(backup, str):
            raise invalid("passphrase and backup are required")
        try:
            blob = base64.b64decode(backup, validate=True)
            ids = json.loads(blob[36:]) if blob.startswith(b"LKB1") else None
        except ValueError:
            ids = None
        if not isinstance(ids, list):
            raise invalid("this is not a Latchkey key backup")
        check = hmac.new(passphrase.encode(), blob[4:20], "sha256").digest()[:16]
        if not hmac.compare_digest(check, blob[20:36]):
            raise invalid("wrong passphrase, or the backup is damaged")
        self.confirm("keys.import")
        with self.lock:
            restored = [lock_id for lock_id in ids if lock_id in self.backups]
            for lock_id in restored:
                self.locks.setdefault(lock_id, copy.deepcopy(self.backups[lock_id]))
        return {"imported": restored}

    @rpc("audit.list", audited=False)
    def audit_list(self, ctx: Context, params: dict) -> dict:
        before = int_param(params, "before", lo=1)
        limit = int_param(params, "limit", default=50, lo=1, hi=200)
        with self.lock:
            older = [entry for entry in reversed(self.audit) if before is None or entry["seq"] < before]
        return {"entries": [dict(entry) for entry in older[:limit]], "more": len(older) > limit}

    def _mqtt_view(self) -> dict:
        view = {key: value for key, value in self.mqtt.items() if key != "password"}
        view["passwordSet"] = bool(self.mqtt["password"])
        view["connected"] = self.mqtt["enabled"]
        view["problem"] = None
        return view

    @rpc("mqtt.get", audited=False)
    def mqtt_get(self, ctx: Context, params: dict) -> dict:
        return self._mqtt_view()

    @rpc("mqtt.set")
    def mqtt_set(self, ctx: Context, params: dict) -> dict:
        enabled = bool_param(params, "enabled")
        host = text_param(params, "host", max_len=64, required=enabled)
        if host and not HOST_NAME.match(host):
            raise invalid(HOST_MESSAGE)
        port = int_param(params, "port", default=1883, lo=1, hi=65535)
        username = text_param(params, "username", max_len=64)
        if any(ord(c) < 0x20 or ord(c) == 0x7F for c in username):
            raise invalid("username must be at most 64 printable characters")
        prefix = text_param(params, "prefix", max_len=32) or "homeassistant"
        if not HA_ID.match(prefix):
            raise invalid("prefix must be 1 to 32 letters, digits, - or _")
        password = params.get("password")
        if password is not None and (not isinstance(password, str) or len(password.encode()) > 64):
            raise invalid("password must be a string of at most 64 bytes")
        with self.lock:
            same_broker = (self.mqtt["host"], self.mqtt["port"], self.mqtt["username"]) == (host, port, username)
            self.mqtt.update({"enabled": enabled, "host": host, "port": port, "username": username, "prefix": prefix})
            if password is not None:
                self.mqtt["password"] = password
            elif not same_broker:
                self.mqtt["password"] = ""
        return self._mqtt_view()


class Server(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address: tuple[str, int], mock: Mock, web_dir: Path, verbose: bool) -> None:
        super().__init__(address, Handler)
        self.mock = mock
        self.web_dir = web_dir
        self.verbose = verbose

    def handle_error(self, request: Any, client_address: Any) -> None:
        if isinstance(sys.exc_info()[1], ConnectionError):
            return
        super().handle_error(request, client_address)


def _ws_frame(opcode: int, payload: bytes) -> bytes:
    size = len(payload)
    if size < 126:
        header = struct.pack("!BB", 0x80 | opcode, size)
    elif size < 65536:
        header = struct.pack("!BBH", 0x80 | opcode, 126, size)
    else:
        header = struct.pack("!BBQ", 0x80 | opcode, 127, size)
    return header + payload


def _recv_exact(sock: socket.socket, count: int) -> bytes:
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise ConnectionError("websocket closed")
        data += chunk
    return data


def _ws_read(sock: socket.socket) -> tuple[int, bytes]:
    first, second = _recv_exact(sock, 2)
    size = second & 0x7F
    if size == 126:
        size = struct.unpack("!H", _recv_exact(sock, 2))[0]
    elif size == 127:
        size = struct.unpack("!Q", _recv_exact(sock, 8))[0]
    if size > MAX_BODY:
        raise ConnectionError("websocket frame too large")
    mask = _recv_exact(sock, 4) if second & 0x80 else b"\x00\x00\x00\x00"
    payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(_recv_exact(sock, size)))
    return first & 0x0F, payload


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "latchkey-mock"
    sys_version = ""
    server: Server

    def log_message(self, format: str, *args: Any) -> None:
        if self.server.verbose:
            super().log_message(format, *args)

    def _common_headers(self) -> None:
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")

    def _send(self, status: int, body: bytes, content_type: str, headers: list[tuple[str, str]] | None = None) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self._common_headers()
        for name, value in headers or []:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, status: int, payload: Any, headers: list[tuple[str, str]] | None = None) -> None:
        self._send(status, json.dumps(payload).encode(), "application/json", headers)

    def _error(self, status: int, code: str, message: str, *, close: bool = False) -> None:
        headers = [("Connection", "close")] if close else []
        if close:
            self.close_connection = True
        self._json(status, {"id": None, "error": {"code": code, "message": message}}, headers)

    def _token(self) -> str | None:
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        cookie = SimpleCookie()
        try:
            cookie.load(raw)
        except CookieError:
            return None
        morsel = cookie.get(SESSION_COOKIE)
        return morsel.value if morsel else None

    def _origin_ok(self) -> bool:
        origin = self.headers.get("Origin")
        return origin is None or urlsplit(origin).netloc == self.headers.get("Host")

    def _body(self, limit: int) -> bytes | None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return None
        if not 0 <= length <= limit:
            return None
        return self.rfile.read(length)

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path in ("/", "/index.html"):
            try:
                html, policy = build_web.build(self.server.web_dir)
            except build_web.BuildError as err:
                return self._send(500, str(err).encode(), "text/plain; charset=utf-8")
            page = gzip.compress(html, compresslevel=9, mtime=0)
            headers = [("Content-Encoding", "gzip"), ("Content-Security-Policy", policy)]
            return self._send(200, page, "text/html; charset=utf-8", headers)
        if path == "/api/events":
            return self._events()
        if path == "/__mock/health":
            return self._json(200, {"ok": True})
        if path == "/__mock/calls":
            with self.server.mock.lock:
                return self._json(200, {"calls": list(self.server.mock.calls)})
        return self._error(404, "not_found", f"no resource {path}")

    def do_POST(self) -> None:
        path = urlsplit(self.path).path
        if path == "/api/rpc":
            return self._rpc()
        if path == "/api/ota":
            return self._ota()
        if path == "/__mock/control":
            return self._control()
        self._body(MAX_BODY)
        return self._error(404, "not_found", f"no resource {path}")

    def _rpc(self) -> None:
        body = self._body(MAX_BODY)
        if body is None:
            return self._error(413, "invalid_argument", "request too large", close=True)
        if not self._origin_ok():
            return self._error(403, "forbidden", "cross-origin request refused")
        if self.headers.get_content_type() != "application/json":
            return self._error(415, "invalid_argument", "send application/json")
        try:
            request = json.loads(body)
            method = request["method"]
            request_id = request.get("id")
            params = request.get("params", {})
        except (ValueError, KeyError, TypeError, AttributeError):
            return self._error(400, "invalid_argument", "malformed request")
        if not isinstance(method, str):
            return self._error(400, "invalid_argument", "method must be a string")
        ctx = Context(token=self._token())
        try:
            result = self.server.mock.dispatch(method, params if params is not None else {}, ctx)
        except RpcError as err:
            payload: dict[str, Any] = {"id": request_id, "error": err.to_json()}
        else:
            payload = {"id": request_id, "result": result}
        self._json(200, payload, [("Set-Cookie", cookie) for cookie in ctx.cookies])

    def _ota(self) -> None:
        mock = self.server.mock
        if not self._origin_ok():
            return self._error(403, "forbidden", "cross-origin request refused", close=True)
        if not mock.session_valid(self._token()):
            return self._error(401, "unauthorized", "sign in first", close=True)
        if self.headers.get_content_type() != "application/octet-stream":
            return self._error(415, "invalid_argument", "send application/octet-stream", close=True)
        image = self._body(OTA_SLOT_BYTES)
        if image is None:
            return self._error(
                413, "invalid_argument", f"the image is larger than the {OTA_SLOT_BYTES}-byte app slot", close=True
            )
        with mock.lock:
            mock.calls.append({"method": "ota", "params": {"bytes": len(image)}})
        if not image or image[0] != 0xE9:
            mock.append_audit("ota", Context(token=None), {}, "invalid_argument")
            return self._error(400, "invalid_argument", "not an ESP32 app image (missing the 0xE9 magic byte)")
        try:
            mock.confirm("ota")
        except RpcError as err:
            mock.append_audit("ota", Context(token=None), {}, err.code)
            return self._error(403, err.code, err.message)
        mock.append_audit("ota", Context(token=None), {}, "ok")
        mock.later(0.5, mock.events.disconnect)
        return self._json(200, {"result": {"bytes": len(image), "rebooting": True}})

    def _control(self) -> None:
        body = self._body(MAX_BODY)
        try:
            self.server.mock.control(json.loads(body or b"{}"))
        except (ValueError, KeyError, TypeError) as err:
            return self._error(400, "invalid_argument", f"bad control request: {err}")
        except RpcError as err:
            return self._error(400, err.code, err.message)
        return self._json(200, {"ok": True})

    def _events(self) -> None:
        mock = self.server.mock
        token = self._token()
        if not self._origin_ok():
            return self._error(403, "forbidden", "cross-origin request refused", close=True)
        if not mock.session_valid(token):
            return self._error(401, "unauthorized", "sign in first", close=True)
        key = self.headers.get("Sec-WebSocket-Key")
        if self.headers.get("Upgrade", "").lower() != "websocket" or not key:
            return self._error(400, "invalid_argument", "expected a WebSocket upgrade", close=True)
        accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
        self.send_response(101, "Switching Protocols")
        self.send_header("Upgrade", "websocket")
        self.send_header("Connection", "Upgrade")
        self.send_header("Sec-WebSocket-Accept", accept)
        self.end_headers()
        self.close_connection = True
        client, inbox = mock.events.subscribe(token)
        sock = self.connection
        try:
            while True:
                readable, _, _ = select.select([sock], [], [], 0.1)
                if readable:
                    opcode, payload = _ws_read(sock)
                    if opcode == 0x8:
                        sock.sendall(_ws_frame(0x8, payload[:2]))
                        return
                    if opcode == 0x9:
                        sock.sendall(_ws_frame(0xA, payload))
                while True:
                    try:
                        message = inbox.get_nowait()
                    except queue.Empty:
                        break
                    if message is None:
                        sock.sendall(_ws_frame(0x8, struct.pack("!H", 1001)))
                        return
                    sock.sendall(_ws_frame(0x1, message.encode()))
        except (ConnectionError, OSError):
            return
        finally:
            mock.events.unsubscribe(client)


def main() -> None:
    parser = argparse.ArgumentParser(description="Latchkey mock API for the web UI")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--web-dir", type=Path, default=build_web.DEFAULT_WEB_DIR)
    parser.add_argument("--verbose", action="store_true", help="log every request")
    args = parser.parse_args()
    server = Server((args.host, args.port), Mock(), args.web_dir, args.verbose)
    print(
        f"latchkey mock on http://{args.host}:{args.port}/ (password {MOCK_PASSWORD!r}, code {MOCK_TOTP!r})", flush=True
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
