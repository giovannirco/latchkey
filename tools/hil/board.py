# SPDX-License-Identifier: GPL-3.0-or-later
"""Requests to the board under test that the HIL suites share."""

from __future__ import annotations

import json
import time
from typing import Any

from latchkey_cli import Console

REQUEST_TIMEOUT_S = 30.0
IDLE_TIMEOUT_S = 45.0


def error_code(console: Console, method: str, params: dict[str, Any] | None = None) -> str | None:
    reply = console.request(method, params, timeout=REQUEST_TIMEOUT_S)
    return reply.get("error", {}).get("code")


def set_clock(console: Console) -> float:
    now = time.time()
    assert console.call("system.time.set", {"utc": int(now)}) == {}
    return now


def is_json_object(line: str) -> bool:
    try:
        return isinstance(json.loads(line), dict)
    except ValueError:
        return False


def prepare(console: Console) -> dict[str, Any]:
    info = console.wait_ready()
    assert console.call("system.time.set", {"utc": int(time.time())}) == {}
    assert console.call("system.log.set", {"tag": "ble", "level": "debug"}) == {}
    console.wait_info(lambda state: state["ble"]["ready"], 15.0, "the Bluetooth host to sync")
    return info


def wait_idle(console: Console) -> dict[str, Any]:
    return console.wait_info(lambda state: not state["ble"]["connected"], IDLE_TIMEOUT_S, "the lock link to close")


def stored(console: Console, mac: str) -> dict[str, Any] | None:
    return next((lock for lock in console.call("locks.list")["locks"] if lock["id"] == mac), None)


def events_for(console: Console, name: str, mac: str) -> list[dict[str, Any]]:
    return [event["data"] for event in console.events if event["event"] == name and event["data"].get("lock") == mac]
