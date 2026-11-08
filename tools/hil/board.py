# SPDX-License-Identifier: GPL-3.0-or-later
"""Requests to the board under test that the HIL suites share."""

from __future__ import annotations

import json
import time
from typing import Any

from latchkey_cli import Console

REQUEST_TIMEOUT_S = 30.0


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
