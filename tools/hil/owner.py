# SPDX-License-Identifier: GPL-3.0-or-later
"""Claiming a board and computing its TOTP codes in the HIL tests.

Secrets live only in memory, wrapped so that pytest tracebacks and assertion messages print <private>.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import re
import struct
import time
from typing import Any

import pytest
from latchkey_cli import Console

OTPAUTH = re.compile(
    r"otpauth://totp/Latchkey:(?P<board>[a-z0-9-]+)\?secret=(?P<secret>[A-Z2-7]{32})"
    r"&issuer=Latchkey&algorithm=SHA1&digits=6&period=30"
)
TOTP_STEP_S = 30
SAFE_STEP_WINDOW = (2.0, 24.0)
WIFI_JOIN_S = 45.0
claims: list[bytes] = []


class Private(str):
    def __repr__(self) -> str:
        return "<private>"


class PrivateBytes(bytes):
    def __repr__(self) -> str:
        return "<private>"


def hide(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: hide(item) for key, item in value.items()}
    if isinstance(value, str):
        return Private(value)
    return value


def wifi_params(secrets: dict[str, Any], board: dict[str, Any]) -> dict[str, Any]:
    return {
        "ssid": secrets["wifi_ssid"],
        "password": secrets["wifi_password"],
        "ip": board["static_ip"],
        "gateway": secrets["gateway"],
        "netmask": secrets["netmask"],
        "dns": secrets["dns"],
    }


def setup_params(secrets: dict[str, Any], board: dict[str, Any], wifi: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"wifi": {**wifi_params(secrets, board), **(wifi or {})}, "password": secrets["owner_password"]}


def otpauth_secret(uri: str, expected_board: str) -> bytes:
    match = OTPAUTH.fullmatch(uri)
    shaped = match is not None
    assert shaped, "otpauth URI does not have the expected shape"
    assert match["board"] == expected_board
    secret = PrivateBytes(base64.b32decode(match["secret"]))
    length = len(secret)
    assert length == 20
    nonzero = any(secret)
    assert nonzero, "TOTP secret is all zeros"
    claims.append(secret)
    return secret


def claim_secret(
    console: Console,
    secrets: dict[str, Any],
    board: dict[str, Any],
    expected_board: str,
    wifi: dict[str, Any] | None = None,
) -> bytes:
    result = console.call("system.setup", setup_params(secrets, board, wifi), timeout=30.0)
    only_otpauth = set(result) == {"otpauth"}
    assert only_otpauth, "system.setup returned more than the otpauth URI"
    return otpauth_secret(result["otpauth"], expected_board)


def holds_no_secret(text: str, secrets: dict[str, Any], extra: tuple[str, ...] = ()) -> bool:
    needles = [secrets["owner_password"], secrets["wifi_password"], *extra]
    needles += [base64.b32encode(secret).decode() for secret in claims]
    return not any(needle in text for needle in needles)


def totp_code(secret: bytes, unix: float, steps: int = 0) -> str:
    counter = int(unix) // TOTP_STEP_S + steps
    digest = hmac.new(secret, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = (int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF) % 1_000_000
    return Private(f"{value:06d}")


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


def joined(console: Console, info: dict[str, Any], ssid: str) -> bool:
    deadline = time.monotonic() + WIFI_JOIN_S
    while info["claimed"] and info["wifi"]["ssid"] == ssid and not info["wifi"]["connected"]:
        if time.monotonic() > deadline:
            break
        time.sleep(1.0)
        info = console.call("system.info")
    return info["claimed"] and info["wifi"]["connected"] and info["wifi"]["ssid"] == ssid


def prepare_web_login(console: Console, secrets: dict[str, Any], board: dict[str, Any]) -> Codes:
    """Gets the board online on the real Wi-Fi and returns codes for its owner login.

    A claimed board set up for the real Wi-Fi gets time to join it. A board that is not online is claimed again
    only when it holds neither lock keys nor the owner's login.
    """
    info = console.wait_ready()
    owned = board.get("totp_uri")
    online = joined(console, info, secrets["wifi_ssid"])
    if not online:
        if owned or console.call("locks.list")["locks"]:
            pytest.fail("the board is not online on the real Wi-Fi and holds lock keys or the owner's login")
        console.call_and_wait_restart("system.factoryReset")
        claim_secret(console, secrets, board, info["board"])
        console.wait_info(lambda state: state["wifi"]["connected"], 60.0, "wifi to connect")
    console.wait_info(lambda state: state["time"]["synced"], 90.0, "SNTP to sync")
    console.wait_info(lambda state: state["certFingerprint"] is not None, 60.0, "the HTTPS certificate")
    if owned:
        return Codes(otpauth_secret(owned, info["board"]))
    rotated = console.call("auth.rotateTotp", timeout=30.0)
    return Codes(otpauth_secret(rotated["otpauth"], info["board"]))
