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
from typing import Any

from latchkey_cli import Console

OTPAUTH = re.compile(
    r"otpauth://totp/Latchkey:(?P<board>[a-z0-9-]+)\?secret=(?P<secret>[A-Z2-7]{32})"
    r"&issuer=Latchkey&algorithm=SHA1&digits=6&period=30"
)
TOTP_STEP_S = 30
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
