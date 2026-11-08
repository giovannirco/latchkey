# SPDX-License-Identifier: GPL-3.0-or-later
"""Hardware-in-the-loop fixtures: one board on one USB serial port, settings from secrets.local.json."""

from __future__ import annotations

import json
import re
from collections.abc import Iterator
from contextlib import ExitStack
from pathlib import Path
from typing import Any

import pytest
from latchkey_cli import Console
from owner import Private, claim_secret, hide

SECRETS = Path(__file__).resolve().parents[2] / "secrets.local.json"
OTPAUTH_SECRET = re.compile(r"secret=[A-Z2-7]+")
SECRET_VALUE = re.compile(r'"(code|adminPasscode)":"[0-9]+"|"(reply)":"[0-9a-f]+"')


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addoption("--port", action="store", default=None, help="serial port of the board under test")
    parser.addoption("--console-log", action="store", default=None, help="file that receives every console line")
    parser.addoption(
        "--touch-file",
        action="store",
        default=None,
        help="file the pairing test writes (UTC time) while someone must touch the lock's keypad",
    )
    parser.addoption(
        "--button-file",
        action="store",
        default=None,
        help="file the update tests write (UTC time) while someone must press the board button",
    )
    parser.addoption(
        "--allow-lock-reset",
        action="store_true",
        default=False,
        help="let the lock suite factory-reset the paired lock",
    )
    parser.addoption(
        "--allow-admin-passcode-change",
        action="store_true",
        default=False,
        help="let the lock feature suite change the keypad admin passcode and put the original back",
    )


def redact(line: str) -> str:
    masked = SECRET_VALUE.sub(lambda found: f'"{found.group(1) or found.group(2)}":"REDACTED"', line)
    return OTPAUTH_SECRET.sub("secret=REDACTED", masked)


@pytest.fixture(scope="session")
def secrets() -> dict[str, Any]:
    if not SECRETS.exists():
        pytest.fail(f"{SECRETS.name} is missing: copy secrets.example.json and fill it in")
    return hide(json.loads(SECRETS.read_text()))


@pytest.fixture(scope="session")
def console(request: pytest.FixtureRequest) -> Iterator[Console]:
    port = request.config.getoption("--port")
    if not port:
        pytest.fail("pass --port <serial port of the board>")
    log_path = request.config.getoption("--console-log")
    with ExitStack() as stack:
        log = stack.enter_context(open(log_path, "a", encoding="utf-8")) if log_path else None
        on_line = (lambda line: print(redact(line), file=log, flush=True)) if log else None
        yield stack.enter_context(Console(port, on_line=on_line))


@pytest.fixture(scope="session")
def board_settings(console: Console, secrets: dict[str, Any]) -> dict[str, Any]:
    chip = console.wait_ready()["chip"]
    return secrets["boards"][chip]


@pytest.fixture(scope="session")
def lock_mac(secrets: dict[str, Any]) -> str:
    mac = secrets.get("lock_mac")
    if not mac:
        pytest.fail(f"{SECRETS.name} has no lock_mac")
    return Private(mac.upper())


@pytest.fixture(scope="session")
def touch_file(request: pytest.FixtureRequest) -> Path | None:
    path = request.config.getoption("--touch-file")
    return Path(path) if path else None


@pytest.fixture(scope="session")
def button_file(request: pytest.FixtureRequest) -> Path | None:
    path = request.config.getoption("--button-file")
    return Path(path) if path else None


@pytest.fixture(scope="session")
def allow_lock_reset(request: pytest.FixtureRequest) -> bool:
    return bool(request.config.getoption("--allow-lock-reset"))


@pytest.fixture(scope="session")
def allow_admin_passcode_change(request: pytest.FixtureRequest) -> bool:
    return bool(request.config.getoption("--allow-admin-passcode-change"))


def held_locks(console: Console) -> list[dict[str, Any]]:
    reply = console.request("locks.list")
    return reply.get("result", {}).get("locks", [])


@pytest.fixture
def fresh(console: Console, board_settings: dict[str, Any]) -> list[str]:
    console.wait_ready()
    if board_settings.get("totp_uri"):
        pytest.skip("the owner holds this board's login (totp_uri in secrets.local.json): no factory reset")
    if held_locks(console):
        pytest.skip("the board holds lock keys, which a factory reset would erase")
    console.lines.clear()
    console.events.clear()
    console.call_and_wait_restart("system.factoryReset")
    return list(console.lines)


@pytest.fixture
def claimed(console: Console, fresh: list[str], secrets: dict[str, Any], board_settings: dict[str, Any]) -> bytes:
    return claim_secret(console, secrets, board_settings, console.call("system.info")["board"])


@pytest.fixture
def online(console: Console, claimed: bytes) -> dict[str, Any]:
    return console.wait_info(lambda state: state["wifi"]["connected"], 45.0, "wifi to connect")
