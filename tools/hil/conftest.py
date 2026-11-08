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

SECRETS = Path(__file__).resolve().parents[2] / "secrets.local.json"
OTPAUTH_SECRET = re.compile(r"secret=[A-Z2-7]+")


class Private(str):
    def __repr__(self) -> str:
        return "<private>"


def hide(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: hide(item) for key, item in value.items()}
    if isinstance(value, str):
        return Private(value)
    return value


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
        "--allow-lock-reset",
        action="store_true",
        default=False,
        help="let the lock suite factory-reset the paired lock",
    )


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
        on_line = (
            (lambda line: print(OTPAUTH_SECRET.sub("secret=REDACTED", line), file=log, flush=True)) if log else None
        )
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
def allow_lock_reset(request: pytest.FixtureRequest) -> bool:
    return bool(request.config.getoption("--allow-lock-reset"))
