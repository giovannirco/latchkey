# SPDX-License-Identifier: GPL-3.0-or-later
"""HTTP checks against a board from a host on its network, for a test machine that cannot reach it.

The optional `hil_relay` key of secrets.local.json holds the command that runs a Python 3 script read from its
standard input on such a host, with `{timeout}` replaced by a time limit in seconds:

    "hil_relay": {"command": ["ssh", "relay.example", "timeout", "{timeout}", "python3", "-"], "timeout_s": 150}

Each run sends relay_runner.py and the plan on that standard input, never on a command line. The command may
print the runner's JSON directly or wrapped the way a QEMU guest agent reports a process (exitcode, out-data,
err-data). Response bodies come back base64-encoded; Set-Cookie values are wrapped so that they print as
<private>.
"""

from __future__ import annotations

import base64
import json
import subprocess
from pathlib import Path
from typing import Any

from owner import Private

RUNNER = Path(__file__).with_name("relay_runner.py")


class RelayError(Exception):
    pass


class Relay:
    def __init__(self, command: list[str], timeout_s: int, host: str) -> None:
        self.command = command
        self.timeout_s = timeout_s
        self.host = host

    def run(self, plan: list[dict[str, Any]], timeout_s: int | None = None) -> list[dict[str, Any]]:
        limit = timeout_s or self.timeout_s
        script = RUNNER.read_text(encoding="utf-8")
        script += f"\nmain(json.loads({json.dumps(str(self.host))!r}), json.loads({json.dumps(plan)!r}))\n"
        command = [part.replace("{timeout}", str(limit)) for part in self.command]
        try:
            completed = subprocess.run(command, input=script.encode(), capture_output=True, timeout=limit + 30)
        except subprocess.TimeoutExpired:
            raise RelayError(f"the relay did not finish within {limit + 30} s") from None
        if completed.returncode != 0:
            raise RelayError(f"the relay command exited with {completed.returncode}")
        output = unwrap(completed.stdout.decode("utf-8", "replace"))
        return [private_cookies(step) for step in json.loads(output)["steps"]]

    def step(self, step: dict[str, Any], timeout_s: int | None = None) -> dict[str, Any]:
        return self.run([step], timeout_s)[0]


def unwrap(stdout: str) -> str:
    try:
        outer = json.loads(stdout)
    except ValueError:
        raise RelayError("the relay printed something that is not JSON") from None
    if "steps" in outer:
        return stdout
    if outer.get("exitcode") != 0 or outer.get("out-truncated") or "out-data" not in outer:
        detail = (outer.get("err-data") or "").strip().splitlines()[-1:] or ["no error output"]
        raise RelayError(f"the runner failed on the relay host (exit code {outer.get('exitcode')}): {detail[0]}")
    return outer["out-data"]


def private_cookies(result: dict[str, Any]) -> dict[str, Any]:
    if "headers" in result:
        result["headers"] = [
            [name.strip(), Private(value.strip()) if name.strip().lower() == "set-cookie" else value.strip()]
            for name, value in result["headers"]
        ]
    if "steps" in result:
        result["steps"] = [private_cookies(step) for step in result["steps"]]
    return result


def header(result: dict[str, Any], name: str) -> str | None:
    values = headers(result, name)
    return values[0] if values else None


def headers(result: dict[str, Any], name: str) -> list[str]:
    return [value for key, value in result.get("headers", []) if key.lower() == name.lower()]


def body(result: dict[str, Any]) -> bytes:
    return base64.b64decode(result.get("body_b64", ""))


def json_body(result: dict[str, Any]) -> Any:
    return json.loads(body(result))
