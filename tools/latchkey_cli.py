#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""JSON-lines client for the Latchkey USB serial console.

The board reads one JSON request per line and writes one JSON line per reply or event.
Lines that start with '#' are log output and are skipped, as is anything that is not a JSON object.
"""

from __future__ import annotations

import argparse
import glob
import json
import sys
import time
from collections.abc import Callable
from typing import Any, Self

import serial

BAUDRATE = 115200
READ_CHUNK = 4096
WRITE_TIMEOUT_S = 5.0
USB_MODEM_PREFIX = "/dev/cu.usbmodem"

EventHook = Callable[[dict[str, Any]], None]


class LatchkeyError(Exception):
    def __init__(self, method: str, code: str, message: str) -> None:
        super().__init__(f"{method}: {code}: {message}")
        self.method = method
        self.code = code
        self.message = message


class ConsoleTimeout(Exception):
    pass


class Console:
    def __init__(self, port: str, baudrate: int = BAUDRATE, on_line: Callable[[str], None] | None = None) -> None:
        self.port = port
        self.baudrate = baudrate
        self.on_line = on_line
        self.handle: serial.Serial | None = None
        self.pending = b""
        self.next_id = 1
        self.events: list[dict[str, Any]] = []
        self.lines: list[str] = []
        self.reply_ids: list[Any] = []
        self.methods: dict[int, str] = {}
        self.unclaimed: list[dict[str, Any]] = []

    def __enter__(self) -> Self:
        return self.open()

    def __exit__(self, *_: object) -> None:
        self.close()

    def open(self) -> Self:
        handle = serial.Serial()
        handle.port = self.port
        handle.baudrate = self.baudrate
        handle.timeout = 0.05
        handle.write_timeout = WRITE_TIMEOUT_S
        handle.open()
        self.handle = handle
        self.pending = b""
        return self

    def close(self) -> None:
        if self.handle is not None:
            try:
                self.handle.close()
            except (serial.SerialException, OSError):
                pass
        self.handle = None

    def send_line(self, text: str) -> None:
        data = text.encode() + b"\n"
        deadline = time.monotonic() + 15.0
        while True:
            try:
                if self.handle is None:
                    raise serial.SerialException("port closed")
                self.handle.write(data)
                return
            except serial.SerialTimeoutException:
                raise ConsoleTimeout(f"{self.port} did not accept a request within {WRITE_TIMEOUT_S:.0f} s") from None
            except (serial.SerialException, OSError):
                if not self._reopen(deadline):
                    raise ConsoleTimeout(f"{self.port} did not come back within 15 s") from None

    def start(self, method: str, params: dict[str, Any] | None = None) -> int:
        request_id = self.next_id
        self.next_id += 1
        payload: dict[str, Any] = {"id": request_id, "method": method}
        if params is not None:
            payload["params"] = params
        self.methods[request_id] = method
        self.send_line(json.dumps(payload, separators=(",", ":")))
        return request_id

    def finish(self, request_id: int, timeout: float = 10.0, on_event: EventHook | None = None) -> dict[str, Any]:
        reply = self._wait_reply(lambda message: message.get("id") == request_id, timeout, on_event)
        if reply is None:
            method = self.methods.get(request_id, "request")
            raise ConsoleTimeout(f"no reply to {method} (id {request_id}) within {timeout:.0f} s")
        return reply

    def request(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        timeout: float = 10.0,
        on_event: EventHook | None = None,
    ) -> dict[str, Any]:
        return self.finish(self.start(method, params), timeout, on_event)

    def request_raw(self, text: str, reply_id: int | str | None = None, timeout: float = 10.0) -> dict[str, Any]:
        self.send_line(text)
        reply = self._wait_reply(lambda message: "id" in message and message["id"] == reply_id, timeout)
        if reply is None:
            raise ConsoleTimeout(f"no reply to a raw line within {timeout:.0f} s")
        return reply

    def call(
        self,
        method: str,
        params: dict[str, Any] | None = None,
        timeout: float = 10.0,
        on_event: EventHook | None = None,
    ) -> Any:
        reply = self.request(method, params, timeout, on_event)
        if "error" in reply:
            error = reply["error"]
            raise LatchkeyError(method, error.get("code", ""), error.get("message", ""))
        return reply.get("result")

    def wait_ready(self, timeout: float = 45.0) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                return self.call("system.info", timeout=min(2.0, max(0.1, deadline - time.monotonic())))
            except ConsoleTimeout:
                continue
        raise ConsoleTimeout(f"board on {self.port} did not answer system.info within {timeout:.0f} s")

    def call_and_wait_restart(self, method: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        started = time.monotonic()
        self.call(method, params, timeout=30.0)
        deadline = started + 60.0
        while time.monotonic() < deadline:
            info = self.wait_ready(timeout=max(1.0, deadline - time.monotonic()))
            if info["uptime"] < time.monotonic() - started:
                return info
            time.sleep(0.2)
        raise ConsoleTimeout(f"{method} did not restart the board within 60 s")

    def wait_info(self, predicate: Callable[[dict[str, Any]], bool], timeout: float, what: str) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while True:
            info = self.call("system.info")
            if predicate(info):
                return info
            if time.monotonic() >= deadline:
                raise ConsoleTimeout(f"timed out after {timeout:.0f} s waiting for {what}")
            time.sleep(1.0)

    def wait_event(self, matches: Callable[[dict[str, Any]], bool], timeout: float) -> dict[str, Any] | None:
        deadline = time.monotonic() + timeout
        while True:
            line = self._read_line(deadline)
            if line is None:
                return None
            message = self._classify(line)
            if message is None:
                continue
            if "event" not in message:
                self.unclaimed.append(message)
            elif matches(message):
                return message

    def _wait_reply(
        self, matches: Callable[[dict[str, Any]], bool], timeout: float, on_event: EventHook | None = None
    ) -> dict[str, Any] | None:
        for index, message in enumerate(self.unclaimed):
            if matches(message):
                return self.unclaimed.pop(index)
        deadline = time.monotonic() + timeout
        while True:
            line = self._read_line(deadline)
            if line is None:
                return None
            message = self._classify(line)
            if message is None:
                continue
            if "event" in message:
                if on_event is not None:
                    on_event(message)
                continue
            if matches(message):
                return message
            if message.get("id") is not None:
                self.unclaimed.append(message)

    def _classify(self, line: str) -> dict[str, Any] | None:
        self.lines.append(line)
        if self.on_line is not None:
            self.on_line(line)
        if not line or line.startswith("#"):
            return None
        try:
            message = json.loads(line)
        except ValueError:
            return None
        if not isinstance(message, dict):
            return None
        if "event" in message:
            self.events.append(message)
        elif "id" in message:
            self.reply_ids.append(message["id"])
        return message

    def _read_line(self, deadline: float) -> str | None:
        while True:
            if b"\n" in self.pending:
                raw, self.pending = self.pending.split(b"\n", 1)
                return raw.decode("utf-8", "replace").rstrip("\r")
            if time.monotonic() >= deadline:
                return None
            try:
                if self.handle is None:
                    raise serial.SerialException("port closed")
                self.pending += self.handle.read(READ_CHUNK)
            except (serial.SerialException, OSError):
                if not self._reopen(deadline):
                    return None

    def _reopen(self, deadline: float) -> bool:
        self.close()
        while time.monotonic() < deadline:
            for candidate in self._candidates():
                try:
                    self.port = candidate
                    self.open()
                    return True
                except (serial.SerialException, OSError):
                    continue
            time.sleep(0.2)
        return False

    def _candidates(self) -> list[str]:
        if not self.port.startswith(USB_MODEM_PREFIX):
            return [self.port]
        present = sorted(glob.glob(USB_MODEM_PREFIX + "*"))
        if self.port in present:
            return [self.port]
        return present if len(present) == 1 else []


def read_params(text: str | None) -> dict[str, Any] | None:
    if text is None:
        return None
    source = sys.stdin.read() if text == "-" else text
    params = json.loads(source)
    if not isinstance(params, dict):
        raise SystemExit("params must be a JSON object")
    return params


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Send one request to a Latchkey board over its USB serial console.")
    parser.add_argument("--port", required=True, help="serial port, for example /dev/cu.usbserial-0001")
    parser.add_argument("--timeout", type=float, default=10.0, help="seconds to wait for the reply")
    parser.add_argument("--logs", action="store_true", help="echo every line the board sends to stderr")
    parser.add_argument("method", help="RPC method, for example system.info")
    parser.add_argument("params", nargs="?", help="params as a JSON object, or - to read them from stdin")
    args = parser.parse_args(argv)
    params = read_params(args.params)
    echo = (lambda line: print(line, file=sys.stderr)) if args.logs else None
    with Console(args.port, on_line=echo) as console:
        reply = console.request(args.method, params, args.timeout)
    print(json.dumps(reply, indent=2))
    return 1 if "error" in reply else 0


if __name__ == "__main__":
    sys.exit(main())
