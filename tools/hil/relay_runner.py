# SPDX-License-Identifier: GPL-3.0-or-later
"""Runs a plan of HTTP and WebSocket steps against a board and prints one JSON object.

tools/hil/relay.py sends this file to a Python 3 interpreter on a host that can reach the board, followed by
a call to main() with the plan. It uses the standard library only, follows no redirects, accepts the board's
self-signed certificate and reports its SHA-256 fingerprint, and never prints the headers it sends.

Step types:
- http: method, path, headers, body (text), tls (default true), port, timeout_s; reports status, headers,
  body_b64, fingerprint, elapsed_ms;
- ws: path, headers, tls, steps (http or sleep steps run while the socket is open), until ({"event", "job_from"}:
  stop at that event, for job.done the one whose job id the nested step at index job_from replied with),
  collect_s; reports status, headers, events, steps, closed (the board closed the socket);
- sleep: seconds.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import os
import socket
import ssl
import struct
import time

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
MAX_FRAME = 1 << 20


class Closed(Exception):
    pass


def fingerprint(der: bytes) -> str:
    return ":".join(f"{byte:02X}" for byte in hashlib.sha256(der).digest())


def tls_context() -> ssl.SSLContext:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    return context


def describe(err: BaseException) -> str:
    return f"{type(err).__name__}: {err}"


def http_step(host: str, step: dict) -> dict:
    tls = step.get("tls", True)
    port = step.get("port", 443 if tls else 80)
    timeout = step.get("timeout_s", 30)
    if tls:
        connection = http.client.HTTPSConnection(host, port, timeout=timeout, context=tls_context())
    else:
        connection = http.client.HTTPConnection(host, port, timeout=timeout)
    started = time.monotonic()
    result: dict = {}
    try:
        body = step.get("body")
        connection.request(
            step.get("method", "GET"),
            step["path"],
            body=body.encode() if isinstance(body, str) else None,
            headers=step.get("headers", {}),
        )
        if tls:
            result["fingerprint"] = fingerprint(connection.sock.getpeercert(binary_form=True))
        response = connection.getresponse()
        payload = response.read()
        result.update(
            status=response.status,
            headers=[[name, value] for name, value in response.getheaders()],
            body_b64=base64.b64encode(payload).decode(),
        )
    except (OSError, http.client.HTTPException) as err:
        result["error"] = describe(err)
    finally:
        connection.close()
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000)
    return result


def recv_exact(sock: socket.socket, count: int) -> bytes:
    data = b""
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        if not chunk:
            raise Closed()
        data += chunk
    return data


def read_head(sock: socket.socket) -> bytes:
    head = b""
    while b"\r\n\r\n" not in head:
        chunk = sock.recv(1)
        if not chunk:
            raise Closed()
        head += chunk
        if len(head) > 8192:
            raise OSError("handshake response too long")
    return head


def read_frame(sock: socket.socket) -> tuple[int, bytes]:
    first, second = recv_exact(sock, 2)
    size = second & 0x7F
    if size == 126:
        size = struct.unpack("!H", recv_exact(sock, 2))[0]
    elif size == 127:
        size = struct.unpack("!Q", recv_exact(sock, 8))[0]
    if size > MAX_FRAME:
        raise OSError("frame too large")
    mask = recv_exact(sock, 4) if second & 0x80 else b"\0\0\0\0"
    payload = bytes(byte ^ mask[index % 4] for index, byte in enumerate(recv_exact(sock, size)))
    return first & 0x0F, payload


def masked_frame(opcode: int, payload: bytes) -> bytes:
    mask = os.urandom(4)
    header = struct.pack("!BB", 0x80 | opcode, 0x80 | len(payload))
    return header + mask + bytes(byte ^ mask[index % 4] for index, byte in enumerate(payload))


def job_id(result: dict) -> str | None:
    try:
        reply = json.loads(base64.b64decode(result["body_b64"]))
        return reply["result"]["job"]
    except (KeyError, TypeError, ValueError):
        return None


class EventReader:
    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.events: list = []
        self.closed = False

    def drain(self, seconds: float, stop) -> bool:
        deadline = time.monotonic() + seconds
        while not self.closed:
            left = deadline - time.monotonic()
            if left <= 0:
                return False
            self.sock.settimeout(left)
            try:
                opcode, payload = read_frame(self.sock)
            except (socket.timeout, TimeoutError):
                return False
            except (Closed, ConnectionError, ssl.SSLError):
                self.closed = True
                return False
            if opcode == 0x8:
                self.closed = True
                return False
            if opcode != 0x1:
                continue
            try:
                event = json.loads(payload)
            except ValueError:
                event = {"unparsed": payload.decode("utf-8", "replace")}
            self.events.append(event)
            if stop(event):
                return True
        return False


def ws_step(host: str, step: dict) -> dict:
    started = time.monotonic()
    result: dict = {"events": [], "steps": [], "closed": False}
    try:
        raw = socket.create_connection((host, step.get("port", 443)), timeout=step.get("timeout_s", 30))
    except OSError as err:
        result["error"] = describe(err)
        return result
    sock: socket.socket = raw
    try:
        if step.get("tls", True):
            sock = tls_context().wrap_socket(raw)
        key = base64.b64encode(os.urandom(16)).decode()
        lines = [
            f"GET {step['path']} HTTP/1.1",
            f"Host: {host}",
            "Upgrade: websocket",
            "Connection: Upgrade",
            f"Sec-WebSocket-Key: {key}",
            "Sec-WebSocket-Version: 13",
        ]
        lines += [f"{name}: {value}" for name, value in step.get("headers", {}).items()]
        sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode())
        head = read_head(sock).decode("latin-1").split("\r\n")
        result["status"] = int(head[0].split(" ")[1])
        result["headers"] = [line.split(":", 1) for line in head[1:] if ":" in line]
        expected = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
        accepted = {name.strip().lower(): value.strip() for name, value in result["headers"]}
        if result["status"] != 101 or accepted.get("sec-websocket-accept") != expected:
            return result
        reader = EventReader(sock)
        reader.drain(step.get("settle_s", 0.5), lambda event: False)
        for nested in step.get("steps", []):
            if nested["type"] == "sleep":
                reader.drain(nested["seconds"], lambda event: False)
                result["steps"].append({})
            else:
                result["steps"].append(http_step(host, nested))
                reader.drain(0.2, lambda event: False)
        until = step.get("until")
        if until is not None:
            wanted = job_id(result["steps"][until["job_from"]]) if "job_from" in until else None

            def stop(event: dict) -> bool:
                data = event.get("data") or {}
                return event.get("event") == until["event"] and (wanted is None or data.get("job") == wanted)

            if not any(stop(event) for event in reader.events):
                reader.drain(step.get("collect_s", 10), stop)
        else:
            reader.drain(step.get("collect_s", 0), lambda event: False)
        result["events"] = reader.events
        result["closed"] = reader.closed
        if not reader.closed:
            sock.sendall(masked_frame(0x8, struct.pack("!H", 1000)))
    except Closed:
        result["closed"] = True
        result.setdefault("error", "closed by the board")
    except (OSError, ValueError, IndexError) as err:
        result["error"] = describe(err)
    finally:
        sock.close()
        result["elapsed_ms"] = round((time.monotonic() - started) * 1000)
    return result


def run_step(host: str, step: dict) -> dict:
    if step["type"] == "http":
        return http_step(host, step)
    if step["type"] == "ws":
        return ws_step(host, step)
    if step["type"] == "sleep":
        time.sleep(step["seconds"])
        return {}
    return {"error": f"unknown step type {step['type']}"}


def main(host: str, plan: list) -> None:
    print(json.dumps({"steps": [run_step(host, step) for step in plan]}))
