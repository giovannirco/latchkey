# SPDX-License-Identifier: GPL-3.0-or-later
import io
import re
import struct
from zoneinfo import ZoneInfo

NAME = r"(?:[A-Za-z]{3,}|<[A-Za-z0-9+-]{3,}>)"
CLOCK = r"[+-]?[0-9]{1,2}(?::[0-9]{2}(?::00)?)?"
RULE = r"(?:J[0-9]{1,3}|M[0-9]{1,2}\.[0-9]\.[0-9]|[0-9]{1,3})(?:/[+-]?[0-9]{1,3}(?::[0-9]{2}(?::[0-9]{2})?)?)?"
ZONE = re.compile(rf"{NAME}(?P<standard>{CLOCK})(?:{NAME}(?P<daylight>{CLOCK})?,(?P<start>{RULE}),(?P<end>{RULE}))?")


def clock_seconds(text: str, maximum: int) -> int:
    parts = [int(part) for part in text.lstrip("+-").split(":")]
    if any(part >= 60 for part in parts[1:]):
        raise ValueError("invalid clock minutes or seconds")
    seconds = sum(part * factor for part, factor in zip(parts, (3600, 60, 1)))
    if seconds > maximum:
        raise ValueError("clock exceeds supported range")
    return -seconds if text.startswith("-") else seconds


def parse_timezone(text: str) -> ZoneInfo:
    if not isinstance(text, str) or not 1 <= len(text) <= 64:
        raise ValueError("time zone must contain 1 to 64 characters")
    match = ZONE.fullmatch(text)
    if match is None:
        raise ValueError("expected a POSIX time zone with explicit daylight rules")
    standard = -clock_seconds(match["standard"], 86399)
    if match["start"] is not None:
        daylight = -clock_seconds(match["daylight"], 86399) if match["daylight"] else standard + 3600
        if not -86400 < daylight < 86400:
            raise ValueError("daylight offset exceeds supported range")
        for rule in (match["start"], match["end"]):
            if "/" in rule:
                clock_seconds(rule.split("/", 1)[1], 167 * 3600)
    header = b"TZif2" + bytes(15) + struct.pack(">6l", 0, 0, 0, 0, 1, 4)
    record = struct.pack(">lbb", 0, 0, 0) + b"UTC\0"
    return ZoneInfo.from_file(io.BytesIO((header + record) * 2 + b"\n" + text.encode("ascii") + b"\n"))
