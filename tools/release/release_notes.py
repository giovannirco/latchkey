#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Print the CHANGELOG.md section of one version, for the GitHub Release notes.

    python3 tools/release/release_notes.py 0.1.0 [--changelog CHANGELOG.md]

A section starts at its heading, `## [0.1.0] - 2026-11-20`, and ends at the next `## ` heading or
at the end of the file. The release fails when the version has no section or an empty one.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
HEADING = re.compile(r"## \[([^\]]+)\]")
DEFAULT_CHANGELOG = Path(__file__).resolve().parents[2] / "CHANGELOG.md"


class NotesError(Exception):
    pass


def section(text: str, version: str) -> str:
    if not VERSION.fullmatch(version):
        raise NotesError(f"version {version} is not MAJOR.MINOR.PATCH")
    lines = text.splitlines()
    starts = [index for index, line in enumerate(lines) if (match := HEADING.match(line)) and match.group(1) == version]
    if not starts:
        raise NotesError(f"CHANGELOG.md has no section for {version}")
    body = []
    for line in lines[starts[0] + 1 :]:
        if line.startswith("## "):
            break
        body.append(line)
    notes = "\n".join(body).strip("\n")
    if not notes.strip():
        raise NotesError(f"the CHANGELOG.md section for {version} is empty")
    return notes + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("version", help="release version, MAJOR.MINOR.PATCH")
    parser.add_argument("--changelog", type=Path, default=DEFAULT_CHANGELOG)
    args = parser.parse_args(argv)
    try:
        notes = section(args.changelog.read_text(encoding="utf-8"), args.version)
    except (NotesError, OSError) as err:
        print(f"release_notes: {err}", file=sys.stderr)
        return 1
    print(notes, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
