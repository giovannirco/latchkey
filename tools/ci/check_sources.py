#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Repository rules that CI enforces on every file git tracks or would add.

    python3 tools/ci/check_sources.py [--root DIR]

- Every file carries `SPDX-License-Identifier: <license expression>` in its first five lines,
  except files that cannot hold a comment or are not ours to edit (EXEMPT) and binary files.
- Nothing under components/ttlock or components/latchkey_util includes an ESP-IDF header
  (`esp_*` or `freertos/*`), not even behind #ifdef: both components build and run on the host.

Files come from `git ls-files --cached --others --exclude-standard`, so ignored build output is
skipped and new files are checked before they are added. Exit status: 0 clean, 1 problems, 2 error.
"""

from __future__ import annotations

import argparse
import fnmatch
import re
import subprocess
import sys
from pathlib import Path

HEADER_LINES = 5
EXEMPT = (
    "LICENSE",
    "NOTICE",
    "*.json",
    "*.lock",
    "dependencies.lock.*",
    "components/ttlock/src/third_party/*",
)
PURE_COMPONENTS = ("components/ttlock/", "components/latchkey_util/")
C_SUFFIXES = (".c", ".cc", ".cpp", ".h", ".hpp", ".inc", ".ipp")
SPDX = re.compile(r"SPDX-License-Identifier:(.*)")
LICENSE_EXPRESSION = re.compile(r"[A-Za-z0-9.+\-()]+(?: [A-Za-z0-9.+\-()]+)*")
INCLUDE = re.compile(r"^\s*#\s*include(?:_next)?\s*[<\"]([^>\"]+)[>\"]")
IDF_HEADER = re.compile(r"^(?:esp_|freertos/)", re.IGNORECASE)


class CheckError(Exception):
    pass


def repository_files(root: Path) -> list[str]:
    command = ["git", "-C", str(root), "ls-files", "-z", "--cached", "--others", "--exclude-standard"]
    try:
        listed = subprocess.run(command, check=True, capture_output=True).stdout
    except (OSError, subprocess.CalledProcessError) as err:
        raise CheckError(f"cannot list files with git in {root}: {err}") from err
    names = sorted({name for name in listed.decode("utf-8").split("\0") if name})
    return [name for name in names if (root / name).is_file()]


def is_exempt(name: str) -> bool:
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in EXEMPT)


def is_binary(data: bytes) -> bool:
    return b"\0" in data[:8192]


def license_expression(line: str) -> str | None:
    match = SPDX.search(line)
    if match is None:
        return None
    text = match.group(1).strip()
    for terminator in ("-->", "*/"):
        if text.endswith(terminator):
            text = text[: -len(terminator)].strip()
    return text


def spdx_problems(name: str, lines: list[str]) -> list[str]:
    for line in lines[:HEADER_LINES]:
        expression = license_expression(line)
        if expression is None:
            continue
        if not LICENSE_EXPRESSION.fullmatch(expression):
            return [f"{name}:1: SPDX-License-Identifier has no valid license expression: {expression!r}"]
        return []
    return [f"{name}:1: no SPDX-License-Identifier in the first {HEADER_LINES} lines"]


def include_problems(name: str, lines: list[str]) -> list[str]:
    if not name.startswith(PURE_COMPONENTS) or not name.endswith(C_SUFFIXES):
        return []
    problems = []
    for number, line in enumerate(lines, start=1):
        match = INCLUDE.match(line)
        if match and IDF_HEADER.match(match.group(1)):
            problems.append(f"{name}:{number}: includes ESP-IDF header {match.group(1)}; this component must build on the host")
    return problems


def file_problems(root: Path, name: str) -> list[str]:
    data = (root / name).read_bytes()
    if is_binary(data):
        return []
    lines = data.decode("utf-8", errors="replace").splitlines()
    problems = include_problems(name, lines)
    if not is_exempt(name):
        problems = spdx_problems(name, lines) + problems
    return problems


def find_problems(root: Path) -> tuple[int, list[str]]:
    names = repository_files(root)
    problems = []
    for name in names:
        problems.extend(file_problems(root, name))
    return len(names), problems


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[2])
    args = parser.parse_args(argv)
    try:
        count, problems = find_problems(args.root)
    except CheckError as err:
        print(f"check_sources: {err}", file=sys.stderr)
        return 2
    for problem in problems:
        print(problem)
    if problems:
        print(f"check_sources: {len(problems)} problem(s) in {count} files", file=sys.stderr)
        return 1
    print(f"check_sources: {count} files OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
