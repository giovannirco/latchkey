#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Verify downloaded release assets and add ESP Web Tools manifests without rebuilding firmware."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

from merge_images import manifest

VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
CHECKSUM = re.compile(r"([0-9a-f]{64})  (.+)")
BOARDS = ("esp32", "esp32s3")


class PreparationError(Exception):
    pass


def prepare(version: str, dist: Path) -> None:
    if not VERSION.fullmatch(version):
        raise PreparationError("version must be MAJOR.MINOR.PATCH")
    images = {f"latchkey-{version}-{board}-{kind}.bin" for board in BOARDS for kind in ("factory", "ota")}
    expected = images | {"SHA256SUMS"}
    paths = list(dist.iterdir())
    if {path.name for path in paths} != expected:
        raise PreparationError("release assets must contain exactly four versioned images and SHA256SUMS")
    if any(path.is_symlink() or not path.is_file() for path in paths):
        raise PreparationError("release assets must be regular files, not directories or symlinks")
    checksums = {}
    for line in (dist / "SHA256SUMS").read_text(encoding="ascii").splitlines():
        match = CHECKSUM.fullmatch(line)
        if match is None:
            raise PreparationError("SHA256SUMS contains a malformed checksum line")
        digest, name = match.groups()
        if name not in images:
            raise PreparationError("SHA256SUMS contains an unexpected checksum filename")
        if name in checksums:
            raise PreparationError("SHA256SUMS contains a duplicate filename")
        checksums[name] = digest
    if set(checksums) != images:
        raise PreparationError("SHA256SUMS must cover exactly the four release images")
    for name, expected_hash in checksums.items():
        with (dist / name).open("rb") as image:
            actual_hash = hashlib.file_digest(image, "sha256").hexdigest()
        if actual_hash != expected_hash:
            raise PreparationError(f"checksum mismatch for {name}")
    for board in BOARDS:
        content = manifest(version, board, f"latchkey-{version}-{board}-factory.bin")
        with (dist / f"manifest-{board}.json").open("x", encoding="utf-8") as output:
            output.write(json.dumps(content, indent=2) + "\n")
    print(f"verified four v{version} images and generated two manifests")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--dist", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        prepare(args.version, args.dist)
    except (PreparationError, OSError, UnicodeError) as error:
        print(f"prepare_site_release: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
