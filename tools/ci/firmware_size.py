#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Report the app image sizes of both firmware builds and enforce the classic ESP32 budget.

    python3 tools/ci/firmware_size.py [--build-root .pio/build] [--summary FILE]

The esp32 app image (firmware.bin) must stay at or below 1.8 MB (1,887,436 bytes), which leaves
room in its 0x1E0000-byte OTA slot for updates. The Markdown table goes to stdout and, with
--summary, is appended to FILE (the job summary in GitHub Actions), also when the gate fails.
Exit status: 0 within budget, 1 over budget, 2 an image is missing.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ENVS = ("esp32", "esp32s3")
LIMITS = {"esp32": 1_887_436}
DEFAULT_BUILD_ROOT = Path(__file__).resolve().parents[2] / ".pio" / "build"


def table(sizes: dict[str, int]) -> str:
    rows = ["| Env | App image (bytes) | Limit (bytes) | Headroom (bytes) |", "|---|---:|---:|---:|"]
    for env, size in sizes.items():
        limit = LIMITS.get(env)
        if limit is None:
            rows.append(f"| {env} | {size:,} | none | |")
        else:
            rows.append(f"| {env} | {size:,} | {limit:,} | {limit - size:,} |")
    return "\n".join(rows) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--build-root", type=Path, default=DEFAULT_BUILD_ROOT)
    parser.add_argument("--summary", type=Path, help="append the table to this Markdown file")
    args = parser.parse_args(argv)

    sizes = {}
    for env in ENVS:
        image = args.build_root / env / "firmware.bin"
        if not image.is_file():
            print(f"firmware_size: {image} is missing; build the {env} env first", file=sys.stderr)
            return 2
        sizes[env] = image.stat().st_size

    report = "### Firmware app images\n\n" + table(sizes)
    print(report, end="")
    if args.summary is not None:
        with args.summary.open("a", encoding="utf-8") as summary:
            summary.write(report)

    over = [env for env, limit in LIMITS.items() if sizes[env] > limit]
    for env in over:
        print(f"firmware_size: {env} app image is {sizes[env]:,} bytes, above the {LIMITS[env]:,}-byte limit", file=sys.stderr)
    return 1 if over else 0


if __name__ == "__main__":
    sys.exit(main())
