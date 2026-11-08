#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Assemble the GitHub Pages site: docs/ plus one release's images and manifests, same-origin.

    python3 tools/release/build_site.py --version 0.1.0 --dist dist --out site [--docs docs]

docs/ is copied to the site root and every image, manifest and SHA256SUMS from --dist goes under
firmware/<version>/, next to each other, so ESP Web Tools fetches them from the page's own origin.
index.html must contain `<meta name="latchkey-version" content="">` once; the site's copy names
the version, which the page turns into the manifest paths. The build fails when --out exists or
a manifest names an image that is not in --dist.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from pathlib import Path

VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
VERSION_MARKER = '<meta name="latchkey-version" content="">'
RELEASE_FILES = ("*.bin", "manifest-*.json", "SHA256SUMS")
DEFAULT_DOCS = Path(__file__).resolve().parents[2] / "docs"


class SiteError(Exception):
    pass


def release_files(dist: Path) -> list[Path]:
    files = sorted({path for pattern in RELEASE_FILES for path in dist.glob(pattern)})
    manifests = [path for path in files if path.name.startswith("manifest-")]
    if not manifests:
        raise SiteError(f"{dist} has no manifest-*.json")
    for manifest in manifests:
        for build in json.loads(manifest.read_text(encoding="utf-8"))["builds"]:
            for part in build["parts"]:
                if not (dist / part["path"]).is_file():
                    raise SiteError(f"{manifest.name} names {part['path']}, which is not in {dist}")
    return files


def build(version: str, docs: Path, dist: Path, out: Path) -> None:
    if not VERSION.fullmatch(version):
        raise SiteError(f"version {version} is not MAJOR.MINOR.PATCH")
    if out.exists():
        raise SiteError(f"{out} already exists; the site is built from scratch")
    index = (docs / "index.html").read_text(encoding="utf-8")
    if index.count(VERSION_MARKER) != 1:
        raise SiteError(f"docs/index.html must contain {VERSION_MARKER} exactly once")
    files = release_files(dist)
    shutil.copytree(docs, out)
    (out / "index.html").write_text(index.replace(VERSION_MARKER, f'<meta name="latchkey-version" content="{version}">'), encoding="utf-8")
    firmware = out / "firmware" / version
    firmware.mkdir(parents=True)
    for path in files:
        shutil.copy2(path, firmware / path.name)
    print(f"{out}: docs and {len(files)} release files under firmware/{version}/")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", required=True, help="release version, MAJOR.MINOR.PATCH")
    parser.add_argument("--dist", type=Path, required=True, help="output of merge_images.py")
    parser.add_argument("--out", type=Path, required=True, help="site directory to create")
    parser.add_argument("--docs", type=Path, default=DEFAULT_DOCS)
    args = parser.parse_args(argv)
    try:
        build(args.version, args.docs, args.dist, args.out)
    except (SiteError, OSError, ValueError, KeyError) as err:
        print(f"build_site: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
