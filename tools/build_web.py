# SPDX-License-Identifier: GPL-3.0-or-later
"""Bundle web/ into one self-contained, gzipped index.html for the firmware.

    python3 tools/build_web.py <output.gz> [--web-dir web] [--budget 61440]

web/index.html must contain each of these markers exactly once:

- `<link rel="stylesheet" href="style.css">`, replaced by `<style>` + style.css;
- `<script type="module" src="app.js"></script>`, replaced by an inline module with app.js;
- `<!-- icons -->`, replaced by icons.svg (the SVG sprite that `<use href="#i-...">` points at);
- `__CSP__`, replaced by a Content-Security-Policy whose script-src and style-src allow
  only the sha256 hashes of the inlined script and style.

The gzip stream has no file name and mtime 0, so the same sources give the same bytes.
The build fails above the gzipped size budget (default 60 KiB).
"""

from __future__ import annotations

import argparse
import base64
import gzip
import hashlib
import re
import sys
from pathlib import Path

STYLE_MARKER = '<link rel="stylesheet" href="style.css">'
SCRIPT_MARKER = '<script type="module" src="app.js"></script>'
ICONS_MARKER = "<!-- icons -->"
CSP_MARKER = "__CSP__"
DEFAULT_BUDGET = 60 * 1024
DEFAULT_WEB_DIR = Path(__file__).resolve().parents[1] / "web"
STYLE_ATTRIBUTE = re.compile(r"\sstyle\s*=", re.IGNORECASE)


class BuildError(Exception):
    pass


def _csp_hash(text: str) -> str:
    digest = hashlib.sha256(text.encode("utf-8")).digest()
    return "'sha256-" + base64.b64encode(digest).decode("ascii") + "'"


def _policy(css: str, js: str) -> str:
    directives = [
        "default-src 'none'",
        f"script-src {_csp_hash(js)}",
        f"style-src {_csp_hash(css)}",
        "img-src 'self' data:",
        "connect-src 'self' ws: wss:",
        "base-uri 'none'",
        "form-action 'none'",
    ]
    return "; ".join(directives)


def _read(web_dir: Path, name: str) -> str:
    path = web_dir / name
    if not path.is_file():
        raise BuildError(f"{path} is missing")
    return path.read_text(encoding="utf-8")


def _check_sources(template: str, css: str, js: str, icons: str) -> None:
    for marker in (STYLE_MARKER, SCRIPT_MARKER, ICONS_MARKER, CSP_MARKER):
        count = template.count(marker)
        if count != 1:
            raise BuildError(f"index.html must contain {marker!r} exactly once, found {count}")
    if "</style" in css.lower():
        raise BuildError("style.css must not contain '</style'")
    if "</script" in js.lower():
        raise BuildError("app.js must not contain '</script'")
    for name, text in (("index.html", template), ("icons.svg", icons)):
        if STYLE_ATTRIBUTE.search(text):
            raise BuildError(f"{name} has a style attribute, which the hash-based CSP blocks; use a class")


def bundle(web_dir: Path) -> bytes:
    web_dir = Path(web_dir)
    template = _read(web_dir, "index.html")
    css = _read(web_dir, "style.css")
    js = _read(web_dir, "app.js")
    icons = _read(web_dir, "icons.svg")
    _check_sources(template, css, js, icons)
    replacements = {
        CSP_MARKER: _policy(css, js),
        ICONS_MARKER: icons.strip(),
        STYLE_MARKER: f"<style>{css}</style>",
        SCRIPT_MARKER: f'<script type="module">{js}</script>',
    }
    pattern = re.compile("|".join(re.escape(marker) for marker in replacements))
    html = pattern.sub(lambda match: replacements[match.group(0)], template)
    return html.encode("utf-8")


def gzip_bundle(web_dir: Path) -> bytes:
    return gzip.compress(bundle(web_dir), compresslevel=9, mtime=0)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("output", type=Path, help="where to write the gzipped page")
    parser.add_argument("--web-dir", type=Path, default=DEFAULT_WEB_DIR)
    parser.add_argument("--budget", type=int, default=DEFAULT_BUDGET, help="maximum gzipped bytes")
    args = parser.parse_args(argv)

    try:
        raw = bundle(args.web_dir)
    except BuildError as err:
        print(f"build_web: {err}", file=sys.stderr)
        return 1
    data = gzip.compress(raw, compresslevel=9, mtime=0)
    if len(data) > args.budget:
        print(f"build_web: {len(data)} gzipped bytes exceed the budget of {args.budget}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    partial = args.output.with_name(args.output.name + ".partial")
    partial.write_bytes(data)
    partial.replace(args.output)
    print(f"{args.output}: {len(raw)} bytes, {len(data)} gzipped (budget {args.budget})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
