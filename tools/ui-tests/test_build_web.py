# SPDX-License-Identifier: GPL-3.0-or-later
"""Unit tests for tools/build_web.py.

python3 -m unittest discover -s tools/ui-tests -p 'test_*.py'
"""

import base64
import gzip
import hashlib
import io
import re
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

TOOLS = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(TOOLS))
sys.dont_write_bytecode = True

import build_web  # noqa: E402

TEMPLATE = """<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
<!doctype html>
<html lang="en">
<head>
<meta http-equiv="Content-Security-Policy" content="__CSP__">
<link rel="stylesheet" href="style.css">
</head>
<body>
<!-- icons -->
<div id="app"></div>
<script type="module" src="app.js"></script>
</body>
</html>
"""

CSS = "/* SPDX-License-Identifier: GPL-3.0-or-later */\nbody { color: red; }\n"
JS = "// SPDX-License-Identifier: GPL-3.0-or-later\ndocument.body.dataset.ok = '1';\n"
ICONS = '<!-- SPDX-License-Identifier: GPL-3.0-or-later -->\n<svg hidden><symbol id="i-x"></symbol></svg>\n'


def csp_hash(text: str) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(text.encode()).digest()).decode() + "'"


class WebDir:
    def __init__(self, template=TEMPLATE, css=CSS, js=JS, icons=ICONS):
        self._tmp = tempfile.TemporaryDirectory()
        self.path = Path(self._tmp.name)
        (self.path / "index.html").write_text(template)
        (self.path / "style.css").write_text(css)
        (self.path / "app.js").write_text(js)
        (self.path / "icons.svg").write_text(icons)

    def __enter__(self):
        return self.path

    def __exit__(self, *exc):
        self._tmp.cleanup()


class BundleTest(unittest.TestCase):
    def test_inlines_style_script_and_icons(self):
        with WebDir() as web:
            html = build_web.bundle(web).decode()
        self.assertIn(f"<style>{CSS}</style>", html)
        self.assertIn(f'<script type="module">{JS}</script>', html)
        self.assertIn('<symbol id="i-x">', html)
        for marker in ("__CSP__", "<!-- icons -->", 'href="style.css"', 'src="app.js"'):
            self.assertNotIn(marker, html)

    def test_policy_hashes_the_exact_inline_text(self):
        with WebDir() as web:
            html = build_web.bundle(web).decode()
        policy = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', html).group(1)
        directives = dict(d.strip().split(" ", 1) for d in policy.split(";") if d.strip())
        self.assertEqual(directives["default-src"], "'none'")
        self.assertEqual(directives["script-src"], csp_hash(JS))
        self.assertEqual(directives["style-src"], csp_hash(CSS))
        self.assertIn("'self'", directives["connect-src"])

    def test_header_policy_is_the_meta_policy_plus_frame_ancestors(self):
        with WebDir() as web:
            html, header = build_web.build(web)
            self.assertEqual(build_web.header_policy(web), header)
        meta = re.search(r'http-equiv="Content-Security-Policy" content="([^"]+)"', html.decode()).group(1)
        self.assertNotIn("frame-ancestors", meta)
        self.assertEqual(header, f"{meta}; frame-ancestors 'none'")

    def test_inserted_text_is_not_rescanned_for_markers(self):
        js = "// SPDX-License-Identifier: GPL-3.0-or-later\nconst a = '<!-- icons -->', b = '__CSP__';\n"
        with WebDir(js=js) as web:
            html = build_web.bundle(web).decode()
        self.assertIn(f'<script type="module">{js}</script>', html)
        self.assertEqual(html.count('<symbol id="i-x">'), 1)

    def test_missing_marker_fails(self):
        with WebDir(template=TEMPLATE.replace("<!-- icons -->\n", "")) as web:
            with self.assertRaisesRegex(build_web.BuildError, "icons"):
                build_web.bundle(web)

    def test_duplicate_marker_fails(self):
        doubled = TEMPLATE.replace('<div id="app">', '<link rel="stylesheet" href="style.css"><div id="app">')
        with WebDir(template=doubled) as web:
            with self.assertRaisesRegex(build_web.BuildError, "style.css"):
                build_web.bundle(web)

    def test_closing_tag_inside_script_fails(self):
        with WebDir(js="const s = '</script>';\n") as web:
            with self.assertRaisesRegex(build_web.BuildError, "app.js"):
                build_web.bundle(web)

    def test_closing_tag_inside_style_fails(self):
        with WebDir(css="a::after { content: '</style>'; }\n") as web:
            with self.assertRaisesRegex(build_web.BuildError, "style.css"):
                build_web.bundle(web)

    def test_inline_style_attribute_fails(self):
        with WebDir(template=TEMPLATE.replace('<div id="app">', '<div id="app" style="color: red">')) as web:
            with self.assertRaisesRegex(build_web.BuildError, "style attribute"):
                build_web.bundle(web)


class MainTest(unittest.TestCase):
    def run_main(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = build_web.main(list(args))
        return code, out.getvalue(), err.getvalue()

    def test_writes_reproducible_gzip_of_the_bundle(self):
        with WebDir() as web, tempfile.TemporaryDirectory() as out_dir:
            first = Path(out_dir) / "a" / "index.html.gz"
            second = Path(out_dir) / "b.gz"
            self.assertEqual(self.run_main(str(first), "--web-dir", str(web))[0], 0)
            self.assertEqual(self.run_main(str(second), "--web-dir", str(web))[0], 0)
            self.assertEqual(first.read_bytes(), second.read_bytes())
            self.assertEqual(gzip.decompress(first.read_bytes()), build_web.bundle(web))
            self.assertEqual(first.read_bytes(), build_web.gzip_bundle(web))

    def test_writes_the_header_policy_next_to_the_gzip(self):
        with WebDir() as web, tempfile.TemporaryDirectory() as out_dir:
            target = Path(out_dir) / "index.html.gz"
            self.assertEqual(self.run_main(str(target), "--web-dir", str(web))[0], 0)
            policy = (Path(out_dir) / "index.html.gz.csp.txt").read_text()
            self.assertEqual(policy, build_web.header_policy(web))
            self.assertIn(csp_hash(JS), policy)
            self.assertTrue(policy.endswith("; frame-ancestors 'none'"))

    def test_budget_exceeded_fails_without_writing(self):
        with WebDir() as web, tempfile.TemporaryDirectory() as out_dir:
            target = Path(out_dir) / "index.html.gz"
            code, _, err = self.run_main(str(target), "--web-dir", str(web), "--budget", "10")
            self.assertEqual(code, 1)
            self.assertIn("budget", err)
            self.assertFalse(target.exists())
            self.assertFalse((Path(out_dir) / "index.html.gz.csp.txt").exists())


class RealWebTest(unittest.TestCase):
    def test_repository_ui_builds_within_budget(self):
        web = TOOLS.parent / "web"
        data = build_web.gzip_bundle(web)
        self.assertLessEqual(len(data), build_web.DEFAULT_BUDGET)


if __name__ == "__main__":
    unittest.main()
