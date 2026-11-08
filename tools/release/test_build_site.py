# SPDX-License-Identifier: GPL-3.0-or-later
"""Unit tests for tools/release/build_site.py.

python3 -m unittest discover -s tools/release -p 'test_*.py'
"""

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True

import build_site  # noqa: E402

INDEX = """<!doctype html>
<html lang="en">
<head>
<meta name="latchkey-version" content="">
<title>Latchkey</title>
</head>
</html>
"""


def manifest(env: str) -> str:
    part = {"path": f"latchkey-1.2.3-{env}-factory.bin", "offset": 0}
    return json.dumps({"name": "Latchkey", "version": "1.2.3", "builds": [{"chipFamily": "ESP32", "parts": [part]}]})


class BuildSiteTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.docs = self.root / "docs"
        self.docs.mkdir()
        (self.docs / "index.html").write_text(INDEX)
        (self.docs / "protocol.md").write_text("# Protocol\n")
        self.dist = self.root / "dist"
        self.dist.mkdir()
        for env in ("esp32", "esp32s3"):
            (self.dist / f"latchkey-1.2.3-{env}-factory.bin").write_bytes(b"\xff" * 64)
            (self.dist / f"latchkey-1.2.3-{env}-ota.bin").write_bytes(b"\xe9" * 32)
            (self.dist / f"manifest-{env}.json").write_text(manifest(env))
        (self.dist / "SHA256SUMS").write_text("0" * 64 + "  latchkey-1.2.3-esp32-factory.bin\n")
        (self.dist / "release-notes.md").write_text("- notes\n")
        self.site = self.root / "site"

    def run_main(self, version: str = "1.2.3") -> tuple[int, str]:
        argv = ["--version", version, "--docs", str(self.docs), "--dist", str(self.dist), "--out", str(self.site)]
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = build_site.main(argv)
        return code, out.getvalue() + err.getvalue()

    def test_docs_go_to_the_site_root(self):
        code, output = self.run_main()
        self.assertEqual(code, 0, output)
        self.assertEqual((self.site / "protocol.md").read_text(), "# Protocol\n")
        self.assertTrue((self.site / "index.html").is_file())

    def test_release_files_go_under_firmware_version(self):
        self.assertEqual(self.run_main()[0], 0)
        published = sorted(path.name for path in (self.site / "firmware" / "1.2.3").iterdir())
        self.assertEqual(
            published,
            [
                "SHA256SUMS",
                "latchkey-1.2.3-esp32-factory.bin",
                "latchkey-1.2.3-esp32-ota.bin",
                "latchkey-1.2.3-esp32s3-factory.bin",
                "latchkey-1.2.3-esp32s3-ota.bin",
                "manifest-esp32.json",
                "manifest-esp32s3.json",
            ],
        )

    def test_index_html_names_the_release_and_the_source_stays_unchanged(self):
        self.assertEqual(self.run_main()[0], 0)
        html = (self.site / "index.html").read_text()
        self.assertIn('<meta name="latchkey-version" content="1.2.3">', html)
        self.assertNotIn('content=""', html)
        self.assertEqual((self.docs / "index.html").read_text(), INDEX)

    def test_index_html_without_the_version_marker_fails(self):
        (self.docs / "index.html").write_text(INDEX.replace('<meta name="latchkey-version" content="">\n', ""))
        code, output = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("latchkey-version", output)

    def test_manifest_naming_a_missing_image_fails(self):
        (self.dist / "latchkey-1.2.3-esp32s3-factory.bin").unlink()
        code, output = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn("latchkey-1.2.3-esp32s3-factory.bin", output)

    def test_existing_output_directory_fails(self):
        self.site.mkdir()
        (self.site / "stale.html").write_text("old")
        code, output = self.run_main()
        self.assertEqual(code, 1)
        self.assertIn(str(self.site), output)

    def test_version_must_be_major_minor_patch(self):
        code, output = self.run_main(version="1.2.3-rc1")
        self.assertEqual(code, 1)
        self.assertIn("1.2.3-rc1", output)


if __name__ == "__main__":
    unittest.main()
