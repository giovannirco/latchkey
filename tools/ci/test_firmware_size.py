# SPDX-License-Identifier: GPL-3.0-or-later
"""Unit tests for tools/ci/firmware_size.py.

python3 -m unittest discover -s tools/ci -p 'test_*.py'
"""

import io
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True

import firmware_size  # noqa: E402


class Builds:
    def __init__(self, **sizes: int):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        for env, size in sizes.items():
            image = self.root / env / "firmware.bin"
            image.parent.mkdir(parents=True)
            with image.open("wb") as handle:
                handle.truncate(size)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self._tmp.cleanup()

    def run(self, *extra: str) -> tuple[int, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = firmware_size.main(["--build-root", str(self.root), *extra])
        return code, out.getvalue() + err.getvalue()


class FirmwareSizeTest(unittest.TestCase):
    def test_classic_image_at_the_limit_passes(self):
        with Builds(esp32=1_887_436, esp32s3=900_000) as builds:
            code, output = builds.run()
        self.assertEqual(code, 0, output)

    def test_classic_image_one_byte_over_the_limit_fails(self):
        with Builds(esp32=1_887_437, esp32s3=900_000) as builds:
            code, output = builds.run()
        self.assertEqual(code, 1)
        self.assertIn("1,887,437", output)
        self.assertIn("1,887,436", output)

    def test_s3_image_has_no_1_8_mb_gate(self):
        with Builds(esp32=800_000, esp32s3=2_500_000) as builds:
            code, output = builds.run()
        self.assertEqual(code, 0, output)

    def test_summary_lists_both_sizes(self):
        with Builds(esp32=811_234, esp32s3=905_678) as builds:
            summary = builds.root / "summary.md"
            summary.write_text("earlier step\n")
            code, _ = builds.run("--summary", str(summary))
            text = summary.read_text()
        self.assertEqual(code, 0)
        self.assertTrue(text.startswith("earlier step\n"))
        self.assertIn("| esp32 | 811,234 |", text)
        self.assertIn("| esp32s3 | 905,678 |", text)

    def test_summary_is_written_when_the_gate_fails(self):
        with Builds(esp32=1_900_000, esp32s3=900_000) as builds:
            summary = builds.root / "summary.md"
            code, _ = builds.run("--summary", str(summary))
            text = summary.read_text()
        self.assertEqual(code, 1)
        self.assertIn("| esp32 | 1,900,000 |", text)

    def test_missing_image_is_an_error(self):
        with Builds(esp32=800_000) as builds:
            code, output = builds.run()
        self.assertEqual(code, 2)
        self.assertIn("esp32s3", output)


if __name__ == "__main__":
    unittest.main()
