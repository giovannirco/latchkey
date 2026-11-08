# SPDX-License-Identifier: GPL-3.0-or-later
"""Unit tests for tools/release/release_notes.py.

python3 -m unittest discover -s tools/release -p 'test_*.py'
"""

import io
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True

import release_notes  # noqa: E402

CHANGELOG = """<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Changelog

## [Unreleased]

- Work in progress.

## [10.1.0] - 2027-01-02

- Ten.

## [0.1.01] - 2026-12-01

- Not a version anyone should match.

## [0.1.0] - 2026-11-20

### Added

- First release.

## [0.0.9] - 2026-11-01

## [0.0.1] - 2026-10-01

- Skeleton.
"""


class ReleaseNotesTest(unittest.TestCase):
    def run_main(self, version: str, text: str = CHANGELOG) -> tuple[int, str, str]:
        with tempfile.TemporaryDirectory() as tmp:
            changelog = Path(tmp) / "CHANGELOG.md"
            changelog.write_text(text)
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = release_notes.main([version, "--changelog", str(changelog)])
        return code, out.getvalue(), err.getvalue()

    def test_prints_only_the_section_of_that_version(self):
        code, notes, _ = self.run_main("0.1.0")
        self.assertEqual(code, 0)
        self.assertEqual(notes, "### Added\n\n- First release.\n")

    def test_last_section_runs_to_the_end_of_the_file(self):
        code, notes, _ = self.run_main("0.0.1")
        self.assertEqual(code, 0)
        self.assertEqual(notes, "- Skeleton.\n")

    def test_version_without_a_section_fails(self):
        code, notes, err = self.run_main("0.2.0")
        self.assertEqual(code, 1)
        self.assertEqual(notes, "")
        self.assertIn("0.2.0", err)

    def test_empty_section_fails(self):
        code, _, err = self.run_main("0.0.9")
        self.assertEqual(code, 1)
        self.assertIn("0.0.9", err)

    def test_unreleased_section_is_not_a_version(self):
        code, notes, err = self.run_main("Unreleased")
        self.assertEqual(code, 1)
        self.assertEqual(notes, "")
        self.assertIn("MAJOR.MINOR.PATCH", err)


if __name__ == "__main__":
    unittest.main()
