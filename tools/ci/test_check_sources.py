# SPDX-License-Identifier: GPL-3.0-or-later
"""Self-test for tools/ci/check_sources.py.

python3 -m unittest discover -s tools/ci -p 'test_*.py'
"""

import io
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True

import check_sources  # noqa: E402

GPL = "SPDX-License-Identifier: GPL-3.0-or-later"


class Tree:
    """A throwaway git work tree: check_sources lists files through git."""

    def __init__(self, files: dict[str, str | bytes]):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True)
        for name, content in files.items():
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                path.write_bytes(content)
            else:
                path.write_text(content)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self._tmp.cleanup()

    def check(self) -> tuple[int, str]:
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = check_sources.main(["--root", str(self.root)])
        return code, out.getvalue() + err.getvalue()


CLEAN = {
    "src/main.cpp": f"// {GPL}\n#include \"esp_log.h\"\n",
    "components/ttlock/src/frame.cpp": f"// {GPL}\n#include <cstdint>\n#include \"ttlock/frame.h\"\n",
    "tools/cli.py": f"#!/usr/bin/env python3\n# {GPL}\nprint('hi')\n",
    "docs/notes.md": f"<!-- {GPL} -->\n# Notes\n",
    "web/index.html": f"<!-- {GPL} -->\n<!doctype html>\n",
    ".github/workflows/ci.yml": f"# {GPL}\nname: CI\n",
    "CMakeLists.txt": f"# {GPL}\nproject(x)\n",
    "LICENSE": "GNU GENERAL PUBLIC LICENSE\n",
    "NOTICE": "Latchkey\n",
    "secrets.example.json": "{}\n",
    "dependencies.lock.esp32": "dependencies: {}\n",
    "tools/vectors/deno.lock": "{}\n",
    "components/ttlock/src/third_party/aes/aes.c": "/* public domain */\n#include <string.h>\n",
}


class CheckSourcesTest(unittest.TestCase):
    def test_clean_tree_passes(self):
        with Tree(CLEAN) as tree:
            code, output = tree.check()
        self.assertEqual(code, 0, output)

    def test_file_without_spdx_fails(self):
        with Tree({**CLEAN, "src/wifi.cpp": "#include \"wifi.h\"\n"}) as tree:
            code, output = tree.check()
        self.assertEqual(code, 1)
        self.assertIn("src/wifi.cpp", output)
        self.assertNotIn("src/main.cpp", output)

    def test_esp_log_include_under_ttlock_fails(self):
        source = f"// {GPL}\n#include <cstdint>\n#include \"esp_log.h\"\n"
        with Tree({**CLEAN, "components/ttlock/src/session.cpp": source}) as tree:
            code, output = tree.check()
        self.assertEqual(code, 1)
        self.assertIn("components/ttlock/src/session.cpp:3", output)
        self.assertIn("esp_log.h", output)

    def test_freertos_include_under_latchkey_util_fails(self):
        source = f"// {GPL}\n#  include <freertos/FreeRTOS.h>\n"
        with Tree({**CLEAN, "components/latchkey_util/src/queue.cpp": source}) as tree:
            code, output = tree.check()
        self.assertEqual(code, 1)
        self.assertIn("components/latchkey_util/src/queue.cpp:2", output)

    def test_esp_header_guarded_by_esp_platform_still_fails(self):
        source = f"// {GPL}\n#ifdef ESP_PLATFORM\n#include \"esp_timer.h\"\n#endif\n"
        with Tree({**CLEAN, "components/ttlock/include/ttlock/clock.h": source}) as tree:
            code, output = tree.check()
        self.assertEqual(code, 1)
        self.assertIn("components/ttlock/include/ttlock/clock.h:3", output)

    def test_vendored_code_under_ttlock_is_checked_for_includes(self):
        source = "/* public domain */\n#include \"esp_attr.h\"\n"
        with Tree({**CLEAN, "components/ttlock/src/third_party/aes/aes.c": source}) as tree:
            code, output = tree.check()
        self.assertEqual(code, 1)
        self.assertIn("components/ttlock/src/third_party/aes/aes.c:2", output)

    def test_commented_out_include_passes(self):
        source = f"// {GPL}\n// #include \"esp_log.h\"\n"
        with Tree({**CLEAN, "components/ttlock/src/frame.cpp": source}) as tree:
            code, output = tree.check()
        self.assertEqual(code, 0, output)

    def test_spdx_below_the_header_fails(self):
        late = "\n" * 5 + f"// {GPL}\n"
        with Tree({**CLEAN, "src/late.cpp": late}) as tree:
            code, output = tree.check()
        self.assertEqual(code, 1)
        self.assertIn("src/late.cpp", output)

    def test_empty_license_expression_fails(self):
        with Tree({**CLEAN, "src/empty.cpp": "// SPDX-License-Identifier:\n"}) as tree:
            code, output = tree.check()
        self.assertEqual(code, 1)
        self.assertIn("src/empty.cpp", output)

    def test_file_type_without_comment_syntax_is_not_exempt_by_default(self):
        with Tree({**CLEAN, "tools/flash.ps1": "Write-Host hi\n"}) as tree:
            code, output = tree.check()
        self.assertEqual(code, 1)
        self.assertIn("tools/flash.ps1", output)

    def test_binary_file_is_exempt(self):
        with Tree({**CLEAN, "docs/board.png": b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"}) as tree:
            code, output = tree.check()
        self.assertEqual(code, 0, output)

    def test_gitignored_file_is_skipped(self):
        files = {**CLEAN, ".gitignore": f"# {GPL}\nbuild/\n", "build/out.cpp": "int x;\n"}
        with Tree(files) as tree:
            code, output = tree.check()
        self.assertEqual(code, 0, output)

    def test_directory_outside_git_fails(self):
        with tempfile.TemporaryDirectory() as plain:
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                code = check_sources.main(["--root", plain])
        self.assertEqual(code, 2)
        self.assertIn("git", err.getvalue())


if __name__ == "__main__":
    unittest.main()
