# SPDX-License-Identifier: GPL-3.0-or-later
"""Validate published firmware before assembling a Pages-only deployment."""

import hashlib
import importlib
import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True


class PrepareSiteReleaseTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tool = importlib.import_module("prepare_site_release")
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.dist = self.root / "dist"
        self.dist.mkdir()
        self.images = {}
        for board in ("esp32", "esp32s3"):
            for kind in ("factory", "ota"):
                name = f"latchkey-1.2.3-{board}-{kind}.bin"
                self.images[name] = f"fixture {board} {kind}".encode()
                (self.dist / name).write_bytes(self.images[name])
        self.sums = "".join(
            f"{hashlib.sha256(data).hexdigest()}  {name}\n" for name, data in sorted(self.images.items())
        )
        (self.dist / "SHA256SUMS").write_text(self.sums, encoding="utf-8")

    def run_main(self, version: str = "1.2.3") -> tuple[int, str]:
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = self.tool.main(["--version", version, "--dist", str(self.dist)])
        return code, stdout.getvalue() + stderr.getvalue()

    def assert_refused(self, message: str) -> None:
        code, output = self.run_main()
        self.assertEqual(code, 1, output)
        self.assertIn(message, output)
        self.assertEqual(list(self.dist.glob("manifest-*.json")), [])

    def test_verified_images_generate_manifests_without_changing_release_bytes(self) -> None:
        code, output = self.run_main()
        self.assertEqual(code, 0, output)
        for name, data in self.images.items():
            self.assertEqual((self.dist / name).read_bytes(), data)
        self.assertEqual((self.dist / "SHA256SUMS").read_text(), self.sums)
        for board, family in (("esp32", "ESP32"), ("esp32s3", "ESP32-S3")):
            manifest = json.loads((self.dist / f"manifest-{board}.json").read_text())
            self.assertEqual(
                manifest,
                {
                    "name": "Latchkey",
                    "version": "1.2.3",
                    "new_install_prompt_erase": True,
                    "new_install_improv_wait_time": 0,
                    "builds": [
                        {
                            "chipFamily": family,
                            "parts": [
                                {
                                    "path": f"latchkey-1.2.3-{board}-factory.bin",
                                    "offset": 0,
                                }
                            ],
                        }
                    ],
                },
            )

    def test_missing_image_is_refused(self) -> None:
        name = next(iter(self.images))
        (self.dist / name).unlink()
        self.assert_refused("release assets")

    def test_extra_image_is_refused(self) -> None:
        (self.dist / "unlisted.bin").write_bytes(b"extra")
        self.assert_refused("release assets")

    def test_extra_private_file_is_refused(self) -> None:
        (self.dist / "backup.lkb").write_bytes(b"fixture")
        self.assert_refused("release assets")

    def test_directory_with_an_expected_image_name_is_refused(self) -> None:
        path = self.dist / next(iter(self.images))
        path.unlink()
        path.mkdir()
        self.assert_refused("regular files")

    def test_symlink_with_an_expected_image_name_is_refused(self) -> None:
        path = self.dist / next(iter(self.images))
        data = path.read_bytes()
        path.unlink()
        target = self.root / "outside.bin"
        target.write_bytes(data)
        path.symlink_to(target)
        self.assert_refused("regular files")

    def test_hash_mismatch_leaves_no_manifests(self) -> None:
        path = self.dist / max(self.images)
        path.write_bytes(b"damaged")
        self.assert_refused("checksum mismatch")

    def test_missing_checksum_file_is_refused(self) -> None:
        (self.dist / "SHA256SUMS").unlink()
        self.assert_refused("release assets")

    def test_duplicate_checksum_entry_is_refused(self) -> None:
        (self.dist / "SHA256SUMS").write_text(self.sums + self.sums.splitlines()[0] + "\n")
        self.assert_refused("duplicate")

    def test_missing_checksum_entry_is_refused(self) -> None:
        (self.dist / "SHA256SUMS").write_text("\n".join(self.sums.splitlines()[:-1]) + "\n")
        self.assert_refused("exactly")

    def test_path_traversal_checksum_entry_is_refused(self) -> None:
        name = next(iter(self.images))
        (self.dist / "SHA256SUMS").write_text(self.sums.replace(name, f"../{name}"))
        self.assert_refused("unexpected checksum")

    def test_malformed_checksum_is_refused(self) -> None:
        (self.dist / "SHA256SUMS").write_text("g" + self.sums[1:])
        self.assert_refused("malformed")

    def test_binary_checksum_separator_is_refused(self) -> None:
        (self.dist / "SHA256SUMS").write_text(self.sums.replace("  latchkey", " *latchkey"))
        self.assert_refused("malformed")

    def test_version_must_be_major_minor_patch(self) -> None:
        for version in ("v1.2.3", "1.2", "1.2.3-rc1", "../1.2.3", "1.2.3\n"):
            with self.subTest(version=version):
                code, output = self.run_main(version)
                self.assertEqual(code, 1, output)
                self.assertIn("MAJOR.MINOR.PATCH", output)
        self.assertEqual(list(self.dist.glob("manifest-*.json")), [])

    def test_existing_manifests_are_not_overwritten(self) -> None:
        path = self.dist / "manifest-esp32.json"
        path.write_text("existing")
        code, output = self.run_main()
        self.assertEqual(code, 1, output)
        self.assertIn("release assets", output)
        self.assertEqual(path.read_text(), "existing")


if __name__ == "__main__":
    unittest.main()
