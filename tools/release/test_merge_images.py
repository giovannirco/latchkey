# SPDX-License-Identifier: GPL-3.0-or-later
"""Unit tests for tools/release/merge_images.py.

python3 -m unittest discover -s tools/release -p 'test_*.py'
"""

import hashlib
import io
import json
import struct
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True

import merge_images  # noqa: E402

CHIP_IDS = {"esp32": 0, "esp32s3": 9, "esp32c3": 5}
OTA_0_SIZES = {"esp32": 0x1E0000, "esp32s3": 0x300000, "esp32c3": 0x1E0000}


def partition_entry(label: str, kind: int, subtype: int, offset: int, size: int) -> bytes:
    return b"\xaa\x50" + struct.pack("<BBII", kind, subtype, offset, size) + label.encode().ljust(16, b"\0") + b"\0" * 4


def partition_table(ota_0_offset: int, ota_0_size: int) -> bytes:
    entries = [
        partition_entry("nvs", 1, 0x02, 0x9000, 0x10000),
        partition_entry("otadata", 1, 0x00, 0x19000, 0x2000),
        partition_entry("phy_init", 1, 0x01, 0x1B000, 0x1000),
        partition_entry("ota_0", 0, 0x10, ota_0_offset, ota_0_size),
        partition_entry("ota_1", 0, 0x11, ota_0_offset + ota_0_size, ota_0_size),
    ]
    table = b"".join(entries)
    md5 = b"\xeb\xeb" + b"\xff" * 14 + hashlib.md5(table).digest()
    return (table + md5).ljust(0xC00, b"\xff")


def app_image(chip_id: int, version: str, size: int) -> bytes:
    header = bytes([0xE9, 1, 2, 0x20]) + struct.pack("<I", 0x40080000)
    extended = bytes([0xEE, 0, 0, 0]) + struct.pack("<H", chip_id) + b"\0" * 9 + b"\x01"
    segment = struct.pack("<II", 0x3F400020, size - 32)
    desc = struct.pack("<II", 0xABCD5432, 0) + b"\0" * 8
    desc += version.encode().ljust(32, b"\0") + b"latchkey".ljust(32, b"\0")
    image = header + extended + segment + desc
    return image + bytes((i * 7) % 251 for i in range(size - len(image)))


class Build:
    """A PlatformIO build directory with flasher_args.json as ESP-IDF writes it."""

    def __init__(self, root: Path, env: str, chip: str | None = None, version: str = "1.2.3", **overrides):
        chip = chip or env
        self.dir = root / env
        self.dir.mkdir(parents=True)
        self.bootloader_offset = overrides.get("bootloader_offset", 0x0 if chip == "esp32s3" else 0x1000)
        self.app_offset = overrides.get("app_offset", 0x20000)
        self.bootloader = overrides.get("bootloader", b"\xe9\x03\x02\x20" + bytes(range(256)) * 80)
        self.partitions = partition_table(overrides.get("ota_0_offset", 0x20000), OTA_0_SIZES[chip])
        self.otadata = b"\xff" * 0x2000
        app_chip = overrides.get("app_chip_id", CHIP_IDS[chip])
        self.app = app_image(app_chip, overrides.get("app_version", version), overrides.get("app_size", 0x5000))
        for name, data in (
            ("bootloader.bin", self.bootloader),
            ("partitions.bin", self.partitions),
            ("ota_data_initial.bin", self.otadata),
            ("firmware.bin", self.app),
        ):
            (self.dir / name).write_bytes(data)
        sections = {
            "bootloader": (self.bootloader_offset, "bootloader/bootloader.bin"),
            "partition-table": (0x8000, "partition_table/partition-table.bin"),
            "otadata": (0x19000, "ota_data_initial.bin"),
            "app": (self.app_offset, "latchkey.bin"),
        }
        flash_files = {hex(offset): path for offset, path in sections.values()}
        flash_files.update(overrides.get("extra_files", {}))
        args = {
            "write_flash_args": ["--flash-mode", "dio", "--flash-size", "4MB", "--flash-freq", "40m"],
            "flash_settings": {"flash_mode": "dio", "flash_size": "4MB", "flash_freq": "40m"},
            "flash_files": flash_files,
            "extra_esptool_args": {"after": "hard-reset", "before": "default-reset", "stub": True, "chip": chip},
        }
        for name, (offset, path) in sections.items():
            args[name] = {"offset": hex(offset), "file": path, "encrypted": "false"}
        (self.dir / "flasher_args.json").write_text(json.dumps(args))


class MergeImagesTest(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.builds = Path(self._tmp.name) / "build"
        self.out = Path(self._tmp.name) / "dist"

    def run_main(self, *envs: str, version: str = "1.2.3") -> tuple[int, str]:
        argv = ["--version", version, "--build-root", str(self.builds), "--out", str(self.out), *envs]
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = merge_images.main(argv)
        return code, out.getvalue() + err.getvalue()

    def test_classic_factory_image_has_each_part_at_its_offset(self):
        build = Build(self.builds, "esp32")
        code, output = self.run_main("esp32")
        self.assertEqual(code, 0, output)
        image = (self.out / "latchkey-1.2.3-esp32-factory.bin").read_bytes()
        self.assertEqual(image[:0x1000], b"\xff" * 0x1000)
        self.assertEqual(image[0x1000 : 0x1000 + len(build.bootloader)], build.bootloader)
        self.assertEqual(image[0x8000 : 0x8000 + len(build.partitions)], build.partitions)
        self.assertEqual(image[0x9000:0x19000], b"\xff" * 0x10000)
        self.assertEqual(image[0x19000:0x1B000], build.otadata)
        self.assertEqual(image[0x20000:], build.app)

    def test_s3_factory_image_starts_with_the_bootloader(self):
        build = Build(self.builds, "esp32s3")
        code, output = self.run_main("esp32s3")
        self.assertEqual(code, 0, output)
        image = (self.out / "latchkey-1.2.3-esp32s3-factory.bin").read_bytes()
        self.assertEqual(image[: len(build.bootloader)], build.bootloader)
        self.assertEqual(image[0x8000 : 0x8000 + len(build.partitions)], build.partitions)
        self.assertEqual(image[0x20000:], build.app)

    def test_ota_image_is_the_app_image_unchanged(self):
        build = Build(self.builds, "esp32")
        self.assertEqual(self.run_main("esp32")[0], 0)
        self.assertEqual((self.out / "latchkey-1.2.3-esp32-ota.bin").read_bytes(), build.app)

    def test_manifest_points_each_chip_family_at_its_factory_image(self):
        Build(self.builds, "esp32")
        Build(self.builds, "esp32s3")
        self.assertEqual(self.run_main("esp32", "esp32s3")[0], 0)
        for env, family in (("esp32", "ESP32"), ("esp32s3", "ESP32-S3")):
            manifest = json.loads((self.out / f"manifest-{env}.json").read_text())
            self.assertEqual(
                manifest,
                {
                    "name": "Latchkey",
                    "version": "1.2.3",
                    "new_install_prompt_erase": True,
                    "new_install_improv_wait_time": 0,
                    "builds": [
                        {"chipFamily": family, "parts": [{"path": f"latchkey-1.2.3-{env}-factory.bin", "offset": 0}]}
                    ],
                },
            )

    def test_sha256sums_cover_every_image(self):
        Build(self.builds, "esp32")
        Build(self.builds, "esp32s3")
        self.assertEqual(self.run_main("esp32", "esp32s3")[0], 0)
        lines = (self.out / "SHA256SUMS").read_text().splitlines()
        names = sorted(path.name for path in self.out.glob("*.bin"))
        self.assertEqual(len(names), 4)
        expected = [f"{hashlib.sha256((self.out / name).read_bytes()).hexdigest()}  {name}" for name in names]
        self.assertEqual(lines, expected)

    def test_extra_flash_image_fails(self):
        Build(self.builds, "esp32", extra_files={"0x210000": "storage.bin"})
        code, output = self.run_main("esp32")
        self.assertEqual(code, 1)
        self.assertIn("0x210000", output)
        self.assertFalse((self.out / "latchkey-1.2.3-esp32-factory.bin").exists())

    def test_bootloader_at_the_wrong_offset_for_the_chip_fails(self):
        Build(self.builds, "esp32", bootloader_offset=0x0)
        code, output = self.run_main("esp32")
        self.assertEqual(code, 1)
        self.assertIn("bootloader", output)

    def test_app_offset_must_be_the_ota_0_partition(self):
        Build(self.builds, "esp32", ota_0_offset=0x30000)
        code, output = self.run_main("esp32")
        self.assertEqual(code, 1)
        self.assertIn("ota_0", output)

    def test_app_larger_than_ota_0_fails(self):
        Build(self.builds, "esp32", app_size=0x1E0001)
        code, output = self.run_main("esp32")
        self.assertEqual(code, 1)
        self.assertIn("ota_0", output)

    def test_overlapping_parts_fail(self):
        Build(self.builds, "esp32", bootloader=b"\xe9" * 0x7001)
        code, output = self.run_main("esp32")
        self.assertEqual(code, 1)
        self.assertIn("overlap", output)

    def test_app_built_for_another_chip_fails(self):
        Build(self.builds, "esp32", app_chip_id=9)
        code, output = self.run_main("esp32")
        self.assertEqual(code, 1)
        self.assertIn("chip", output)

    def test_unsupported_chip_fails(self):
        Build(self.builds, "esp32c3")
        code, output = self.run_main("esp32c3")
        self.assertEqual(code, 1)
        self.assertIn("esp32c3", output)

    def test_app_version_must_match_the_release(self):
        Build(self.builds, "esp32", app_version="1.2.2")
        code, output = self.run_main("esp32")
        self.assertEqual(code, 1)
        self.assertIn("1.2.2", output)

    def test_version_must_be_major_minor_patch(self):
        Build(self.builds, "esp32", version="1.2")
        code, output = self.run_main("esp32", version="1.2")
        self.assertEqual(code, 1)
        self.assertIn("1.2", output)


if __name__ == "__main__":
    unittest.main()
