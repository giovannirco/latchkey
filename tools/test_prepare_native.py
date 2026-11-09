# SPDX-License-Identifier: GPL-3.0-or-later
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import cast

from idf_component_tools.hash_tools.calculate import hash_dir
from idf_component_tools.hash_tools.errors import HashNotEqualError
from prepare_native import locked_cjson, prepare


class NativeComponentTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.lock = (
            Path(__file__).resolve().parents[1] / "dependencies.lock.esp32"
        ).read_text()
        for target in ("esp32", "esp32s3"):
            (self.root / f"dependencies.lock.{target}").write_text(self.lock)

    def cached(self) -> Path:
        source = self.root / "source"
        (source / "cJSON").mkdir(parents=True)
        (source / "cJSON" / "cJSON.c").write_text("int cjson_fixture;\n")
        (source / "cJSON" / "cJSON.h").write_text("extern int cjson_fixture;\n")
        digest = hash_dir(source)
        old = cast(str, locked_cjson(self.root).component_hash)
        for target in ("esp32", "esp32s3"):
            (self.root / f"dependencies.lock.{target}").write_text(
                self.lock.replace(old, digest)
            )
        destination = self.root / ".pio" / "native_components" / digest
        destination.parent.mkdir(parents=True)
        source.rename(destination)
        return destination / "cJSON"

    def test_selects_the_same_locked_parser_as_both_targets(self) -> None:
        component = locked_cjson(self.root)
        self.assertEqual("espressif/cjson", component.name)
        self.assertEqual("1.7.19~2", str(component.version))

    def test_disagreeing_target_locks_are_refused(self) -> None:
        (self.root / "dependencies.lock.esp32s3").write_text(
            self.lock.replace("1.7.19~2", "1.7.18")
        )
        with self.assertRaisesRegex(ValueError, "disagree"):
            locked_cjson(self.root)

    def test_verified_cached_source_needs_no_network(self) -> None:
        source = self.cached()
        self.assertEqual(source, prepare(self.root))

    def test_modified_cached_source_fails_instead_of_being_replaced(self) -> None:
        source = self.cached()
        (source / "cJSON.c").write_text("changed\n")
        with self.assertRaises(HashNotEqualError):
            prepare(self.root)
        self.assertEqual("changed\n", (source / "cJSON.c").read_text())

    def test_missing_lock_is_refused(self) -> None:
        (self.root / "dependencies.lock.esp32s3").unlink()
        with self.assertRaises(ValueError):
            locked_cjson(self.root)


if __name__ == "__main__":
    unittest.main()
