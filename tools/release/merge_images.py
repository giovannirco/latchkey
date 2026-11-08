#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Package the release images of PlatformIO builds: factory image, OTA image, ESP Web Tools manifest.

    python3 tools/release/merge_images.py --version 0.1.0 --out dist [--build-root .pio/build] esp32 esp32s3

For each env it writes into --out:

- latchkey-<version>-<env>-factory.bin: bootloader, partition table, otadata and app at the
  offsets ESP-IDF wrote into .pio/build/<env>/flasher_args.json, gaps filled with 0xFF (what
  `esptool merge-bin` produces), flashable at 0x0;
- latchkey-<version>-<env>-ota.bin: the app image alone, for an over-the-air update;
- manifest-<env>.json: the ESP Web Tools manifest for that chip family;

then SHA256SUMS over every .bin in --out. Before writing anything it checks that flasher_args.json
lists exactly those four images, that the bootloader offset is the one the chip's ROM loads, that
the app goes into the ota_0 partition of the built partition table and fits it, and that the app
image was built for that chip and reports --version.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import struct
import sys
from dataclasses import dataclass
from pathlib import Path

CHIP_FAMILIES = {"esp32": "ESP32", "esp32s3": "ESP32-S3"}
CHIP_IDS = {"esp32": 0, "esp32s3": 9}
BOOTLOADER_OFFSETS = {"esp32": 0x1000, "esp32s3": 0x0}
SECTIONS = (
    ("bootloader", "bootloader.bin"),
    ("partition-table", "partitions.bin"),
    ("otadata", "ota_data_initial.bin"),
    ("app", "firmware.bin"),
)
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
PARTITION_MAGIC = b"\xaa\x50"
PARTITION_ENTRY_SIZE = 32
APP_PARTITION, OTA_0_SUBTYPE = 0x00, 0x10
DATA_PARTITION, OTA_DATA_SUBTYPE = 0x01, 0x00
APP_CHIP_ID_OFFSET = 12
APP_DESC_OFFSET = 32
APP_DESC_MAGIC = 0xABCD5432
DEFAULT_BUILD_ROOT = Path(__file__).resolve().parents[2] / ".pio" / "build"


class ReleaseError(Exception):
    pass


@dataclass(frozen=True)
class Partition:
    kind: int
    subtype: int
    offset: int
    size: int


@dataclass(frozen=True)
class Build:
    env: str
    chip: str
    parts: dict[str, tuple[int, bytes]]


def read_partitions(table: bytes) -> list[Partition]:
    partitions = []
    for start in range(0, len(table), PARTITION_ENTRY_SIZE):
        entry = table[start : start + PARTITION_ENTRY_SIZE]
        if entry[:2] != PARTITION_MAGIC:
            break
        kind, subtype, offset, size = struct.unpack_from("<BBII", entry, 2)
        partitions.append(Partition(kind, subtype, offset, size))
    return partitions


def find_partition(partitions: list[Partition], kind: int, subtype: int, name: str) -> Partition:
    for partition in partitions:
        if partition.kind == kind and partition.subtype == subtype:
            return partition
    raise ReleaseError(f"the partition table has no {name} partition")


def app_version(app: bytes) -> str:
    magic = struct.unpack_from("<I", app, APP_DESC_OFFSET)[0]
    if magic != APP_DESC_MAGIC:
        raise ReleaseError("the app image has no ESP-IDF app description")
    return app[APP_DESC_OFFSET + 16 : APP_DESC_OFFSET + 48].split(b"\0", 1)[0].decode("ascii")


def read_flasher_args(build_dir: Path, env: str) -> tuple[str, dict[str, tuple[int, bool]], set[int]]:
    flasher = json.loads((build_dir / "flasher_args.json").read_text(encoding="utf-8"))
    try:
        chip = flasher["extra_esptool_args"]["chip"]
        sections = {
            section: (int(flasher[section]["offset"], 16), flasher[section]["encrypted"] != "false")
            for section, _ in SECTIONS
        }
        listed = {int(offset, 16) for offset in flasher["flash_files"]}
    except KeyError as err:
        raise ReleaseError(f"{env}: flasher_args.json has no {err} entry") from err
    return chip, sections, listed


def read_build(build_dir: Path, env: str) -> Build:
    chip, sections, listed = read_flasher_args(build_dir, env)
    if chip not in CHIP_FAMILIES:
        raise ReleaseError(f"{env}: chip {chip} has no release image layout")
    parts = {}
    for section, name in SECTIONS:
        offset, encrypted = sections[section]
        if encrypted:
            raise ReleaseError(f"{env}: the {section} image is encrypted")
        parts[section] = (offset, (build_dir / name).read_bytes())
    unexpected = sorted(listed - {offset for offset, _ in parts.values()})
    if unexpected:
        raise ReleaseError(f"{env}: flasher_args.json lists images this script does not package: {', '.join(hex(o) for o in unexpected)}")
    return Build(env, chip, parts)


def check_build(build: Build, version: str) -> None:
    bootloader_offset = build.parts["bootloader"][0]
    if bootloader_offset != BOOTLOADER_OFFSETS[build.chip]:
        raise ReleaseError(f"{build.env}: bootloader at {bootloader_offset:#x}, but the {build.chip} ROM loads it from {BOOTLOADER_OFFSETS[build.chip]:#x}")
    partitions = read_partitions(build.parts["partition-table"][1])
    otadata = find_partition(partitions, DATA_PARTITION, OTA_DATA_SUBTYPE, "otadata")
    if build.parts["otadata"][0] != otadata.offset:
        raise ReleaseError(f"{build.env}: otadata image at {build.parts['otadata'][0]:#x}, partition at {otadata.offset:#x}")
    ota_0 = find_partition(partitions, APP_PARTITION, OTA_0_SUBTYPE, "ota_0")
    app_offset, app = build.parts["app"]
    if app_offset != ota_0.offset:
        raise ReleaseError(f"{build.env}: app image at {app_offset:#x}, but ota_0 starts at {ota_0.offset:#x}")
    if len(app) > ota_0.size:
        raise ReleaseError(f"{build.env}: app image of {len(app):,} bytes does not fit ota_0 ({ota_0.size:,} bytes)")
    chip_id = struct.unpack_from("<H", app, APP_CHIP_ID_OFFSET)[0]
    if chip_id != CHIP_IDS[build.chip]:
        raise ReleaseError(f"{build.env}: the app image was built for chip id {chip_id}, not {build.chip}")
    built = app_version(app)
    if built != version:
        raise ReleaseError(f"{build.env}: the app image reports version {built}, not {version}")


def merge(parts: list[tuple[int, bytes]]) -> bytes:
    image = bytearray()
    for offset, data in sorted(parts, key=lambda part: part[0]):
        if offset < len(image):
            raise ReleaseError(f"the image at {offset:#x} would overlap the one before it, which ends at {len(image):#x}")
        image += b"\xff" * (offset - len(image))
        image += data
    return bytes(image)


def manifest(version: str, chip: str, factory_name: str) -> dict:
    return {
        "name": "Latchkey",
        "version": version,
        "new_install_prompt_erase": True,
        "new_install_improv_wait_time": 0,
        "builds": [{"chipFamily": CHIP_FAMILIES[chip], "parts": [{"path": factory_name, "offset": 0}]}],
    }


def write_sums(out: Path) -> None:
    lines = [f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}\n" for path in sorted(out.glob("*.bin"))]
    (out / "SHA256SUMS").write_text("".join(lines), encoding="utf-8")


def package(version: str, build_root: Path, out: Path, envs: list[str]) -> None:
    if not VERSION.fullmatch(version):
        raise ReleaseError(f"version {version} is not MAJOR.MINOR.PATCH")
    builds = [read_build(build_root / env, env) for env in envs]
    for build in builds:
        check_build(build, version)
    images = {build.env: merge(list(build.parts.values())) for build in builds}
    out.mkdir(parents=True, exist_ok=True)
    for build in builds:
        factory = f"latchkey-{version}-{build.env}-factory.bin"
        (out / factory).write_bytes(images[build.env])
        (out / f"latchkey-{version}-{build.env}-ota.bin").write_bytes(build.parts["app"][1])
        text = json.dumps(manifest(version, build.chip, factory), indent=2) + "\n"
        (out / f"manifest-{build.env}.json").write_text(text, encoding="utf-8")
        print(f"{build.env}: {factory} ({len(images[build.env]):,} bytes), app {len(build.parts['app'][1]):,} bytes")
    write_sums(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--version", required=True, help="release version, MAJOR.MINOR.PATCH")
    parser.add_argument("--out", type=Path, required=True, help="directory for the images, manifests and SHA256SUMS")
    parser.add_argument("--build-root", type=Path, default=DEFAULT_BUILD_ROOT)
    parser.add_argument("envs", nargs="+", help="PlatformIO envs to package, for example esp32 esp32s3")
    args = parser.parse_args(argv)
    try:
        package(args.version, args.build_root, args.out, args.envs)
    except (ReleaseError, OSError, ValueError) as err:
        print(f"merge_images: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
