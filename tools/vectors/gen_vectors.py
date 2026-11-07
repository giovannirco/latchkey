# SPDX-License-Identifier: GPL-3.0-or-later
"""Generate the C++ test vectors in test/vectors/ from the ttlock-ble reference.

Run from anywhere:

    uv run -q --no-project --python 3.14 --with ttlock-ble==0.3.4 python -I tools/vectors/gen_vectors.py

Every expected value comes from ttlock-ble 0.3.4 (roquerodrigo/ttlock-ble, MIT):
CRCs from `crypto.crc_compute`, AES from `crypto.aes_encrypt` / `aes_decrypt`,
frames from `protocol.Frame`, the XOR codec from `crypto.codec_decode`, adverts
from `models.LockAdvertisement`. Inputs are synthetic or use the factory default
AES key; nothing comes from a paired lock or from the owner's devices. The lock
responses in KIND3R_CAPTURES are copied from kind3r/ttlock-sdk-js
(`docs/Bad CRC quest.md`, `tools/debug.js`, GPL-3.0) and checked against
ttlock-ble before they are written. The script is deterministic: a second run
rewrites identical files.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from ttlock_ble import crypto
from ttlock_ble.constants import LockState
from ttlock_ble.models import LockAdvertisement, LockVersion
from ttlock_ble.protocol import Frame

REFERENCE = "ttlock-ble 0.3.4"
OUT_DIR = Path(__file__).resolve().parents[2] / "test" / "vectors"

DEFAULT_KEY = bytes.fromhex("987623e8a923a1bb3d9e7d0378124588")
SYNTHETIC_KEY = bytes(range(16))
SYNTHETIC_LOCK_KEY = bytes.fromhex("00112233445566778899aabbccddeeff")

REQUEST_VERSION = LockVersion(protocolType=5, protocolVersion=3, scene=1, groupId=1, orgId=1)
RESPONSE_VERSION = LockVersion(protocolType=5, protocolVersion=3, scene=2, groupId=1, orgId=1)

CMD_MANAGE_KEYBOARD_PASSWORD = 0x03
CMD_GET_AES_KEY = 0x19
CMD_INITIALIZATION = 0x45
CMD_RESPONSE = 0x54
COMMAND_SUCCESS = 0x01
WIRE_OVERHEAD = 3
HEADER_LENGTH = 12
NOTIFICATION_SIZE = 20
CRC_QUIRK_INDEX = 0x21

KIND3R_CAPTURES = [
    ("bad_crc_quest_response_1", "7f5a0503020001000154aa102d2f9276f7eea8794974e465f0e99e18090d0a"),
    (
        "bad_crc_quest_response_3",
        "7f5a0503020001000154aa20df862dda9de19dbdf73afce5eb29d32a24feca385bf44991075a85692353d6acd00d0a",
    ),
    ("debug_js_response", "7f5a0503020001000154aa1095a3bd4703fde2b76397587b6ee44b7b280d0a"),
    ("bad_crc_quest_request_1", "7f5a0503010001000107aa10ade4c30cccffef87e7a4b85e76213d43fe0d0a"),
]

ADVERTS = [
    ("factory_dormant", "05 03 02 1c 3a aa bb cc dd ee ff 66 55 44 33 22 11"),
    ("paired_locked", "05 03 02 00 50 00 00 00 00 00 00 06 05 04 03 02 01"),
    ("paired_unlocked", "05 03 02 01 64 00 00 00 00 00 00 06 05 04 03 02 01"),
    ("paired_dormant", "05 03 02 10 4c 00 00 00 00 00 00 06 05 04 03 02 01"),
    ("paired_new_records", "05 03 02 02 32 00 00 00 00 00 00 06 05 04 03 02 01"),
    ("unpaired_awake", "05 03 02 04 3a 00 00 00 00 00 00 06 05 04 03 02 01"),
    ("minimum_length", "05 03 02 00 21 00 00 00 00 06 05 04 03 02 01"),
    ("offset_layout_v2s_plus", "00 00 00 00 05 04 00 01 01 46 00 00 00 06 05 04 03 02 01"),
    ("offset_layout_v2s", "00 00 00 00 05 01 00 01 01 46 00 00 00 06 05 04 03 02 01"),
    ("offset_layout_protocol_3", "00 00 00 00 03 00 00 01 01 46 00 00 00 06 05 04 03 02 01"),
    ("dfu_18_25", "12 19 00 00 00 00 00 00 00 00 00 00 00 00 00"),
    ("dfu_ff_ff", "ff ff 00 00 00 00 00 00 00 00 00 00 00 00 00"),
    ("too_short", "05 03 02 00 50 00 00 00 06 05 04 03 02 01"),
]

CODEC_CASES = [
    ("len1", 1, 0x01),
    ("len7", 7, 0x5A),
    ("len16", 16, 0x7F),
    ("len33_table_quirk", 33, 0x2C),
    ("len64", 64, 0x80),
]


def plain_dallas_crc8(data: bytes) -> int:
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0x8C if crc & 1 else crc >> 1
    return crc


def crc_path_hits_quirk(data: bytes) -> bool:
    crc = 0
    for byte in data:
        if crc ^ byte == CRC_QUIRK_INDEX:
            return True
        crc = crypto.crc_compute(bytes([crc ^ byte]))
    return False


def cbc_encrypt_raw(data: bytes, key: bytes) -> bytes:
    encryptor = Cipher(algorithms.AES(key), modes.CBC(key)).encryptor()
    return encryptor.update(data) + encryptor.finalize()


def build_frame(version: LockVersion, command: int, payload: bytes, key: bytes) -> bytes:
    frame = Frame.for_lock(version, command, payload)
    if payload:
        frame = frame.encrypt_data(key)
    return frame.build()


def build_raw_frame(version: LockVersion, command: int, data: bytes) -> bytes:
    return Frame.for_lock(version, command, data).build()


def search_payload(prefix: bytes, version: LockVersion, command: int, accept: Callable[[bytes], bool]) -> bytes:
    for counter in range(1 << 20):
        payload = prefix + counter.to_bytes(4, "big")
        if accept(build_frame(version, command, payload, DEFAULT_KEY)):
            return payload
    raise RuntimeError(f"no payload found for prefix {prefix!r}")


def c_array(name: str, data: bytes) -> str:
    rows = [", ".join(f"0x{byte:02x}" for byte in data[i : i + 12]) for i in range(0, len(data), 12)]
    body = ",\n    ".join(rows)
    return f"inline constexpr uint8_t {name}[] = {{\n    {body},\n}};\n"


def c_blob(name: str, data: bytes) -> str:
    return f"{name}, sizeof({name})" if data else "nullptr, 0"


def c_bool(value: bool) -> str:
    return "true" if value else "false"


def camel(name: str) -> str:
    return "".join(part[:1].upper() + part[1:] for part in name.split("_"))


def header(namespace: str, body: str) -> str:
    return (
        "// SPDX-License-Identifier: GPL-3.0-or-later\n"
        f"// Generated by tools/vectors/gen_vectors.py from {REFERENCE}. Do not edit.\n"
        "#pragma once\n\n"
        "#include <cstddef>\n"
        "#include <cstdint>\n\n"
        f"namespace vectors::{namespace} {{\n\n"
        f"{body}"
        f"\n}}  // namespace vectors::{namespace}\n"
    )


def frame_cases() -> list[tuple[str, LockVersion, int, bytes, bytes, bytes]]:
    crlf_payload = search_payload(
        b"crlf-split-",
        RESPONSE_VERSION,
        CMD_RESPONSE,
        lambda wire: wire[NOTIFICATION_SIZE - 2 : NOTIFICATION_SIZE] == b"\r\n",
    )
    quirk_payload = search_payload(
        b"crc-quirk-",
        REQUEST_VERSION,
        CMD_GET_AES_KEY,
        lambda wire: crc_path_hits_quirk(wire[:-WIRE_OVERHEAD]),
    )
    specs = [
        ("initialization", REQUEST_VERSION, CMD_INITIALIZATION, b"", DEFAULT_KEY),
        ("get_aes_key", REQUEST_VERSION, CMD_GET_AES_KEY, b"SCIENER", DEFAULT_KEY),
        (
            "aes_key_response",
            RESPONSE_VERSION,
            CMD_RESPONSE,
            bytes([CMD_GET_AES_KEY, COMMAND_SUCCESS]) + SYNTHETIC_LOCK_KEY,
            DEFAULT_KEY,
        ),
        ("synthetic_key_64_bytes", REQUEST_VERSION, CMD_MANAGE_KEYBOARD_PASSWORD, bytes(range(64)), SYNTHETIC_KEY),
        (
            "max_payload_239_bytes",
            REQUEST_VERSION,
            CMD_MANAGE_KEYBOARD_PASSWORD,
            bytes(i & 0xFF for i in range(239)),
            DEFAULT_KEY,
        ),
        ("crlf_at_notification_boundary", RESPONSE_VERSION, CMD_RESPONSE, crlf_payload, DEFAULT_KEY),
        ("crc_table_quirk", REQUEST_VERSION, CMD_GET_AES_KEY, quirk_payload, DEFAULT_KEY),
    ]
    cases = []
    for name, version, command, payload, key in specs:
        wire = build_frame(version, command, payload, key)
        length = wire[HEADER_LENGTH - 1]
        assert len(wire) == HEADER_LENGTH + length + WIRE_OVERHEAD
        assert wire[-2:] == b"\r\n"
        assert crypto.crc_compute(wire[:-WIRE_OVERHEAD]) == wire[-WIRE_OVERHEAD]
        if payload:
            assert crypto.aes_decrypt(wire[HEADER_LENGTH : HEADER_LENGTH + length], key) == payload
        cases.append((name, version, command, payload, key, wire))
    quirk_wire = cases[-1][5]
    assert plain_dallas_crc8(quirk_wire[:-WIRE_OVERHEAD]) != quirk_wire[-WIRE_OVERHEAD]
    return cases


def bad_padding_cases() -> list[tuple[str, bytes]]:
    blocks = [
        ("pad_byte_zero", bytes(15) + b"\x00"),
        ("pad_byte_17", bytes(15) + b"\x11"),
        ("pad_bytes_mismatch", bytes(14) + b"\x01\x02"),
        ("pad_16_mismatch", bytes(15) + b"\x10"),
        ("two_blocks_pad_byte_zero", bytes(16) + bytes(15) + b"\x00"),
    ]
    cases = []
    for name, padded in blocks:
        cipher = cbc_encrypt_raw(padded, DEFAULT_KEY)
        try:
            crypto.aes_decrypt(cipher, DEFAULT_KEY)
        except ValueError:
            cases.append((name, cipher))
            continue
        raise AssertionError(f"{name} decrypts under ttlock-ble")
    return cases


def crc_header(frames: list[tuple[str, LockVersion, int, bytes, bytes, bytes]]) -> str:
    table = bytes(crypto.crc_compute(bytes([i])) for i in range(256))
    check_input = b"123456789"
    check_value = crypto.crc_compute(check_input)
    assert check_value == 0xA1
    body = (
        "struct CrcCase {\n    const char* name;\n    const uint8_t* data;\n    size_t size;\n    uint8_t crc;\n};\n\n"
    )
    body += c_array("kTable", table) + "\n"
    body += c_array("kCheckInput", check_input)
    body += f"inline constexpr uint8_t kCheckValue = 0x{check_value:02x};\n\n"
    frame_rows = []
    for name, *_rest, wire in frames:
        array = f"kFrame{camel(name)}"
        body += c_array(array, wire[:-WIRE_OVERHEAD])
        frame_rows.append(f'    {{"{name}", {c_blob(array, wire)}, 0x{wire[-WIRE_OVERHEAD]:02x}}},')
    body += "\ninline constexpr CrcCase kFrames[] = {\n" + "\n".join(frame_rows) + "\n};\n\n"
    capture_rows = []
    for name, hex_wire in KIND3R_CAPTURES:
        wire = bytes.fromhex(hex_wire)
        assert wire[-2:] == b"\r\n"
        frame_body, crc = wire[:-WIRE_OVERHEAD], wire[-WIRE_OVERHEAD]
        assert crypto.crc_compute(frame_body) == crc
        assert (plain_dallas_crc8(frame_body) != crc) == crc_path_hits_quirk(frame_body)
        array = f"kCapture{camel(name)}"
        body += c_array(array, frame_body)
        capture_rows.append(f'    {{"{name}", {array}, sizeof({array}), 0x{crc:02x}}},')
    assert sum(crc_path_hits_quirk(bytes.fromhex(h)[:-WIRE_OVERHEAD]) for _, h in KIND3R_CAPTURES) == 2
    body += "\ninline constexpr CrcCase kKind3rCaptures[] = {\n" + "\n".join(capture_rows) + "\n};\n"
    return header("crc", body)


def aes_header() -> str:
    plaintexts = [
        ("len0", DEFAULT_KEY, b""),
        ("len1", DEFAULT_KEY, b"\x00"),
        ("sciener", DEFAULT_KEY, b"SCIENER"),
        ("len15", DEFAULT_KEY, bytes(range(15))),
        ("len16", DEFAULT_KEY, bytes(range(16))),
        ("len17", DEFAULT_KEY, bytes(range(17))),
        ("len32", DEFAULT_KEY, bytes(range(32))),
        ("synthetic_key_len16", SYNTHETIC_KEY, b"latchkey-vector!"),
    ]
    body = (
        "struct AesCase {\n    const char* name;\n    const uint8_t* key;\n"
        "    const uint8_t* plain;\n    size_t plainSize;\n    const uint8_t* cipher;\n    size_t cipherSize;\n};\n\n"
        "struct CipherCase {\n    const char* name;\n    const uint8_t* cipher;\n    size_t size;\n};\n\n"
    )
    body += c_array("kDefaultKey", DEFAULT_KEY) + c_array("kSyntheticKey", SYNTHETIC_KEY) + "\n"
    rows = []
    for name, key, plain in plaintexts:
        cipher = crypto.aes_encrypt(plain, key)
        assert crypto.aes_decrypt(cipher, key) == plain
        key_name = "kDefaultKey" if key == DEFAULT_KEY else "kSyntheticKey"
        plain_name, cipher_name = f"kPlain{camel(name)}", f"kCipher{camel(name)}"
        if plain:
            body += c_array(plain_name, plain)
        body += c_array(cipher_name, cipher)
        rows.append(f'    {{"{name}", {key_name}, {c_blob(plain_name, plain)}, {c_blob(cipher_name, cipher)}}},')
    body += "\ninline constexpr AesCase kCases[] = {\n" + "\n".join(rows) + "\n};\n\n"
    bad_rows = []
    for name, cipher in bad_padding_cases():
        array = f"kBad{camel(name)}"
        body += c_array(array, cipher)
        bad_rows.append(f'    {{"{name}", {array}, sizeof({array})}},')
    body += "\ninline constexpr CipherCase kBadPadding[] = {\n" + "\n".join(bad_rows) + "\n};\n"
    return header("aes", body)


def frame_header(frames: list[tuple[str, LockVersion, int, bytes, bytes, bytes]]) -> str:
    body = (
        "struct FrameCase {\n    const char* name;\n    uint8_t protocolType;\n    uint8_t protocolVersion;\n"
        "    uint8_t scene;\n    uint16_t groupId;\n    uint16_t orgId;\n    uint8_t command;\n"
        "    const uint8_t* key;\n    const uint8_t* payload;\n    size_t payloadSize;\n"
        "    const uint8_t* wire;\n    size_t wireSize;\n};\n\n"
    )
    body += c_array("kDefaultKey", DEFAULT_KEY) + c_array("kSyntheticKey", SYNTHETIC_KEY) + "\n"
    rows = []
    for index, (name, version, command, payload, key, wire) in enumerate(frames):
        payload_name, wire_name = f"kPayload{camel(name)}", f"kWire{camel(name)}"
        if payload:
            body += c_array(payload_name, payload)
        body += c_array(wire_name, wire)
        key_name = "kDefaultKey" if key == DEFAULT_KEY else "kSyntheticKey"
        rows.append(
            f'    {{"{name}", {version.protocolType}, {version.protocolVersion}, {version.scene}, '
            f"{version.groupId}, {version.orgId}, 0x{command:02x}, {key_name}, "
            f"{c_blob(payload_name, payload)}, {c_blob(wire_name, wire)}}},"
        )
        if name in ("crlf_at_notification_boundary", "crc_table_quirk"):
            body += f"inline constexpr size_t k{camel(name)}Index = {index};\n"
    body += "\ninline constexpr FrameCase kFrames[] = {\n" + "\n".join(rows) + "\n};\n\n"
    bad_cipher = dict(bad_padding_cases())["pad_byte_zero"]
    bad_wire = build_raw_frame(RESPONSE_VERSION, CMD_RESPONSE, bad_cipher)
    assert crypto.crc_compute(bad_wire[:-WIRE_OVERHEAD]) == bad_wire[-WIRE_OVERHEAD]
    body += c_array("kWireBadPadding", bad_wire)
    return header("frame", body)


def advert_header() -> str:
    body = (
        "struct AdvertCase {\n    const char* name;\n    const uint8_t* data;\n    size_t size;\n    bool ok;\n"
        "    uint8_t protocolType;\n    uint8_t protocolVersion;\n    uint8_t scene;\n    bool paired;\n"
        "    bool hasLockState;\n    bool locked;\n    int battery;\n    const char* mac;\n};\n\n"
    )
    rows = []
    for name, hex_data in ADVERTS:
        data = bytes.fromhex(hex_data)
        advert = LockAdvertisement.from_manufacturer_data(int.from_bytes(data[:2], "little"), data[2:])
        array = f"kAdvert{camel(name)}"
        body += c_array(array, data)
        if advert is None:
            rows.append(f'    {{"{name}", {array}, sizeof({array}), false, 0, 0, 0, false, false, false, 0, ""}},')
            continue
        rows.append(
            f'    {{"{name}", {array}, sizeof({array}), true, {advert.protocol_type}, {advert.protocol_version}, '
            f"{advert.scene}, {c_bool(not advert.is_setting_mode)}, {c_bool(advert.lock_state is not None)}, "
            f'{c_bool(advert.lock_state == LockState.LOCKED)}, {advert.battery}, "{advert.lock_mac}"}},'
        )
    factory = LockAdvertisement.from_manufacturer_data(0x0305, bytes.fromhex(ADVERTS[0][1])[2:])
    assert factory is not None
    assert (factory.protocol_type, factory.protocol_version, factory.scene) == (5, 3, 2)
    assert factory.is_setting_mode and factory.lock_state is None and factory.battery == 58
    assert factory.lock_mac == "11:22:33:44:55:66"
    body += "\ninline constexpr AdvertCase kAdverts[] = {\n" + "\n".join(rows) + "\n};\n"
    return header("advert", body)


def codec_header() -> str:
    body = (
        "struct CodecCase {\n    const char* name;\n    const uint8_t* encoded;\n    const uint8_t* plain;\n"
        "    size_t size;\n    uint8_t seed;\n};\n\n"
    )
    rows = []
    for name, size, seed in CODEC_CASES:
        encoded = bytes((i * 37 + 11) & 0xFF for i in range(size))
        plain = crypto.codec_decode(encoded + bytes([seed]))
        assert len(plain) == size
        encoded_name, plain_name = f"kEncoded{camel(name)}", f"kPlain{camel(name)}"
        body += c_array(encoded_name, encoded) + c_array(plain_name, plain)
        rows.append(f'    {{"{name}", {encoded_name}, {plain_name}, {size}, 0x{seed:02x}}},')
    quirk = next(case for case in CODEC_CASES if case[1] == CRC_QUIRK_INDEX)
    assert crypto.crc_compute(bytes([quirk[1]])) != plain_dallas_crc8(bytes([quirk[1]]))
    body += "\ninline constexpr CodecCase kCases[] = {\n" + "\n".join(rows) + "\n};\n"
    return header("codec", body)


def main() -> None:
    frames = frame_cases()
    outputs = {
        "crc_vectors.h": crc_header(frames),
        "aes_vectors.h": aes_header(),
        "frame_vectors.h": frame_header(frames),
        "advert_vectors.h": advert_header(),
        "codec_vectors.h": codec_header(),
    }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for file_name, text in outputs.items():
        (OUT_DIR / file_name).write_text(text)
        print(f"wrote {OUT_DIR / file_name}")


if __name__ == "__main__":
    main()
