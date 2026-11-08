# SPDX-License-Identifier: GPL-3.0-or-later
"""Generate the C++ test vectors in test/vectors/ from the ttlock-ble reference.

Run from anywhere:

    uv run -q --no-project --python 3.14 --with ttlock-ble==0.3.4 python -I tools/vectors/gen_vectors.py

Every expected value comes from ttlock-ble 0.3.4 (roquerodrigo/ttlock-ble, MIT):
CRCs from `crypto.crc_compute`, AES from `crypto.aes_encrypt` / `aes_decrypt`,
frames from `protocol.Frame`, the XOR codec from `crypto.codec_decode`, adverts
from `models.LockAdvertisement`.

Where the inputs come from:

- Payloads, plaintexts, codec bytes and adverts are synthetic. Frames and AES
  cases use the factory default key or the synthetic key 00..0f.
- `factory_dormant` keeps the first five bytes (05 03 02 1c 3a: protocol type,
  protocol version, scene, flags, battery) of an advert from the owner's
  factory-state lock. Its other twelve bytes, the MAC included, are synthetic.
- KIND3R_CAPTURES are four frames published in kind3r/ttlock-sdk-js
  (`docs/Bad CRC quest.md`, `tools/debug.js`, GPL-3.0): three responses from
  kind3r's own paired lock and one request kind3r sent to it, encrypted under
  that lock's key. Only their CRCs are used, and each is checked against
  ttlock-ble before it is written.
- command_vectors.h holds command payloads from the `commands` builders and
  expected fields from the `commands` parsers and `models.LockEvent`, all over
  synthetic inputs (made-up passcodes, card numbers and ids). The epoch-to-
  civil-date cases come from the Python standard library.

Commands that ttlock-ble does not implement get their vectors from
tools/vectors/kind3r_vectors.ts, which runs kind3r's own command classes.

The script is deterministic: a second run rewrites identical files.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Callable
from pathlib import Path

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from ttlock_ble import commands as cmd
from ttlock_ble import crypto
from ttlock_ble.constants import KeyboardPwdType, LockState
from ttlock_ble.models import LockAdvertisement, LockEvent, LockVersion
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


def c_scalar(type_name: str, name: str, value: int) -> str:
    suffix = "ULL" if type_name == "uint64_t" else ""
    return f"inline constexpr {type_name} {name} = {value}{suffix};\n"


def c_string(name: str, value: str) -> str:
    assert value.isascii() and '"' not in value and "\\" not in value
    return f'inline constexpr const char* {name} = "{value}";\n'


def c_optional(value: int | None) -> int:
    return -1 if value is None else value


def date_fields(value: dt.datetime | None, fallback: tuple[int, ...]) -> tuple[int, ...]:
    if value is None:
        return fallback
    return (value.year, value.month, value.day, value.hour, value.minute, value.second)


START_SENTINEL_FIELDS = (2000, 1, 1, 0, 0, 0)
END_SENTINEL_FIELDS = (2099, 1, 1, 0, 0, 0)

EPOCH_SECONDS = [
    -1,
    0,
    951782400,
    1704067199,
    1704067200,
    1709164800,
    1735689599,
    1762524000,
    4102444799,
    4107542399,
    4107542400,
]

LOG_RECORDS = [
    ("app_unlock", 1, (123).to_bytes(4, "big") + (456).to_bytes(4, "big")),
    ("keypad_unlock", 4, bytes([4]) + b"1357" + bytes([0])),
    ("keypad_modify", 5, bytes([4]) + b"1357" + bytes([5]) + b"24680"),
    ("wrong_passcode", 7, bytes([4]) + b"0000"),
    ("clear_all_passcodes", 8, bytes([25, 11, 7, 14, 23])),
    ("card_unlock", 17, (0xABCDEF).to_bytes(4, "big")),
    ("fingerprint_unlock", 20, (0x010203040506).to_bytes(6, "big")),
    ("ble_lock", 26, (7).to_bytes(4, "big") + (8).to_bytes(4, "big")),
    ("mechanical_key", 27, b""),
    ("door_sensor", 30, bytes([77])),
    ("remote_control_key", 37, (1).to_bytes(4, "big") + (2).to_bytes(4, "big") + bytes([9])),
    ("key_fob", 55, bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 3, 88])),
    ("wireless_keypad", 56, bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 42])),
    ("bong_unlock", 19, bytes([0x33, 0x22, 0x11, 0xCC, 0xBB, 0xAA])),
]
LOG_DATE = bytes([25, 11, 7, 14, 23, 7])
LOG_BATTERY = 90
LOG_SEQUENCE = 40


def log_page_data() -> bytes:
    records = bytearray()
    for _name, record_type, tail in LOG_RECORDS:
        record = bytes([record_type]) + LOG_DATE + bytes([LOG_BATTERY]) + tail
        records.append(len(record))
        records.extend(record)
    body = LOG_SEQUENCE.to_bytes(2, "big") + bytes(records)
    return len(body).to_bytes(2, "big") + body


def success(command: int, data: bytes) -> bytes:
    return bytes([command, cmd.RESPONSE_SUCCESS]) + data


def handshake_vectors() -> str:
    body = ""
    body += c_array("kCheckUserTimeDefault", cmd.payload_check_user_time())
    body += c_array("kCheckUserTimeFlagAndUid", cmd.payload_check_user_time(uid=0x01020304, lock_flag_pos=0x123456))
    body += c_array("kCheckAdminDefault", cmd.payload_check_admin(0, "12345678", 0))
    body += c_array("kCheckAdminFlagAndUid", cmd.payload_check_admin(0x01020304, "12345678", 0x123456))
    body += c_array("kCheckRandom", cmd.payload_check_random(0x01020304, 87654321))
    body += c_array("kCheckRandomWraps", cmd.payload_check_random(0xFFFFFFF0, 0x20))
    ps = 0x87654321
    assert cmd.parse_check_user_time_response(success(0x55, ps.to_bytes(4, "big") + b"\x09")) == ps
    assert cmd.parse_check_admin_response(success(0x41, ps.to_bytes(4, "big"))) == ps
    body += c_scalar("uint32_t", "kPsFromLock", ps)
    body += c_array("kPsFromLockData", ps.to_bytes(4, "big") + b"\x09")
    body += c_array("kUnlock", cmd.payload_unlock(0x0A0B0C0D, 87654321, 1762524000 * 1000))
    body += c_array("kUnlockWraps", cmd.payload_unlock(0xFFFFFFFF, 2, 1762524000 * 1000))
    calibrate_time = dt.datetime(2025, 11, 7, 11, 0, 5)
    body += c_array("kCalibrateTime", cmd.payload_time_calibrate(calibrate_time))
    body += c_array("kSearchStatus", cmd.payload_query_state())
    return body


def status_vectors() -> str:
    body = "struct StatusCase {\n    const uint8_t* data;\n    size_t size;\n    int state;\n    int battery;\n};\n\n"
    rows = []
    for name, data in [("Locked", bytes([0x2C, 0x00])), ("Unlocked", bytes([0x2C, 0x01])), ("Odd", bytes([0x2C, 9]))]:
        plain = success(0x14, data)
        state = cmd.parse_lock_status(plain)
        battery = cmd.parse_state_battery(plain)
        array = f"kStatus{name}"
        body += c_array(array, data)
        rows.append(
            f"    {{{array}, sizeof({array}), {c_optional(None if state is None else int(state))}, {battery}}},"
        )
    return body + "\ninline constexpr StatusCase kStatusCases[] = {\n" + "\n".join(rows) + "\n};\n"


def feature_vectors() -> str:
    body = "struct FeatureCase {\n    const uint8_t* data;\n    size_t size;\n    uint64_t mask;\n};\n\n"
    rows = []
    cases = [
        ("TwoWords", bytes([0x5A]) + bytes.fromhex("754cf5f7") + bytes.fromhex("00000804")),
        ("OneWord", bytes([0x64]) + bytes.fromhex("00000011")),
        ("PartialWord", bytes([0x64]) + bytes.fromhex("00000001") + bytes([0xFF, 0xFF])),
    ]
    for name, data in cases:
        features = cmd.parse_device_feature_response(success(0x01, data))
        array = f"kFeatures{name}"
        body += c_array(array, data)
        rows.append(f"    {{{array}, sizeof({array}), 0x{features.mask:016x}ULL}},")
    return body + "\ninline constexpr FeatureCase kFeatureCases[] = {\n" + "\n".join(rows) + "\n};\n"


def device_info_vectors() -> str:
    body = ""
    for item in range(1, 5):
        body += c_array(f"kReadDeviceInfo{item}", cmd.payload_device_property(item))
    data = b"LK100_TEST\x00"
    body += c_array("kDeviceInfoStringData", data)
    body += c_string("kDeviceInfoString", cmd.parse_device_property_string(success(0x90, data)))
    return body


def passcode_vectors() -> str:
    body = ""
    body += c_array("kPasscodeAddPermanent", cmd.payload_passcode_add(KeyboardPwdType.PERMANENT, "13579", "0001010000"))
    body += c_array(
        "kPasscodeAddPeriod", cmd.payload_passcode_add(KeyboardPwdType.PERIOD, "246810", "2511070900", "2512312359")
    )
    body += c_array(
        "kPasscodeAddCount", cmd.payload_passcode_add(KeyboardPwdType.COUNT, "8642", "2511070900", "2511071500")
    )
    body += c_array("kPasscodeDelete", cmd.payload_passcode_delete(KeyboardPwdType.PERMANENT, "13579"))
    body += c_array("kPasscodeClear", cmd.payload_passcode_clear())
    body += c_array("kPasscodeListRequest0", cmd.payload_passcode_list(0))
    body += c_array("kPasscodeListRequest336", cmd.payload_passcode_list(336))
    body += (
        "struct PasscodePageCase {\n    const char* name;\n    const uint8_t* data;\n    size_t size;\n"
        "    bool hasItem;\n    uint8_t type;\n    const char* code;\n    uint16_t next;\n"
        "    uint16_t start[6];\n    uint16_t end[6];\n};\n\n"
    )
    pages = [
        ("period", "002000011d0308323436383133353708323436383133353700010100001b09061100"),
        ("permanent", "001b015018010839373533313836340839373533313836340001010000"),
        ("cyclic", "001f00021c040931333537393234363809313335373932343638000101110004c0"),
        ("last_entry", "00180000150304383634320438363432190b070900190b070f00"),
        ("end_of_list", "0000"),
    ]
    rows = []
    for name, hex_data in pages:
        data = bytes.fromhex(hex_data)
        entry, next_sequence = cmd.parse_passcode_list_response(success(0x07, data))
        array = f"kPasscodePage{camel(name)}"
        body += c_array(array, data)
        if entry is None:
            rows.append(f'    {{"{name}", {array}, sizeof({array}), false, 0, "", {next_sequence}, {{}}, {{}}}},')
            continue
        start = date_fields(entry.start_date, START_SENTINEL_FIELDS)
        end = date_fields(entry.end_date, END_SENTINEL_FIELDS)
        rows.append(
            f'    {{"{name}", {array}, sizeof({array}), true, {int(entry.pwd_type)}, "{entry.passcode}", '
            f"{next_sequence}, {{{', '.join(map(str, start))}}}, {{{', '.join(map(str, end))}}}}},"
        )
    return body + "\ninline constexpr PasscodePageCase kPasscodePages[] = {\n" + "\n".join(rows) + "\n};\n"


def credential_vectors() -> str:
    body = ""
    body += c_array("kFingerprintListRequest0", cmd.payload_fingerprint_list(0))
    body += c_array("kFingerprintListRequest300", cmd.payload_fingerprint_list(300))
    body += c_array("kCardListRequest0", cmd.payload_card_list(0))
    body += c_array("kCardListRequest300", cmd.payload_card_list(300))
    body += (
        "struct CredentialPageCase {\n    const char* name;\n    const uint8_t* data;\n    size_t size;\n"
        "    bool hasItem;\n    uint64_t id;\n    uint16_t start[6];\n    uint16_t end[6];\n};\n\n"
    )
    fingerprints = [
        (
            "explicit_start",
            bytes([0x64, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0x2A, 0x00, 0x03, 26, 3, 1, 8, 0]) + cmd.END_DATE_SENTINEL,
        ),
        (
            "timed",
            bytes([0x64, 0x06, 0x00, 0x02, 0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x04])
            + cmd.START_DATE_SENTINEL
            + bytes([26, 12, 31, 23, 59]),
        ),
        ("end_of_list", bytes([0x64, 0x06, 0xFF, 0xFF])),
    ]
    rows = []
    for name, data in fingerprints:
        entry = cmd.parse_fingerprint_list_response(success(0x06, data))
        array = f"kFingerprintPage{camel(name)}"
        body += c_array(array, data)
        if entry is None:
            rows.append(f'    {{"{name}", {array}, sizeof({array}), false, 0, {{}}, {{}}}},')
            continue
        identifier = (int.from_bytes(entry.fingerprint_id, "big") << 16) | entry.slot
        start = date_fields(entry.start_date, START_SENTINEL_FIELDS)
        end = date_fields(entry.end_date, END_SENTINEL_FIELDS)
        rows.append(
            f'    {{"{name}", {array}, sizeof({array}), true, 0x{identifier:x}ULL, '
            f"{{{', '.join(map(str, start))}}}, {{{', '.join(map(str, end))}}}}},"
        )
    body += "\ninline constexpr CredentialPageCase kFingerprintPages[] = {\n" + "\n".join(rows) + "\n};\n\n"
    cards = [
        (
            "short_id",
            bytes([0x64, 0x01, 0x00, 0x01, 0x11, 0x22, 0x33, 0x44])
            + cmd.START_DATE_SENTINEL
            + bytes([0x1D, 0x09, 0x1D, 0x14, 0x2A]),
        ),
        (
            "long_id",
            bytes([0x64, 0x01, 0x00, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88])
            + cmd.START_DATE_SENTINEL
            + cmd.END_DATE_SENTINEL,
        ),
        ("end_of_list", bytes([0x55, 0x01, 0xFF, 0xFF])),
    ]
    rows = []
    for name, data in cards:
        entry = cmd.parse_card_list_response(success(0x05, data))
        array = f"kCardPage{camel(name)}"
        body += c_array(array, data)
        if entry is None:
            rows.append(f'    {{"{name}", {array}, sizeof({array}), false, 0, {{}}, {{}}}},')
            continue
        start = date_fields(entry.start_date, START_SENTINEL_FIELDS)
        end = date_fields(entry.end_date, END_SENTINEL_FIELDS)
        rows.append(
            f'    {{"{name}", {array}, sizeof({array}), true, 0x{int.from_bytes(entry.card_id, "big"):x}ULL, '
            f"{{{', '.join(map(str, start))}}}, {{{', '.join(map(str, end))}}}}},"
        )
    return body + "\ninline constexpr CredentialPageCase kCardPages[] = {\n" + "\n".join(rows) + "\n};\n"


def settings_vectors() -> str:
    body = ""
    body += c_array("kAutoLockQuery", cmd.payload_auto_lock_search())
    body += c_array("kAutoLockSet300", cmd.payload_auto_lock_set(300))
    auto_lock_data = bytes([0x5A, 0x01]) + (30).to_bytes(2, "big") + (5).to_bytes(2, "big") + (900).to_bytes(2, "big")
    seconds, battery = cmd.parse_auto_lock_response(success(0x36, auto_lock_data))
    limits = cmd.parse_auto_lock_limits_response(success(0x36, auto_lock_data))
    body += c_array("kAutoLockReply", auto_lock_data)
    body += c_scalar("uint16_t", "kAutoLockSeconds", seconds)
    body += c_scalar("int", "kAutoLockBattery", battery or 0)
    body += c_scalar("uint16_t", "kAutoLockMin", limits.min_allowed)
    body += c_scalar("uint16_t", "kAutoLockMax", limits.max_allowed)
    body += c_array("kSoundQuery", cmd.payload_get_lock_sound())
    body += c_array("kSoundOn", cmd.payload_set_lock_sound(enabled=True))
    body += c_array("kSoundOff", cmd.payload_set_lock_sound(enabled=False))
    body += c_array("kSoundVolume3", cmd.payload_set_lock_volume(3))
    for name, data in [("WithVolume", bytes([0x5A, 0x01, 0x01, 0x05])), ("WithoutVolume", bytes([0x5A, 0x01, 0x00]))]:
        sound = cmd.parse_lock_sound_response(success(0x62, data))
        body += c_array(f"kSoundReply{name}", data)
        body += f"inline constexpr bool kSoundReply{name}Enabled = {c_bool(sound.enabled)};\n"
        body += c_scalar("uint8_t", f"kSoundReply{name}Volume", 0 if sound.volume is None else int(sound.volume))
    return body


def log_vectors() -> str:
    body = ""
    body += c_array("kLogRequestNew", cmd.payload_operate_log_request())
    body += c_array("kLogRequest5", cmd.payload_operate_log_request(5))
    data = log_page_data()
    entries, sequence = cmd.parse_operate_log_response(success(0x25, data))
    assert len(entries) == len(LOG_RECORDS)
    body += c_array("kLogPage", data)
    body += c_scalar("uint16_t", "kLogPageSequence", sequence)
    body += (
        "struct LogCase {\n    const char* name;\n    uint16_t recordNumber;\n    uint8_t type;\n"
        "    uint16_t time[6];\n    uint8_t battery;\n    uint32_t uid;\n    uint32_t recordId;\n"
        "    const char* credential;\n    const char* newCredential;\n    int keyId;\n    int accessoryBattery;\n};\n\n"
    )
    rows = []
    for (name, record_type, _tail), entry in zip(LOG_RECORDS, entries, strict=True):
        assert int(entry.record_type) == record_type
        time = date_fields(entry.operate_date, (0, 0, 0, 0, 0, 0))
        rows.append(
            f'    {{"{name}", {entry.record_number}, {record_type}, {{{", ".join(map(str, time))}}}, '
            f"{entry.lock_battery}, {entry.uid or 0}, {entry.record_id or 0}, "
            f'"{entry.password or ""}", "{entry.new_password or ""}", {c_optional(entry.key_id)}, '
            f"{c_optional(entry.accessory_battery)}}},"
        )
    body += "inline constexpr LogCase kLogCases[] = {\n" + "\n".join(rows) + "\n};\n\n"
    truncated = (3).to_bytes(2, "big") + (1).to_bytes(2, "big") + bytes([0x05, 0x99])
    truncated_entries, truncated_sequence = cmd.parse_operate_log_response(success(0x25, truncated))
    assert truncated_entries == [] and truncated_sequence == 1
    body += c_array("kLogPageTruncated", truncated)
    return body


def event_vectors() -> str:
    body = ""
    state_push = bytes([0x5A, 0x01, 0x00])
    event = LockEvent.from_payload(0x14, cmd.RESPONSE_SUCCESS, state_push)
    assert event.lock_state == LockState.UNLOCKED
    body += c_array("kStatePush", state_push)
    body += c_scalar("int", "kStatePushBattery", event.battery or 0)
    body += c_scalar("int", "kStatePushState", int(event.lock_state))
    log_push = bytes([0x5A]) + (0).to_bytes(4, "big") + (42).to_bytes(4, "big") + bytes([25, 11, 7, 14, 0, 5])
    event = LockEvent.from_payload(0x14, cmd.RESPONSE_SUCCESS, log_push)
    assert event.timestamp is not None
    body += c_array("kLogPush", log_push)
    body += c_scalar("uint32_t", "kLogPushUid", event.uid or 0)
    body += c_scalar("uint32_t", "kLogPushRecordId", event.record_id or 0)
    stamp = event.timestamp
    fields = (stamp.year, stamp.month, stamp.day, stamp.hour, stamp.minute, stamp.second)
    body += f"inline constexpr uint16_t kLogPushTime[] = {{{', '.join(map(str, fields))}}};\n"
    return body


def epoch_vectors() -> str:
    body = (
        "struct EpochCase {\n    int64_t seconds;\n    uint16_t year;\n    uint8_t month;\n    uint8_t day;\n"
        "    uint8_t hour;\n    uint8_t minute;\n    uint8_t second;\n};\n\n"
    )
    rows = []
    for seconds in EPOCH_SECONDS:
        civil = dt.datetime.fromtimestamp(seconds, dt.UTC)
        rows.append(
            f"    {{{seconds}, {civil.year}, {civil.month}, {civil.day}, {civil.hour}, {civil.minute}, {civil.second}}},"
        )
    return body + "inline constexpr EpochCase kEpochCases[] = {\n" + "\n".join(rows) + "\n};\n"


COMMAND_SECTIONS = (
    handshake_vectors,
    status_vectors,
    feature_vectors,
    device_info_vectors,
    passcode_vectors,
    credential_vectors,
    settings_vectors,
    log_vectors,
    event_vectors,
    epoch_vectors,
)


def command_header() -> str:
    return header("command", "\n".join(section() for section in COMMAND_SECTIONS))


def main() -> None:
    frames = frame_cases()
    outputs = {
        "crc_vectors.h": crc_header(frames),
        "aes_vectors.h": aes_header(),
        "frame_vectors.h": frame_header(frames),
        "advert_vectors.h": advert_header(),
        "codec_vectors.h": codec_header(),
        "command_vectors.h": command_header(),
    }
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    for file_name, text in outputs.items():
        (OUT_DIR / file_name).write_text(text)
        print(f"wrote {OUT_DIR / file_name}")


if __name__ == "__main__":
    main()
