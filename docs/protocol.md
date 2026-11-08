<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# TTLock Bluetooth LE protocol, as Latchkey implements it

These notes describe the part of the TTLock protocol that `components/ttlock` implements, for V3 locks (protocol type 5 and later). The code is a C++ port of [kind3r/ttlock-sdk-js](https://github.com/kind3r/ttlock-sdk-js), cross-checked against [roquerodrigo/ttlock-ble](https://github.com/roquerodrigo/ttlock-ble); the host tests in `test/` run it against vectors generated from both. What has been confirmed on real locks is listed under [Verified on hardware](#verified-on-hardware).

## Transport

- GATT service `0x1910`. The board writes requests to characteristic `0xFFF2` and receives replies and events as notifications on `0xFFF4`.
- A frame goes out in writes of at most 20 bytes (`chunk()`). Notifications are concatenated (`Reassembler`) until the buffer ends with `0D 0A` and holds the length its header declares; a buffer that grows past 512 bytes is dropped.
- A lock accepts one Bluetooth connection at a time.
- A factory-fresh lock sleeps: it becomes discoverable for a few seconds after its keypad is touched (kind3r's notes give 10 to 15 s).

## Advertisement

`parseAdvert()` reads the manufacturer-specific data, including the two bytes that sit where a company id would be.

- When the data starts with `05 03` (protocol type 5, sub-version 3) the compact layout applies: protocol type at byte 0, sub-version at 1, scene at 2, flags at 3, battery at 4. Otherwise the protocol type is at byte 4, the sub-version at 5, the scene at 7, the flags at 8 and the battery at 9.
- The last 6 bytes are the lock's MAC address, least significant byte first.
- Flags: `0x04` set means the lock is in setting mode, that is, not paired; `0x10` set means dormant, and the advert then carries no lock state; otherwise `0x01` set means unlocked.
- Data shorter than 15 bytes, locks in firmware-update mode (type 18 version 25, or `FF FF`), V2S locks (type 5 version 1) and older protocol types are ignored.

## Frame

| Offset | Size | Field |
|---:|---:|---|
| 0 | 2 | `7F 5A` |
| 2 | 1 | protocol type (5 for V3) |
| 3 | 1 | protocol sub-version |
| 4 | 1 | scene |
| 5 | 2 | group id, big-endian |
| 7 | 2 | organization id, big-endian |
| 9 | 1 | command |
| 10 | 1 | `0xAA`: the payload is encrypted |
| 11 | 1 | payload length *n* |
| 12 | *n* | payload, AES-128-CBC ciphertext (absent when *n* is 0) |
| 12 + *n* | 1 | CRC-8 of bytes 0 to 11 + *n* |
| 13 + *n* | 2 | `0D 0A` |

- Requests to a V3 lock carry the header `05 03 01 00 01 00 01` (type 5, sub-version 3, scene 1, group 1, organization 1), the V3 entry of kind3r's lock-type table.
- The plaintext of a request is at most 239 bytes, so the ciphertext fits the one-byte length.
- Replies come in frames whose command byte is `0x54`. Their plaintext starts with the command being answered, then a status byte (`0x01` for success), then the data. On failure the first data byte is the lock's error code. A frame that does not answer the command in progress is an event pushed by the lock and goes to the event sink.
- Frames with protocol type 1 to 4 (V2 locks and older, which use an XOR codec instead of AES) are refused as unsupported.

## CRC

CRC-8 Dallas/Maxim: reflected polynomial `0x8C`, initial value 0, no final XOR, computed with a 256-entry table. One entry differs from the textbook table: entry `0x21` is `0x07` instead of `0x7D`. Real locks compute their CRC with that table: the frames kind3r logged as bad-CRC replies match it, and ttlock-ble uses it. The plain `crc8("123456789") == 0xA1` check value does not touch that entry. A reply to the command in progress that fails the CRC ends the command with `bad_crc`; other frames with a bad CRC are dropped.

## Encryption

- AES-128-CBC with the key itself as the IV and PKCS#7 padding. Empty payloads are not encrypted.
- Before pairing, every lock uses the same public default key: `98 76 23 E8 A9 23 A1 BB 3D 9E 7D 03 78 12 45 88`.
- During pairing the lock sends its own key in the reply to `GET_AES_KEY`, encrypted with the default key; every later frame uses the lock's key. Anyone who records the Bluetooth traffic of a pairing can therefore learn that key.
- There is no message authentication beyond the CRC and the padding check, and identical plaintexts encrypt identically.

## Pairing

`Session::pair()` follows kind3r's `initLock`:

1. `INITIALIZATION` (`0x45`), no payload; any reply with a good CRC.
2. `GET_AES_KEY` (`0x19`) with `SCIENER`; the reply carries the lock's 16-byte key.
3. `ADD_ADMIN` (`0x56`) with two random numbers from 1 to 999,999,999, `adminPs` and `unlockKey`, plus `SCIENER`, which the lock echoes. The keys are stored right after this step, so a link that drops later still leaves keys that can reset the lock.
4. `TIME_CALIBRATE` (`0x43`) with the board's local time; a timeout or a lock error does not stop the pairing.
5. `SEARCH_DEVICE_FEATURE` (`0x01`): the feature bits.
6. Settings reads, each one only when the lock reports the feature, a lock error tolerated: `COMM_SWITCH` (`0x68`) for the reset button, tamper alert or privacy lock, `AUDIO_MANAGE` (`0x62`), `SHOW_PASSWORD` (`0x59`), `AUTO_LOCK_MANAGE` (`0x36`) and `GET_ADMIN_CODE` (`0x65`).
7. `SET_ADMIN_KEYBOARD_PWD` (`0x53`) with a random 7-digit admin passcode, stored before it is sent.
8. `INIT_PASSWORDS` (`0x31`): ten random code and secret seeds and the year, the base of the lock's offline passcodes.
9. `CONTROL_REMOTE_UNLOCK` (`0x37`) query, when the lock reports `config_gateway_unlock`.
10. `OPERATE_FINISHED` (`0x57`).

kind3r's `initLock` has the switch read, the lamp read and `INIT_PASSWORDS` commented out, and keeps the admin passcode a lock reports through `GET_ADMIN_CODE`; Latchkey sends the switch read and `INIT_PASSWORDS`, skips the lamp and always sets a new random admin passcode.

## Admin login, lock and unlock

- Admin commands start with `CHECK_ADMIN` (`0x41`: `adminPs`, the lock flag position and uid 0), whose reply carries a random `psFromLock`, then `CHECK_RANDOM` (`0x30`) with `psFromLock + unlockKey`, wrapping at 32 bits.
- Lock and unlock start with `CHECK_USER_TIME` (`0x55`: a validity window from 2000-01-31 14:00 to 2099-11-30 14:00, the lock flag position and uid 0), which also returns `psFromLock`, then `UNLOCK` (`0x47`) or `LOCK` (`0x58`) with `psFromLock + unlockKey` and the UTC time. The reply carries the battery level and, when present, the operation record (uid, record id, time).
- Commands that send a time refuse to run until the board's clock has been set (SNTP or `system.time.set` over USB) and never send a time before 2024.

## Commands

Feature bits come from `SEARCH_DEVICE_FEATURE`: after one leading byte, one or two big-endian 32-bit words, the first for bits 0 to 31 and the second for bits 32 to 63. A gated command is refused with `unsupported`, with no Bluetooth traffic, when the lock does not report its bit. The table lists every command `components/ttlock` sends; names are kind3r's `CommandType` without the `COMM_` prefix.

| Opcode | Name | Used for | Feature bit |
|---|---|---|---|
| `0x01` | `SEARCHE_DEVICE_FEATURE` | feature bits (pairing, `lock.features`) | none |
| `0x03` | `MANAGE_KEYBOARD_PASSWORD` | add, update, delete and clear passcodes | `passcode` (0) |
| `0x05` | `IC_MANAGE` | list, enrol, set validity, delete and clear IC cards | `ic` (1) |
| `0x06` | `FR_MANAGE` | list, enrol, set validity, delete and clear fingerprints | `finger_print` (2) |
| `0x07` | `PWD_LIST` | list passcodes | `passcode` (0) |
| `0x14` | `SEARCH_BICYCLE_STATUS` | lock state and battery | none |
| `0x19` | `GET_AES_KEY` | pairing | none |
| `0x25` | `GET_OPERATE_LOG` | operation log, page by page | none |
| `0x30` | `CHECK_RANDOM` | admin login, second step | none |
| `0x31` | `INIT_PASSWORDS` | pairing | none |
| `0x36` | `AUTO_LOCK_MANAGE` | auto-lock delay, read and set | `auto_lock` (4) |
| `0x37` | `CONTROL_REMOTE_UNLOCK` | remote unlock switch, read and set | `config_gateway_unlock` (14) |
| `0x41` | `CHECK_ADMIN` | admin login, first step | none |
| `0x43` | `TIME_CALIBRATE` | pairing, `lock.time.sync` | none |
| `0x45` | `INITIALIZATION` | pairing | none |
| `0x47` | `UNLOCK` | unlock | none |
| `0x52` | `RESET_LOCK` | factory reset of the lock | none |
| `0x53` | `SET_ADMIN_KEYBOARD_PWD` | admin passcode: pairing, and later changes | `passcode` (0), outside pairing |
| `0x55` | `CHECK_USER_TIME` | lock and unlock, first step | none |
| `0x56` | `ADD_ADMIN` | pairing | none |
| `0x57` | `GET_ALARM_ERRCORD_OR_OPERATION_FINISHED` | end of pairing | none |
| `0x58` | `FUNCTION_LOCK` | lock | none |
| `0x59` | `SHOW_PASSWORD` | whether the keypad screen shows the passcode, read and set | `password_display_or_hide` (9) |
| `0x62` | `AUDIO_MANAGE` | sound on or off, volume 1 to 5 | `audio_management` (15) |
| `0x65` | `GET_ADMIN_CODE` | read during pairing | `get_admin_code` (18) |
| `0x66` | `CONFIGURE_PASSAGE_MODE` | passage mode periods: list, add, delete, clear | `passage_mode` (22) |
| `0x68` | `SWITCH` | reset button (item `0x02`), tamper alert (`0x01`), privacy lock (`0x04`), read and set | `reset_button` (29), `tamper_alert` (28), `privacy_lock` (30), per item |
| `0x70` | `CYCLIC_CMD` | weekly time windows of IC cards and fingerprints | `cyclic_ic_or_finger_print` (34), plus `ic` (1) or `finger_print` (2) |
| `0x90` | `READ_DEVICE_INFO` | model, hardware, firmware and manufacture date | none |

Passcodes have 4 to 9 digits and are permanent, limited to a number of uses, or valid for a period. Cyclic passcodes can be listed and deleted but not added or changed. The lock also reports bits that have no command here because no reference implementation exists to port: `freeze_lock` (11), `lamp` (25), `dead_lock` (32), `unlock_direction` (36) and `cyclic_password` (12) among them. Latchkey offers no control for those.

`SWITCH` writes send `02`, the item as a big-endian 32-bit word, then the same word to enable or zero to disable; reads send `01` and get the state word after two bytes. The read follows kind3r's `GetSwitchStateCommand`; the write layout was learned by reading bazuchan's esphome-ttlock (that project has no license, and no code was taken from it). Until the table below confirms them on a real lock, the privacy lock and tamper alert items are experimental, and the hardening step that disables the reset button waits for disabling and then re-enabling it to be confirmed.

## Verified on hardware

Filled in by the hardware-in-the-loop tests (`tools/hil/`) as they run against real locks.

| Lock model | Lock firmware | Protocol (type.sub-version) | Feature bits | Verified commands | Date |
|---|---|---|---|---|---|
| | | | | | |

## Credits

- [kind3r/ttlock-sdk-js](https://github.com/kind3r/ttlock-sdk-js), GPL-3.0: the primary reference. The frame codec, the advertisement parser, the command builders and parsers and the session flows are ported from it, with credit in each ported file.
- [roquerodrigo/ttlock-ble](https://github.com/roquerodrigo/ttlock-ble), MIT: the second reference, used to cross-check commands and frames and to generate test vectors. The CRC table quirk, the dormant advertisement bit, the passcode and card listing layouts, the feature words, the operation-log record types, the push events and matching replies on the echoed command follow its code.
- [kokke/tiny-AES-c](https://github.com/kokke/tiny-AES-c), public domain: the AES implementation, vendored unmodified.

`NOTICE` has the license terms.
