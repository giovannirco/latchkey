<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# TTLock Bluetooth LE protocol, as Latchkey implements it

These notes describe the part of the TTLock protocol that `components/ttlock` implements, for V3 locks (protocol type 5 and later). The code is a C++ port of [kind3r/ttlock-sdk-js](https://github.com/kind3r/ttlock-sdk-js), cross-checked against [roquerodrigo/ttlock-ble](https://github.com/roquerodrigo/ttlock-ble); the host tests in `test/` run it against vectors generated from both. What has been confirmed on real locks is listed under [Verified on hardware](#verified-on-hardware).

Command names are kind3r's `CommandType` constants without the `COMM_` prefix, spelled as kind3r spells them: `SEARCHE_DEVICE_FEATURE` and `GET_ALARM_ERRCORD_OR_OPERATION_FINISHED` are its constant names, misspellings included.

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
5. `SEARCHE_DEVICE_FEATURE` (`0x01`): the feature bits.
6. Settings reads, each one only when the lock reports the feature, a lock error tolerated: `SWITCH` (`0x68`) for the reset button, tamper alert or privacy lock, `AUDIO_MANAGE` (`0x62`), `SHOW_PASSWORD` (`0x59`), `AUTO_LOCK_MANAGE` (`0x36`) and `GET_ADMIN_CODE` (`0x65`).
7. `SET_ADMIN_KEYBOARD_PWD` (`0x53`) with a random 7-digit admin passcode, stored before it is sent.
8. `INIT_PASSWORDS` (`0x31`): ten random code and secret seeds and the year, the base of the lock's offline passcodes.
9. `CONTROL_REMOTE_UNLOCK` (`0x37`) query, when the lock reports `config_gateway_unlock`.
10. `GET_ALARM_ERRCORD_OR_OPERATION_FINISHED` (`0x57`), which ends the pairing.

kind3r's `initLock` has the switch read, the lamp read and `INIT_PASSWORDS` commented out, and keeps the admin passcode a lock reports through `GET_ADMIN_CODE`; Latchkey sends the switch read and `INIT_PASSWORDS`, skips the lamp and always sets a new random admin passcode.

## Admin login, lock and unlock

- Admin commands start with `CHECK_ADMIN` (`0x41`: `adminPs`, the lock flag position and uid 0), whose reply carries a random `psFromLock`, then `CHECK_RANDOM` (`0x30`) with `psFromLock + unlockKey`, wrapping at 32 bits.
- Lock and unlock start with `CHECK_USER_TIME` (`0x55`: a validity window from 2000-01-31 14:00 to 2099-11-30 14:00, the lock flag position and uid 0), which also returns `psFromLock`, then `UNLOCK` (`0x47`) or `FUNCTION_LOCK` (`0x58`) with `psFromLock + unlockKey` and the UTC time. The reply carries the battery level and, when present, the operation record (uid, record id, time).
- Commands that send a time refuse to run until the board's clock has been set (SNTP or `system.time.set` over USB) and never send a time before 2024.

## Commands

Feature bits come from `SEARCHE_DEVICE_FEATURE`: after one leading byte, one or two big-endian 32-bit words, the first for bits 0 to 31 and the second for bits 32 to 63. A gated command is refused with `unsupported`, with no Bluetooth traffic, when the lock does not report its bit. The table lists every command `components/ttlock` sends.

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
| `0x65` | `GET_ADMIN_CODE` | read during pairing, and after the admin login to show the keypad admin passcode | `get_admin_code` (18) |
| `0x66` | `CONFIGURE_PASSAGE_MODE` | passage mode periods: list, add, delete, clear | `passage_mode` (22) |
| `0x68` | `SWITCH` | reset button (item `0x02`), tamper alert (`0x01`), privacy lock (`0x04`), read and set | `reset_button` (29), `tamper_alert` (28), `privacy_lock` (30), per item |
| `0x70` | `CYCLIC_CMD` | weekly time windows of IC cards and fingerprints | `cyclic_ic_or_finger_print` (34), plus `ic` (1) or `finger_print` (2) |
| `0x90` | `READ_DEVICE_INFO` | model, hardware, firmware and manufacture date | none |

Passcodes have 4 to 9 digits and are permanent, limited to a number of uses, or valid for a period. Cyclic passcodes can be listed and deleted but not added or changed. The lock also reports bits that have no command here because no reference implementation exists to port: `freeze_lock` (11), `lamp` (25), `dead_lock` (32), `unlock_direction` (36) and `cyclic_password` (12) among them. Latchkey offers no control for those.

`SWITCH` writes send `02`, the item as a big-endian 32-bit word, then the same word to enable or zero to disable; reads send `01` and get the state word after two bytes. The read follows kind3r's `GetSwitchStateCommand`; the write layout was learned by reading bazuchan's esphome-ttlock (that project has no license, and no code was taken from it). Until the table below confirms them on a real lock, the privacy lock and tamper alert items are experimental, and the hardening step that disables the reset button waits for disabling and then re-enabling it to be confirmed. Reads of all three items are verified on the lock below; writes are not. bazuchan sends `1` or `0` as the value word where Latchkey sends the item's own bit, and a lock that took the value word as the whole switch state would clear the other items, the reset button among them, so no SWITCH write has been sent to that lock yet. Over the web, `lock.resetButton.set` waits for the board's button either way, and turning the button off answers `backup_required` until the encrypted key backup exists.

## Operation log

`GET_OPERATE_LOG` (`0x25`) takes a big-endian slot number. The verified lock answers one record per page; the page names the next slot to ask, and the record's number is that slot minus one. A record of a passcode added over Bluetooth (type 93) takes two slots: asking its first slot answers it under the second number. Asking a slot past the newest record answers an empty page or record 0 again, and slots of about 3000 and up, `0xFFFF` included, answer the record read last or an empty page: on that lock `0xFFFF` does not follow a "since last read" cursor. Latchkey therefore keeps its own cursor per lock in NVS. The first time, it finds the end by bisection (16 reads, on the rule that every answer past the end carries a lower record number or none) and judges none of the records already there. After that it reads on from the cursor after every connection it makes for another reason and every six hours and a quarter, at most eight pages at a time. What the lock does once its log is full is unverified: a record numbered below the cursor but newer than the newest one read is taken as the log starting over.

App unlocks (type 1) and app locks (type 26) carry uid 0 and a record id equal to the UTC seconds the board put in its `UNLOCK` or `FUNCTION_LOCK` frame; the unlock reply carries the same id. Log times are the lock's local clock, read with the offset Latchkey last set that clock with. Latchkey matches its own unlocks by time only, 120 s either side of the request and one log record per request, so a second app unlock inside that window still raises an alert; matching by record id would be stricter. An app or gateway unlock nobody explains, and a forced opening (type 29), raise `lock.alert`. Passcode records carry the code typed, so log entries leave the board as `{seq, time, type, battery}` only.

The lock's clock carries no time zone. Latchkey stores the offset it set the clock with and sets the clock again when the board's offset changes (a new time zone or a daylight-saving change), reading the log first so that older records keep their offset, and once a day against drift.

## Verified on hardware

Filled in by the hardware-in-the-loop tests (`tools/hil/`) as they run against real locks.

| Lock model | Lock firmware | Protocol (type.sub-version) | Feature bits | Verified commands | Date |
|---|---|---|---|---|---|
| SN9325-SN139-T2-T16-INT_PV53 (keypad, fingerprint and card lock; Bluetooth name `A260BLE_…`) | 6.4.37.240425 (hardware 1.1) | 5.3 (device info reports 3.1) | passcode, ic, finger_print, auto_lock, passcode_with_delete_function, firmware_setting, modify_passcode_function, manual_lock, cyclic_password, magnetometer, config_gateway_unlock, audio_management, get_admin_code, hotel_lock, passage_mode, wireless_keyboard, tamper_alert, reset_button, privacy_lock, cyclic_ic_or_finger_print, telink_chip, cyclic_passcode_can_recovery, wireless_key_fob, accessory_battery | pairing from an ESP32-S3 (through the web UI), status and battery, device info, feature bits, unlock and lock with their events, two requests in order, time sync, keys surviving a board reboot, scan, a lock job over HTTPS; passcode list, add, modify (code and window) and delete for permanent, timed and one-time passcodes; reading the admin passcode (`0x65`) and writing it (`0x53`, with the code it holds); the start of a fingerprint and a card enrolment, and their lists; auto-lock, sound and passage-mode reads and writes, the three SWITCH reads, the operation log page by page and setting the clock after a time-zone change; every reply passed the CRC check | 2026-11-08 |

Observed on that lock:

- A factory-fresh lock advertises only after a keypad touch, for roughly 10 to 15 s; pairing has to start inside that window.
- Once paired, an untouched lock advertises in bursts: in one minute it was seen at 2 s and 9 s, then not for 29 s, then every 4 to 5 s. A command can wait up to about 30 s for the lock to become reachable.
- Once paired, its adverts carry the dormant flag (`0x10`), so they never say whether it is locked: after a reboot the board knows the state only after a command, a status read or a push while connected. Their battery byte still matches the status reply (57 % in both).
- Its Bluetooth address is public (address type 0).
- Right after pairing its passcode list (`0x07`) was empty: the keypad admin passcode is not listed, and there is no factory passcode such as 123456. A passcode added with `0x03` is listed at once with the window the board sent, for timed and one-time passcodes alike, and a modify that changes the code lists the new code.
- `GET_ADMIN_CODE` after the admin login answers `[battery][length][ASCII digits]`, nine bytes for a seven-digit code with nothing after it, and the digits are the code the board set at pairing with `SET_ADMIN_KEYBOARD_PWD`. Setting the code it already holds is accepted.
- A fingerprint enrolment without a finger enters add mode (status `0x02`), then the lock ends it by itself with a failure reply carrying `0xe4`, 8 to 15 s after the request. A card enrolment without a card enters add mode and then sends nothing; the board stops waiting after 10 s. In both cases the next command was answered within a few seconds, without an `in_setting` refusal.
- By hand at the lock, with the board's web UI: `GET_ADMIN_CODE` read the admin passcode set at pairing, matching the board's copy; a nine-digit admin passcode then set with `SET_ADMIN_KEYBOARD_PWD` opens the lock from the keypad, and a later `GET_ADMIN_CODE` (the HIL suite) answered eleven bytes, `[battery][9][nine digits]`, matching the board's new copy; a chosen six-digit passcode and a random one added with `0x03` open it; a fingerprint enrolment (four scans) and an IC card enrolment with a real finger and card completed, and both open the lock.
- Settings as found: auto-lock 5 s (range 1 to 900 s), sound on at volume 5 of 5, no passage windows, and the reset button, privacy lock and tamper alert switches all on. An auto-lock delay and a sound change written with `0x36` and `0x62` read back as sent, and a weekly passage window added with `0x66` was listed at once with the window sent and deleted again; each setting was put back as found.
- Its log held about 170 records after a day of tests: app unlocks and locks (1, 26), keypad passcode unlocks (4), wrong passcodes (7), a card unlock (17), a super admin passcode unlock (92), and passcodes added, changed and deleted over Bluetooth (93, 5, 6). An unlock through Latchkey was logged within a second of the request, followed by the lock that ended the test.
- Anti-peeping: by hand, a valid six-digit code followed by one to three more digits opens the lock, and a different six-digit code does not; digits typed before a code were not tried, so the rule may be wider (the code anywhere inside the digits typed). Either way someone watching cannot tell the code from the digits entered, and a short code is found by chance more easily. Prefer 7 to 9 digits that are not a run or one repeated digit; the board warns about those, without refusing them.


## Credits

- [kind3r/ttlock-sdk-js](https://github.com/kind3r/ttlock-sdk-js), GPL-3.0: the primary reference. The frame codec, the advertisement parser, the command builders and parsers and the session flows are ported from it, with credit in each ported file.
- [roquerodrigo/ttlock-ble](https://github.com/roquerodrigo/ttlock-ble), MIT: the second reference, used to cross-check commands and frames and to generate test vectors. The CRC table quirk, the dormant advertisement bit, the passcode and card listing layouts, the feature words, the operation-log record types, the push events and matching replies on the echoed command follow its code.
- [kokke/tiny-AES-c](https://github.com/kokke/tiny-AES-c), public domain: the AES implementation, vendored unmodified.

`NOTICE` has the license terms.
