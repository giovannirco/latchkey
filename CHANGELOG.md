<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Changelog

Notable changes to Latchkey, in the format of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/). A release has a heading `## [x.y.z] - YYYY-MM-DD`: the release workflow publishes that section as the GitHub Release notes and stops when the tag has no section.

## [Unreleased]

### Added

- Lock settings from the board, each checked against the lock's feature bits before any Bluetooth: `lock.autolock.get`/`set`, `lock.passage.list`/`add`/`delete`/`clear` (weekly windows in the lock's local time), `lock.sound.get`/`set`, `lock.resetButton.get`, `lock.privacyLock.get` and `lock.tamperAlert.get`. All three switches are read-only until their write layout is verified on hardware; writes refuse with `unverified` before any Bluetooth frame or button prompt. Turning the reset button off without a key backup refuses first with `backup_required`.
- The lock's operation log: `lock.log.fetch` reads new records from a cursor the board keeps per lock in NVS (found by bisection the first time) and answers the newest entries, or those after `since`, as `{entries, last, more}`; passcodes the lock records in its log never leave the board.
- Unlock alerts: the board reads each lock's log after the connections it makes anyway, and about every six hours otherwise, and raises `lock.alert {lock, method, time, seq, type}` with an audit entry (source `board`) for every unlock from an app it did not make and every forced opening. The web UI shows a notice that stays until dismissed.
- The lock's clock follows the board's time zone: the board sets it again after a time-zone change or a daylight-saving change, and once a day against drift.
- Web UI: reset button, privacy lock and tamper alert shown read-only, features the board does not use listed apart, and the log reads on until it has every new entry.
- `tools/hil/test_lock_settings.py` and `tools/hil/test_lock_log.py`, run on the owner's lock.

### Changed

- The remote unlock control is gone from the web UI and the mock: the board does not implement it, and the lock's `config_gateway_unlock` bit is listed as reported but not used.

### Fixed

- Unlock alerts match the lock's returned record id before using a time window, and each log page advances its cursor and consumes matching unlocks together.
- Clock changes wait until the log backlog is read. Routine clock corrections preserve the preceding UTC offset, and old records across the most recent offset change keep their original times without raising duplicate alerts.

## [0.2.0] - 2026-11-08

### Added

- Passcodes on the lock from the board: `lock.passcodes.list`, `add`, `update`, `delete` and `clear`, with ids derived from the lock's key, names and a managed flag kept on the board, and codes shown once when added and never listed. Duplicates and the admin passcode are refused before anything is sent; cyclic passcodes answer `unsupported`.
- Fingerprints and IC cards: `lock.fingerprints.*` and `lock.cards.*` list, enrol with `enroll.progress` events, set validity with an optional weekly window where the lock supports it, delete and clear.
- The keypad's super admin passcode: `locks.pair` takes an optional `adminPasscode`, `lock.adminPasscode.set` changes it and `lock.adminPasscode.get` reads it back from the lock, both after a press of the board's button from the web; `lock.adminPasscode.raw` (USB only) returns the lock's raw reply.
- Pairing stores the offline-code seed table before it goes out, and a lock that answers as another lock type than its advert fails with a message naming both.
- Web UI: an optional super admin passcode when adding a lock, Show and Change admin passcode on the lock's settings, and weekly windows for fingerprints and cards; cyclic passcodes are no longer offered.
- `tools/hil/test_lock_features.py`, run on a real lock; the lock's behaviour is recorded in `docs/protocol.md`.

- An NVS reserve for pairing a lock and the audit ring: writes that would grow the board's names into it answer `storage_full`; `system.info.nvs.reservedEntries` reports it.
- Lists render straight to JSON text and answer `too_large` instead of running out of memory on boards with little free heap.
- Easy codes (a run or one repeated digit) are taken with a warning, and the passcode page explains the lock's anti-peeping behaviour.
- Web UI: every result `warning` shows until dismissed; fingerprints and cards choose Always, Between dates or a weekly schedule with day toggles and a plain summary; date fields name the time zones; code fields no longer look like passwords to browsers.
- Home Assistant over MQTT, off until configured with `mqtt.set`: plain MQTT over TCP with a retained availability topic and last will, retained discovery configs for each stored lock (lock, battery, last event, Bluetooth link, unlock alert), state, battery and last event after each lock event, a status read after boot and every 6 hours (one lock at a time, only while no web job waits), `LOCK` and `UNLOCK` on each held lock's own `set` topic through the web job queue (one queued command per lock), every command that runs audited with the source `mqtt` and refusals counted into at most one entry a minute per kind, retained commands ignored, the entities of a forgotten lock, a stale lock, an old prefix or broker, and of a factory-reset board removed, and reconnects that wait from 1 s up to 2 min. `mqtt.get` never returns the password and reports `connected` and `problem`; a new host, port or username clears the stored password unless a new one is given. `system.info.stackFree` reports `mqtt` and `mqttClient`.

### Changed

- `lock_error` messages carry the lock's error code in hex.
- A code on the lock and the admin passcode are refused with the same "already in use" answer, a code whose id would collide with another passcode's is refused, and `lock.adminPasscode.set` refuses a user passcode and keeps its candidate unconfirmed until the lock takes it.
- The passcode list no longer carries an `admin` flag.

### Fixed

- `audit.list` renders its page one entry at a time and replies no longer keep their JSON tree while the text is copied: a page of 50 entries, as the web UI's Audit page asks for, took about 34 KB of heap on the classic ESP32 at its peak.

## [0.1.0] - 2026-11-08

### Added

- Pairing and control verified on a real TTLock lock (model SN9325-SN139-T2-T16-INT_PV53, firmware 6.4.37.240425) from an ESP32-S3 through the web UI; the details are in `docs/protocol.md` under Verified on hardware.
- TTLock protocol core (`components/ttlock`), free of ESP-IDF and tested on the host: CRC-8 with the lock's table quirk, AES-128-CBC, frames and their reassembly, advertisements, and the session flows for pairing, lock and unlock, status, device info and feature bits, time sync, passcodes, IC cards and fingerprints with their validity and weekly windows, auto-lock, passage mode, sound, the remote unlock, reset button, privacy lock and tamper alert switches, the passcode display, the operation log and factory reset. Commands a lock does not report in its feature bits answer `unsupported` without touching the radio.
- Firmware foundation for the classic ESP32 (4 MB) and the ESP32-S3 (8 MB): a JSON-lines console over USB serial, claiming the board over USB with Wi-Fi settings and an owner password (PBKDF2-HMAC-SHA256) that returns the TOTP secret once, Wi-Fi with a static address, SNTP time, an audit log in NVS, and two app slots for over-the-air updates.
- Owner web UI in plain HTML, CSS and JavaScript with a hash-based Content-Security-Policy, built and tested against a mock of the board API, and served by the board over HTTPS.
- CI on every push and pull request: source checks, host tests, both firmware builds with the 1.8 MB gate for the classic ESP32, and the web UI suite.
- Release workflow for `v*` tags: factory and OTA images per board with `SHA256SUMS`, a GitHub Release, and the browser flasher on GitHub Pages with the images on the same origin.
- `SECURITY.md`, protocol notes (`docs/protocol.md`) and hardware notes (`docs/hardware.md`).
- Owner login checks on the board: `auth.login` with the owner password and a TOTP code (one step of drift, replayed steps refused, compared in constant time), a login rate limit whose 30 s to 15 min wait survives reboots, and web sessions kept as token hashes in RAM with idle and absolute limits; `auth.logout`, `auth.sessions`, `auth.revoke`, `auth.changePassword` and `auth.rotateTotp`. Over USB a login takes `dryRun` and only checks.
- A time zone setting: `system.timezone.get` and `system.timezone.set` with a POSIX TZ string; the lock is given local time, and `system.info` reports `timezone` and `localTime`.
- HTTPS on the board: a self-signed EC P-256 certificate made on the board the first time it has an address, valid from 2024-01-01 with no expiry date (fingerprint in `system.info.certFingerprint`, renewed by a factory reset), the web UI and `POST /api/rpc` on port 443, a redirect on port 80, the page's Content-Security-Policy and the other security headers on every response, JSON error bodies, the `lk_session` cookie, and refusals for a `Host` or `Origin` other than the board's own address, a body that is not JSON, and requests over 8 KiB or 256 JSON values.
- Live events over a WebSocket at `/api/events`, opened only with a valid session cookie and closed when the session ends.
- From the web, lock methods and button-gated methods answer `{"job": id}` and end with `job.done` to the session that asked; button-gated ones check their parameters first, then wait up to 30 s for a press of the board's button (`confirm.required`, `confirm.result`, `confirm_timeout`), which replaces their refusal with `forbidden`. A job of a session that has ended runs nothing and ends `unauthorized`. After the press, a web `locks.pair` without `wait` waits 120 s for the lock to advertise (30 s over USB), time to walk from the board to the lock.
- ESP32-S3 images read the confirmation button on GPIO0, the button of the M5Stack StampS3; an AtomS3 needs a build with `LATCHKEY_BUTTON_GPIO=41`.
