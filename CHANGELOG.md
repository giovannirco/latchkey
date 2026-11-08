<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Changelog

Notable changes to Latchkey, in the format of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/). A release has a heading `## [x.y.z] - YYYY-MM-DD`: the release workflow publishes that section as the GitHub Release notes and stops when the tag has no section.

## [Unreleased]

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
