<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Changelog

Notable changes to Latchkey, in the format of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/). A release has a heading `## [x.y.z] - YYYY-MM-DD`: the release workflow publishes that section as the GitHub Release notes and stops when the tag has no section.

## [Unreleased]

### Added

- TTLock protocol core (`components/ttlock`), free of ESP-IDF and tested on the host: CRC-8 with the lock's table quirk, AES-128-CBC, frames and their reassembly, advertisements, and the session flows for pairing, lock and unlock, status, device info and feature bits, time sync, passcodes, IC cards and fingerprints with their validity and weekly windows, auto-lock, passage mode, sound, the remote unlock, reset button, privacy lock and tamper alert switches, the passcode display, the operation log and factory reset. Commands a lock does not report in its feature bits answer `unsupported` without touching the radio.
- Firmware foundation for the classic ESP32 (4 MB) and the ESP32-S3 (8 MB): a JSON-lines console over USB serial, claiming the board over USB with Wi-Fi settings and an owner password (PBKDF2-HMAC-SHA256) that returns the TOTP secret once, Wi-Fi with a static address, SNTP time, an audit log in NVS, and two app slots for over-the-air updates.
- Owner web UI in plain HTML, CSS and JavaScript with a hash-based Content-Security-Policy, built and tested against a mock of the board API; the firmware does not serve it yet.
- CI on every push and pull request: source checks, host tests, both firmware builds with the 1.8 MB gate for the classic ESP32, and the web UI suite.
- Release workflow for `v*` tags: factory and OTA images per board with `SHA256SUMS`, a GitHub Release, and the browser flasher on GitHub Pages with the images on the same origin.
- `SECURITY.md`, protocol notes (`docs/protocol.md`) and hardware notes (`docs/hardware.md`).
