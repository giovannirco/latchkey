<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# v1.0.0 readiness

This is the checklist for v1.0.0. The latest release is [v0.5.0](https://github.com/giovannirco/latchkey/releases/tag/v0.5.0) (2026-11-09); v1.0.0 is not ready to tag. The roadmap and its discussion are in [#26](https://github.com/giovannirco/latchkey/issues/26); `CHANGELOG.md` lists what each release contains.

## Released

| Release | Contents |
|---|---|
| v0.1.0 | Protocol core, pairing from the board, lock and unlock, the HTTPS web UI, owner login with password and TOTP, button confirmation, audit log, browser flasher. |
| v0.2.0 | Passcodes, fingerprints and IC cards, the keypad's super admin passcode, Home Assistant over MQTT. |
| v0.3.0 | Lock settings, the operation log, persistent unlock alerts, lock clock sync. |
| v0.4.0 | Log lines on the board, syslog shipping, the full Wi-Fi form. |
| v0.5.0 | Encrypted key export/import, pending admin-code recovery, previewed partial hardening with the reset-button step skipped. |

## Required for v1.0.0

| Item | Status |
|---|---|
| Remote-unlock (gateway) control | Not built. The protocol core has `CONTROL_REMOTE_UNLOCK`; the board API, the web UI and their tests are missing. |
| Backup, recovery and hardening on hardware ([#19](https://github.com/giovannirco/latchkey/issues/19)) | Built in v0.5.0 with native and browser tests. On an ESP32-S3 holding the real lock, a USB export and a hardening preview were checked. Unverified: import on a board, a two-board restore, a real hardening run, the web button flow for these, and the classic ESP32's heap during a backup. Mock results in the browser tests are not evidence of recovery on hardware. |
| Final review ([#25](https://github.com/giovannirco/latchkey/issues/25)) | Open: whole-branch review of the required work, CI on the final `main` commit. |

## Unverified on hardware

| Item | Status |
|---|---|
| Switch writes ([#20](https://github.com/giovannirco/latchkey/issues/20)) | Reset button, privacy lock and tamper alert writes refuse before any Bluetooth frame until their layout is proven on a real lock. Full hardening (turning the reset button off) depends on this. |
| Passage readback ([#31](https://github.com/giovannirco/latchkey/issues/31)) | A passage write was acknowledged once and its readback connection then dropped; untraced. |
| Classic ESP32 heap ([#21](https://github.com/giovannirco/latchkey/issues/21)) | One stress run recorded a 27,576-byte minimum heap; later runs passed the 30 KB check. Other review follow-ups are in the same issue. |

## Deferred beyond v1.0.0

| Item | Status |
|---|---|
| Weekly (cyclic) passcode creation and editing ([#22](https://github.com/giovannirco/latchkey/issues/22)) | Not built. Weekly passcodes can be listed and deleted; the command layout for writing their window lacks protocol evidence. Fingerprint and card weekly windows work. |
| Board firmware updates from the web page, with rollback ([#23](https://github.com/giovannirco/latchkey/issues/23)) | Not in any release; paused on branch `feat/ota`. The System page of the web UI shows a Firmware update form, but the board does not serve `/api/ota`. |
| Update and rollback on hardware ([#24](https://github.com/giovannirco/latchkey/issues/24)) | Waits for #23. |
| Rotating OTP keypad codes and per-user unlock attribution ([#37](https://github.com/giovannirco/latchkey/issues/37)) | Not built. |
| Other ideas ([#22](https://github.com/giovannirco/latchkey/issues/22)) | Offline guest codes, metrics, MQTT over TLS, wireless keypad and key fob support. Reported hotel and accessory feature bits have no controls. |

## Checks before tagging

Run the non-device checks from the repository root:

```sh
uvx platformio==6.2.0 test -e native
uvx platformio==6.2.0 run -e esp32 -e esp32s3
sh tools/ui-tests/run.sh
python3 -m unittest discover -s tools/ci -p 'test_*.py'
python3 -m unittest discover -s tools/release -p 'test_*.py'
python3 tools/ci/check_sources.py
git diff --check
```

Optional screenshot checks require `LK_SHOTS_DIR`; otherwise those cases skip. Concurrent Playwright runs need different `LK_UI_PORT` values and separate `--output` directories.

Before tagging v1.0.0: finish the required items, close #25, confirm CI on the final `main` commit, and state in the release notes which items stay unverified on hardware.
