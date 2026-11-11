<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# v1.0.0 readiness

This is the checklist for v1.0.0. The latest release is [v0.6.0](https://github.com/giovannirco/latchkey/releases/tag/v0.6.0) (2026-11-11); v1.0.0 is not ready to tag. The roadmap and its discussion are in [#26](https://github.com/giovannirco/latchkey/issues/26); `CHANGELOG.md` lists what each release contains.

## Released

| Release | Contents |
|---|---|
| v0.1.0 | Protocol core, pairing from the board, lock and unlock, the HTTPS web UI, owner login with password and TOTP, button confirmation, audit log, browser flasher. |
| v0.2.0 | Passcodes, fingerprints and IC cards, the keypad's super admin passcode, Home Assistant over MQTT. |
| v0.3.0 | Lock settings, the operation log, persistent unlock alerts, lock clock sync. |
| v0.4.0 | Log lines on the board, syslog shipping, the full Wi-Fi form. |
| v0.5.0 | Encrypted key export/import, pending admin-code recovery, previewed partial hardening with the reset-button step skipped. |
| v0.6.0 | Time-zone controls, HTTP and logging hardening, bounded MQTT state, credential cleanup and alert persistence recovery. |

Gateway-unlock API/UI controls are not planned for the installation or v1. The protocol primitive remains available; its effect on Latchkey unlocking is unverified.

## Required for v1.0.0

| Item | Status |
|---|---|
| Final review ([#25](https://github.com/giovannirco/latchkey/issues/25)) | Local #21 fixes and broader code/UI review completed on `fix/readiness-findings`. Still required: CI on the final `main` commit before tagging. |

## Unverified on hardware

Hardware acceptance is deferred beyond v1.0.0; these stay listed as unverified in the release notes.

| Item | Status |
|---|---|
| Backup, recovery and hardening ([#19](https://github.com/giovannirco/latchkey/issues/19)) | Built in v0.5.0 with native and browser tests. A real ESP32-S3 USB export and hardening preview were checked. Before v0.6.0, a fresh authenticated export was imported onto a classic ESP32; keys survived restart, the restored spare unlocked the real lock, and the S3 locked it again. Unverified: a real hardening run, the web button flow for these, maximum-size backups and the classic ESP32's heap under backup plus concurrent load. Mock results are not evidence of hardware recovery. |
| Switch writes ([#20](https://github.com/giovannirco/latchkey/issues/20)) | Reset button, privacy lock and tamper alert writes refuse before any Bluetooth frame until their layout is proven on a real lock. Full hardening (turning the reset button off) depends on this. |
| Passage readback ([#31](https://github.com/giovannirco/latchkey/issues/31)) | Further investigation is outside the installation and v1 scope by decision on 2026-11-11. The acknowledged write followed by a dropped readback connection remains unresolved; existing passage controls remain available. |
| Classic ESP32 heap and HTTPS ([#21](https://github.com/giovannirco/latchkey/issues/21)) | One stress run recorded a 27,576-byte minimum heap; later runs passed the 30 KB check. The first TLS connection closing during MQTT announcements, minimum heap under combined load, and stack headroom with a full log page and active alert monitoring remain untraced on hardware. Native fixes do not establish their cause. |

## Issue #21 review

The November 2026 review covers the issue body and follow-up comments. Already released fixes remain distinguished from the v0.6.0 fixes; neither category substitutes for the hardware checks above.

| Finding | Disposition |
|---|---|
| Unknown HTTPS stack reported as zero; HIL checks skipped zero | HTTPS reports `null` until observed, preserving genuine zero. HIL requires headroom for exercised tasks and checks the MQTT client when connected. |
| S3 identified as an Atom board | Default name is `esp32s3`, retaining GPIO0. The HIL TOTP parser accepts the exact previously issued S3 label without rotating credentials. |
| MQTT password retained while disabled; moved-from settings; unbounded pruned identifiers | Unused pending passwords are wiped, loaded settings avoid moved-from password copies, and the pruning history is bounded to 32 entries. |
| Pairing seed storage charged the lock reserve twice | Seed storage uses its protected reserve directly, like the lock record. Actual NVS write failures still propagate. |
| Credential copies retained by record updates | Record update/read/rename, storage listing and startup copies are wiped on success and failure. Broader review also fixed Wi-Fi validation/load/setup and generated-owner cleanup paths. |
| Slow anonymous HTTP bodies monopolized the worker | Two-second absolute anonymous body deadline; ten seconds for authenticated bodies. Socket shutdown precedes asynchronous-request release. Native tests cover stalls and TLS read/write readiness. |
| CMake source discovery; WebSocket byte bounds and failed delivery | Already fixed on `main`: the utility component source glob uses `CONFIGURE_DEPENDS`; WebSocket admission bounds allocated bytes and closes affected sessions on undeliverable results. |
| Confirmed versus pending admin codes; anti-peeping guidance | Already fixed in v0.5.0. Pending candidates remain separate recovery evidence; UI guidance avoids unsupported claims. |
| UTC default and missing time-zone setup guidance | System edits the saved POSIX zone explicitly, offers a fixed browser offset, and explains daylight-saving rules. Pairing and lock pages show offset mismatches. USB-only claiming remains unchanged; setup documentation directs owners to review the zone before pairing and sync existing locks after changes. |
| Weekly passage records carried an irrelevant month | Weekly readback normalizes month to zero; monthly and unknown types retain their original data. This does not resolve the hardware disconnect in #31. |
| Mock auto-lock range and passage day count | Mock follows optional firmware ranges and accepts eight passage-day entries; invalid requests leave state unchanged. HIL chooses a supported auto-lock test value and restores the original. |
| Unlock-log baseline lost dated evidence | Undated trailing records retain the last valid timestamp; restart inference requires a known prior timestamp. An entirely undated history cannot prove a restart. |
| Alert persistence ordering and acknowledgement after cursor failure/restart | Failure-injection tests cover actual log reads and encoded persistence. Alerts save before the cursor; failed saves retain the cursor and own-unlock ledger. Acknowledgement waits for queued monitoring and refuses unresolved durability. Startup can require complete successful catch-up before acknowledgement, including after a log reset. Undated alert identities stay stable across retries. |
| Undocumented own-unlock ledger bounds | README and security model document 16 unmatched unlocks per lock, 24-hour expiry, and possible false alerts after displacement, expiry or restart. |
| Syslog retry reset and activation persistence | Reconnect backoff survives peer close and local-only sends; enabling requires a worker before settings are persisted. |
| Truncated or interrupted log lines could expose secrets | Ring/syslog capture withholds incomplete lines, orphaned continuations and secret-shaped tags. The raw USB console is not a redaction boundary. |
| Unsupported OTA form; time-zone form absent; reset refusal drift | OTA upload is hidden. System exposes the time-zone form. Reset-button disabling refuses with `backup_required` before backup and `unverified` afterwards, without Bluetooth or a button prompt. |
| Mock/API drift | Audit pagination, reboot/reset replies, firmware identity, diagnostics, paired-record flags and event documentation match the firmware interface. |
| OTA error response followed by connection reset | Remains with paused OTA work in #23; the released board has no upload endpoint. |

Alert deduplication remains bounded to eight entries. A longer backlog and failed cursor write can cause repeated notifications after earlier entries are displaced; exactly-once delivery is not guaranteed.

Local verification on 2026-11-11: 869 native tests, 177 browser tests including desktop/phone screenshots, 23 browser-build/mock Python tests, 22 CI-tool tests and 28 release-tool tests passed. A subsequent mock log identity correction passed all 10 log-view browser tests. Both target builds passed; the v0.6.0 classic ESP32 image was 1,403,360 bytes against the 1,887,436-byte limit. Updated hardware suites collected 75 cases without running them against a device. The separate v0.6.0 hardware checks verified the two-board restore and one unlock/lock cycle, preserving the enabled reset button. CI on the final `main` commit remains the release gate.

## Deferred beyond v1.0.0

| Item | Status |
|---|---|
| Weekly (cyclic) passcode creation and editing ([#22](https://github.com/giovannirco/latchkey/issues/22)) | Not built. Weekly passcodes can be listed and deleted; the command layout for writing their window lacks protocol evidence. Fingerprint and card weekly windows work. |
| Board firmware updates from the web page, with rollback ([#23](https://github.com/giovannirco/latchkey/issues/23)) | Not in any release; paused on branch `feat/ota`. The System page hides the upload form because the board does not serve `/api/ota`. |
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
node --check web/app.js
git diff --check
```

Optional screenshot checks require `LK_SHOTS_DIR`; otherwise those cases skip. Concurrent Playwright runs need different `LK_UI_PORT` values and separate `--output` directories.

Before tagging v1.0.0: finish the required items, close #25, confirm CI on the final `main` commit, and state in the release notes which items stay unverified on hardware.
