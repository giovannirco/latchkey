<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Changelog

Notable changes to Latchkey, in the format of [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow [Semantic Versioning](https://semver.org/). A release has a heading `## [x.y.z] - YYYY-MM-DD`: the release workflow publishes that section as the GitHub Release notes and stops when the tag has no section.

## [Unreleased]

## [0.7.0] - 2026-11-11

### Added

- Credential details in operation logs for supported fingerprint, passcode and IC-card unlocks, locking, additions, changes, deletions and failed attempts. Exact IDs resolve to current saved labels; up to 16 retired labels per lock preserve last-known names after removal. Labels are explicitly marked as current or last-known, not asserted as historical identity.
- Failed-attempt outcomes and record details, including the lock's event type and available app user/operation IDs. Unknown attempts remain unidentified. PINs are matched by exact opaque keyed IDs; entered PIN digits and replacement codes never appear in logs, including incorrect or padded attempts.
- Persistent low-battery alerts below 40%, with a live browser warning and dashboard badge. Acknowledgement survives restart and suppresses repeated warnings for that low-battery episode. A fresh reading of at least 40% clears the warning and rearms it. Battery alerts survive overflow of the bounded alert list; existing v0.6.0 alerts are preserved on upgrade.

### Scope and known limits

- Identification depends on what the lock records. An unrecognized fingerprint often has no usable ID; clear-all records do not identify individual credentials. Current and retired names are descriptive labels, not proof of who acted, and reused IDs cannot establish historical identity. No anti-peeping substring matching or guessed PIN identity is performed.
- Retired labels are local bounded history, excluded from key backups. Previous deletions whose names were already discarded cannot be reconstructed. The spare maintains its own log metadata and alert state.
- Battery warnings use fresh authenticated status/push/operation responses, not cached or unauthenticated advertisement values. Background monitoring checks status while connected and on its existing approximately six-hour schedule when the lock is reachable; this is not an instant remote notification service. Existing Home Assistant battery reporting remains available.
- Existing update, hardware and hardening limitations from v0.6.0 remain in effect.

## [0.6.0] - 2026-11-11

### Added

- System time-zone form initialized from the board's POSIX setting, with browser zone guidance, an explicit fixed-offset suggestion and daylight-saving rules. Pairing and lock pages warn about current offset differences; existing locks have a named Sync time action. Browser and mock API regressions cover saving, validation, persistence and failures.

### Fixed

- Hide the firmware upload form while the released board API has no upload endpoint.
- Reset-button disabling checks stored backup status: `backup_required` before export, `unverified` after it, and `internal` for unreadable metadata. Native tests confirm no Bluetooth write or button prompt; switch writes remain unverified on hardware.
- Align mock audit pagination, reboot/reset replies, diagnostics and paired-record flags with the firmware API.
- Limit anonymous HTTP body reads to two seconds and authenticated reads to ten seconds, including stalled TLS reads. Abandoned requests shut down their owned socket before releasing it. HTTPS stack telemetry distinguishes unavailable (`null`) from an observed zero watermark.
- Bound MQTT stale-identifier history to 32 entries and wipe unused pending passwords. Settings loads and lock-record updates clear temporary credential copies. Pairing seed storage no longer charges the protected lock reserve twice.
- Identify the default ESP32-S3 build as `esp32s3`, retaining GPIO0. Existing TOTP credentials remain usable; the HIL parser accepts the previously issued S3 label.
- Normalize the unused month of weekly passage records, retain dated operation-log evidence through undated records, and require a known previous timestamp before inferring a log restart.
- Serialize alert acknowledgement with monitoring and refuse it while alert/cursor persistence is unresolved, including after restart. Undated alert identities remain stable across retries; recovery tests exercise failed writes, restart, log rollover and acknowledgement retries. Deduplication remains limited to eight retained alerts.
- Withhold truncated and interrupted lines and secret-shaped tags from the captured log ring and syslog. Syslog reconnect backoff survives peer closure and local-only sends, and enabled settings are persisted only after the worker can start.
- Match mock auto-lock limits and eight-entry passage-day lists to the firmware; hardware checks choose supported auto-lock values and no longer skip genuine zero stack watermarks for exercised tasks.

### Scope and known limits

- Gateway-unlock API/UI controls and further passage-readback investigation are outside the installation and v1 scope. Existing passage controls remain available; the previously observed readback disconnect is unresolved.
- Reset-button, privacy-lock and tamper-alert writes remain disabled pending protocol verification. Hardening remains partial. OTA updates and rollback are not included; update existing boards with a normal PlatformIO upload that preserves NVS, never a merged factory image.
- Classic ESP32 heap under combined load and the first TLS connection dropping during MQTT announcements remain hardware investigations. Alert deduplication retains eight entries and does not guarantee exactly-once notifications through storage failures.
- Hardware acceptance verified an authenticated ESP32-S3 USB export, restoration onto a classic ESP32, retained keys after restart, and one unlock from the restored spare followed by a lock from the S3. The lock ended locked with its reset button enabled. Web backup button flows, maximum-size device backups and installed-door operation remain unverified; an encrypted backup excludes board login, Wi-Fi and MQTT settings.

## [0.5.0] - 2026-11-09

### Added

- Encrypted key export/import for one lock or all locks, using a versioned AES-256-GCM envelope with PBKDF2-HMAC-SHA256. Backups preserve labels, seeds and pending admin recovery, refuse existing identities and capacity overflow, and journal new identities for rollback after failure or restart. Plaintext is limited to 8 KiB; passphrases preserve spaces and require 12 to 128 UTF-8 bytes without NUL.
- Read-only hardening preview followed by explicit, button-confirmed execution. Per-step reports preserve completed work after a failure and explain admin-code provenance. Reset-button writes remain skipped as unverified, so execution reports partial completion and keeps `hardened:false`.
- Pending admin-code recovery retains the confirmed and candidate copies across lost acknowledgements and reboot. Later owner changes reconcile first and return `admin_reconciled` or `admin_unresolved` without another write. Forget and board reset refuse erasure of reset-button-off locks or unreadable recovery records.
- Native and browser regression coverage for backup, hardening and recovery. On an ESP32-S3 holding a real lock, a USB export (an LKB2 backup in about 17 s, no drop in minimum free heap) and a hardening preview (admin code preserved, reset button skipped) were checked; import on a board, the web button flow, the classic ESP32's heap during a backup and a two-board restore remain unverified. OTA and hardware acceptance are deferred beyond v1.0.0.

### Changed

- Authenticated HTTP requests and serial lines allow 16 KiB; unauthenticated HTTP keeps its 8 KiB limit. Replies and queued WebSocket bytes have explicit allocation bounds.
- Backup jobs use the browser's 240-second deadline. Export/import validate passphrases by UTF-8 bytes and reject malformed results without downloading an empty file or claiming success.

### Fixed

- Web requests keep their timeout until the response body finishes, so a stalled reply cannot leave an action waiting indefinitely.
- The web UI refuses malformed or mismatched RPC success replies instead of reporting an action as successful without a valid result.
- Signing out clears pending and cached browser jobs; responses from an earlier session cannot reopen secret dialogs or end a later session.
- A failed event connection after sign-in shows a retry action that uses the existing session instead of leaving the page blank.
- Passcode guidance describes the tested trailing digits without claiming that digits before the code also work.

## [0.4.0] - 2026-11-09

### Added

- Recent log lines on the board: every line the USB console prints with `#` (ESP-IDF's and Latchkey's, with lines the Wi-Fi driver writes in pieces joined) goes into a RAM ring with its level, tag and boot time, 6 KiB on the classic ESP32 (in RTC memory, so it costs no heap) and 16 KiB on the ESP32-S3. `system.logs {since?, level?, limit?}` pages through it; a line shaped like a secret is kept only as a notice and counted in `system.info.logs.withheld`.
- Remote logging over syslog, off until configured: `system.syslog.set {enabled, host, port?, transport?, appName?, level?}` ships the lines as RFC 5424 over UDP, or over TCP with octet counting, to a collector such as rsyslog, Grafana Alloy or a NAS log centre; `system.syslog.get` and `system.info.syslog` report what was sent, dropped and refused. Each change is audited.
- Web UI: a Logs view on the System page (level filter, refresh every few seconds, copy as text), the remote logging settings, and the Wi-Fi form's IP address, gateway, netmask and DNS server, prefilled from `system.info.wifi`, which now reports `gateway`, `netmask` and `dns`.

### Fixed

- `system.wifi.set` from the web now gets its reply: the board answers first and switches networks a second later, where it used to stop Wi-Fi before the reply left.
- Repeated Wi-Fi changes release their temporary configuration instead of retaining heap.
- Leaving System during a log read stops polling, including an unfinished page of results.
- Lower task-stack allocation leaves more heap available for concurrent Bluetooth, MQTT, syslog and HTTPS.
- HTTPS releases temporary startup credentials and completed-handshake allocations, and sends large responses in smaller TLS records.
- Passage-window additions wait up to ten seconds for the lock's acknowledgement; authentication and other commands keep their five-second waits. Slow acknowledgements no longer trigger an early timeout, and writes are never resent.
- A passage-window addition that fails after storing some of its windows says how many it added, in its message and as `added` in the error. After any failed addition the web UI reads the lock's windows again and says that some may have been added, so it shows what the lock really holds.
- A lock whose stored alerts cannot be read keeps being monitored: the board starts a new alert list holding a persistent warning (kind `alerts_unreadable`, in `locks.list`, `lock.alerts.list`, `system.info` and the web UI, never sent as `lock.alert`) until it is acknowledged, saves over the unreadable table, and keeps reading the log and setting the lock's clock. It used to refuse every alert, stop log monitoring and clock sync, and clear only with `locks.forget`.
- A new unlock alert is announced (event, audit entry, MQTT) even when it cannot be saved; its log page is still retried until the save succeeds, without announcing it again.
- The log ring is wiped at every start. On the classic ESP32 it lives in RTC memory, where earlier lines used to stay readable in memory across a restart or a factory reset.
- `lock.resetButton.set` from the web answers its refusal even while another request runs, where it could answer `busy`.

### Known issues

- One classic ESP32 stress run recorded a 27,576-byte minimum heap; later unchanged runs passed the 30 KB check. The earlier low point remains untraced ([#21](https://github.com/giovannirco/latchkey/issues/21)).
- A passage-window write was acknowledged once and then its readback connection dropped; later hardware checks pass, but that disconnect remains untraced ([#31](https://github.com/giovannirco/latchkey/issues/31)).

## [0.3.0] - 2026-11-09

### Added

- Lock settings from the board, each checked against the lock's feature bits before any Bluetooth: `lock.autolock.get`/`set`, `lock.passage.list`/`add`/`delete`/`clear` (weekly windows in the lock's local time), `lock.sound.get`/`set`, `lock.resetButton.get`, `lock.privacyLock.get` and `lock.tamperAlert.get`. All three switches are read-only until their write layout is verified on hardware; writes refuse with `unverified` before any Bluetooth frame or button prompt. Turning the reset button off without a key backup refuses first with `backup_required`.
- The lock's operation log: `lock.log.fetch` reads new records from a cursor the board keeps per lock in NVS (found by bisection the first time) and answers the newest entries, or those after `since`, as `{entries, last, more}`; passcodes the lock records in its log never leave the board.
- Unlock alerts: the board reads each lock's log after the connections it makes anyway, and about every six hours otherwise, and raises `lock.alert {lock, method, time, seq, type}` with an audit entry (source `board`) for every unlock from an app it did not make and every forced opening. The newest eight unacknowledged alerts per lock survive a restart in NVS and appear in the dashboard badge and lock page; `lock.alerts.list` and `lock.alerts.ack {through}` leave later arrivals unread. Live notices stay until dismissed.
- The lock's clock follows the board's time zone: the board sets it again after a time-zone change or a daylight-saving change, and once a day against drift.
- Web UI: reset button, privacy lock and tamper alert shown read-only, features the board does not use listed apart, and the log reads on until it has every new entry.
- `tools/hil/test_lock_settings.py` and `tools/hil/test_lock_log.py`, run on the owner's lock.

### Changed

- The remote unlock control is gone from the web UI and the mock: the board does not implement it, and the lock's `config_gateway_unlock` bit is listed as reported but not used.

### Fixed

- A corrupt operation-log cursor raises a persistent monitoring warning, also in `system.info.warnings`; dedicated log connections skip locks without a recent advertisement.
- Reloading a lock-detail page waits for its event socket before issuing job-based requests, so fast results are received.
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
