<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Latchkey

[![CI](https://github.com/giovannirco/latchkey/actions/workflows/ci.yml/badge.svg)](https://github.com/giovannirco/latchkey/actions/workflows/ci.yml)

Latchkey is firmware for ESP32 boards that takes a TTLock Bluetooth LE smart lock off the TTLock cloud and puts it under one owner's control: the board pairs with the lock by itself, manages what the TTLock app can manage on that lock, and serves an owner-only web UI, with no phone app, TTLock account or computer Bluetooth involved.

Latchkey is in early development; the current release is v0.4.0. Pairing from the board, locking and unlocking, passcodes, fingerprints, IC cards, the keypad's super admin passcode, lock settings and the operation log have been checked on a real lock. Unlock alerts persist until acknowledged, Home Assistant can drive the lock over MQTT, and the System page shows recent logs with optional syslog shipping. Board firmware updates from the web page are being built; hardening and the encrypted key backup come next. The [roadmap](https://github.com/giovannirco/latchkey/issues/26) tracks what is left.

## Why

- TTLock locks are sold under many brands and normally need the vendor's phone app and cloud account. Latchkey keeps every key and every decision on a board you own, on your network.
- The open-source alternatives run the protocol on a computer or a phone, or use an ESP32 only to relay Bluetooth to one. Latchkey runs the whole protocol on the ESP32, from the first pairing on.
- It aims to make the lock harder to take over than it is out of the box: claiming only over USB, a password and TOTP code for the web, a button press on the board for destructive actions, an audit log, and a hardening step that replaces the lock's default credentials and disables its reset button once the keys are safely backed up.

## Features

Works today:

- TTLock protocol core (`components/ttlock`), tested on the host: pairing, lock and unlock, status and battery, device info and feature bits, time sync, passcodes, IC cards and fingerprints with validity periods and weekly windows, auto-lock, passage mode, sound, remote unlock, the reset button, privacy lock and tamper alert switches, the passcode display, the operation log and factory reset. A command the lock does not report in its feature bits answers `unsupported` without touching the radio.
- Firmware for the classic ESP32 and the ESP32-S3: a JSON-lines console over USB, claiming the board, Wi-Fi with a static address, SNTP time with a configurable time zone, an audit log, the owner login (password, TOTP code and rate limit) with web sessions, and HTTPS with a certificate the board makes itself: the web UI, the JSON API behind a session cookie, live events over a WebSocket, and a press of the board's button before destructive actions from the web.
- Pairing from the board, checked on a real lock: the web UI starts it and a press of the board's button confirms it; then lock, unlock, status, battery and time sync from the web.
- Lock access from the board, checked on a real lock: passcodes (permanent, timed and one-time, listed by id and never by code), fingerprints and IC cards (enrolment with live progress, validity, weekly windows), and the keypad's super admin passcode, which pairing can take from the owner and the web UI can show and change after a press of the board's button.
- Lock settings (auto-lock, passage mode, sound, and read-only reset button, privacy lock and tamper alert switches), the lock's operation log, and unlock alerts: the board reads each lock's log and raises an alert, with an audit entry, for every unlock from an app it did not make and every forced opening. The lock's clock follows the board's time zone, daylight-saving changes included.
- The owner web UI (`web/`), served by the board and tested against a mock of the board API.
- Home Assistant over MQTT, off until configured: each lock appears as a device with a lock entity, battery, last event, Bluetooth link and an unlock alert, through MQTT discovery, and LOCK and UNLOCK from Home Assistant run through the same queue as the web.
- Logs: the board keeps its recent log lines in RAM and shows them on the System page, and can ship them to a syslog collector (RFC 5424 over UDP or TCP), off until configured.

In progress: board firmware updates from the web page, with rollback. Next: lock hardening and the encrypted key backup. The web UI already shows the Export and Harden steps, but the board answers them only once they are built.

## Security model

- The board is claimed only over its USB serial console, which counts as physical presence.
- Web login with the owner password (PBKDF2-HMAC-SHA256) and a TOTP code, with a growing wait after failed attempts.
- Destructive actions from the web also need a press of the board's button.
- HTTPS with a certificate the board generates, whose fingerprint you check once.
- An audit log of every action, never containing secrets.
- Hardening (planned): a random admin passcode on the lock, unknown passcodes removed, the lock's reset button disabled only after an encrypted backup of its keys.
- No cloud: the board only reaches the internet for DNS and SNTP.
- MQTT, when you turn it on, is plain MQTT over TCP to a broker you choose: whoever may publish to a lock's command topic there can lock and unlock it.
- Remote logging, when you turn it on, is plain-text syslog to a collector you choose: the lines hold no secrets, but anyone on the path can read them.
- Profile P1: lock keys sit in plaintext NVS, so whoever reads the flash of a stolen board can use them. Flash encryption is possible but not the default.

[SECURITY.md](SECURITY.md) has the full model and how to report a vulnerability; [docs/protocol.md](docs/protocol.md) has the protocol notes and its limits.

An unlock alert just after a board restart can be the board's own unlock if it restarted before reading that unlock from the lock's log. Otherwise its unlock replies are matched by record id; only replies without an id use a time window. Log timestamps use the current and preceding clock offsets, so older history spanning more offset changes can have inaccurate times.

## Supported boards

| Env | Board name | Flash | Button | Console |
|---|---|---|---|---|
| `esp32` | `esp32-devkit` (classic ESP32) | 4 MB | GPIO0 | UART0, 115200 baud |
| `esp32s3` | `esp32s3-atom` (ESP32-S3, such as the M5Stack StampS3) | 8 MB | GPIO0 | USB-Serial/JTAG |
| `native` | host unit tests for `components/ttlock` and `components/latchkey_util` | | | |

An M5 ATOM runs the `esp32` build with `LATCHKEY_BUTTON_GPIO=39`, and an M5Stack AtomS3 the `esp32s3` build with `LATCHKEY_BUTTON_GPIO=41`. The ESP8266 cannot work: it has no Bluetooth. [docs/hardware.md](docs/hardware.md) covers the button pins, flashing, power and where to put the board.

## Quick start

1. Flash the board: with Chrome or Edge, open the [browser flasher](https://giovannirco.github.io/latchkey/) once a release is published, or build and flash from source as below. Flashing erases the board.
2. Claim it over USB with `system.setup`, sending the Wi-Fi settings (static IPv4) and an owner password of 12 to 128 bytes from a file, so they stay out of your shell history:

   ```sh
   uv run -q --no-project --python 3.14 --with pyserial==3.5 python -I tools/latchkey_cli.py --port <port> system.setup - < setup.json
   ```

   ```json
   {"wifi": {"ssid": "your-network", "password": "your-wifi-password", "ip": "192.0.2.50", "gateway": "192.0.2.1", "netmask": "255.255.255.0", "dns": "192.0.2.1"}, "password": "a long owner password"}
   ```

3. Add the `otpauth://` URI from the reply to an authenticator app; the board returns it only once. Then delete `setup.json`.

## Build, test, flash

Run PlatformIO only through `uvx` at the pinned version, from the repository root.

```sh
uvx platformio==6.2.0 test -e native
uvx platformio==6.2.0 run -e esp32 -e esp32s3
uvx platformio==6.2.0 run -e esp32 -t upload --upload-port <port>
uvx platformio==6.2.0 run -e esp32s3 -t upload --upload-port <port>
uvx platformio==6.2.0 device monitor -e esp32 --port <port>
```

The other checks CI runs:

```sh
python3 tools/ci/check_sources.py                                   # SPDX headers, no ESP-IDF headers in the host components
python3 tools/ci/firmware_size.py                                   # app image sizes; esp32 at most 1.8 MB (1,887,436 bytes)
python3 -m unittest discover -s tools/ci -p 'test_*.py'             # self-tests of the CI tools
python3 -m unittest discover -s tools/release -p 'test_*.py'        # self-tests of the release tools
sh tools/ui-tests/run.sh                                            # web UI: bundler tests and the Playwright suite
```

[web/README.md](web/README.md) explains the web UI, its mock and its tests.

### Serial console

The console speaks JSON lines: send one request per line, `{"id": 1, "method": "system.info", "params": {}}`, and read one line per reply, `{"id": 1, "result": {...}}` or `{"id": 1, "error": {"code": "...", "message": "..."}}`. Events arrive as `{"event": "...", "data": {...}}` lines. Every log line of the application starts with `#`, the first one being `# latchkey <fw-version> board=<board> chip=<chip> idf=<idf-version>`; the ROM and bootloader lines before it are plain text, and the CLI skips every line that is not a JSON object. Requests over the console count as physical presence: they need no session and no button press. `system.setup` (claim the board: Wi-Fi with a static IP and the owner password; returns the TOTP `otpauth://` URI once) and `system.time.set` are accepted only there. The owner password is stored as PBKDF2-HMAC-SHA256 with a random 16-byte salt. The iteration count is calibrated to about 1 s on the classic ESP32 at 160 MHz (4400 iterations, about 0.6 s on the ESP32-S3) and stored with the hash, so a later firmware can raise it without breaking an existing claim. Requests nested deeper than 8 arrays or objects are refused before parsing, and wrong or missing parameters answer `invalid_argument` in every method. `system.timezone.set {"tz"}` takes a POSIX TZ string such as `CET-1CEST,M3.5.0,M10.5.0/3` or `<-03>3` (daylight time needs its rules); the lock is given local time, `system.info` reports `timezone` and `localTime`, and `system.timezone.get` answers `{"tz", "utcOffset"}`.

### Owner login

- `auth.login {"password", "totp"}` checks the owner password and the current six-digit code (one 30 s step of drift either way; a code whose step was already accepted is refused). Over HTTPS it opens a session and sets the session cookie; over the console, where the owner needs none, it takes `"dryRun": true` and answers `{"ok": true}`, so the checks can be tested over USB. It answers `unauthorized` for a wrong password or code, `time_unsynced` until the clock is set, and `rate_limited` with `retryAfter` seconds once five attempts in a row have failed: the wait starts at 30 s and doubles up to 15 minutes, survives a reboot, and the next successful login resets the count.
- Web sessions, opened only by a login over HTTPS, live in RAM only (a reboot ends them all): at most four, 15 minutes idle and 12 hours at most. `auth.sessions` lists them, `auth.revoke {"id"}` ends one and `auth.logout {"all"?}` ends the caller's own or all of them.
- `auth.changePassword {"current", "new"}` re-hashes with a new salt and ends the other sessions; a wrong current password answers `invalid_argument` and counts as a failed attempt. `auth.rotateTotp` (a press of the board's button from the web) returns the new `otpauth://` URI once, retires the old secret at once and ends the other sessions.

### Web

The first time the board has an address it starts HTTPS on port 443 and, on port 80, a server that only redirects to `https://<address>/`. It makes its certificate once: an EC P-256 key and a self-signed certificate for the board name and its static address, valid from 2024-01-01 with no expiry date (9999-12-31, as RFC 5280 allows), kept in NVS until a factory reset. Compare the SHA-256 fingerprint the browser shows the first time with `certFingerprint` in `system.info` or the `HTTPS certificate SHA-256` line on the console. The certificate keeps the address it was made for: after `system.wifi.set` moves the board elsewhere, browsers also report a name mismatch until a factory reset makes a new one.

- `GET /` serves the web UI. Every response carries its Content-Security-Policy (with `frame-ancestors 'none'`), `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`, `X-Content-Type-Options: nosniff` and `Cache-Control: no-store`, and every error answers with the JSON error envelope.
- Open the UI at `https://<board IP address>/`. The API and the event socket answer only requests whose `Host`, and `Origin` when present, name that address (403 otherwise), so a page on another name that resolves to the board cannot use them.
- `POST /api/rpc` takes the same JSON requests as the console, with `Content-Type: application/json`, at most 8 KiB and at most 256 JSON values (object keys included). A web login sets the `lk_session` cookie (`Path=/; Secure; HttpOnly; SameSite=Strict`) and never returns the token; `auth.logout` clears it.
- `GET /api/events` is a WebSocket of `{"event", "data"}` messages: the events the console prints, plus `job.done` for that session's jobs. It opens only with a valid session cookie, and closes when that session ends.
- From the web, the lock methods (`locks.scan`, `locks.pair`, `lock.*`) and the methods that need the board's button answer `{"job": "<id>"}` at once and end with a `job.done {job, result|error}` event on the sockets of the session that asked. A job ends `unauthorized` if its session ends before it runs. A method that needs the button first checks its parameters and preconditions (a bad address, a lock the board does not hold, `locks_paired`) and fails without asking; then it emits `confirm.required {action, timeoutMs}`, waits up to 30 s for a press, emits `confirm.result {action, confirmed}`, and fails with `confirm_timeout` without one, or `unauthorized` if the session ends during the wait: today `locks.pair`, `lock.factoryReset`, `lock.adminPasscode.set`, `lock.adminPasscode.get`, `auth.rotateTotp` and `system.factoryReset`. A button request that cannot start at once, because another web job is running or queued, answers `busy`.
- The classic ESP32 keeps at most three HTTPS connections, enough for two browser tabs, each holding an event socket; the ESP32-S3 keeps four. A new connection beyond that closes the least recently used one. With Bluetooth scanning, one tab and its event socket, the classic kept at least 40 KB of free heap in testing.

## Locks

The board is a Bluetooth LE central for TTLock locks (service `0x1910`, protocol 3). Lock methods take `{"lock": "<MAC>"}`, the address `locks.list` reports as `id`:

- `locks.scan {"seconds": 1-30}` answers `{"seconds"}` at once and streams one `scan.result {mac, name, rssi, paired, lock?}` event per lock it hears.
- `locks.pair {"mac", "name"?, "wait"?, "adminPasscode"?}` waits up to `wait` seconds (at most 600) for that lock to advertise, then pairs it. Without `wait` it waits 30 s over USB and 120 s from the web, where the wait starts after the press on the board's button and leaves time to walk to the lock. A factory-fresh lock advertises for about 15 s after a touch on its keypad. The keys are stored in the NVS `locks` namespace the moment the lock accepts the board as its admin, and again when pairing ends. `adminPasscode` (4 to 9 digits, checked before any wait) becomes the keypad's super admin passcode; without it the lock gets 7 random digits. The offline-code seed table pairing sends is stored in the NVS `seeds` namespace before it goes out.
- `locks.list`, `locks.rename {"lock", "name"}` and `locks.forget` (drops the keys on the board only) need no Bluetooth.
- `lock.status`, `lock.info`, `lock.features`, `lock.unlock`, `lock.lock`, `lock.time.sync` and `lock.factoryReset` connect to the lock. Unlock and lock emit `lock.state` and `lock.event`, and keep the link for 25 s for the events the lock pushes.
- `lock.passcodes.list` answers `{passcodes: [{id, type, name, validity, managed}]}`: `id` is 12 hex digits derived from the lock's key and the code, the same on any board holding that lock, `type` is `permanent`, `timed`, `one_time` or `cyclic`, `validity` is `{start, end}` in UTC seconds or `null`, `managed` says Latchkey created it; codes are never listed. `lock.passcodes.add {"lock", "type", "code"?, "name"?, "validity"?}` answers the passcode once with its `code` (6 random digits without one); `lock.passcodes.update {"lock", "id", "code"?, "name"?, "validity"?}` needs `modify_passcode_function`, and a new code gives a new id; `lock.passcodes.delete {"lock", "id"}` and `lock.passcodes.clear`. A code already on the lock and the admin passcode are refused with the same `lock_error` "that code is already in use on the lock" before anything is sent, so a request cannot test which code is the admin passcode, and so is a code whose id would collide with another passcode's. An easy code (a run or one repeated digit) is taken with a `warning`: the lock opens when a code appears anywhere in the digits typed, so 7 to 9 digits are safer. Cyclic passcodes answer `unsupported`: no reference shows how a lock takes their weekly window.
- `lock.fingerprints.*` and `lock.cards.*`: `list` answers `{fingerprints|cards: [{id, name, validity, cycle?}]}` with ids as decimal text; `enroll {"lock", "name"?, "validity"?}` emits `enroll.progress {lock, kind, stage, scans, total}` (stage `waiting`, `progress`, then `added` with the `id`) and ends when the lock adds the credential, ends the enrolment itself, or sends nothing for 10 s; `setValidity {"lock", "id", "validity", "cycle"?}` takes a weekly window `{days, start, end}` (weekdays 1 Monday to 7 Sunday, `HH:MM`) where the lock reports `cyclic_ic_or_finger_print`; `delete {"lock", "id"}` and `clear`.
- `lock.autolock.get` answers `{seconds, min, max}` (0 is off; `min` and `max` are `null` when the lock does not report a range) and `lock.autolock.set {"lock", "seconds"}` refuses a delay outside the lock's range. `lock.passage.list` answers `{modes: [{type, day, start, end}]}` in the lock's local time (`day` 0 every day, 1 Monday to 7 Sunday; monthly modes the lock already holds carry `month`); `lock.passage.add {"lock", "days", "start", "end"}` adds a weekly window per day, `lock.passage.delete {"lock", "type", "day", "start", "end"}` removes one listed mode, and `lock.passage.clear` removes them all. `lock.sound.get` answers `{enabled, volume, levels}` (`volume` 1 to 5, `null` when the lock reports none) and `lock.sound.set {"lock", "enabled", "volume"?}` writes them.
- `lock.resetButton.get`, `lock.privacyLock.get` and `lock.tamperAlert.get` answer `{enabled}`. All three switches are read-only: their `.set {"lock", "enabled"}` methods refuse with `unverified` before any Bluetooth frame or button prompt until their write layout is proven on a real lock. Turning the reset button off refuses first with `backup_required`, before the `unverified` refusal.
- `lock.log.fetch {"lock", "since"?}` reads the records the lock wrote since the board last looked, then answers `{entries: [{seq, time, type, battery}], last, more}`: without `since` the newest 16 slots of the log, with `since` the entries after that record number, 16 slots at a time. `time` is UTC; `type` is the lock's record type; `more` says there is more to read. The board keeps its place in each lock's log in the NVS `watch` namespace, reads on after every connection it makes for another reason and about every six hours otherwise, one lock at a time and only while no lock job waits, and emits `lock.alert {lock, method, time, seq, type}` with an audit entry (source `board`) for each unlock from an app it did not make (method `app` or `remote`) and each forced opening (`forced`). It sets a lock's clock again when the board's UTC offset changes and once a day.
- `lock.alerts.list {"lock"}` reads the newest eight unacknowledged alerts, kept per lock in NVS, as `{alerts, warnings}`. Each alert has an increasing `id`, a `kind` (`unexpected_unlock` or `watch_state_unreadable`), `time`, `method`, `seq` and `type`. `lock.alerts.ack {"lock", "through"}` acknowledges only ids up to the newest one the owner saw; an alert arriving meanwhile stays unread. The dashboard shows an alert badge and every lock page has an Alerts section.
- A corrupt operation-log cursor becomes a persistent monitoring warning instead of an unlock alarm, also reported by `system.info.warnings`. Dedicated log connections wait until the lock has advertised within the last three minutes; reads on an already open connection still run.
- `lock.adminPasscode.set {"lock", "code"?}` sets the keypad's super admin passcode (7 random digits without `code`, answered once as `{code}`). It refuses a code that is already a user passcode, and stores the candidate as unconfirmed before sending it: the lock's success confirms it, its refusal puts the old code back, and a lost reply leaves the copy marked uncertain (`adminPasscodeConfirmed: false` in `lock.status`). `lock.adminPasscode.get` answers `{code, source}`: read from the lock through `GET_ADMIN_CODE` (`source: "lock"`, with `matchesBoard`), or the board's copy (`source: "board"`) when the lock does not report `get_admin_code` or its reply cannot be read. `lock.adminPasscode.raw` (serial only, not audited) returns that reply as hex for hardware checks.

Names, the managed flags and the weekly windows of credentials live in the NVS `labels` namespace, at most 32 per lock and kind; they and the seed table are erased with the lock's keys. The board keeps part of NVS for pairing a lock and for the rest of the audit ring (`system.info.nvs.reservedEntries`): a write that would grow the names into it answers `storage_full` before anything is sent. A list answers `too_large` when the board lacks the free memory to render it (the ESP32-S3 handles the longest lists). A method checks its parameters, that the board holds the lock and that the lock reports the feature before it sends anything; otherwise it answers `invalid_argument`, `not_paired` or `unsupported` without a Bluetooth frame. A result may carry a `warning` the UI shows until dismissed: names that could not be stored, offline-code seeds lost at pairing (offline codes will not work for that pairing), or an easy code.

One worker runs every lock job in the order they arrive; a job that waits more than 60 s fails with `busy`. Between jobs the board tracks its stored locks from their adverts and emits `lock.state` when the state or the battery changes. From the web, `locks.pair` and `lock.factoryReset` wait for a press of the board's button; over serial they run at once. `system.factoryReset` also erases the lock keys, and refuses with `locks_paired` while any lock is stored unless it gets `{"force": true}`. `system.log.set {"tag", "level"}` (serial only) sets a log tag's level: `{"tag": "ble", "level": "debug"}` logs the length and CRC check of every frame, never its content.

```sh
uv run -q --no-project --python 3.14 --with pyserial==3.5 python -I tools/latchkey_cli.py --port <port> system.info
uv run -q --no-project --python 3.14 --with pytest==9.1.1 --with pyserial==3.5 pytest tools/hil/test_system.py --port <port>
uv run -q --no-project --python 3.14 --with pytest==9.1.1 --with pyserial==3.5 pytest tools/hil/test_lock_core.py -s --port <port> --touch-file <path>
```

`tools/latchkey_cli.py` reads params as a JSON argument or from stdin with `-`. The hardware-in-the-loop suites in `tools/hil/` read the Wi-Fi settings, the owner password, each board's static IP and the lock's address (`lock_mac`) from the gitignored `secrets.local.json` (shape in `secrets.example.json`). `test_system.py` factory-resets the board it runs on, and skips those tests on a board that holds lock keys. `test_lock_core.py` pairs the lock only on an ESP32-S3 that holds no keys for it, writing the UTC time into the `--touch-file` while someone must touch the keypad, and keeps the lock paired; on any other board it only scans. It factory-resets the lock only with `--allow-lock-reset`. `test_lock_settings.py` reads every setting the lock reports and checks the reset-button refusal; only with `--allow-lock-writes` does it change auto-lock and sound and put them back, and add one passage window on a day that is not today and delete it, retrying the clean-up and failing with what it left on the lock if it cannot. It sends no SWITCH write. `test_lock_log.py` reads the log, unlocks and locks the lock once and checks that no alert follows, and changes the board's time zone for a few minutes to see the lock's clock set again, then puts the zone back. `test_lock_features.py` adds, lists, changes and deletes passcodes it creates on the held lock, reads the admin passcode back without printing it, and runs enrolments that end without a finger or a card; it never clears a list or resets the lock, and changes the admin passcode only with `--allow-admin-passcode-change`, putting the original back. `test_http.py` checks HTTPS, the redirect, the headers, the cookie, the CSRF refusals, the events, web jobs and the button from a host on the boards' network: the optional `hil_relay` key names a command that runs a Python 3 script from its standard input there (see `tools/hil/relay.py`), and the suite skips without it. A board whose entry has a `totp_uri` belongs to its owner: the suites compute its codes from that URI and never reset, re-claim or rotate it.

`sdkconfig.<env>` is generated and not tracked. After editing `sdkconfig.defaults` or `sdkconfig.defaults.<target>`, delete `sdkconfig.<env>` and `.pio/build/<env>`. After adding source files to a component or dependencies to `src/idf_component.yml`, delete `.pio/build/<env>`: PlatformIO does not re-run the CMake configure for those changes.

### Pinned versions

- PlatformIO Core 6.2.0.
- `espressif32@8.0.0` with exact `platform_packages` in `[esp_common]`: `framework-espidf` 4.60100.0 (ESP-IDF v6.1.0), `toolchain-xtensa-esp-elf` 15.2.0+20251204, `tool-esptool` 2.50400.0 (esptool v5.4.0), `tool-cmake` 3.30.2, `tool-ninja` 1.13.2. The platform itself pins `toolchain-riscv32-esp` 15.2.0+20251204 (S3 ULP) and `tool-esp-rom-elfs` 0.0.1+20241011; `toolchain-esp32ulp` still resolves from `~1.23800.0` (1.23800.240113 today).
- `tool-ninja` 1.13.2 is published for macOS only, so the firmware builds in CI and in the release workflow run on macOS (`macos-15`, arm64); the host tests, the source checks and the web UI suite run on Ubuntu.
- `native@1.2.1` with Unity 2.6.1 for host tests.
- ESP-IDF managed components are declared in `src/idf_component.yml` and locked per target in `dependencies.lock.esp32` and `dependencies.lock.esp32s3`.
- The headers in `test/vectors/` are generated. `tools/vectors/gen_vectors.py` uses ttlock-ble 0.3.4: `uv run -q --no-project --python 3.14 --with ttlock-ble==0.3.4 python -I tools/vectors/gen_vectors.py`. `tools/vectors/kind3r_vectors.ts` uses Deno 2.9.8 and a kind3r/ttlock-sdk-js checkout at 8c84cda, with moment 2.29.1 locked in `tools/vectors/deno.lock`: `TZ=UTC deno run --allow-env --allow-read --allow-write=test/vectors --config tools/vectors/kind3r_deno.json tools/vectors/kind3r_vectors.ts <checkout>`.
- GitHub Actions are pinned to commit SHAs in `.github/workflows/`; ESP Web Tools 10.4.0 on the flasher page is pinned by version and by the SHA-384 hash of each of its modules.

### Releasing

1. Move the `[Unreleased]` entries of `CHANGELOG.md` under `## [x.y.z] - YYYY-MM-DD` and set `PROJECT_VER` in `CMakeLists.txt` to `x.y.z`, merge that to `main` and wait for CI to pass there.
2. Push a tag `vx.y.z` on that commit of `main`. `.github/workflows/release.yml` refuses a tag whose commit is not on `main`, runs the host tests, builds both boards, checks that the app images report `x.y.z`, writes per board a factory image (flashable at `0x0`), an OTA image and an ESP Web Tools manifest plus `SHA256SUMS`, creates the GitHub Release with the changelog section as its notes, and deploys GitHub Pages with the flasher and the images under `firmware/x.y.z/`.

A release relies on CI having passed on `main`: the workflow checks that the tagged commit is on `main` and reruns the host tests and builds, but it neither looks up the CI results nor runs the source checks and the web UI suite again. Require the CI jobs in a branch protection rule for `main`, and protect `v*` tags with a tag ruleset so that only maintainers can create them.

Once per repository, before the first release: in Settings, set Pages to deploy from GitHub Actions; in the `github-pages` environment, allow deployments from tags matching `v*` (by default it only accepts the default branch); and enable private vulnerability reporting.

To move the flasher to another ESP Web Tools version, change the version in `docs/index.html` and regenerate the import map from the npm package, whose integrity `npm pack` checks:

```sh
npm pack esp-web-tools@<version> && tar -xzf esp-web-tools-<version>.tgz
for f in package/dist/web/*.js; do
  printf '"https://unpkg.com/esp-web-tools@<version>/dist/web/%s": "sha384-%s",\n' "${f##*/}" "$(openssl dgst -sha384 -binary "$f" | openssl base64 -A)"
done
```

## Home Assistant over MQTT

MQTT is off until you configure it, on the System page of the web UI or with `mqtt.set {"enabled", "host", "port"?, "username"?, "password"?, "prefix"?}`. The host is a name or an IPv4 address, the port defaults to 1883 and the discovery prefix to `homeassistant`; fields left out take those defaults. The password is cleared by `""`, and kept when left out only while the host, port and username stay the same: a change to any of them without a password clears it, so the stored password never goes to another broker. `mqtt.get` answers `{enabled, host, port, username, prefix, passwordSet, connected, problem}`, with `problem` null or why the board is not connected (`cannot reach the broker`, `the broker refused the username or password`, `the broker refused a subscription`), and never the password. The board connects over plain TCP (no TLS), as client `<board>`, and reconnects at once after a change. After a failure it waits 1 s, then twice as long each time up to 2 min; the wait starts again from 1 s only after a connection has held for a minute.

Topics, with `<board>` = `latchkey-` and the last three bytes of the board's Wi-Fi MAC address, and `<lock>` = the lock's MAC address as 12 lowercase hex digits:

| Topic | Payload |
|---|---|
| `latchkey/<board>/availability` | `online` when connected, `offline` as the last will and when MQTT is turned off; retained |
| `latchkey/<board>/<lock>/state` | `LOCKED` or `UNLOCKED`; retained |
| `latchkey/<board>/<lock>/battery` | battery level, 0 to 100; retained |
| `latchkey/<board>/<lock>/last_event` | the last lock or unlock, as the web UI words it (`Unlocked from the app`); retained |
| `latchkey/<board>/<lock>/link` | `ON` while the board has heard the lock within the last 2 minutes, else `OFF`; retained |
| `latchkey/<board>/<lock>/alert` | `{"event_type": "unexpected_unlock", "method", "time"}` for each `lock.alert` event raised by the operation-log check; not retained |
| `latchkey/<board>/<lock>/set` | commands from Home Assistant: `LOCK` or `UNLOCK` |

- On each connection the board publishes, retained, one discovery config per entity of every lock it holds, under `<prefix>/<component>/<board>/<object>/config`: a `lock`, a battery `sensor`, a last-event `sensor`, a link `binary_sensor` and an unlock-alert `event`, grouped as one device per lock (its name, model and firmware). It checks its locks every 30 s and after each command: a lock that is renamed is announced again, and one that is forgotten or reset loses its configs and state topics (empty retained messages, sent again until they go out). A config under the board's node id for a lock the board does not hold, which the board finds when it connects, loses that lock's configs and state topics too. A new discovery prefix or broker first removes the board's entities under the old one, and waits up to 3 s for the broker to confirm each removal. `system.factoryReset` removes every entity and the availability topic from the broker the same way before it erases the board; if MQTT is not connected at that moment, or the broker does not confirm in time, Home Assistant keeps an unavailable device until you delete it there.
- The board subscribes to the `set` topic of each lock it holds, so commands for other lock ids never reach it. `LOCK` and `UNLOCK` run as web jobs do, through the same queue and without a button press, and every command that runs is audited with the source `mqtt`. A lock takes one queued MQTT command at a time. Commands refused because one is already queued (`queued`), because the job queue is full (`busy`) or because the board's own queue overflowed (`dropped`) are counted: the first refusal of each kind gives an audit entry `mqtt.command` with the result `<kind> x<count>` at once, the later ones at most one entry a minute, so a flood of messages cannot wear out the flash. Any other payload is ignored and logged, and so is a retained command: the broker hands a retained message to every new subscription, so a retained `UNLOCK` would otherwise open the door each time the board reconnects. These log lines, too, come at most once a minute per kind, with a count.
- The state and the battery follow every `lock.state` event, and the last event every `lock.event`. A paired lock's adverts carry no lock state, so the board also reads each lock's status once MQTT is connected after a boot, then every 6 hours, or 15 minutes after a read the lock did not answer; any other job that brings a fresh battery level postpones that read. It reads one lock at a time, only when no web job is waiting, and at least a minute after the previous read, so with several locks the reads spread out. A status read is one Bluetooth connection, up to the 30 s a paired lock may take to advertise.
- `test_mqtt.py` runs against a board and the broker of the optional `mqtt` key in `secrets.local.json` (`{host, port, username, password}`; it skips without it, and on a board whose MQTT is on or set for another broker) with paho-mqtt 2.1.0, and uses its own discovery prefixes, `latchkey_hil` and `latchkey_hil2`, so Home Assistant does not pick its entities up. On a board that holds the lock it unlocks and locks the lock from MQTT and leaves it locked; on a board without locks or an owner login it also factory-resets the board and claims it again. It also checks the retries against a wrong password, a name that does not resolve and an address that does not answer. At the end it turns MQTT off, clears the retained messages it caused and restores the board's settings.

```sh
uv run -q --no-project --python 3.14 --with pytest==9.1.1 --with pyserial==3.5 --with paho-mqtt==2.1.0 pytest tools/hil/test_mqtt.py --port <port>
```

## Logs

The board files every log line the USB console prints with `#` (ESP-IDF's and Latchkey's) in a ring in RAM: 6 KiB on the classic ESP32, about 100 lines, kept in RTC memory so it costs no heap, and 16 KiB on the ESP32-S3, about 300 lines. The ring starts empty at each boot, numbers its lines from 1, and drops the oldest line when full. Lines the Wi-Fi driver writes in pieces are joined into one, as the console shows them. The ROM and bootloader lines before the application starts, and the console's replies and events, are not log lines and never reach the ring.

- `system.logs {"since"?, "level"?, "limit"?}` (not audited) answers `{"lines": [{"seq", "uptimeMs", "utcMs", "level", "tag", "message"}], "more", "next", "missed"}`, oldest line first. `level` is `error`, `warn`, `info`, `debug` or `verbose` and keeps that level and the more severe ones (default `verbose`); `limit` is 1 to 100 (default 100). Without `since` it gives the newest lines; with it, the lines after that sequence number. Pass `next` as `since` to continue: `more` says matching lines follow, and the board also stops early when a page would be long (2 KiB of text on the classic ESP32, 4 KiB on the ESP32-S3). `missed` counts lines that left the ring after `since` before you asked. `utcMs` is null until the clock is set, and is worked out from the line's age, so lines from before the first SNTP sync get a time too. A `next` below the `since` you sent means the board restarted.
- A line shaped like a secret is filed as `line withheld: it matched a secret pattern` and counted in `system.info.logs` (`{lines, capacity, withheld}`); [SECURITY.md](SECURITY.md) says which shapes.
- The System page of the web UI shows the lines newest first, filters them by level, asks for new ones every 3 s while it is open (it can be turned off) and copies the shown lines as text.

### Remote logging (syslog)

Off until you turn it on, on the System page or with `system.syslog.set {"enabled", "host", "port"?, "transport"?, "appName"?, "level"?}` (audited). The host is a name or an IPv4 address, required to turn it on; the port defaults to 514, the transport to `udp` (or `tcp`), the app name to `latchkey` (1 to 48 printable ASCII characters) and the level to `info`; fields left out take those defaults. `system.syslog.get` answers the settings plus `{connected, sent, dropped, errors}`, and `system.info.syslog` has `{enabled, connected, sent, dropped, errors}`. The settings are one NVS item and survive a restart; `system.factoryReset` erases them.

```text
<134>1 2026-11-08T14:03:07.512Z esp32s3-atom latchkey - wifi [meta sequenceId="4812" sysUpTime="130412"] connected, ip 192.0.2.62
```

- Each line is one RFC 5424 message: facility `local0`, severity from the level (error 3, warn 4, info 6, debug and verbose 7), the UTC time with milliseconds or `-` before the clock is set, the board name (`system.info.board`) as HOSTNAME, the app name, the log tag as MSGID (`-` for none), and a `meta` element with the line's sequence number and the board's uptime in hundredths of a second, so a collector can spot gaps. Two boards of the same model share a board name: give them different app names. Over UDP each message is one datagram of at most 1,024 bytes; over TCP each is framed with octet counting (RFC 6587: the byte count, a space, the message).
- When remote logging is turned on, the board first sends the lines the ring already holds, then each new line as it comes. A task created the first time remote logging is turned on does the sending (it stays until the next restart, about 4 KB of RAM); the logger only files lines in the ring and never waits for the network. Lines the ring overwrites before they could be sent, because the collector was unreachable or slower than the log, are counted in `dropped`. After a failure the board waits 1 s, then twice as long each time up to 2 minutes, and logs one warning per run of failures. A TCP collector that closes an idle connection is reconnected at the next line without a warning. On the classic ESP32, prefer UDP: a TCP collector that stops reading can hold up to about 6 KB of unacknowledged lines in the board's memory. Remote logging costs the classic about 4.5 KB of RAM while it is on. Hardware checks require at least 30 KB of minimum free heap with MQTT, syslog and HTTPS active, and at least 1 KiB spare in each active task stack.
- Receivers: rsyslog (`imudp` and `imtcp`, which take octet counting by default), Grafana Alloy's `loki.source.syslog` with `syslog_format = "rfc5424"` (forwarding to Loki), and the log centres of NAS systems that accept RFC 5424 (IETF) syslog.
- `test_logs.py` checks the ring and the settings on a board; with the optional `hil_syslog` key in `secrets.local.json` (`{host, port}`: a free port on the `hil_relay` host, at the address the boards reach it by) it also runs a listener there for under a minute and checks the lines the board sends over TCP and UDP. It puts the board's remote logging settings back at the end.

```sh
uv run -q --no-project --python 3.14 --with pytest==9.1.1 --with pyserial==3.5 pytest tools/hil/test_logs.py --port <port>
```

## Contributing

- Pull requests run CI: the source checks, the host tests, both firmware builds and the web UI suite.
- Every file starts with an SPDX line, `SPDX-License-Identifier: GPL-3.0-or-later`; `python3 tools/ci/check_sources.py` lists the exceptions.
- `components/ttlock` and `components/latchkey_util` include no ESP-IDF header: they build and run on the host.
- Add tests with the change: Unity in `test/` for the components, `unittest` for the Python tools, Playwright in `tools/ui-tests/` for the web UI.
- Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/).
- Nothing about a real network or device goes into the repository: examples and tests use RFC 5737 addresses (`192.0.2.0/24`) and made-up MAC addresses, and local settings stay in the gitignored `secrets.local.json`.
- Report vulnerabilities privately, as [SECURITY.md](SECURITY.md) explains.

## Credits

- [kind3r/ttlock-sdk-js](https://github.com/kind3r/ttlock-sdk-js) (GPL-3.0), the primary reference for the TTLock protocol; the protocol core is ported from it.
- [roquerodrigo/ttlock-ble](https://github.com/roquerodrigo/ttlock-ble) (MIT), the second reference and the source of most test vectors.
- [kokke/tiny-AES-c](https://github.com/kokke/tiny-AES-c) (public domain), vendored for AES-128-CBC.
- [ESP Web Tools](https://github.com/esphome/esp-web-tools) (Apache-2.0) for the browser flasher, and ESP-IDF, PlatformIO, cJSON, Unity and Playwright for everything else.

`NOTICE` has the details and license terms.

## License

GPL-3.0-or-later. See `LICENSE` and `NOTICE`.
