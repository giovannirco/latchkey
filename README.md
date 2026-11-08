<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Latchkey

[![CI](https://github.com/giovannirco/latchkey/actions/workflows/ci.yml/badge.svg)](https://github.com/giovannirco/latchkey/actions/workflows/ci.yml)

Latchkey is firmware for ESP32 boards that takes a TTLock Bluetooth LE smart lock off the TTLock cloud and puts it under one owner's control: the board pairs with the lock by itself, manages what the TTLock app can manage on that lock, and serves an owner-only web UI, with no phone app, TTLock account or computer Bluetooth involved.

Latchkey is in early development. The TTLock protocol core, the USB serial console, claiming the board, Wi-Fi, time and the audit log are in place; pairing from the board, the web UI on the board, HTTPS, TOTP login, button confirmation, hardening and key backup are being built.

## Why

- TTLock locks are sold under many brands and normally need the vendor's phone app and cloud account. Latchkey keeps every key and every decision on a board you own, on your network.
- The open-source alternatives run the protocol on a computer or a phone, or use an ESP32 only to relay Bluetooth to one. Latchkey runs the whole protocol on the ESP32, from the first pairing on.
- It aims to make the lock harder to take over than it is out of the box: claiming only over USB, a password and TOTP code for the web, a button press on the board for destructive actions, an audit log, and a hardening step that replaces the lock's default credentials and disables its reset button once the keys are safely backed up.

## Features

Works today:

- TTLock protocol core (`components/ttlock`), tested on the host: pairing, lock and unlock, status and battery, device info and feature bits, time sync, passcodes, IC cards and fingerprints with validity periods and weekly windows, auto-lock, passage mode, sound, remote unlock, the reset button, privacy lock and tamper alert switches, the passcode display, the operation log and factory reset. A command the lock does not report in its feature bits answers `unsupported` without touching the radio.
- Firmware for the classic ESP32 and the ESP32-S3: a JSON-lines console over USB, claiming the board, Wi-Fi with a static address, SNTP time and an audit log.
- The owner web UI (`web/`), built and tested against a mock of the board API.

In progress: the Bluetooth link and lock manager on the board, the web UI served by the board over HTTPS, TOTP login, button confirmation, over-the-air updates, lock hardening and the encrypted key backup.

## Security model

- The board is claimed only over its USB serial console, which counts as physical presence.
- Web login with the owner password (PBKDF2-HMAC-SHA256) and a TOTP code (in progress).
- Destructive actions from the web also need a press of the board's button (in progress).
- HTTPS with a certificate the board generates, whose fingerprint you check once (in progress).
- An audit log of every action, never containing secrets.
- Hardening (in progress): a random admin passcode on the lock, unknown passcodes removed, the lock's reset button disabled only after an encrypted backup of its keys.
- No cloud: the board only reaches the internet for DNS and SNTP.
- Profile P1: lock keys sit in plaintext NVS, so whoever reads the flash of a stolen board can use them. Flash encryption is possible but not the default.

[SECURITY.md](SECURITY.md) has the full model and how to report a vulnerability; [docs/protocol.md](docs/protocol.md) has the protocol notes and its limits.

## Supported boards

| Env | Board name | Flash | Button | Console |
|---|---|---|---|---|
| `esp32` | `esp32-devkit` (classic ESP32) | 4 MB | GPIO0 | UART0, 115200 baud |
| `esp32s3` | `esp32s3-atom` (ESP32-S3, AtomS3-class) | 8 MB | GPIO41 | USB-Serial/JTAG |
| `native` | host unit tests for `components/ttlock` and `components/latchkey_util` | | | |

An M5 ATOM runs the `esp32` build with `LATCHKEY_BUTTON_GPIO=39`. The ESP8266 cannot work: it has no Bluetooth. [docs/hardware.md](docs/hardware.md) covers the button pins, flashing, power and where to put the board.

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

The console speaks JSON lines: send one request per line, `{"id": 1, "method": "system.info", "params": {}}`, and read one line per reply, `{"id": 1, "result": {...}}` or `{"id": 1, "error": {"code": "...", "message": "..."}}`. Events arrive as `{"event": "...", "data": {...}}` lines. Every log line of the application starts with `#`, the first one being `# latchkey <fw-version> board=<board> chip=<chip> idf=<idf-version>`; the ROM and bootloader lines before it are plain text, and the CLI skips every line that is not a JSON object. Requests over the console count as physical presence: they need no session and no button press. `system.setup` (claim the board: Wi-Fi with a static IP and the owner password; returns the TOTP `otpauth://` URI once) and `system.time.set` are accepted only there. The owner password is stored as PBKDF2-HMAC-SHA256 with a random 16-byte salt. The iteration count is calibrated to about 1 s on the classic ESP32 at 160 MHz (4400 iterations, about 0.6 s on the ESP32-S3) and stored with the hash, so a later firmware can raise it without breaking an existing claim. Requests nested deeper than 8 arrays or objects are refused before parsing.

```sh
uv run -q --no-project --python 3.14 --with pyserial==3.5 python -I tools/latchkey_cli.py --port <port> system.info
uv run -q --no-project --python 3.14 --with pytest==9.1.1 --with pyserial==3.5 pytest tools/hil -k system --port <port>
```

`tools/latchkey_cli.py` reads params as a JSON argument or from stdin with `-`. The hardware-in-the-loop suite in `tools/hil/` factory-resets the board it runs on and reads the Wi-Fi settings, the owner password and each board's static IP from the gitignored `secrets.local.json` (shape in `secrets.example.json`).

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
