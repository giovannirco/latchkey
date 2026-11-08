# Latchkey

Latchkey is firmware for ESP32 boards that takes a TTLock Bluetooth LE smart lock off the TTLock cloud and puts it under one owner's control: the board pairs with the lock by itself, manages what the TTLock app can manage on that lock, and serves an owner-only web UI, with no phone app, TTLock account or computer Bluetooth involved. This is the repository skeleton: the firmware builds for both boards and prints a boot line; the protocol core and the services come next.

## Build, test, flash

Run PlatformIO only through `uvx` at the pinned version, from the repository root.

```sh
uvx platformio==6.2.0 test -e native
uvx platformio==6.2.0 run -e esp32 -e esp32s3
uvx platformio==6.2.0 run -e esp32 -t upload --upload-port /dev/cu.usbserial-0001
uvx platformio==6.2.0 run -e esp32s3 -t upload --upload-port /dev/cu.usbmodem11201
uvx platformio==6.2.0 device monitor -e esp32 --port /dev/cu.usbserial-0001
```

| Env | Board name | Flash | Button | Console |
|---|---|---|---|---|
| `esp32` | `esp32-devkit` (classic ESP32) | 4 MB | GPIO0 | UART0, 115200 baud |
| `esp32s3` | `esp32s3-atom` (ESP32-S3, AtomS3-class) | 8 MB | GPIO41 | USB-Serial/JTAG |
| `native` | host unit tests for `components/ttlock` and `components/latchkey_util` | | | |

## Serial console

The console speaks JSON lines: send one request per line, `{"id": 1, "method": "system.info", "params": {}}`, and read one line per reply, `{"id": 1, "result": {...}}` or `{"id": 1, "error": {"code": "...", "message": "..."}}`. Events arrive as `{"event": "...", "data": {...}}` lines. Every log line of the application starts with `#`, the first one being `# latchkey <fw-version> board=<board> chip=<chip> idf=<idf-version>`; the ROM and bootloader lines before it are plain text, and the CLI skips every line that is not a JSON object. Requests over the console count as physical presence: they need no session and no button press. `system.setup` (claim the board: Wi-Fi with a static IP and the owner password; returns the TOTP `otpauth://` URI once) and `system.time.set` are accepted only there.

```sh
uv run -q --no-project --python 3.14 --with pyserial==3.5 python -I tools/latchkey_cli.py --port <port> system.info
uv run -q --no-project --python 3.14 --with pytest==9.1.1 --with pyserial==3.5 pytest tools/hil -k system --port <port>
```

`tools/latchkey_cli.py` reads params as a JSON argument or from stdin with `-`. The hardware-in-the-loop suite in `tools/hil/` factory-resets the board it runs on and reads the Wi-Fi settings, the owner password and each board's static IP from the gitignored `secrets.local.json` (shape in `secrets.example.json`).

`sdkconfig.<env>` is generated and not tracked. After editing `sdkconfig.defaults` or `sdkconfig.defaults.<target>`, delete `sdkconfig.<env>` and `.pio/build/<env>`. After adding source files to a component or dependencies to `src/idf_component.yml`, delete `.pio/build/<env>`: PlatformIO does not re-run the CMake configure for those changes.

## Pinned versions

- PlatformIO Core 6.2.0.
- `espressif32@8.0.0` with exact `platform_packages` in `[esp_common]`: `framework-espidf` 4.60100.0 (ESP-IDF v6.1.0), `toolchain-xtensa-esp-elf` 15.2.0+20251204, `tool-esptool` 2.50400.0 (esptool v5.4.0), `tool-cmake` 3.30.2, `tool-ninja` 1.13.2. The platform itself pins `toolchain-riscv32-esp` 15.2.0+20251204 (S3 ULP) and `tool-esp-rom-elfs` 0.0.1+20241011; `toolchain-esp32ulp` still resolves from `~1.23800.0` (1.23800.240113 today).
- `native@1.2.1` with Unity 2.6.1 for host tests.
- ESP-IDF managed components are declared in `src/idf_component.yml` and locked per target in `dependencies.lock.esp32` and `dependencies.lock.esp32s3`.
- The headers in `test/vectors/` are generated. `tools/vectors/gen_vectors.py` uses ttlock-ble 0.3.4: `uv run -q --no-project --python 3.14 --with ttlock-ble==0.3.4 python -I tools/vectors/gen_vectors.py`. `tools/vectors/kind3r_vectors.ts` uses Deno 2.9.8 and a kind3r/ttlock-sdk-js checkout at 8c84cda, with moment 2.29.1 locked in `tools/vectors/deno.lock`: `TZ=UTC deno run --allow-env --allow-read --allow-write=test/vectors --config tools/vectors/kind3r_deno.json tools/vectors/kind3r_vectors.ts <checkout>`.

## License

GPL-3.0-or-later. See `LICENSE` and `NOTICE`.
