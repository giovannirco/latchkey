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
| `native` | host unit tests for `components/ttlock` | | | |

At boot the console prints `latchkey <fw-version> board=<board> chip=<chip> idf=<idf-version>`, then the free heap every 10 s.

`sdkconfig.<env>` is generated and not tracked. After editing `sdkconfig.defaults` or `sdkconfig.defaults.<target>`, delete `sdkconfig.<env>` and `.pio/build/<env>`. After adding source files to a component or dependencies to `src/idf_component.yml`, delete `.pio/build/<env>`: PlatformIO does not re-run the CMake configure for those changes.

## Pinned versions

- PlatformIO Core 6.2.0.
- `espressif32@8.0.0`, resolved to `framework-espidf` 4.60100.0 (ESP-IDF v6.1.0), `toolchain-xtensa-esp-elf` 15.2.0+20251204, `tool-esptool` 2.50400.0 (esptool v5.4.0), `tool-cmake` 3.30.2, `tool-ninja` 1.13.2.
- `native@1.2.1` with Unity 2.6.1 for host tests.
- ESP-IDF managed components are declared in `src/idf_component.yml` and locked per target in `dependencies.lock.esp32` and `dependencies.lock.esp32s3`.

## License

GPL-3.0-or-later. See `LICENSE` and `NOTICE`.
