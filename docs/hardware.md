<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Hardware

## Supported boards

| Board | Chip | Flash | Build env | Release images | Button | Console |
|---|---|---|---|---|---|---|
| ESP32 DevKit, or any classic ESP32 board with 4 MB of flash | ESP32 | 4 MB | `esp32` | `latchkey-<version>-esp32-*.bin` | GPIO0 (BOOT) | UART0 through the board's USB-to-serial chip, 115200 baud |
| M5 ATOM | ESP32-PICO-D4 | 4 MB | `esp32`, built with `LATCHKEY_BUTTON_GPIO=39` | none | GPIO39 | UART0 through the board's USB-to-serial chip, 115200 baud |
| M5Stack StampS3, or another ESP32-S3 board with 8 MB of flash and its button on GPIO0 | ESP32-S3FN8 | 8 MB | `esp32s3` | `latchkey-<version>-esp32s3-*.bin` | GPIO0 (BOOT) | USB Serial/JTAG on the chip's own USB port |
| M5Stack AtomS3 | ESP32-S3 | 8 MB | `esp32s3`, built with `LATCHKEY_BUTTON_GPIO=41` | none | GPIO41 | USB Serial/JTAG on the chip's own USB port |

- The button pin is a build setting: `LATCHKEY_BUTTON_GPIO` in the env's `build_flags` in `platformio.ini`. The firmware reads it with the internal pull-up enabled and treats low as pressed. The release image for the classic ESP32 reads GPIO0, so an M5 ATOM needs its own build with GPIO39; GPIO39 is input-only and has no internal pull-up, so a button there relies on the pull-up of the board's own circuit. The ESP32-S3 release image reads GPIO0 too, the StampS3's button, so an AtomS3 needs its own build with `-DLATCHKEY_BUTTON_GPIO=41`.
- The button confirms destructive actions requested from the web UI: pairing or resetting a lock, showing or changing a lock's super admin passcode, exporting or importing the key backup, running lock hardening, a new TOTP secret and a factory reset of the board wait up to 30 s for a press. Requests over USB serial need no press, because USB counts as physical presence.
- GPIO0 is a strapping pin on the ESP32 and the ESP32-S3: holding it while the board resets starts the ROM download mode instead of Latchkey. On boards whose button is GPIO0, such as the DevKit and the StampS3, do not hold the button while plugging the board in or resetting it.
- `system.info` reports the board as `esp32-devkit` or `esp32s3`, the names the two envs build in. Older S3 firmware used `esp32s3-atom`; existing authenticator entries and certificates keep their issued labels and remain valid.

### Flash layout

Both layouts keep two app slots, reserved for over-the-air updates with rollback (`partitions/4mb.csv`, `partitions/8mb.csv`):

| Region | Offset | 4 MB board | 8 MB board |
|---|---|---|---|
| bootloader | `0x1000` on the ESP32, `0x0` on the ESP32-S3 | | |
| partition table | `0x8000` | | |
| `nvs`: settings, owner, lock keys, audit log | `0x9000` | 64 KB | 64 KB |
| `otadata` | `0x19000` | 8 KB | 8 KB |
| `phy_init` | `0x1B000` | 4 KB | 4 KB |
| `ota_0` | `0x20000` | 1,920 KB | 3,072 KB |
| `ota_1` | `0x200000` (4 MB), `0x320000` (8 MB) | 1,920 KB | 3,072 KB |

The factory image of a release covers everything from `0x0` to the end of the app in `ota_0`, gaps filled with `0xFF`, which is why flashing it wipes `nvs`. CI fails when the classic ESP32 app image grows past 1.8 MB (1,887,436 bytes), which keeps headroom in its 1,920 KB slot.

## Flashing

- The browser flasher needs Chrome or Edge on a desktop computer: it reaches the board through Web Serial.
- On Linux, opening a serial port needs membership of the `dialout` group (Debian, Ubuntu) or `uucp` (Arch).
- Classic boards talk through a USB-to-serial bridge: Silicon Labs CP210x, WCH CH340/CH9102 or FTDI. If no port appears, install the bridge vendor's driver. PlatformIO uploads at 460800 baud, which CP210x and FTDI bridges handle; with a long cable or a flaky clone bridge, flash at 115200 with esptool instead: `esptool --chip esp32 --port <port> --baud 115200 write-flash 0x0 latchkey-<version>-esp32-factory.bin`.
- If a classic board does not answer the flasher, enter download mode by hand: hold BOOT (GPIO0), press and release EN (reset), release BOOT, then try again.
- The ESP32-S3 port is the chip's own USB: it disappears and comes back whenever the chip resets, after flashing, after a reboot and when it enters download mode, and the computer may give it a new name (`/dev/cu.usbmodem*` on macOS, `/dev/ttyACM*` on Linux, a new `COM` number on Windows). Pick the port again after a reset. `tools/latchkey_cli.py` reopens a `/dev/cu.usbmodem*` port by itself when exactly one such device is present.
- When an S3 does not enter download mode on its own, for example because the running firmware no longer answers on USB, hold the board's download-mode button while plugging it in, as the board vendor documents.
- Flashing the factory image erases the board, lock keys included: never write it, with esptool or the browser flasher, to a board that holds a lock. Updates from the web page are not in any release ([docs/v1-readiness.md](https://github.com/giovannirco/latchkey/blob/main/docs/v1-readiness.md)), so a board in use is updated from a checkout of the release tag: `uvx platformio==6.2.0 run -e <env> -t upload --upload-port <port>` writes the bootloader, partition table, `otadata` and app at their offsets and leaves `nvs` alone, so the keys survive. Never add `-t nobuild`: without the build step the app is written at the default offset, over `nvs`.

## Browser setup and recovery

After installing on a new board, close the flashing dialog and choose **Connect for setup** on the [installer](https://giovannirco.github.io/latchkey/). Pick the board's running USB port again if the S3 has re-enumerated. The page reads its status before offering owner setup or a local encrypted backup import. Close other serial tools first.

Setup sends static Wi-Fi settings and an owner password over USB, then displays the authenticator secret once. Save it before continuing. An existing `.lkb` backup restores lock data only: it excludes Wi-Fi, owner login, TLS identity and MQTT settings. The replacement board generates its own certificate; compare the SHA-256 fingerprint read over USB with the browser's certificate before trusting it. Neither credentials nor backups are uploaded to the Pages server or saved in browser storage.

The final connection check reads the board's status; it does not verify physical lock operation. Test access with the door open. Browser setup and restore have automated serial/browser coverage; commissioning a new empty board through this flow still needs hardware acceptance. Existing configured boards must not be factory-flashed to test it.

### Recovering a lost setup reply

If USB drops during `system.setup`, the owner may have been stored even though the authenticator reply was lost. Do not reset or reflash. Reconnect and read `system.info`: `claimed: false` means setup can be attempted again; `claimed: true` means an owner is already stored.

If claimed, keep the owner password you supplied. If you saved the authenticator secret, verify login with it. Otherwise, after deliberately choosing to replace this board's authenticator, disconnect the browser's USB session and use the CLI from a checkout:

```sh
umask 077
uv run -q --no-project --python 3.14 --with pyserial==3.5 python -I tools/latchkey_cli.py --port <port> auth.rotateTotp > owner-recovery.json
```

This invalidates the previous authenticator secret immediately; it does not change the password or lock keys. Import the returned `otpauth://` URI from the private output file into your authenticator, verify login, then delete the file. Never publish that output. A lost rotation reply needs the same deliberate recovery process, not an automatic retry. If you also lost the owner password, stop and plan recovery over the physically trusted USB console before any reset; preserve a verified lock backup first.

## Power

- USB at 5 V from a supply of at least 1 A and a short, decent cable. Wi-Fi transmit peaks draw short current spikes: a weak supply or a long thin cable makes the brownout detector reset the board.
- The board only runs Latchkey: the lock has its own batteries, and its keypad, fingerprint reader and card reader keep working while the board is off. The web UI and lock events are gone until the board is back.
- The board has no battery-backed clock. After a power cut it takes the time from SNTP once Wi-Fi is up, or from `system.time.set` over USB; lock commands that send the time wait for it.

## Placement

- Inside, out of reach from outside the door. The board's button approves destructive actions and its USB port counts as physical presence, so whoever can reach the board can approve them or claim a reset board.
- Within Bluetooth range of the lock. Bluetooth LE through a door or a wall reaches a few metres, less through metal; check from the intended spot before mounting the board.
- Within Wi-Fi range. The claim gives the board a static IPv4 address: keep it out of your router's DHCP pool so nothing else takes it.
- Not in a metal box, which blocks both radios.

## Why not the ESP8266

The ESP8266 has Wi-Fi but no Bluetooth radio, and the locks Latchkey manages only talk Bluetooth LE. No firmware can add the missing radio, so there is no ESP8266 build. The same goes for the ESP32-S2 (no Bluetooth), the ESP32-H2 (no Wi-Fi for the web UI) and the ESP32-P4 (no radio). The ESP32-C3, C5, C6 and C61 have both radios but no build or test yet.
