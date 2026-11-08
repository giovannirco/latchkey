<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Working on Latchkey

Instructions for coding agents and people working in this repository. Read `README.md` for what Latchkey is, `SECURITY.md` for the security model, `docs/protocol.md` for the TTLock protocol notes and `docs/hardware.md` for boards and flashing.

## Layout

| Path | What lives there |
|---|---|
| `components/ttlock/` | TTLock protocol core: CRC, AES, frames, commands, session flows. No ESP-IDF headers; tested on the host. |
| `components/latchkey_util/` | Pure helpers with host tests: TOTP, rate limit, time zones, sessions, request checks, storage budget, Home Assistant payloads, and more. No ESP-IDF headers. |
| `src/` | Firmware services: serial and HTTPS RPC, WebSocket events, owner auth, button confirmation, jobs, BLE central, lock manager, storage, audit, MQTT, access methods. |
| `web/` | The owner web UI (plain HTML, CSS and JavaScript). |
| `tools/mock_api.py` | A mock of the board API. It defines the JSON shapes; the firmware follows it. |
| `tools/ui-tests/` | Playwright tests of the UI against the mock. |
| `tools/hil/` | Hardware-in-the-loop tests (pytest) that drive real boards over USB serial and HTTPS. |
| `test/` | Host tests (Unity) for the components. |

## Commands

```sh
uvx platformio==6.2.0 test -e native            # host tests (add -f <suite> to filter)
uvx platformio==6.2.0 run -e esp32 -e esp32s3    # firmware builds; CI fails above 1,887,436 bytes for esp32
sh tools/ui-tests/run.sh                         # UI tests against the mock
python3 tools/ci/check_sources.py                # SPDX headers, no ESP-IDF includes in components
python3 tools/mock_api.py --port 8765            # the UI against the mock: http://127.0.0.1:8765
```

Hardware tests read board ports, addresses and credentials from a gitignored `secrets.local.json` at the repository root (see `secrets.example.json`):

```sh
uv run --no-project --python 3.14 --with pytest==9.1.1 --with pyserial==3.5 \
  pytest tools/hil/test_system.py --port <serial port> -v
```

## Flashing safely

- Flash with `uvx platformio==6.2.0 run -e <env> -t upload --upload-port <port>`. This writes the bootloader, partition table and app at their offsets and keeps the settings partition (NVS), where the lock keys live.
- Never add `-t nobuild` to an upload: without the build step the app is written at the default offset, over NVS.
- Never write a merged factory image (the release's `*-factory.bin`, or the browser flasher) to a board that already holds a lock: it starts at address 0 and erases the lock keys. Factory images are for new boards.

## Rules

- Write the test first and see it fail for the right reason, then make it pass.
- No comments in code; names and small functions carry the meaning.
- No fallbacks that hide failures: fail clearly instead.
- Every source file starts with `SPDX-License-Identifier: GPL-3.0-or-later`.
- Keep `components/ttlock` and `components/latchkey_util` free of ESP-IDF headers; put pure logic there with host tests.
- The public repository holds no real IP addresses, network names, MAC addresses, people's names, private paths or credentials. Examples use RFC 5737 addresses and documentation MACs (`00:00:5E:00:53:xx`). Private values belong in `secrets.local.json`.
- No secret (lock keys, passcodes, the admin passcode, the owner's password hash, TOTP secrets, session tokens, Wi-Fi or MQTT passwords) in logs, RPC results, events, audit entries, MQTT payloads or test output.
- Tests that run against a real lock leave it as they found it: delete only what they created, never clear credentials, restore names and settings, leave it locked. Destructive steps need an explicit opt-in flag.
- A button press or a keypad touch is a person's action: tests wait for it and skip without it; nothing simulates one.
- Commits are small conventional commits (`feat(fw): …`, `fix(ui): …`, `test(hil): …`, `docs: …`), with no trailers.

## Releases

A release moves the `## [Unreleased]` entries of `CHANGELOG.md` into a dated `## [x.y.z]` section and sets `PROJECT_VER` in `CMakeLists.txt`. A `vX.Y.Z` tag on `main` then builds the images, publishes the GitHub Release with that section as its notes, and updates the browser flasher on GitHub Pages.
