<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Security

## Reporting a vulnerability

Report it privately through GitHub: the "Report a vulnerability" button on the repository's Security tab, or [this form](https://github.com/giovannirco/latchkey/security/advisories/new). Please do not open a public issue. Include the firmware version and board from `system.info`, what you did and what happened. Only the latest release is supported while Latchkey is at 0.x.

## Status

Latchkey is in early development. This document is the security design. Parts that are not in the firmware yet are marked *in progress*: they are the plan, and nothing marked that way has been tested.

## The model in plain words

The owner is whoever holds the owner password and the TOTP secret, and whoever is physically at the board.

- **Claiming happens over USB only.** A fresh board has no owner. `system.setup` (Wi-Fi with a static IPv4 address, owner password) is accepted only on the USB serial console; it returns the TOTP secret once, as an `otpauth://` URI. A claimed board refuses a second claim.
- **USB serial counts as physical presence.** Requests over the serial console need no session and no button press: that includes `system.factoryReset`, which from the web also needs a press of the board's button, and `system.time.set`, which only the console accepts. Anyone who can plug into the board's USB port can therefore reset it and claim it again, and a compromised computer left connected to the board can run destructive actions without a press. Keep the board where only you can reach it, and do not leave it connected to a computer you do not trust.
- **Owner password.** Stored as PBKDF2-HMAC-SHA256 with a random 16-byte salt. The cost is 4400 iterations, about 1 s on the classic ESP32 at 160 MHz and about 0.6 s on the ESP32-S3; it is stored with the hash, so a later firmware can raise it without breaking an existing claim. The password itself is wiped from memory after hashing. Today the hash cost is the only protection against guessing the password; the TOTP code and the login rate limiting meant to carry most of that weight come with the web login (*in progress*).
- **TOTP.** RFC 6238 with SHA-1, 6 digits and 30-second steps; the 20-byte secret is generated on the board when it is claimed. Web login asks for the password and a current code, accepting one step of clock drift either way (*in progress*).
- **Web sessions** (*in progress*). A random session token in a cookie marked `Secure`, `HttpOnly` and `SameSite=Strict`, with an idle timeout; failed logins slow down with a growing backoff. The API accepts only JSON from the page's own origin.
- **Button confirmation** (*in progress*). Destructive actions requested from the web wait up to 30 seconds for a press of the board's button: factory resets of the board or a lock, pairing, hardening, key export and import, changing the lock's admin passcode, re-enabling the lock's reset button, rotating the TOTP secret and firmware updates.
- **HTTPS** (*in progress*). On first boot the board generates its own EC P-256 key and self-signed certificate and keeps them. The certificate's SHA-256 fingerprint is shown on the serial console and in `system.info`: compare it with what the browser shows the first time you connect. Plain HTTP only redirects to HTTPS.
- **Audit log.** The last 200 actions, each with the time, the origin (serial or web), the method, the target and the result, kept in NVS; `audit.list` reads them. Methods can add entries but not change them; `system.factoryReset` clears the log. Entries never contain secrets.
- **Secrets stay on the board.** Lock keys, the owner hash, the TOTP secret, session tokens and the Wi-Fi password never appear in logs, RPC results, events or audit entries, except the TOTP secret in the one-time `system.setup` reply over USB serial, as the `otpauth://` URI.
- **Lock hardening** (*in progress*, `lock.harden`). Pairing already gives the lock a random 7-digit admin passcode in place of the factory one. Hardening then removes every passcode Latchkey did not create, the factory defaults included, and disables the lock's physical reset button, but only after an encrypted backup of that lock's keys has succeeded, so the keys are never held by a single board with no way back.
- **Key backup** (*in progress*, `keys.export` and `keys.import`). Lock keys leave the board only inside an AES-256-GCM blob whose key comes from a passphrase through PBKDF2-HMAC-SHA256, with a random salt and nonce in the blob.
- **No cloud.** The board talks to the lock over Bluetooth LE and to your browser over your own network. Its only traffic to the internet is DNS and SNTP time queries to `pool.ntp.org` and `time.cloudflare.com`, because the lock protocol needs the correct time. There is no TTLock account, no phone app and no telemetry.

## Security profile P1

Latchkey targets one threat profile, P1: someone may get hold of the board, but will not read its flash chip.

- Lock keys (the lock's AES key, `adminPs`, `unlockKey`, the admin passcode), the owner password hash and the TOTP secret sit in NVS in plaintext. Confidentiality at rest is not claimed: whoever reads the flash of a stolen board can operate the locks it manages.
- Flash encryption with NVS encryption (`nvs_flash_secure_init()`, profile P2) protects against that, but it is opt-in and not the default. It burns eFuses in the chip, which cannot be undone, and a mistake during that step can leave a board that never boots again. An encrypted board also no longer takes the plaintext release images or the browser flasher, so updates and recovery get harder. Latchkey does not ship a P2 configuration yet; owners who accept those costs can build one.
- In practice: mount the board indoors, out of reach from outside the door. If a board is lost or stolen, treat the keys of its locks as known to someone else: restore the encrypted backup on another board, factory-reset each lock from there and pair it again (*in progress*); a lock whose reset button is still enabled can also be reset at the lock.

## Limits of the TTLock protocol

These come from the locks and are outside Latchkey's control; [docs/protocol.md](docs/protocol.md) has the details.

- Before pairing, every lock uses the same public AES key, and the lock sends its own key during pairing encrypted only with that public key. Someone who records the Bluetooth traffic of a pairing learns the lock's key. Pair where nobody else is within Bluetooth range.
- Frames are AES-128-CBC with the key as the IV and no message authentication. Lock and unlock answer a random challenge the lock sends first; whether a given lock rejects a replayed frame depends on its firmware and has not been tested by this project.

## Out of scope

- Reading the board's flash, or any attack that needs the board in hand (profile P1).
- A compromised computer connected to the board's USB port.
- Physical and mechanical attacks on the lock, its keypad, fingerprint and card readers, and its own firmware.
- Bluetooth or Wi-Fi jamming, which can stop the board from reaching the lock but not open it.
- Reproducible builds: they are not claimed. Release images are built by GitHub Actions from the tagged commit with the pinned toolchain.

## Supply chain

- The toolchain is pinned: PlatformIO Core 6.2.0, `espressif32@8.0.0` (ESP-IDF 6.1.0) with exact package versions in `platformio.ini`, and the ESP-IDF managed components locked per target in `dependencies.lock.esp32` and `dependencies.lock.esp32s3`.
- Every GitHub Action is pinned to a full commit SHA. Each job gets only the permissions it needs, CI needs no secrets, only the release job can write releases and only the Pages job can deploy the site.
- Each release publishes `SHA256SUMS` next to its images. The browser flasher serves the images from the same origin as the page and loads ESP Web Tools 10.4.0 from unpkg with every module pinned by its SHA-384 hash, so a modified file is refused by the browser. To avoid third-party code altogether, check the image against `SHA256SUMS` and flash it with esptool ([docs/hardware.md](docs/hardware.md)).
