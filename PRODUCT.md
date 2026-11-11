<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Latchkey

Latchkey lets an owner manage a TTLock Bluetooth LE lock through an ESP32 and a local, owner-only web interface. No vendor cloud or phone app is required for lock management.

## Installer surface

The GitHub Pages site serves people commissioning a new board or recovering lock access on a replacement. Its primary task is to get the correct firmware installed, establish owner access, and explain the next safe step. The firmware's own web UI is a separate surface.

- Supported release images: classic ESP32 with 4 MB flash and ESP32-S3 with 8 MB flash and native USB. Both use GPIO0 for confirmation.
- Factory images erase board settings and lock keys. Existing configured boards must use the documented update procedure instead.
- USB setup requires static IPv4 settings, an owner password, and saving the board's one-time authenticator secret.
- Existing encrypted `.lkb` backups contain lock recovery data, not Wi-Fi, owner login, or TLS identity.
- Backups and credentials must stay between the user's browser and the connected board. They must never be hosted on Pages, sent to analytics, or persisted in browser storage.
- Each board generates its own TLS identity. The installer must show the certificate fingerprint for verification.
- Unsupported browsers, missing releases, disconnects, and uncertain write results need explicit next steps.
- The installer must work on narrow screens; browser flashing requires desktop Web Serial support.

## Success

A first-time visitor can distinguish installation from an existing-board update, choose a supported board, and proceed without terminal instructions being the primary path. Technical downloads and recovery limitations remain accessible.
