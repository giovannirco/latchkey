<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# v1.0.0 readiness

As of 2026-11-09 UTC, v0.4.0 is the latest published release. v1.0.0 is not ready to tag. The owner authorized backup/hardening application code and offline tests, and confirmed that weekly passcode creation/editing and remote-unlock controls remain required for v1.0.0. OTA and its hardware checks are deferred beyond v1.0.0. Flashing, real-device operations and unverified switch writes remain excluded from this development pass.

## Release requirements

| Requirement | Evidence and remaining work |
|---|---|
| Lock settings, operation log and alerts | Released in v0.3.0; [#17](https://github.com/giovannirco/latchkey/issues/17) closed. |
| Logging, syslog and Wi-Fi form | Released in [v0.4.0](https://github.com/giovannirco/latchkey/releases/tag/v0.4.0); [#18](https://github.com/giovannirco/latchkey/issues/18) closed. |
| Encrypted backup, hardening and two-board restore | [#19](https://github.com/giovannirco/latchkey/issues/19) is being implemented with offline tests under the [backup/hardening contract](backup-hardening.md). Browser mock success is not evidence of recovery on hardware. Two-board restore remains unverified and outside this pass. |
| Weekly passcode creation and editing | Required for v1.0.0. Listing and deletion exist; creation/editing need a source-backed command layout, protocol tests, board API and UI. |
| Remote-unlock control | Required for v1.0.0. The protocol command exists; the board API, UI and offline integration tests are missing. |
| Switch write layout | [#20](https://github.com/giovannirco/latchkey/issues/20) remains unverified. Writes stay refused; proving the layout requires the owner at the lock and separate device work. |
| Board web updates and rollback | Deferred beyond v1.0.0 by the owner. [#23](https://github.com/giovannirco/latchkey/issues/23) remains on the unmerged `feat/ota` branch; the upload heap budget and review remain open. |
| Update, rollback and key preservation on hardware | Deferred beyond v1.0.0 with OTA. [#24](https://github.com/giovannirco/latchkey/issues/24) remains open and needs the owner's button press. |
| Review follow-ups | [#21](https://github.com/giovannirco/latchkey/issues/21) remains open; firmware findings are not resolved by browser changes. |
| Passage reliability | v0.4.0 includes the longer acknowledgement wait. The separate post-acknowledgement readback disconnect in [#31](https://github.com/giovannirco/latchkey/issues/31) remains untraced. No new hardware proof in this pass. |
| Final review and acceptance | [#25](https://github.com/giovannirco/latchkey/issues/25) remains open. A browser review does not replace whole-branch review, board acceptance or a two-board restore. |

## Remaining feature coverage

The original goal of covering the lock's supported app features is broader than the implemented board API:

- Encrypted backup/import and hardening have browser mock flows; application code and offline tests are in progress. Backup must preserve keys, labels and seed tables; hardening needs a preview, step results, persisted state and recovery protections.
- Reset-button, privacy-lock and tamper-alert reads work. Writes remain refused until their layout is verified on hardware. Full hardening depends on the reset-button verification.
- Weekly/cyclic passcodes can be listed and deleted, but cannot be created or edited. The weekly-window command layout is missing; fingerprint and card schedules already work.
- The remote-unlock/gateway switch exists in the protocol core but is not exposed through the board API or UI. Reported hotel and accessory bits also do not imply implemented controls. See [protocol coverage](protocol.md).

Offline guest-code generation, metrics, MQTT TLS, button discovery and wireless keypad/key-fob support remain unscheduled in [#22](https://github.com/giovannirco/latchkey/issues/22). That list is not an approved v1.0.0 commitment. Weekly passcode creation/editing also appears there, but the owner explicitly retained it and remote-unlock controls as v1.0.0 requirements on 2026-11-09 UTC.

## Browser corrections

- HTTP deadlines include reading the response body.
- Successful RPC replies must match the request and contain an object result; completed jobs also require an object result. Invalid replies cannot become success notices.
- Ending a session clears pending and cached jobs. Old responses cannot reopen secret dialogs or invalidate a newer session.
- Failure to open the event connection after login shows a retry action using the existing session.

Regression tests live in `tools/ui-tests/rpc-response.spec.cjs`, `session-boundary.spec.cjs`, `startup.spec.cjs` and `auth.spec.cjs`. They exercise the browser against the local mock, including controlled response ordering and an interrupted native WebSocket handshake. They do not operate a real board or lock.

## Verification

Run the non-device checks from the repository root:

```sh
sh tools/ui-tests/run.sh
python3 -m unittest discover -s tools/ci -p 'test_*.py'
python3 -m unittest discover -s tools/release -p 'test_*.py'
python3 tools/ci/check_sources.py
node --check web/app.js
git diff --check
```

Optional screenshot checks require `LK_SHOTS_DIR`; otherwise those cases skip. Concurrent Playwright runs need different `LK_UI_PORT` values and separate `--output` directories to avoid shared mock state and artifact deletion.

Before tagging v1.0.0, complete or explicitly revise the unresolved requirements in #25, verify CI on the final main commit, and record the hardware acceptance evidence. Keep the version at 0.4.0 until that release decision; this pass does not publish or flash a release.
