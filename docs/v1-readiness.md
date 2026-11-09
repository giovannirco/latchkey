<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# v1.0.0 readiness

As of 2026-11-09 UTC, v0.4.0 is the latest published release. v1.0.0 is not ready to tag. The current development pass covers the web UI, development tools and documentation; firmware development, flashing and device writes are excluded. This does not waive the remaining release requirements.

## Release requirements

| Requirement | Evidence and remaining work |
|---|---|
| Lock settings, operation log and alerts | Released in v0.3.0; [#17](https://github.com/giovannirco/latchkey/issues/17) closed. |
| Logging, syslog and Wi-Fi form | Released in [v0.4.0](https://github.com/giovannirco/latchkey/releases/tag/v0.4.0); [#18](https://github.com/giovannirco/latchkey/issues/18) closed. |
| Encrypted backup, hardening and two-board restore | [#19](https://github.com/giovannirco/latchkey/issues/19) has a design, no board implementation. Browser mock success is not evidence of backup or recovery on hardware. Requires firmware work outside this pass. |
| Switch write layout | [#20](https://github.com/giovannirco/latchkey/issues/20) remains unverified. Writes stay refused; proving the layout requires the owner at the lock and separate device work. |
| Board web updates and rollback | [#23](https://github.com/giovannirco/latchkey/issues/23) remains on the unmerged `feat/ota` branch. The upload heap budget and review remain open. Excluded from this pass. |
| Update, rollback and key preservation on hardware | [#24](https://github.com/giovannirco/latchkey/issues/24) remains open and needs the owner's button press. Excluded from this pass. |
| Review follow-ups | [#21](https://github.com/giovannirco/latchkey/issues/21) remains open; firmware findings are not resolved by browser changes. |
| Passage reliability | v0.4.0 includes the longer acknowledgement wait. The separate post-acknowledgement readback disconnect in [#31](https://github.com/giovannirco/latchkey/issues/31) remains untraced. No new hardware proof in this pass. |
| Final review and acceptance | [#25](https://github.com/giovannirco/latchkey/issues/25) remains open. A browser review does not replace whole-branch review, board acceptance or a two-board restore. |

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
