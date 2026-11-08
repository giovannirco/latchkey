<!-- SPDX-License-Identifier: GPL-3.0-or-later -->
# Web UI

The owner's single-page app: plain HTML, CSS and JavaScript, no framework and nothing fetched from the internet. `tools/build_web.py` inlines `style.css`, `app.js` and `icons.svg` into `index.html`, adds a Content-Security-Policy that allows only the hashes of that inline script and style, and writes one reproducible gzip for the firmware to serve at `/`.

```sh
python3 tools/build_web.py <output.gz>      # fails above the 60 KiB gzipped budget
```

It also writes `<output.gz>.csp.txt`, the Content-Security-Policy header value: the meta tag's policy plus `frame-ancestors 'none'`, which a meta tag cannot carry.

## Headers the firmware must send

- With the page, `GET /`:
  - `Content-Encoding: gzip`;
  - `Content-Security-Policy:` the contents of `<output.gz>.csp.txt`;
  - `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cache-Control: no-store`.
- With every API response (`/api/rpc`, `/api/ota`): `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`.
- The session cookie: `Secure; HttpOnly; SameSite=Strict; Path=/`. The mock leaves out `Secure` because it serves plain HTTP.

## Develop against the mock

```sh
python3 tools/mock_api.py --port 8765
```

Open http://127.0.0.1:8765/ and sign in with password `owner-pass` and code `123456`. The mock rebuilds the page on every load, so edits in `web/` show on reload. It keeps everything in memory: two demo locks, Front door (every feature) and Shed (passcodes and auto-lock only), plus a factory-fresh lock to pair. Buttons on the board are pressed for you after 2 s.

`tools/mock_api.py` is the reference for the parameters and results of every method in the spec's API table, and for the events the UI listens to: `lock.state`, `lock.event`, `enroll.progress`, `confirm.required`, `confirm.result`, `scan.result`, `audit.appended`, `harden.step` and `job.done`. The lock methods and the button-gated ones answer `{"job": id}`, as the board does, and their outcome arrives later as `job.done` on the sockets of the session that asked; the UI accepts that shape from any method.

## Test

```sh
sh tools/ui-tests/run.sh                    # bundler unit tests, then the Playwright suite
sh tools/ui-tests/run.sh pair.spec.cjs      # extra arguments go to `playwright test`
LK_SHOTS_DIR=/tmp/shots sh tools/ui-tests/run.sh shots.spec.cjs
```

It needs Python 3 and Node.js with `npx`. The script pins Playwright 1.64.1, installs its headless Chromium on the first run, and starts and stops the mock on port 8766 (`LK_UI_PORT` changes it).

## Rules for changes

- Build the DOM with `h()` and text nodes. Never assign `innerHTML`: lock names, advertised Bluetooth names and log entries come from outside.
- No `style` attributes in markup: the hash-based CSP blocks them. Use classes, or `element.style` from script.
- Never render a key. A passcode appears once, in the reply that created it; lists show it masked, and card numbers keep only their last four digits.
