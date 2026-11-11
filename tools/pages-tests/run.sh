# SPDX-License-Identifier: GPL-3.0-or-later
set -eu

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
version=$(sed -n 's/^PLAYWRIGHT_VERSION=//p' "$root/tools/ui-tests/run.sh")
test -n "$version"
node --test "$here/serial.test.mjs"
bin=$(npx --yes --package "playwright@$version" --call 'command -v playwright')
NODE_PATH=$(dirname "$(dirname "$bin")")
export NODE_PATH
if ! install_log=$("$bin" install --only-shell --no-remove chromium 2>&1); then
    printf '%s\n' "$install_log" >&2
    exit 1
fi
"$bin" test --config "$here/playwright.config.cjs" "$@"
