# SPDX-License-Identifier: GPL-3.0-or-later
# Run the web UI checks: sh tools/ui-tests/run.sh [extra `playwright test` arguments]
# Builds the page (size budget), runs the bundler unit tests, then the Playwright
# suite, which starts and stops tools/mock_api.py by itself (playwright.config.cjs).
set -eu

PLAYWRIGHT_VERSION=1.64.1
PYTHONDONTWRITEBYTECODE=1
export PYTHONDONTWRITEBYTECODE

here=$(cd "$(dirname "$0")" && pwd)
root=$(cd "$here/../.." && pwd)
build_dir=$(mktemp -d)
trap 'rm -rf "$build_dir"' EXIT

python3 "$root/tools/build_web.py" "$build_dir/index.html.gz"
python3 -m unittest discover -s "$here" -p 'test_*.py'

bin=$(npx --yes --package "playwright@$PLAYWRIGHT_VERSION" --call 'command -v playwright')
NODE_PATH=$(dirname "$(dirname "$bin")")
export NODE_PATH

if ! install_log=$("$bin" install --only-shell --no-remove chromium 2>&1); then
    printf '%s\n' "$install_log" >&2
    exit 1
fi
"$bin" test --config "$here/playwright.config.cjs" "$@"
