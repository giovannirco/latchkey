// SPDX-License-Identifier: GPL-3.0-or-later
const path = require('node:path');
const { defineConfig } = require('playwright/test');

module.exports = defineConfig({
  testDir: __dirname,
  testMatch: /.*\.spec\.cjs$/,
  outputDir: '/tmp/latchkey-pages-test-results',
  workers: 1,
  forbidOnly: Boolean(process.env.CI),
  retries: 0,
  timeout: 20_000,
  expect: { timeout: 3_000 },
  reporter: [['list']],
  use: { baseURL: 'http://127.0.0.1:8767', headless: true, trace: 'retain-on-failure' },
  webServer: {
    command: 'python3 tools/local_http_server.py --port 8767 --directory docs',
    cwd: path.resolve(__dirname, '../..'),
    url: 'http://127.0.0.1:8767',
    reuseExistingServer: false,
    stdout: 'ignore',
    stderr: 'ignore',
  },
});
