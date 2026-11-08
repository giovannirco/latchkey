// SPDX-License-Identifier: GPL-3.0-or-later
const path = require('node:path');

const { defineConfig, devices } = require('playwright/test');

const PORT = Number(process.env.LK_UI_PORT || 8766);
const ROOT = path.resolve(__dirname, '..', '..');

module.exports = defineConfig({
  testDir: __dirname,
  testMatch: /.*\.spec\.cjs$/,
  outputDir: path.join(__dirname, 'test-results'),
  workers: 1,
  fullyParallel: false,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  timeout: 45_000,
  expect: { timeout: 8_000 },
  reporter: [['list']],
  use: {
    baseURL: `http://127.0.0.1:${PORT}`,
    trace: 'retain-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'], headless: true } }],
  webServer: {
    command: `python3 tools/mock_api.py --port ${PORT}`,
    cwd: ROOT,
    url: `http://127.0.0.1:${PORT}/__mock/health`,
    reuseExistingServer: false,
    timeout: 20_000,
    stdout: 'ignore',
    stderr: 'pipe',
  },
});
