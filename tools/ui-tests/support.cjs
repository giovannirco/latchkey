// SPDX-License-Identifier: GPL-3.0-or-later
const { test: base, expect } = require('playwright/test');

const PASSWORD = 'owner-pass';
const TOTP = '123456';
const FRONT_DOOR = '00:00:5E:00:53:01';
const SHED = '00:00:5E:00:53:02';
const BOARD_BUTTON = 'Press the button on the board';

async function mock(request, body) {
  const response = await request.post('/__mock/control', { data: body });
  expect(response.ok(), `mock control ${JSON.stringify(body)}`).toBe(true);
  return response.json();
}

async function calls(request) {
  const response = await request.get('/__mock/calls');
  expect(response.ok()).toBe(true);
  return (await response.json()).calls;
}

const test = base.extend({
  page: async ({ page, request }, use) => {
    await mock(request, { reset: true });
    const problems = [];
    page.on('pageerror', (error) => problems.push(`uncaught: ${error.message}`));
    page.on('console', (message) => {
      if (message.type() === 'error' && /Content Security Policy|Refused to/i.test(message.text())) {
        problems.push(`csp: ${message.text()}`);
      }
    });
    await page.addInitScript(() => {
      window.__cspViolations = [];
      document.addEventListener('securitypolicyviolation', (event) => {
        window.__cspViolations.push(`${event.violatedDirective} ${event.blockedURI}`);
      });
    });
    await use(page);
    const violations = await page.evaluate(() => window.__cspViolations || []).catch(() => []);
    expect([...problems, ...violations], 'page errors and CSP violations').toEqual([]);
  },
});

async function login(page, hash = '') {
  await page.goto(`/${hash}`);
  await page.getByLabel('Password').fill(PASSWORD);
  await page.getByLabel('Authenticator code').fill(TOTP);
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('button', { name: 'Sign out', exact: true })).toBeVisible();
  await expect(page.locator('#live')).toHaveAttribute('data-live', 'on');
  await settled(page);
}

async function settled(page) {
  await expect(page.locator('#main h1')).toBeVisible();
  await expect(page.locator('[aria-busy="true"]')).toHaveCount(0);
}

async function rerendered(page, action) {
  const before = await page
    .locator('#main h1')
    .elementHandle({ timeout: 1000 })
    .catch(() => null);
  await action();
  if (before) await before.waitForElementState('hidden');
  await settled(page);
}

async function visit(page, hash) {
  await rerendered(page, () => page.goto(`/${hash}`));
}

async function openTab(page, name) {
  await rerendered(page, () => page.getByRole('link', { name, exact: true }).click());
}

function lockCard(page, name) {
  return page.getByRole('article', { name });
}

function boardButton(page) {
  return page.getByRole('dialog', { name: BOARD_BUTTON });
}

async function openLock(page, name, tab) {
  await page.getByRole('link', { name: 'Locks', exact: true }).click();
  await lockCard(page, name).getByRole('link', { name: 'Details' }).click();
  await expect(page.getByRole('heading', { level: 1, name })).toBeVisible();
  await settled(page);
  if (tab) await openTab(page, tab);
}

function toast(page, text) {
  return page.locator('#toasts').getByText(text);
}

module.exports = {
  test,
  expect,
  mock,
  calls,
  login,
  settled,
  rerendered,
  visit,
  openTab,
  lockCard,
  boardButton,
  openLock,
  toast,
  PASSWORD,
  TOTP,
  FRONT_DOOR,
  SHED,
};
