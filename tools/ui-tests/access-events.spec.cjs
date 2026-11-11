// SPDX-License-Identifier: GPL-3.0-or-later
const { test, expect, mock, login, openLock, FRONT_DOOR } = require('./support.cjs');

const fs = require('node:fs');
const path = require('node:path');

const credential = (kind, id, name, nameSource = 'current_label') => ({ kind, id, name, nameSource });

test('PIN lifecycle records do not invent keypad provenance', async ({ page, request }) => {
  const time = Math.floor(Date.now() / 1000);
  await mock(request, { setLock: { id: FRONT_DOOR, log: [5, 6, 8].map((type, index) => ({
    seq: index + 1, time, type, battery: 80,
  })) } });
  await login(page);
  await openLock(page, 'Front door', 'Log');
  const table = page.getByRole('table', { name: 'Operation log' });
  await expect(table).not.toContainText('on the keypad');
  await expect(table.getByText('Passcode changed', { exact: true })).toBeVisible();
  await expect(table.getByText('Passcode deleted', { exact: true })).toBeVisible();
  await expect(table.getByText('All passcodes deleted', { exact: true })).toBeVisible();
});

test('operation records show named credentials, retired labels and unidentified failures safely', async ({ page, request }) => {
  const time = Math.floor(Date.now() / 1000);
  const record = (seq, type, detail, outcome = 'success') => ({ seq, time, type, battery: 80, credential: detail, outcome });
  await mock(request, { setLock: { id: FRONT_DOOR, log: [
    record(1, 20, credential('fingerprint', '1', 'Owner right index')),
    record(2, 93, credential('passcode', 'abcdef123456', 'Visitor PIN')),
    record(3, 18, credential('card', '3141592653', 'Retired card', 'last_known_label')),
    record(4, 7, credential('passcode', null, null, null), 'failure'),
    record(5, 22, credential('fingerprint', null, null, null), 'failure'),
    record(6, 25, credential('card', '42', '<img src=x onerror=alert(1)>'), 'failure'),
  ] } });
  await login(page);
  await openLock(page, 'Front door', 'Log');
  const table = page.getByRole('table', { name: 'Operation log' });
  const row = (text) => table.locator('tbody tr').filter({ hasText: text });
  await expect(row('Unlocked with a fingerprint')).toContainText('Owner right index');
  await expect(row('Passcode added')).toContainText('Visitor PIN');
  await expect(row('Card deleted')).toContainText('Retired card');
  await expect(row('Card deleted')).toContainText('Last-known label');
  await expect(row('Wrong passcode entered')).toContainText('Unidentified passcode');
  await expect(row('Wrong passcode entered')).toContainText('Failed');
  await expect(row('Fingerprint not recognised')).toContainText('Unidentified fingerprint');
  await expect(row('Card refused')).toContainText('<img src=x onerror=alert(1)>');
  await expect(table.locator('img')).toHaveCount(0);
  await expect(row('Card refused')).toContainText('ID 42');
  await expect(table).toContainText('Record 6');
  await page.setViewportSize({ width: 390, height: 844 });
  const identity = row('Unlocked with a fingerprint').locator('td').nth(2);
  expect(await identity.evaluate((element) => element.getBoundingClientRect().right)).toBeLessThanOrEqual(390);
  await page.setViewportSize({ width: 1280, height: 720 });
  if (process.env.LK_SHOTS_DIR) {
    fs.mkdirSync(process.env.LK_SHOTS_DIR, { recursive: true });
    await page.screenshot({ path: path.join(process.env.LK_SHOTS_DIR, 'access-events-desktop.png'), fullPage: true });
    await page.setViewportSize({ width: 390, height: 844 });
    await expect(table).toBeVisible();
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await page.screenshot({ path: path.join(process.env.LK_SHOTS_DIR, 'access-events-mobile.png'), fullPage: true });
  }
});

test('low battery is a persistent battery warning and never an unexpected unlock', async ({ page, request }) => {
  await mock(request, { setLock: { id: FRONT_DOOR, alertNext: 2, alerts: [
    { id: 1, kind: 'low_battery', battery: 39, time: null, method: 'none', seq: 0, type: 0 },
  ] } });
  await login(page);
  await openLock(page, 'Front door');
  const alerts = page.getByRole('region', { name: 'Alerts', exact: true });
  await expect(alerts).toContainText('battery is low (39%)');
  await expect(alerts).toContainText('Replace the batteries');
  await expect(alerts).not.toContainText('was unlocked');
  await page.reload();
  await expect(page.getByRole('region', { name: 'Alerts', exact: true })).toContainText('39%');
  await page.getByRole('button', { name: 'Acknowledge alerts' }).click();
  await expect(page.getByRole('region', { name: 'Alerts', exact: true })).toContainText('No unacknowledged alerts');
});

test('a live battery alert refreshes the badge and gives battery-specific advice', async ({ page, request }) => {
  await login(page);
  await mock(request, { emit: [{ event: 'lock.battery.alert', data: {
    lock: FRONT_DOOR, kind: 'low_battery', battery: 20, time: Math.floor(Date.now() / 1000),
  } }] });
  const notice = page.locator('#toasts .toast-warning');
  await expect(notice).toContainText('battery is low (20%)');
  await expect(notice).toContainText('Replace the batteries');
  await expect(notice).not.toContainText('Check who can open it');
  await expect(page.getByRole('article', { name: 'Front door' })).toContainText('1 alert');
});
