// SPDX-License-Identifier: GPL-3.0-or-later
const path = require('node:path');

const { test, expect, mock, login, settled, openLock, openTab, boardButton } = require('./support.cjs');

const DIR = process.env.LK_SHOTS_DIR;

test.describe('screenshots', () => {
  test.skip(!DIR, 'set LK_SHOTS_DIR to write screenshots');

  test('desktop', async ({ page }) => {
    await page.setViewportSize({ width: 1280, height: 860 });
    await login(page);
    await page.screenshot({ path: path.join(DIR, 'desktop-dashboard.png'), fullPage: true });
    await openLock(page, 'Front door', 'Access');
    await page.screenshot({ path: path.join(DIR, 'desktop-lock-access.png'), fullPage: true });
    await openTab(page, 'Settings');
    await page.screenshot({ path: path.join(DIR, 'desktop-lock-settings.png'), fullPage: true });
    await openLock(page, 'Shed', 'Device');
    await page.screenshot({ path: path.join(DIR, 'desktop-shed-device.png'), fullPage: true });
  });

  test('desktop dark', async ({ page }) => {
    await page.emulateMedia({ colorScheme: 'dark' });
    await page.setViewportSize({ width: 1280, height: 860 });
    await login(page, '#/security');
    await page.screenshot({ path: path.join(DIR, 'desktop-security-dark.png'), fullPage: true });
  });

  test('phone', async ({ page, request }) => {
    await page.setViewportSize({ width: 360, height: 780 });
    await login(page);
    await page.screenshot({ path: path.join(DIR, 'phone-dashboard.png'), fullPage: true });
    await mock(request, { confirm: 'never', confirmTimeoutMs: 30000 });
    await page.getByRole('link', { name: 'Add lock' }).click();
    await page.getByRole('button', { name: 'Scan' }).click();
    await page.getByRole('radio', { name: /LK-MOCK-NEW/ }).check();
    await page.getByLabel('Name').fill('Back door');
    await page.getByRole('button', { name: 'Pair' }).click();
    await expect(boardButton(page)).toBeVisible();
    await page.waitForTimeout(1200);
    await page.screenshot({ path: path.join(DIR, 'phone-confirm-modal.png') });
    await page.keyboard.press('Escape');
    await settled(page);
  });
});
