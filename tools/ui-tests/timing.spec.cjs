// SPDX-License-Identifier: GPL-3.0-or-later
const { test, expect, mock, login, lockCard, toast, FRONT_DOOR } = require('./support.cjs');

test('a slow lock reply is awaited while the rest of the page keeps working', async ({ page, request }) => {
  await login(page);
  await mock(request, { delay: { method: 'lock.unlock', ms: 17000 } });
  const front = lockCard(page, 'Front door');
  const shed = lockCard(page, 'Shed');
  const unlock = front.getByRole('button', { name: 'Unlock' });
  await unlock.click();
  await expect(unlock).toBeDisabled();

  await shed.getByRole('button', { name: 'Lock', exact: true }).click();
  await expect(toast(page, 'Shed locked')).toBeVisible();
  await expect(shed.getByText('Locked', { exact: true })).toBeVisible();

  const time = Math.floor(Date.now() / 1000);
  await mock(request, {
    emit: [{ event: 'lock.event', data: { lock: FRONT_DOOR, action: 'unlock', method: 'fingerprint', time } }],
  });
  await expect(front).toContainText('Unlocked with a fingerprint');
  await expect(unlock).toBeDisabled();

  await expect(toast(page, 'Front door unlocked')).toBeVisible({ timeout: 25_000 });
  await expect(front.getByText('Unlocked', { exact: true })).toBeVisible();
  await expect(page.locator('#toasts [role="alert"]')).toHaveCount(0);
});

test('a short request the board never answers gives up after the short timeout', async ({ page, request }) => {
  await login(page, '#/system');
  await mock(request, { delay: { method: 'system.reboot', ms: 25000 } });
  await page.getByRole('button', { name: 'Restart the board' }).click();
  await page.getByRole('dialog', { name: 'Restart the board?' }).getByRole('button', { name: 'Restart' }).click();
  const error = page.locator('#toasts [role="alert"]');
  await expect(error).toContainText('The board did not answer in time', { timeout: 20_000 });
  await expect(page.getByRole('button', { name: 'Restart the board' })).toBeEnabled();
});
