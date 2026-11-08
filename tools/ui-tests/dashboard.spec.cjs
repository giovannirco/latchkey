// SPDX-License-Identifier: GPL-3.0-or-later
const { test, expect, mock, login, lockCard, toast, FRONT_DOOR, SHED } = require('./support.cjs');

test('the dashboard lists each lock with state, battery and warnings', async ({ page }) => {
  await login(page);
  await expect(page.getByRole('heading', { level: 1, name: 'Locks' })).toBeVisible();

  const front = lockCard(page, 'Front door');
  await expect(front).toContainText('Locked');
  await expect(front).toContainText('87%');
  await expect(front).not.toContainText('Not hardened');

  const shed = lockCard(page, 'Shed');
  await expect(shed).toContainText('Unlocked');
  await expect(shed).toContainText('34%');
  await expect(shed).toContainText('Not hardened');
  await expect(shed).toContainText('No key backup');
});

test('unlock and lock update the card', async ({ page }) => {
  await login(page);
  const front = lockCard(page, 'Front door');
  await front.getByRole('button', { name: 'Unlock' }).click();
  await expect(toast(page, 'Front door unlocked')).toBeVisible();
  await expect(front.getByText('Unlocked', { exact: true })).toBeVisible();

  await front.getByRole('button', { name: 'Lock', exact: true }).click();
  await expect(toast(page, 'Front door locked')).toBeVisible();
  await expect(front.getByText('Locked', { exact: true })).toBeVisible();
});

test('a busy lock queue shows a clear error toast', async ({ page, request }) => {
  await login(page);
  await mock(request, { failNext: { method: 'lock.unlock', code: 'busy', message: 'waited 60 s in the queue' } });
  await lockCard(page, 'Front door').getByRole('button', { name: 'Unlock' }).click();
  const error = page.locator('#toasts [role="alert"]');
  await expect(error).toContainText('The board is busy with another lock operation');
  await expect(error).toContainText(/waited 60 s in the queue/i);
  await expect(lockCard(page, 'Front door').getByText('Locked', { exact: true })).toBeVisible();
});

test('lock events from the board update the dashboard live', async ({ page, request }) => {
  await login(page);
  await mock(request, {
    emit: [
      { event: 'lock.state', data: { lock: SHED, state: 'locked', battery: 33 } },
      {
        event: 'lock.event',
        data: { lock: SHED, action: 'lock', method: 'passcode', time: Math.floor(Date.now() / 1000) },
      },
    ],
  });
  const shed = lockCard(page, 'Shed');
  await expect(shed.getByText('Locked', { exact: true })).toBeVisible();
  await expect(shed).toContainText('33%');
  await expect(shed).toContainText('Locked with a passcode');
  await expect(page.getByText('Live', { exact: true })).toBeVisible();
});

test('names from the board are rendered as text, never as markup', async ({ page, request }) => {
  await login(page);
  const hostile = '<img src=x onerror=__owned=1>';
  await mock(request, {
    emit: [{ event: 'lock.event', data: { lock: FRONT_DOOR, action: 'unlock', method: hostile } }],
  });
  await expect(lockCard(page, 'Front door')).toContainText(hostile);
  await lockCard(page, 'Front door').getByRole('link', { name: 'Details' }).click();
  await page.getByRole('button', { name: 'Rename' }).click();
  const dialog = page.getByRole('dialog', { name: 'Rename lock' });
  await dialog.getByLabel('Name').fill(hostile);
  await dialog.getByRole('button', { name: 'Save' }).click();
  await expect(page.getByRole('heading', { level: 1, name: hostile })).toBeVisible();
  expect(await page.locator('img').count()).toBe(0);
  expect(await page.evaluate(() => window.__owned)).toBeUndefined();
});

test('rename stays disabled until the lock has loaded, so an early click is not lost', async ({ page, request }) => {
  await login(page);
  await mock(request, { delay: { method: 'locks.list', ms: 1500 } });
  await lockCard(page, 'Front door').getByRole('link', { name: 'Details' }).click();
  const rename = page.getByRole('button', { name: 'Rename' });
  await expect(rename).toBeDisabled();
  await rename.click();
  await expect(page.getByRole('dialog', { name: 'Rename lock' })).toBeVisible();
});
