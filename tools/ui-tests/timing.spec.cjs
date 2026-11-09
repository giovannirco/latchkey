// SPDX-License-Identifier: GPL-3.0-or-later
const { test, expect, mock, login, settled, lockCard, openLock, toast, FRONT_DOOR } = require('./support.cjs');

const NO_REPLY = 'The board did not answer in time';
const PASSPHRASE = 'correct horse battery staple';

async function startUnlock(page) {
  await lockCard(page, 'Front door').getByRole('button', { name: 'Unlock' }).click();
}

async function startReboot(page) {
  await page.getByRole('link', { name: 'System', exact: true }).click();
  await page.getByRole('button', { name: 'Restart the board' }).click();
  await settled(page);
  await page.getByRole('dialog', { name: 'Restart the board?' }).getByRole('button', { name: 'Restart' }).click();
}

async function startExport(page) {
  await page.getByRole('link', { name: 'Security', exact: true }).click();
  await page.getByRole('button', { name: 'Export keys' }).click();
  const dialog = page.getByRole('dialog', { name: 'Export keys' });
  await settled(page);
  await dialog.getByLabel('Passphrase', { exact: true }).fill(PASSPHRASE);
  await dialog.getByLabel('Repeat passphrase').fill(PASSPHRASE);
  await dialog.getByRole('button', { name: 'Export' }).click();
}

async function startHarden(page) {
  await openLock(page, 'Shed', 'Device');
  await page.getByRole('button', { name: 'Preview hardening' }).click();
}

async function startImport(page) {
  await page.getByRole('link', { name: 'Security', exact: true }).click();
  await page.getByRole('button', { name: 'Import keys' }).click();
  const dialog = page.getByRole('dialog', { name: 'Import keys' });
  await dialog.getByLabel('Backup file (.lkb)').setInputFiles({ name: 'fixture.lkb', mimeType: 'application/octet-stream', buffer: Buffer.from('opaque fixture') });
  await dialog.getByLabel('Passphrase').fill(PASSPHRASE);
  await dialog.getByRole('button', { name: 'Import', exact: true }).click();
}

async function startPair(page) {
  await page.getByRole('link', { name: 'Add lock' }).click();
  await page.getByRole('button', { name: 'Scan' }).click();
  await page.getByRole('radio', { name: /LK-MOCK-NEW/ }).check();
  await page.getByLabel('Name').fill('Porch');
  await page.getByRole('button', { name: 'Pair' }).click();
}

async function startFactoryReset(page) {
  await openLock(page, 'Front door', 'Device');
  await page.getByRole('button', { name: 'Factory-reset lock' }).click();
  const dialog = page.getByRole('dialog', { name: 'Factory-reset Front door?' });
  await dialog.getByLabel('Type reset to confirm').fill('reset');
  await dialog.getByRole('button', { name: 'Factory reset' }).click();
}

const BUDGETS = [
  ['system.reboot', 15, startReboot],
  ['keys.export', 240, startExport],
  ['keys.import', 240, startImport],
  ['lock.unlock', 100, startUnlock],
  ['lock.harden', 240, startHarden],
  ['locks.pair', 240, startPair],
  ['lock.factoryReset', 240, startFactoryReset],
];

for (const [method, seconds, start] of BUDGETS) {
  test(`${method} waits ${seconds} s for the board before giving up`, async ({ page, request }) => {
    await page.clock.install();
    await login(page);
    await mock(request, { delay: { method, ms: 600_000 } });
    const sent = page.waitForRequest((request) => request.url().endsWith('/api/rpc') && request.postDataJSON()?.method === method);
    await start(page);
    await sent;
    await page.clock.fastForward((seconds - 5) * 1000);
    await page.waitForTimeout(300);
    await expect(page.getByText(NO_REPLY)).toHaveCount(0);
    await page.clock.fastForward(10_000);
    await expect(page.getByText(NO_REPLY).first()).toBeVisible();
  });
}

test('a slow lock reply is awaited while the rest of the page keeps working', async ({ page, request }) => {
  await page.clock.install();
  await login(page);
  await mock(request, { delay: { method: 'lock.unlock', ms: 2500 } });
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
  await page.clock.fastForward(20_000);
  await expect(unlock).toBeDisabled();

  await expect(toast(page, 'Front door unlocked')).toBeVisible();
  await expect(front.getByText('Unlocked', { exact: true })).toBeVisible();
  await expect(page.locator('#toasts [role="alert"]')).toHaveCount(0);
});
