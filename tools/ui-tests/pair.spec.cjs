// SPDX-License-Identifier: GPL-3.0-or-later
const { test, expect, mock, calls, login, lockCard, boardButton } = require('./support.cjs');

const PASSPHRASE = 'correct horse battery staple';

test('the pair wizard scans, pairs with a button press, backs up keys and hardens', async ({ page, request }) => {
  await login(page);
  await page.getByRole('link', { name: 'Add lock' }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Add a lock' })).toBeVisible();

  await page.getByRole('button', { name: 'Scan' }).click();
  const fresh = page.getByRole('radio', { name: /LK-MOCK-NEW/ });
  await expect(fresh).toBeEnabled();
  await expect(page.getByRole('radio', { name: /LK-MOCK-OTHER/ })).toBeDisabled();
  await expect(page.getByRole('radio', { name: /Front door/ })).toBeDisabled();

  await fresh.check();
  await page.getByLabel('Name').fill('Back door');
  await page.getByRole('button', { name: 'Pair' }).click();

  const confirm = boardButton(page);
  await expect(confirm).toBeVisible();
  await expect(confirm).toContainText('Pair the lock');
  await expect(confirm).toBeHidden();

  await expect(page.getByRole('heading', { level: 2, name: 'Harden Back door' })).toBeVisible();
  const steps = page.getByRole('list', { name: 'Hardening steps' });
  await expect(steps.getByRole('listitem')).toHaveCount(5);

  await page.getByRole('button', { name: 'Harden lock' }).click();
  const needBackup = page.getByRole('alert').filter({ hasText: "Back up this lock's keys before hardening it" });
  await expect(needBackup).toBeVisible();
  await expect(confirm).toBeHidden();

  await needBackup.getByRole('button', { name: 'Export keys now' }).click();
  const exportDialog = page.getByRole('dialog', { name: 'Export keys' });
  await exportDialog.getByLabel('Passphrase', { exact: true }).fill(PASSPHRASE);
  await exportDialog.getByLabel('Repeat passphrase').fill(PASSPHRASE);
  const download = page.waitForEvent('download');
  await exportDialog.getByRole('button', { name: 'Export' }).click();
  await expect(confirm).toBeVisible();
  await expect(confirm).toContainText('Export the key backup');
  expect((await download).suggestedFilename()).toMatch(/^latchkey-backup-\d{4}-\d{2}-\d{2}\.lkb$/);
  await expect(exportDialog).toBeHidden();
  await expect(steps.getByRole('listitem').filter({ hasText: 'Back up' })).toContainText('Done');

  await page.getByRole('button', { name: 'Harden lock' }).click();
  await expect(confirm).toBeVisible();
  await expect(confirm).toContainText('Harden the lock');
  await expect(page.getByText('Lock hardened')).toBeVisible({ timeout: 15_000 });
  for (const item of await steps.getByRole('listitem').all()) await expect(item).toContainText('Done');
  await expect(steps).toContainText('1 removed');

  await page.getByRole('link', { name: 'Go to the locks' }).click();
  const back = lockCard(page, 'Back door');
  await expect(back).toBeVisible();
  await expect(back).not.toContainText('Not hardened');

  const exportCall = (await calls(request)).find((call) => call.method === 'keys.export');
  expect(exportCall.params.passphrase).toBe('***');
});

test('a short or mismatched backup passphrase is refused before anything is sent', async ({ page, request }) => {
  await login(page);
  await page.getByRole('link', { name: 'Security', exact: true }).click();
  await page.getByRole('button', { name: 'Export keys' }).click();
  const dialog = page.getByRole('dialog', { name: 'Export keys' });
  await dialog.getByLabel('Passphrase', { exact: true }).fill(PASSPHRASE);
  await dialog.getByLabel('Repeat passphrase').fill(`${PASSPHRASE}!`);
  await dialog.getByRole('button', { name: 'Export' }).click();
  await expect(dialog.getByRole('alert')).toContainText('The passphrases do not match');
  await dialog.getByLabel('Passphrase', { exact: true }).fill('short');
  await dialog.getByLabel('Repeat passphrase').fill('short');
  await dialog.getByRole('button', { name: 'Export' }).click();
  expect(await dialog.getByLabel('Passphrase', { exact: true }).evaluate((input) => input.validity.valid)).toBe(false);
  expect((await calls(request)).filter((call) => call.method === 'keys.export')).toEqual([]);
});

test('advertised names from the radio are shown as text', async ({ page, request }) => {
  const hostile = '<img src=x onerror=__owned=1>';
  await mock(request, { scanExtra: [{ mac: '00:00:5E:00:53:66', name: hostile, rssi: -60, paired: false }] });
  await login(page);
  await page.getByRole('link', { name: 'Add lock' }).click();
  await page.getByRole('button', { name: 'Scan' }).click();
  await expect(
    page.getByRole('radio', { name: new RegExp(hostile.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')) }),
  ).toBeVisible();
  expect(await page.locator('img').count()).toBe(0);
  expect(await page.evaluate(() => window.__owned)).toBeUndefined();
});

async function startPairing(page, name) {
  await page.getByRole('link', { name: 'Add lock' }).click();
  await page.getByRole('button', { name: 'Scan' }).click();
  await page.getByRole('radio', { name: /LK-MOCK-NEW/ }).check();
  await page.getByLabel('Name').fill(name);
  await page.getByRole('button', { name: 'Pair' }).click();
}

test('the pairing result is taken from job.done even when the event beats the reply', async ({ page, request }) => {
  await login(page);
  await mock(request, { confirmDelayMs: 300, jobReplyDelayMs: 3500 });
  await startPairing(page, 'Porch');
  await expect(page.getByRole('heading', { level: 2, name: 'Harden Porch' })).toBeVisible({ timeout: 10_000 });
});

test('a pending job fails fast when the event socket drops, and the wizard keeps its state', async ({
  page,
  request,
}) => {
  await login(page);
  await mock(request, { confirm: 'never', confirmTimeoutMs: 60_000 });
  await startPairing(page, 'Porch');
  await expect(boardButton(page)).toBeVisible();
  await mock(request, { dropSockets: true });
  const lost = page.getByRole('alert').filter({ hasText: 'The connection to the board dropped' });
  await expect(lost).toBeVisible({ timeout: 5000 });
  await expect(boardButton(page)).toBeHidden();
  await expect(page.locator('#live')).toHaveAttribute('data-live', 'on', { timeout: 10_000 });
  await expect(lost).toBeVisible();
  await expect(page.getByRole('radio', { name: /LK-MOCK-NEW/ })).toBeChecked();
});

test('a pairing job that fails shows the error carried by job.done', async ({ page, request }) => {
  await login(page);
  await mock(request, { confirm: 'never', confirmTimeoutMs: 1500 });
  await startPairing(page, 'Porch');
  await expect(boardButton(page)).toBeVisible();
  const failed = page.getByRole('alert').filter({ hasText: 'The button on the board was not pressed in time' });
  await expect(failed).toBeVisible({ timeout: 8000 });
  await expect(boardButton(page)).toBeHidden();
  await expect(page.getByRole('button', { name: 'Pair' })).toBeEnabled();
  expect((await calls(request)).filter((call) => call.method === 'locks.pair')).toHaveLength(1);
});
