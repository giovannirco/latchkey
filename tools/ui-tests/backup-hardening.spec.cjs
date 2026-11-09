// SPDX-License-Identifier: GPL-3.0-or-later
const { readFile } = require('node:fs/promises');

const { test, expect, mock, calls, login, openLock, lockCard, boardButton, FRONT_DOOR, SHED } = require('./support.cjs');

const PASSPHRASE = 'correct horse battery staple';

async function openHardening(page, request, changes = {}) {
  await mock(request, { setLock: { id: FRONT_DOOR, hardened: false, ...changes }, confirmDelayMs: 100 });
  await login(page);
  await openLock(page, 'Front door', 'Device');
  return page.getByRole('region', { name: 'Hardening', exact: true });
}

async function exportForm(page, phrase = PASSPHRASE) {
  await page.getByRole('button', { name: 'Export keys', exact: false }).click();
  const dialog = page.getByRole('dialog', { name: 'Export keys', exact: true });
  await dialog.getByLabel('Passphrase', { exact: true }).fill(phrase);
  await dialog.getByLabel('Repeat passphrase').fill(phrase);
  return dialog;
}

test('preview is read-only and execution reports partial hardening', async ({ page, request }) => {
  const part = await openHardening(page, request);
  await expect(part.getByRole('button', { name: 'Apply hardening' })).toBeDisabled();
  await part.getByRole('button', { name: 'Preview hardening' }).click();
  await expect(part).toContainText('Preview only');
  await expect(boardButton(page)).toBeHidden();
  await expect(part).toContainText('Reset-button protection is unavailable');
  expect((await calls(request)).filter((call) => call.method === 'lock.harden').map((call) => call.params))
    .toEqual([{ lock: FRONT_DOOR, dryRun: true }]);
  const audit = await page.request.post('/api/rpc', { data: { id: 1, method: 'audit.list', params: {} } });
  expect((await audit.json()).result.entries.filter((entry) => entry.method === 'lock.harden' && entry.seq > 7)).toEqual([]);
  await part.getByRole('button', { name: 'Apply hardening' }).click();
  await expect(part).toContainText('Hardening partially completed');
  await expect(part.getByRole('list')).toContainText('Skipped');
  await expect(part).not.toContainText('Lock hardened');
  await expect(part.getByRole('button', { name: 'Apply hardening' })).toBeDisabled();
  await page.getByRole('link', { name: 'All locks' }).click();
  await expect(lockCard(page, 'Front door')).toContainText('Not hardened');
});

test('preview explains missing backup without requesting a button', async ({ page, request }) => {
  const part = await openHardening(page, request, { backedUp: false });
  await part.getByRole('button', { name: 'Preview hardening' }).click();
  await expect(part).toContainText('Back up this lock');
  await expect(part.getByRole('button', { name: 'Apply hardening' })).toBeDisabled();
  await expect(boardButton(page)).toBeHidden();
});

for (const [reason, description] of [
  ['owner', 'owner-managed admin passcode'],
  ['legacy_unknown', 'origin is unknown'],
  ['pairing_generated', 'generated during pairing'],
  ['hardening_generated', 'already replaced by hardening'],
  ['admin_unresolved', 'outcome is unresolved'],
  ['confirm_candidate', 'Confirm the pending admin-code change'],
  ['confirm_previous', 'Confirm the previous admin code'],
]) {
  test(`preview explains admin state ${reason}`, async ({ page, request }) => {
    const part = await openHardening(page, request, { adminProvenance: reason });
    await part.getByRole('button', { name: 'Preview hardening' }).click();
    await expect(part).toContainText(description);
    if (reason === 'admin_unresolved') await expect(part.getByRole('button', { name: 'Apply hardening' })).toBeDisabled();
  });
}

test('a failed step keeps completed steps visible and requires another preview', async ({ page, request }) => {
  const part = await openHardening(page, request, { passcodes: [
    { id: 'fixture-unmanaged', code: '123456', type: 'permanent', managed: false, name: '', validity: null },
  ] });
  await part.getByRole('button', { name: 'Preview hardening' }).click();
  await expect(part.getByRole('button', { name: 'Apply hardening' })).toBeEnabled();
  await mock(request, { failHardenStep: { step: 'passcodes', code: 'storage_error' } });
  await part.getByRole('button', { name: 'Apply hardening' }).click();
  await expect(part).toContainText('Hardening stopped');
  const rows = part.getByRole('listitem');
  await expect(rows.filter({ hasText: "Set the lock's clock" })).toContainText('Done');
  await expect(rows.filter({ hasText: 'unmanaged passcodes' })).toContainText('Failed');
  await expect(rows.filter({ hasText: 'reset button' })).toContainText('Skipped');
  await expect(part.getByRole('button', { name: 'Apply hardening' })).toBeDisabled();
  expect((await calls(request)).filter((call) => call.method === 'lock.harden')).toHaveLength(2);
});

for (const code of ['internal', 'job_lost']) {
  test(`unreported hardening changes require review after ${code}`, async ({ page, request }) => {
    const part = await openHardening(page, request);
    await part.getByRole('button', { name: 'Preview hardening' }).click();
    await expect(part.getByRole('button', { name: 'Apply hardening' })).toBeEnabled();
    await mock(request, { failNext: { method: 'lock.harden', code } });
    await part.getByRole('button', { name: 'Apply hardening' }).click();
    await expect(part.getByRole('alert')).toContainText('Confirmed changes may remain');
    await expect(part.getByRole('button', { name: 'Apply hardening' })).toBeDisabled();
  });
}

for (const [code, text] of [
  ['admin_reconciled', 'No new code was sent'],
  ['admin_unresolved', 'outcome is still uncertain'],
]) {
  test(`admin change explains ${code} without showing a new code`, async ({ page, request }) => {
    await login(page);
    await openLock(page, 'Front door', 'Settings');
    await mock(request, { failNext: { method: 'lock.adminPasscode.set', code } });
    await page.getByRole('button', { name: 'Change admin passcode' }).click();
    const dialog = page.getByRole('dialog', { name: 'Change the super admin passcode' });
    await dialog.getByRole('button', { name: 'Save' }).click();
    await expect(dialog.getByRole('alert')).toContainText(text);
    await expect(page.getByRole('dialog', { name: 'New super admin passcode' })).toHaveCount(0);
  });
}

test('a per-lock backup changes only that lock and restores after forgetting it', async ({ page, request }) => {
  await mock(request, { setLock: { id: FRONT_DOOR, backedUp: false, resetButton: true } });
  await login(page);
  await openLock(page, 'Shed', 'Device');
  const dialog = await exportForm(page);
  const downloaded = page.waitForEvent('download');
  await dialog.getByRole('button', { name: 'Export', exact: true }).click();
  const file = await downloaded;
  const bytes = await readFile(await file.path());
  await expect(dialog).toBeHidden();
  await page.getByRole('link', { name: 'All locks' }).click();
  await expect(lockCard(page, 'Shed')).not.toContainText('No key backup');
  await expect(lockCard(page, 'Front door')).toContainText('No key backup');
  expect((await calls(request)).find((call) => call.method === 'keys.export').params).toEqual({ lock: SHED, passphrase: '***' });
  await page.request.post('/api/rpc', { data: { id: 1, method: 'locks.forget', params: { lock: SHED } } });
  await page.getByRole('link', { name: 'Security', exact: true }).click();
  await page.getByRole('button', { name: 'Import keys' }).click();
  const importing = page.getByRole('dialog', { name: 'Import keys' });
  await importing.getByLabel('Backup file (.lkb)').setInputFiles({ name: 'fixture.lkb', mimeType: 'application/octet-stream', buffer: bytes });
  await importing.getByLabel('Passphrase').fill(PASSPHRASE);
  await importing.getByRole('button', { name: 'Import', exact: true }).click();
  await expect(importing).toBeHidden();
  await expect(page.locator('#toasts')).toContainText('Imported 1 lock');
  expect((await calls(request)).at(-1).method).toBe('locks.list');
  await page.getByRole('link', { name: 'Locks', exact: true }).click();
  await expect(lockCard(page, 'Shed')).toBeVisible();
});

for (const [name, phrase, valid] of [
  ['12 bytes', 'é'.repeat(6), true],
  ['128 bytes', 'é'.repeat(64), true],
  ['under 12 bytes', 'é'.repeat(5), false],
  ['over 128 bytes', 'é'.repeat(65), false],
  ['NUL', 'long enough\0phrase', false],
]) {
  test(`backup passphrase validates ${name} before sending`, async ({ page, request }) => {
    await login(page, '#/security');
    const dialog = await exportForm(page, phrase);
    if (valid) {
      const downloaded = page.waitForEvent('download');
      await dialog.getByRole('button', { name: 'Export', exact: true }).click();
      await downloaded;
      await expect(dialog).toBeHidden();
    } else {
      await dialog.getByRole('button', { name: 'Export', exact: true }).click();
      await expect(dialog.getByRole('alert')).toBeVisible();
      expect((await calls(request)).filter((call) => call.method === 'keys.export')).toEqual([]);
    }
  });
}

test('missing export data never downloads an empty file or claims success', async ({ page }) => {
  await login(page, '#/security');
  await page.route('**/api/rpc', (route) => {
    const body = route.request().postDataJSON();
    return body.method === 'keys.export'
      ? route.fulfill({ json: { id: body.id, result: { locks: [FRONT_DOOR] } } })
      : route.continue();
  });
  let downloads = 0;
  page.on('download', () => downloads++);
  const dialog = await exportForm(page);
  await dialog.getByRole('button', { name: 'Export', exact: true }).click();
  await expect(dialog.getByRole('alert')).toContainText('invalid backup');
  expect(downloads).toBe(0);
  await expect(page.locator('#toasts')).not.toContainText('Key backup saved');
});

test('a stored hardened flag still allows a fresh preview without claiming verified protection', async ({ page, request }) => {
  const part = await openHardening(page, request, { hardened: true });
  await expect(part.getByRole('button', { name: 'Preview hardening' })).toBeVisible();
  await expect(part).not.toContainText('Default passcodes are gone');
});

test('a malformed preview never enables execution', async ({ page, request }) => {
  const part = await openHardening(page, request);
  await page.route('**/api/rpc', (route) => {
    const body = route.request().postDataJSON();
    return body.method === 'lock.harden'
      ? route.fulfill({ json: { id: body.id, result: {
        dryRun: true, completion: 'preview', executable: true, hardened: false,
        steps: [
          { step: 'time', status: 'planned' },
          { step: 'passcodes', status: 'planned' },
          { step: 'admin', status: 'preserved', reason: 'owner' },
          { step: 'resetButton', status: 'skipped', reason: 'unverified_switch_layout' },
        ],
      } } })
      : route.continue();
  });
  await part.getByRole('button', { name: 'Preview hardening' }).click();
  await expect(part.getByRole('alert')).toContainText('invalid hardening report');
  await expect(part.getByRole('button', { name: 'Apply hardening' })).toBeDisabled();
});

for (const code of ['too_large', 'storage_full', 'confirm_timeout']) {
  test(`export failure ${code} keeps the form and backup state`, async ({ page, request }) => {
    await mock(request, { failNext: { method: 'keys.export', code } });
    await login(page, '#/security');
    let downloads = 0;
    page.on('download', () => downloads++);
    const dialog = await exportForm(page);
    await dialog.getByRole('button', { name: 'Export', exact: true }).click();
    await expect(dialog.getByRole('alert')).toBeVisible();
    if (code === 'too_large') await expect(dialog.getByRole('alert')).toContainText('export individual locks');
    expect(downloads).toBe(0);
    await expect(page.locator('#toasts')).not.toContainText('Key backup saved');
    await dialog.getByRole('button', { name: 'Cancel' }).click();
    await page.getByRole('link', { name: 'Locks', exact: true }).click();
    await expect(lockCard(page, 'Shed')).toContainText('No key backup');
  });
}

async function importForm(page, bytes, phrase = PASSPHRASE) {
  await page.getByRole('button', { name: 'Import keys' }).click();
  const dialog = page.getByRole('dialog', { name: 'Import keys' });
  await dialog.getByLabel('Backup file (.lkb)').setInputFiles({ name: 'fixture.lkb', mimeType: 'application/octet-stream', buffer: bytes });
  await dialog.getByLabel('Passphrase').fill(phrase);
  return dialog;
}

test('confirmed import remains explicit when the following list refresh fails', async ({ page, request }) => {
  await mock(request, { confirmDelayMs: 20 });
  await login(page);
  await openLock(page, 'Shed', 'Device');
  const exporting = await exportForm(page);
  const downloaded = page.waitForEvent('download');
  await exporting.getByRole('button', { name: 'Export', exact: true }).click();
  const bytes = await readFile(await (await downloaded).path());
  await expect(exporting).toBeHidden();
  const forgotten = await page.request.post('/api/rpc', { data: { id: 1, method: 'locks.forget', params: { lock: SHED } } });
  expect((await forgotten.json()).error).toBeUndefined();
  await page.getByRole('link', { name: 'Security', exact: true }).click();
  const importing = await importForm(page, bytes);
  await mock(request, { failNext: { method: 'locks.list', code: 'storage_error', message: 'list refresh failed' } });
  await importing.getByRole('button', { name: 'Import', exact: true }).click();
  const notice = page.locator('#toasts .toast-warning');
  await expect(notice).toContainText('Imported 1 lock');
  await expect(notice).toContainText('List refresh failed');
  await expect(importing).toBeHidden();
  await notice.getByRole('link', { name: 'Open locks' }).click();
  await expect(lockCard(page, 'Shed')).toBeVisible();
  expect((await calls(request)).filter((call) => call.method === 'keys.import')).toHaveLength(1);
});

test('all-lock backup preserves spaces and refuses a conflicting import without overwriting names', async ({ page, request }) => {
  await mock(request, { confirmDelayMs: 100, setLock: { id: FRONT_DOOR, backedUp: false } });
  await login(page, '#/security');
  const phrase = ` ${PASSPHRASE} `;
  const exporting = await exportForm(page, phrase);
  const download = page.waitForEvent('download');
  await exporting.getByRole('button', { name: 'Export', exact: true }).click();
  const bytes = await readFile(await (await download).path());
  await expect(exporting).toBeHidden();
  await page.getByRole('link', { name: 'Locks', exact: true }).click();
  for (const name of ['Front door', 'Shed']) await expect(lockCard(page, name)).not.toContainText('No key backup');
  await page.request.post('/api/rpc', { data: { id: 1, method: 'locks.rename', params: { lock: SHED, name: 'Renamed shed' } } });
  await page.getByRole('link', { name: 'Security', exact: true }).click();
  const importing = await importForm(page, bytes, phrase.trim());
  await importing.getByRole('button', { name: 'Import', exact: true }).click();
  await expect(importing.getByRole('alert')).toContainText(/wrong passphrase/i);
  await importing.getByLabel('Passphrase').fill(phrase);
  await importing.getByRole('button', { name: 'Import', exact: true }).click();
  await expect(importing.getByRole('alert')).toContainText('already stored');
  await expect(page.locator('#toasts')).not.toContainText('Imported');
  await importing.getByRole('button', { name: 'Cancel' }).click();
  await page.getByRole('link', { name: 'Locks', exact: true }).click();
  await expect(lockCard(page, 'Renamed shed')).toBeVisible();
  expect((await calls(request)).filter((call) => call.method.startsWith('keys.')).every((call) => call.params.passphrase === '***')).toBe(true);
});

for (const code of ['storage_full', 'confirm_timeout', 'internal']) {
  test(`import failure ${code} never claims restored locks`, async ({ page, request }) => {
    await mock(request, { failNext: { method: 'keys.import', code } });
    await login(page, '#/security');
    const dialog = await importForm(page, Buffer.from('opaque fixture'));
    await dialog.getByRole('button', { name: 'Import', exact: true }).click();
    await expect(dialog.getByRole('alert')).toBeVisible();
    await expect(page.locator('#toasts')).not.toContainText('Imported');
  });
}

for (const phrase of ['é'.repeat(5), 'é'.repeat(65), 'long enough\0phrase']) {
  test(`invalid import passphrase ${Buffer.byteLength(phrase)} bytes is refused before sending`, async ({ page, request }) => {
    await login(page, '#/security');
    const dialog = await importForm(page, Buffer.from('opaque fixture'), phrase);
    await dialog.getByRole('button', { name: 'Import', exact: true }).click();
    await expect(dialog.getByRole('alert')).toBeVisible();
    expect((await calls(request)).filter((call) => call.method === 'keys.import')).toEqual([]);
  });
}

test('a dropped backup job socket cannot create a download after reconnecting', async ({ page, request }) => {
  await mock(request, { confirm: 'never', confirmTimeoutMs: 60_000 });
  await login(page, '#/security');
  let downloads = 0;
  page.on('download', () => downloads++);
  const dialog = await exportForm(page);
  await dialog.getByRole('button', { name: 'Export', exact: true }).click();
  await expect(boardButton(page)).toBeVisible();
  await mock(request, { dropSockets: true });
  await expect(dialog.getByRole('alert')).toContainText('connection to the board dropped');
  await expect(page.locator('#live')).toHaveAttribute('data-live', 'on');
  await expect(dialog).toBeVisible();
  expect(downloads).toBe(0);
  expect((await calls(request)).filter((call) => call.method === 'keys.export')).toHaveLength(1);
});

test('execution rechecks the clock after confirmation', async ({ page, request }) => {
  const part = await openHardening(page, request);
  await part.getByRole('button', { name: 'Preview hardening' }).click();
  await expect(part.getByRole('button', { name: 'Apply hardening' })).toBeEnabled();
  await mock(request, { confirmDelayMs: 1000 });
  await part.getByRole('button', { name: 'Apply hardening' }).click();
  await expect(boardButton(page)).toBeVisible();
  await mock(request, { timeSynced: false });
  await expect(part.getByRole('alert')).toContainText(/clock/i);
  await expect(part).not.toContainText('Hardening partially completed');
  await expect(part.getByRole('button', { name: 'Apply hardening' })).toBeDisabled();
});
