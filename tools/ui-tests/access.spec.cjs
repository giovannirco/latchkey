// SPDX-License-Identifier: GPL-3.0-or-later
const { test, expect, mock, calls, login, openLock, boardButton, toast, FRONT_DOOR } = require('./support.cjs');

test('a new passcode is shown once, listed masked, and can be deleted', async ({ page, request }) => {
  await login(page);
  await openLock(page, 'Front door', 'Access');
  const passcodes = page.getByRole('region', { name: 'Passcodes' });
  await expect(passcodes.getByRole('listitem')).toHaveCount(2);

  await passcodes.getByRole('button', { name: 'Add passcode' }).click();
  const form = page.getByRole('dialog', { name: 'Add passcode' });
  await form.getByLabel('Name').fill('Guest');
  await form.getByLabel('Type').selectOption('permanent');
  await expect(form.getByLabel('Valid from')).toBeHidden();
  await form.getByRole('button', { name: 'Add', exact: true }).click();

  const shown = page.getByRole('dialog', { name: 'New passcode' });
  const code = (await shown.locator('output').textContent()).trim();
  expect(code).toMatch(/^\d{6}$/);
  await expect(shown).toContainText('will not be shown again');
  await shown.getByRole('button', { name: 'Done' }).click();
  await expect(shown).toBeHidden();

  const guest = passcodes.getByRole('listitem').filter({ hasText: 'Guest' });
  await expect(guest).toContainText('Permanent');
  await expect(guest).toContainText('••••••');
  expect(await page.locator('body').innerText()).not.toContain(code);
  const markup = await page.evaluate(() => document.body.innerHTML.replace(/<script[\s\S]*?<\/script>/g, ''));
  expect(markup).not.toContain(code);

  await guest.getByRole('button', { name: 'Delete' }).click();
  const confirm = page.getByRole('dialog', { name: 'Delete passcode' });
  await expect(confirm).toContainText('Guest');
  await confirm.getByRole('button', { name: 'Delete' }).click();
  await expect(guest).toHaveCount(0);
  await expect(passcodes.getByRole('listitem')).toHaveCount(2);

  const listed = (await calls(request)).filter((call) => call.method === 'lock.passcodes.list');
  expect(listed.length).toBeGreaterThan(0);
});

test('a timed passcode needs a validity window', async ({ page }) => {
  await login(page);
  await openLock(page, 'Front door', 'Access');
  await page.getByRole('button', { name: 'Add passcode' }).click();
  const form = page.getByRole('dialog', { name: 'Add passcode' });
  await form.getByLabel('Name').fill('Cleaner Friday');
  await form.getByLabel('Type').selectOption('timed');
  await form.getByLabel('Code (optional)').fill('482913');
  await form.getByLabel('Valid from').fill('2030-01-10T09:00');
  await form.getByLabel('Valid until').fill('2030-01-10T08:00');
  await form.getByRole('button', { name: 'Add', exact: true }).click();
  await expect(form.getByRole('alert')).toContainText('must be after');

  await form.getByLabel('Valid until').fill('2030-01-10T17:00');
  await form.getByRole('button', { name: 'Add', exact: true }).click();
  await page.getByRole('dialog', { name: 'New passcode' }).getByRole('button', { name: 'Done' }).click();
  const item = page
    .getByRole('region', { name: 'Passcodes' })
    .getByRole('listitem')
    .filter({ hasText: 'Cleaner Friday' });
  await expect(item).toContainText('Timed');
  await expect(item).toContainText('2030');
});

test('fingerprint enrolment shows live progress in a modal', async ({ page }) => {
  await login(page);
  await openLock(page, 'Front door', 'Access');
  const region = page.getByRole('region', { name: 'Fingerprints' });
  await region.getByRole('button', { name: 'Add fingerprint' }).click();
  const form = page.getByRole('dialog', { name: 'Add fingerprint' });
  await form.getByLabel('Name').fill('Left thumb');
  await form.getByRole('button', { name: 'Start' }).click();

  const modal = page.getByRole('dialog', { name: 'Enrolling fingerprint' });
  await expect(modal).toContainText('Place your finger on the sensor');
  await expect(modal).toContainText('Scan 2 of 4');
  await expect(modal).toContainText('Scan 4 of 4');
  await expect(modal.getByRole('progressbar')).toBeVisible();
  await expect(modal).toBeHidden({ timeout: 10_000 });
  await expect(region.getByRole('listitem').filter({ hasText: 'Left thumb' })).toBeVisible();
});

test('a failed enrolment is reported in the modal', async ({ page, request }) => {
  await login(page);
  await openLock(page, 'Front door', 'Access');
  await mock(request, { failNext: { method: 'lock.cards.enroll', code: 'timeout', message: 'no card presented' } });
  await page.getByRole('button', { name: 'Add card' }).click();
  await page.getByRole('dialog', { name: 'Add card' }).getByRole('button', { name: 'Start' }).click();
  const modal = page.getByRole('dialog', { name: 'Enrolling card' });
  await expect(modal.getByRole('alert')).toContainText('The lock did not answer in time');
  await modal.getByRole('button', { name: 'Close' }).click();
  await expect(modal).toBeHidden();
});

test('card numbers are masked and validity can be changed', async ({ page, request }) => {
  await login(page);
  await openLock(page, 'Front door', 'Access');
  const cards = page.getByRole('region', { name: 'IC cards' });
  const spare = cards.getByRole('listitem').filter({ hasText: 'Spare card' });
  await expect(spare).toContainText('•••• 2653');
  await expect(spare).not.toContainText('3141592653');
  await expect(spare).toContainText('Permanent');

  await spare.getByRole('button', { name: 'Validity' }).click();
  const dialog = page.getByRole('dialog', { name: 'Card validity' });
  await dialog.getByLabel('Permanent').uncheck();
  await dialog.getByLabel('Valid from').fill('2030-02-01T00:00');
  await dialog.getByLabel('Valid until').fill('2030-03-01T00:00');
  await dialog.getByRole('button', { name: 'Save' }).click();
  await expect(spare).toContainText('2030');

  const set = (await calls(request)).find((call) => call.method === 'lock.cards.setValidity');
  expect(set.params.lock).toBe(FRONT_DOOR);
  expect(set.params.validity.end).toBeGreaterThan(set.params.validity.start);
});

test('cyclic passcodes are not offered, since the board cannot add them', async ({ page }) => {
  await login(page);
  await openLock(page, 'Front door', 'Access');
  await page.getByRole('button', { name: 'Add passcode' }).click();
  const form = page.getByRole('dialog', { name: 'Add passcode' });
  expect(await form.getByLabel('Type').locator('option').allInnerTexts()).toEqual(['Permanent', 'Timed', 'One-time']);
  await expect(form.getByText('Repeats every week')).toHaveCount(0);
});

test('a fingerprint can repeat every week on a lock with cyclic credentials', async ({ page, request }) => {
  await login(page);
  await openLock(page, 'Front door', 'Access');
  const owner = page
    .getByRole('region', { name: 'Fingerprints' })
    .getByRole('listitem')
    .filter({ hasText: 'Owner right index' });
  await owner.getByRole('button', { name: 'Validity' }).click();
  const dialog = page.getByRole('dialog', { name: 'Fingerprint validity' });
  await expect(dialog.getByLabel('Daily from')).toBeHidden();
  await dialog.getByLabel('Repeats every week').check();
  await dialog.getByLabel('Daily from').fill('09:00');
  await dialog.getByLabel('Daily until').fill('17:30');
  await dialog.getByRole('button', { name: 'Save' }).click();
  await expect(owner).toContainText('Mon, Tue, Wed, Thu, Fri, 09:00 to 17:30');

  const set = (await calls(request)).find((call) => call.method === 'lock.fingerprints.setValidity');
  expect(set.params).toEqual({
    lock: FRONT_DOOR,
    id: '1',
    validity: null,
    cycle: { days: [1, 2, 3, 4, 5], start: '09:00', end: '17:30' },
  });

  await owner.getByRole('button', { name: 'Validity' }).click();
  await expect(dialog.getByLabel('Repeats every week')).toBeChecked();
  await dialog.getByLabel('Repeats every week').uncheck();
  await dialog.getByRole('button', { name: 'Save' }).click();
  await expect(owner).not.toContainText('09:00 to 17:30');
});

test('the super admin passcode is shown and changed with the board button', async ({ page, request }) => {
  await login(page);
  await openLock(page, 'Front door', 'Settings');
  const section = page.getByRole('region', { name: 'Super admin passcode' });

  await section.getByRole('button', { name: 'Show admin passcode' }).click();
  await expect(boardButton(page)).toContainText('Show the super admin passcode');
  const shown = page.getByRole('dialog', { name: 'Super admin passcode' });
  await expect(shown).toContainText('Read from the lock');
  const current = (await shown.locator('output').textContent()).trim();
  expect(current).toMatch(/^\d{4,9}$/);
  await shown.getByRole('button', { name: 'Done' }).click();

  await section.getByRole('button', { name: 'Change admin passcode' }).click();
  const form = page.getByRole('dialog', { name: 'Change the super admin passcode' });
  await form.getByLabel('New super admin passcode (optional)').fill('27182818');
  await form.getByRole('button', { name: 'Save' }).click();
  await expect(boardButton(page)).toContainText('Change the super admin passcode');
  await expect(toast(page, 'Super admin passcode changed')).toBeVisible();

  await section.getByRole('button', { name: 'Change admin passcode' }).click();
  await page
    .getByRole('dialog', { name: 'Change the super admin passcode' })
    .getByRole('button', { name: 'Save' })
    .click();
  const fresh = page.getByRole('dialog', { name: 'New super admin passcode' });
  expect((await fresh.locator('output').textContent()).trim()).toMatch(/^\d{7}$/);
  await fresh.getByRole('button', { name: 'Done' }).click();

  const made = await calls(request);
  expect(made.filter((call) => call.method === 'lock.adminPasscode.get')).toHaveLength(1);
  const sets = made.filter((call) => call.method === 'lock.adminPasscode.set');
  expect(sets.map((call) => call.params.code)).toEqual(['***', undefined]);
});

test('the board copy of the super admin passcode is shown when the lock cannot be read', async ({ page, request }) => {
  await login(page);
  await openLock(page, 'Shed', 'Settings');
  await page.getByRole('button', { name: 'Show admin passcode' }).click();
  const shown = page.getByRole('dialog', { name: 'Super admin passcode' });
  await expect(shown).toContainText('the copy the board kept');
  expect((await shown.locator('output').textContent()).trim()).toBe('123456');
});
