// SPDX-License-Identifier: GPL-3.0-or-later
const { test, expect, calls, login, openLock, openTab, SHED } = require('./support.cjs');

const GATED = /^lock\.(fingerprints|cards|passage|sound|resetButton|remoteUnlock)\./;

async function headings(page) {
  return page.locator('#main h2').allInnerTexts();
}

test('controls for features a lock does not report are hidden', async ({ page, request }) => {
  await login(page);

  await openLock(page, 'Front door', 'Access');
  expect(await headings(page)).toEqual(expect.arrayContaining(['Passcodes', 'Fingerprints', 'IC cards']));
  await openTab(page, 'Settings');
  expect(await headings(page)).toEqual(
    expect.arrayContaining([
      'Auto-lock',
      'Passage mode',
      'Sound',
      'Reset button',
      'Remote unlock',
      'Super admin passcode',
      'Clock',
    ]),
  );

  await openLock(page, 'Shed', 'Access');
  expect(await headings(page)).toEqual(['Passcodes']);
  await expect(page.getByRole('button', { name: 'Add passcode' })).toBeVisible();
  await page.getByRole('button', { name: 'Add passcode' }).click();
  const types = await page
    .getByRole('dialog', { name: 'Add passcode' })
    .getByLabel('Type')
    .locator('option')
    .allInnerTexts();
  expect(types).toEqual(['Permanent', 'Timed', 'One-time']);
  await page.getByRole('dialog', { name: 'Add passcode' }).getByRole('button', { name: 'Cancel' }).click();
  await expect(page.getByRole('region', { name: 'Passcodes' }).getByRole('button', { name: 'Edit' })).toHaveCount(0);

  await openTab(page, 'Settings');
  expect(await headings(page)).toEqual(['Auto-lock', 'Super admin passcode', 'Clock']);

  await openTab(page, 'Device');
  const features = page.getByRole('list', { name: 'Reported features' });
  await expect(features).toContainText('Passcodes');
  await expect(features).not.toContainText('Fingerprints');

  const made = await calls(request);
  const unsupported = made.filter((call) => call.params.lock === SHED && GATED.test(call.method));
  expect(unsupported).toEqual([]);
  expect(made.some((call) => call.params.lock === SHED && call.method === 'lock.features')).toBe(true);
});
