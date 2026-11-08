// SPDX-License-Identifier: GPL-3.0-or-later
const { test, expect, mock, calls, login, openLock, boardButton, toast, FRONT_DOOR } = require('./support.cjs');

async function headings(page) {
  return page.locator('#main h2').allInnerTexts();
}

test('privacy lock and tamper alert are marked experimental and remote unlock has no control', async ({
  page,
  request,
}) => {
  await login(page);
  await openLock(page, 'Front door', 'Settings');
  const titles = await headings(page);
  expect(titles).toEqual(expect.arrayContaining(['Privacy lock', 'Tamper alert']));
  expect(titles).not.toContain('Remote unlock');
  for (const name of ['Privacy lock', 'Tamper alert']) {
    await expect(page.getByRole('region', { name })).toContainText('Experimental');
  }
  const privacy = page.getByRole('switch', { name: 'Privacy lock' });
  await expect(privacy).not.toBeChecked();
  await privacy.check();
  await expect(toast(page, 'Privacy lock turned on')).toBeVisible();
  await expect(privacy).toBeChecked();
  const made = await calls(request);
  expect(made.some((call) => call.method.startsWith('lock.remoteUnlock.'))).toBe(false);
  expect(made).toContainEqual({ method: 'lock.privacyLock.set', params: { lock: FRONT_DOOR, enabled: true } });
});

test('the reset button cannot be turned off without a key backup', async ({ page, request }) => {
  await mock(request, { setLock: { id: FRONT_DOOR, resetButton: true, backedUp: false } });
  await login(page);
  await openLock(page, 'Front door', 'Settings');
  const reset = page.getByRole('switch', { name: 'Physical reset button' });
  await expect(reset).toBeChecked();
  await expect(page.getByRole('region', { name: 'Reset button' })).toContainText('needs a key backup');
  await reset.uncheck();
  await expect(page.locator('#toasts [role="alert"]')).toContainText('Back up this lock');
  await expect(reset).toBeChecked();
  await expect(boardButton(page)).toBeHidden();
  const refused = (await calls(request)).filter((call) => call.method === 'lock.resetButton.set');
  expect(refused).toEqual([{ method: 'lock.resetButton.set', params: { lock: FRONT_DOOR, enabled: false } }]);
});

test('a sound setting without a volume shows only the switch', async ({ page, request }) => {
  await mock(request, { setLock: { id: FRONT_DOOR, sound: { enabled: true, volume: null } } });
  await login(page);
  await openLock(page, 'Front door', 'Settings');
  const sound = page.getByRole('region', { name: 'Sound' });
  await expect(sound.getByRole('switch', { name: 'Keypad sounds' })).toBeChecked();
  await expect(sound.getByLabel('Volume')).toHaveCount(0);
});

test('features the board does not use are listed apart', async ({ page }) => {
  await login(page);
  await openLock(page, 'Front door', 'Device');
  const used = page.getByRole('list', { name: 'Reported features' });
  const unused = page.getByRole('list', { name: 'Reported, not used by Latchkey' });
  await expect(used).toContainText('Passage mode');
  await expect(used).not.toContainText('Remote unlock');
  await expect(unused).toContainText('Remote unlock');
});

test('an unlock alert shows a notice that stays until it is dismissed', async ({ page, request }) => {
  await login(page);
  const time = Math.floor(Date.now() / 1000) - 120;
  await mock(request, { emit: [{ event: 'lock.alert', data: { lock: FRONT_DOOR, method: 'app', time, seq: 41 } }] });
  const notice = page.locator('#toasts .toast-alarm');
  await expect(notice).toContainText('Front door was unlocked from the app, and not by Latchkey');
  await page.waitForTimeout(7000);
  await expect(notice).toBeVisible();
  await notice.getByRole('button', { name: 'Dismiss' }).click();
  await expect(notice).toHaveCount(0);

  await mock(request, { emit: [{ event: 'lock.alert', data: { lock: FRONT_DOOR, method: 'forced', time, seq: 42 } }] });
  await expect(page.locator('#toasts .toast-alarm')).toContainText('Front door was forced open');
});
