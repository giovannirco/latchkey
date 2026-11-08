// SPDX-License-Identifier: GPL-3.0-or-later
const {
  test,
  expect,
  mock,
  calls,
  login,
  openLock,
  openTab,
  boardButton,
  toast,
  FRONT_DOOR,
} = require('./support.cjs');

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
  await expect(dialog.getByLabel('Always')).toBeChecked();
  await dialog.getByLabel('Between dates').check();
  await expect(dialog.getByText("this device's time zone")).toBeVisible();
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

test('a fingerprint gets a weekly schedule from day toggles and shortcuts', async ({ page, request }) => {
  await login(page);
  await openLock(page, 'Front door', 'Access');
  const owner = page
    .getByRole('region', { name: 'Fingerprints' })
    .getByRole('listitem')
    .filter({ hasText: 'Owner right index' });
  await owner.getByRole('button', { name: 'Validity' }).click();
  const dialog = page.getByRole('dialog', { name: 'Fingerprint validity' });
  await expect(dialog.getByLabel('Always')).toBeChecked();
  await expect(dialog.getByLabel('From', { exact: true })).toBeHidden();
  await dialog.getByLabel('Weekly schedule').check();
  const days = dialog.getByRole('group', { name: 'Days' });
  await expect(days.getByRole('button', { name: 'Mondays' })).toHaveAttribute('aria-pressed', 'true');
  await expect(days.getByRole('button', { name: 'Saturdays' })).toHaveAttribute('aria-pressed', 'false');
  await expect(dialog.getByText('Weekdays 08:00-18:00')).toBeVisible();
  await dialog.getByRole('button', { name: 'Every day' }).click();
  await expect(dialog.getByText('Every day 08:00-18:00')).toBeVisible();
  await days.getByRole('button', { name: 'Sundays' }).click();
  await expect(dialog.getByText('Mon, Tue, Wed, Thu, Fri, Sat 08:00-18:00')).toBeVisible();
  await dialog.getByRole('button', { name: 'Weekdays' }).click();
  await dialog.getByLabel('From', { exact: true }).fill('09:00');
  await dialog.getByLabel('Until', { exact: true }).fill('17:30');
  await expect(dialog.getByText('Weekdays 09:00-17:30')).toBeVisible();
  await dialog.getByRole('button', { name: 'Save' }).click();
  await expect(owner).toContainText('Weekdays 09:00-17:30');

  const set = (await calls(request)).find((call) => call.method === 'lock.fingerprints.setValidity');
  expect(set.params).toEqual({
    lock: FRONT_DOOR,
    id: '1',
    validity: null,
    cycle: { days: [1, 2, 3, 4, 5], start: '09:00', end: '17:30' },
  });

  await owner.getByRole('button', { name: 'Validity' }).click();
  await expect(dialog.getByLabel('Weekly schedule')).toBeChecked();
  await dialog.getByLabel('Always').check();
  await dialog.getByRole('button', { name: 'Save' }).click();
  await expect(owner).not.toContainText('09:00-17:30');
  const cleared = (await calls(request)).filter((call) => call.method === 'lock.fingerprints.setValidity').pop();
  expect(cleared.params).toEqual({ lock: FRONT_DOOR, id: '1', validity: null, cycle: null });
});

test('a schedule needs a day and a window that runs forward', async ({ page }) => {
  await login(page);
  await openLock(page, 'Front door', 'Access');
  await page.getByRole('region', { name: 'Fingerprints' }).getByRole('button', { name: 'Validity' }).first().click();
  const dialog = page.getByRole('dialog', { name: 'Fingerprint validity' });
  await dialog.getByLabel('Weekly schedule').check();
  for (const day of ['Mondays', 'Tuesdays', 'Wednesdays', 'Thursdays', 'Fridays']) {
    await dialog.getByRole('group', { name: 'Days' }).getByRole('button', { name: day }).click();
  }
  await expect(dialog.getByText('No day picked yet')).toBeVisible();
  await dialog.getByRole('button', { name: 'Save' }).click();
  await expect(dialog.getByRole('alert')).toContainText('Pick at least one day');
  await dialog.getByRole('button', { name: 'Weekdays' }).click();
  await dialog.getByLabel('Until', { exact: true }).fill('07:00');
  await dialog.getByRole('button', { name: 'Save' }).click();
  await expect(dialog.getByRole('alert')).toContainText('must end after it starts');
});

async function choicesStayPut(page) {
  await login(page);
  await openLock(page, 'Front door', 'Access');
  await page.getByRole('region', { name: 'Fingerprints' }).getByRole('button', { name: 'Validity' }).first().click();
  const dialog = page.getByRole('dialog', { name: 'Fingerprint validity' });
  const names = ['Always', 'Between dates', 'Weekly schedule'];
  const boxes = async () => {
    const group = await dialog.locator('fieldset.choices').boundingBox();
    const found = [];
    for (const name of names) {
      const box = await dialog.locator('label.choice').filter({ hasText: name }).boundingBox();
      found.push({ x: box.x - group.x, y: box.y - group.y, width: box.width, height: box.height });
    }
    return found;
  };
  const before = await boxes();
  for (const name of ['Between dates', 'Weekly schedule', 'Always']) {
    await dialog.getByLabel(name).check();
    expect(await boxes(), `after picking ${name}`).toEqual(before);
  }
}

test('the schedule choices stay in place when another is picked', async ({ page }) => {
  await choicesStayPut(page);
});

test.describe('validity editor at phone width', () => {
  test.use({ viewport: { width: 360, height: 740 }, isMobile: true, hasTouch: true });

  test('the schedule choices stay in place when another is picked', async ({ page }) => {
    await choicesStayPut(page);
  });

  test('the choices and day toggles fit without overlapping', async ({ page }) => {
    await login(page);
    await openLock(page, 'Front door', 'Access');
    await page.getByRole('region', { name: 'Fingerprints' }).getByRole('button', { name: 'Validity' }).first().click();
    const dialog = page.getByRole('dialog', { name: 'Fingerprint validity' });
    await dialog.getByLabel('Weekly schedule').check();
    const boxes = [];
    for (const name of ['Always', 'Between dates', 'Weekly schedule']) {
      boxes.push(await dialog.locator('label.choice').filter({ hasText: name }).boundingBox());
    }
    for (const day of ['Mondays', 'Tuesdays', 'Wednesdays', 'Thursdays', 'Fridays', 'Saturdays', 'Sundays']) {
      boxes.push(await dialog.getByRole('button', { name: day }).boundingBox());
    }
    const overlaps = (a, b) =>
      a.x < b.x + b.width - 1 && b.x < a.x + a.width - 1 && a.y < b.y + b.height - 1 && b.y < a.y + a.height - 1;
    for (let i = 0; i < boxes.length; i += 1) {
      for (let j = i + 1; j < boxes.length; j += 1) expect(overlaps(boxes[i], boxes[j]), `${i} and ${j}`).toBe(false);
    }
    const dialogBox = await dialog.boundingBox();
    for (const box of boxes) expect(box.x + box.width).toBeLessThanOrEqual(dialogBox.x + dialogBox.width + 1);
  });
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

test('the passcode page explains that the lock finds a code inside longer digits', async ({ page }) => {
  await login(page);
  await openLock(page, 'Front door', 'Access');
  const passcodes = page.getByRole('region', { name: 'Passcodes' });
  await expect(passcodes).toContainText('appears anywhere among the digits typed');
  await expect(passcodes).toContainText('Use 7 to 9 digits');
});

test('an easy code is added with a warning that stays until dismissed', async ({ page }) => {
  await login(page);
  await openLock(page, 'Front door', 'Access');
  await page.getByRole('button', { name: 'Add passcode' }).click();
  const form = page.getByRole('dialog', { name: 'Add passcode' });
  await form.getByLabel('Name').fill('Weak');
  await form.getByLabel('Code (optional)').fill('123456');
  await form.getByRole('button', { name: 'Add', exact: true }).click();
  await page.getByRole('dialog', { name: 'New passcode' }).getByRole('button', { name: 'Done' }).click();
  const warning = page.locator('#toasts .toast-warning');
  await expect(warning).toContainText('Done, with a warning');
  await expect(warning).toContainText('This code is easy to guess');
  await page.waitForTimeout(7000);
  await expect(warning).toBeVisible();
  await warning.getByRole('button', { name: 'Dismiss' }).click();
  await expect(warning).toHaveCount(0);
});

test('a warning from any method reaches the owner', async ({ page, request }) => {
  await login(page);
  await openLock(page, 'Front door', 'Settings');
  await mock(request, {
    warnNext: {
      method: 'lock.adminPasscode.set',
      warning: 'the lock took the new admin passcode, but the board could not mark its copy as taken',
    },
  });
  const section = page.getByRole('region', { name: 'Super admin passcode' });
  await section.getByRole('button', { name: 'Change admin passcode' }).click();
  const form = page.getByRole('dialog', { name: 'Change the super admin passcode' });
  await form.getByLabel('New super admin passcode (optional)').fill('48291736');
  await form.getByRole('button', { name: 'Save' }).click();
  await expect(page.locator('#toasts .toast-warning')).toContainText('could not mark its copy as taken');

  await openTab(page, 'Access');
  await mock(request, {
    warnNext: { method: 'lock.cards.setValidity', warning: 'the board could not store its names' },
  });
  const spare = page.getByRole('region', { name: 'IC cards' }).getByRole('listitem').filter({ hasText: 'Spare card' });
  await spare.getByRole('button', { name: 'Validity' }).click();
  await page.getByRole('dialog', { name: 'Card validity' }).getByRole('button', { name: 'Save' }).click();
  await expect(page.locator('#toasts .toast-warning').filter({ hasText: 'could not store its names' })).toBeVisible();
});

test('a full board storage is explained', async ({ page, request }) => {
  await login(page);
  await openLock(page, 'Front door', 'Access');
  await mock(request, { failNext: { method: 'lock.passcodes.add', code: 'storage_full', message: 'storage full' } });
  await page.getByRole('button', { name: 'Add passcode' }).click();
  const form = page.getByRole('dialog', { name: 'Add passcode' });
  await form.getByLabel('Name').fill('Guest');
  await form.getByRole('button', { name: 'Add', exact: true }).click();
  await expect(form.getByRole('alert')).toContainText("The board's storage is nearly full");
});

test('code fields are masked without being login passwords', async ({ page }) => {
  await login(page);
  await openLock(page, 'Front door', 'Settings');
  await page.getByRole('button', { name: 'Change admin passcode' }).click();
  const code = page
    .getByRole('dialog', { name: 'Change the super admin passcode' })
    .getByLabel('New super admin passcode (optional)');
  await expect(code).toHaveAttribute('type', 'text');
  await expect(code).toHaveAttribute('autocomplete', 'off');
  expect(await code.evaluate((input) => getComputedStyle(input).webkitTextSecurity)).toBe('disc');
});
