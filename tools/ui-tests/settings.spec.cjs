// SPDX-License-Identifier: GPL-3.0-or-later
const { test, expect, mock, calls, login, openLock, boardButton, toast, FRONT_DOOR } = require('./support.cjs');

async function headings(page) {
  return page.locator('#main h2').allInnerTexts();
}

test('unverified switches are read-only and remote unlock has no control', async ({ page, request }) => {
  await login(page);
  await openLock(page, 'Front door', 'Settings');
  const titles = await headings(page);
  expect(titles).toEqual(expect.arrayContaining(['Privacy lock', 'Tamper alert']));
  expect(titles).not.toContain('Remote unlock');
  for (const [title, label] of [
    ['Privacy lock', 'Privacy lock'],
    ['Tamper alert', 'Tamper alert'],
    ['Reset button', 'Physical reset button'],
  ]) {
    await expect(page.getByRole('region', { name: title })).toContainText('read-only');
    await expect(page.getByRole('switch', { name: label })).toBeDisabled();
  }
  const privacy = page.getByRole('switch', { name: 'Privacy lock' });
  await expect(privacy).not.toBeChecked();
  const made = await calls(request);
  expect(made.some((call) => call.method.startsWith('lock.remoteUnlock.'))).toBe(false);
  expect(made.some((call) => /lock\.(privacyLock|tamperAlert|resetButton)\.set/.test(call.method))).toBe(false);
});

test('the reset button stays read-only without a key backup', async ({ page, request }) => {
  await mock(request, { setLock: { id: FRONT_DOOR, resetButton: true, backedUp: false } });
  await login(page);
  await openLock(page, 'Front door', 'Settings');
  const reset = page.getByRole('switch', { name: 'Physical reset button' });
  await expect(reset).toBeChecked();
  await expect(reset).toBeDisabled();
  await expect(boardButton(page)).toBeHidden();
  const refused = (await calls(request)).filter((call) => call.method === 'lock.resetButton.set');
  expect(refused).toEqual([]);
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
  await mock(request, {
    emit: [{ event: 'lock.alert', data: { lock: FRONT_DOOR, method: 'app', time, seq: 41, type: 1 } }],
  });
  const notice = page.locator('#toasts .toast-alarm');
  await expect(notice).toContainText('Front door was unlocked from the app, and not by Latchkey');
  await page.waitForTimeout(7000);
  await expect(notice).toBeVisible();
  await notice.getByRole('button', { name: 'Dismiss' }).click();
  await expect(notice).toHaveCount(0);

  await mock(request, {
    emit: [{ event: 'lock.alert', data: { lock: FRONT_DOOR, method: 'forced', time, seq: 42, type: 29 } }],
  });
  await expect(page.locator('#toasts .toast-alarm')).toContainText('Front door was forced open');
});

test('the log shows the newest entries and reads on until it has every new one', async ({ page, request }) => {
  const now = Math.floor(Date.now() / 1000);
  const entry = (seq) => ({ seq, time: now - 3600 + seq, type: seq % 2 ? 4 : 26, battery: 80 });
  await mock(request, { setLock: { id: FRONT_DOOR, log: Array.from({ length: 30 }, (_, i) => entry(i + 1)) } });
  await login(page);
  await openLock(page, 'Front door', 'Log');
  const rows = page.getByRole('table', { name: 'Operation log' }).locator('tbody tr');
  await expect(rows).toHaveCount(16);
  await mock(request, { setLock: { id: FRONT_DOOR, log: Array.from({ length: 50 }, (_, i) => entry(i + 1)) } });
  await page.getByRole('button', { name: 'Fetch new entries' }).click();
  await expect(toast(page, '20 new entries')).toBeVisible();
  await expect(rows).toHaveCount(36);
  const fetched = (await calls(request)).filter((call) => call.method === 'lock.log.fetch').map((call) => call.params);
  expect(fetched).toEqual([{ lock: FRONT_DOOR }, { lock: FRONT_DOOR, since: 30 }, { lock: FRONT_DOOR, since: 46 }]);
});

test('an alert raised with no browser open stays visible until acknowledged', async ({ page, request }) => {
  const time = Math.floor(Date.now() / 1000) - 120;
  await mock(request, {
    emit: [{ event: 'lock.alert', data: { lock: FRONT_DOOR, method: 'app', time, seq: 41, type: 1 } }],
  });
  await login(page);
  await expect(page.getByRole('article', { name: 'Front door' })).toContainText('1 alert');
  await openLock(page, 'Front door');
  const alerts = page.getByRole('region', { name: 'Alerts', exact: true });
  await expect(alerts).toContainText('unlocked from the app');
  await page.reload();
  await expect(page.getByRole('region', { name: 'Alerts', exact: true })).toContainText('unlocked from the app');
  await page.getByRole('button', { name: 'Acknowledge alerts' }).click();
  await expect(page.getByRole('region', { name: 'Alerts', exact: true })).toContainText('No unacknowledged alerts');
  await page.reload();
  await expect(page.getByRole('region', { name: 'Alerts', exact: true })).toContainText('No unacknowledged alerts');
  expect((await calls(request)).filter((call) => call.method === 'lock.alerts.ack')).toEqual([
    { method: 'lock.alerts.ack', params: { lock: FRONT_DOOR, through: 1 } },
  ]);
});

test('an unreadable watch state is a monitoring warning without an unlock alarm', async ({ page, request }) => {
  await mock(request, {
    setLock: {
      id: FRONT_DOOR,
      alertNext: 2,
      alerts: [{ id: 1, kind: 'watch_state_unreadable', time: null, method: 'none', seq: 0, type: 0 }],
    },
  });
  await login(page);
  await expect(page.getByRole('article', { name: 'Front door' })).toContainText('Monitoring warning');
  await openLock(page, 'Front door');
  await expect(page.getByRole('region', { name: 'Alerts', exact: true })).toContainText(
    'some events may have been missed',
  );
  await expect(page.locator('#toasts .toast-alarm')).toHaveCount(0);
  await page.getByRole('button', { name: 'Acknowledge alerts' }).click();
  await expect(page.getByRole('region', { name: 'Alerts', exact: true })).toContainText('No unacknowledged alerts');
});

test('an older alert-list response cannot restore an acknowledged badge', async ({ page, request }) => {
  const time = Math.floor(Date.now() / 1000);
  await mock(request, {
    emit: [{ event: 'lock.alert', data: { lock: FRONT_DOOR, method: 'app', time, seq: 41, type: 1 } }],
  });
  await login(page);
  let held;
  let intercepted = false;
  await page.route('**/api/rpc', async (route) => {
    if (route.request().postDataJSON().method === 'lock.alerts.list' && !intercepted) {
      intercepted = true;
      held = route;
      return;
    }
    await route.continue();
  });
  await mock(request, {
    emit: [{ event: 'lock.alert', data: { lock: FRONT_DOOR, method: 'app', time, seq: 42, type: 1 } }],
  });
  await expect.poll(() => Boolean(held)).toBe(true);
  await page.evaluate(async (lock) => {
    await fetch('/api/rpc', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: 999, method: 'lock.alerts.ack', params: { lock, through: 2 } }),
    });
  }, FRONT_DOOR);
  const badge = page
    .getByRole('article', { name: 'Front door' })
    .locator('.badge')
    .filter({ hasText: /^\d+ alerts?$/ });
  await expect(badge).toBeHidden();
  const finished = page.waitForResponse(
    (response) => response.request().postDataJSON()?.id === held.request().postDataJSON().id,
  );
  await held.fulfill({
    json: { id: held.request().postDataJSON().id, result: { alerts: [{ id: 1 }, { id: 2 }], warnings: [] } },
  });
  await (await finished).finished();
  await page.evaluate(() => new Promise((resolve) => requestAnimationFrame(() => requestAnimationFrame(resolve))));
  await expect(
    page
      .getByRole('article', { name: 'Front door' })
      .locator('.badge')
      .filter({ hasText: /^\d+ alerts?$/ }),
  ).toBeHidden();
});
