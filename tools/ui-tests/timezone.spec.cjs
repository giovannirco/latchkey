// SPDX-License-Identifier: GPL-3.0-or-later
const { test, expect, calls, login, openLock, FRONT_DOOR } = require('./support.cjs');

test.use({ timezoneId: 'Asia/Kathmandu' });

test('a zone mismatch is visible before pairing and on every lock tab', async ({ page, request }) => {
  await login(page, '#/pair');
  await expect(page.getByRole('status').filter({ hasText: 'Board time zone differs' })).toBeVisible();
  await openLock(page, 'Front door');
  const notice = page.getByRole('status').filter({ hasText: 'Board time zone differs' });
  await expect(notice).toContainText('UTC+00:00');
  await expect(notice).toContainText('UTC+05:45');
  await notice.getByRole('link', { name: 'Review time zone' }).click();
  const zone = page.getByRole('region', { name: 'Time zone', exact: true });
  await zone.getByLabel('POSIX time zone').fill('UTC-5:45');
  await zone.getByRole('button', { name: 'Save time zone' }).click();
  await expect(page.locator('#toasts')).toContainText('Time zone saved');
  await openLock(page, 'Front door', 'Settings');
  await expect(notice).toHaveCount(0);
  const clock = page.getByRole('region', { name: 'Clock', exact: true });
  await clock.getByRole('button', { name: 'Sync time', exact: true }).click();
  await expect(page.locator('#toasts')).toContainText('Lock clock set');
  expect((await calls(request)).filter((call) => call.method === 'lock.time.sync')).toEqual([
    { method: 'lock.time.sync', params: { lock: FRONT_DOOR } },
  ]);
});
