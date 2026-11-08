// SPDX-License-Identifier: GPL-3.0-or-later
const { test, expect, mock, login, settled, lockCard } = require('./support.cjs');

async function fingerprint(request) {
  await request.post('/api/rpc', {
    data: { id: 1, method: 'auth.login', params: { password: 'owner-pass', totp: '123456' } },
  });
  const response = await request.post('/api/rpc', { data: { id: 2, method: 'system.info', params: {} } });
  return (await response.json()).result.certFingerprint;
}

test('the security page shows the board certificate fingerprint', async ({ page, request }) => {
  const expected = await fingerprint(request);
  expect(expected).toMatch(/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/);
  await login(page, '#/security');
  const card = page.getByRole('region', { name: 'Board certificate' });
  await expect(card).toContainText(expected);
  await expect(card).toContainText('SHA-256');
});

test('the audit log lists actions and grows live', async ({ page, request }) => {
  await login(page);
  await lockCard(page, 'Front door').getByRole('button', { name: 'Unlock' }).click();
  await expect(lockCard(page, 'Front door').getByText('Unlocked', { exact: true })).toBeVisible();

  await page.getByRole('link', { name: 'Security', exact: true }).click();
  await settled(page);
  const audit = page.getByRole('table', { name: 'Audit log' });
  await expect(audit.getByRole('row').filter({ hasText: 'auth.login' }).first()).toBeVisible();
  await expect(audit.getByRole('row').filter({ hasText: 'lock.unlock' })).toContainText('Front door');

  await mock(request, {
    emit: [
      {
        event: 'audit.appended',
        data: {
          seq: 999,
          time: Math.floor(Date.now() / 1000),
          source: 'serial',
          method: 'system.reboot',
          result: 'ok',
        },
      },
    ],
  });
  const first = audit.locator('tbody tr').first();
  await expect(first).toContainText('system.reboot');
  await expect(first).toContainText('serial');
});

test('changing the password checks the repeat and reports success', async ({ page }) => {
  await login(page, '#/security');
  const form = page.getByRole('form', { name: 'Change password' });
  await form.getByLabel('Current password').fill('owner-pass');
  await form.getByLabel('New password', { exact: true }).fill('a much longer pass');
  await form.getByLabel('Repeat new password').fill('a different pass');
  await form.getByRole('button', { name: 'Change password' }).click();
  await expect(form.getByRole('alert')).toContainText('do not match');

  await form.getByLabel('Repeat new password').fill('a much longer pass');
  await form.getByRole('button', { name: 'Change password' }).click();
  await expect(page.locator('#toasts')).toContainText('Password changed');
  await expect(form.getByLabel('Current password')).toHaveValue('');
});

test('sign out everywhere ends every session', async ({ page, request }) => {
  await request.post('/api/rpc', {
    data: { id: 1, method: 'auth.login', params: { password: 'owner-pass', totp: '123456' } },
  });
  await login(page, '#/security');
  await page.getByRole('button', { name: 'Sign out everywhere' }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Sign in' })).toBeVisible();
  const other = await request.post('/api/rpc', { data: { id: 2, method: 'locks.list', params: {} } });
  expect((await other.json()).error.code).toBe('unauthorized');
});
