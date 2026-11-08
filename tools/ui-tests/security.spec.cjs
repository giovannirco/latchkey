// SPDX-License-Identifier: GPL-3.0-or-later
const { test, expect, mock, login, settled, lockCard, SHED } = require('./support.cjs');

const HOLD_MS = 2000;
const ACTIONS_AFTER_SIGN_IN = [
  'auth.login',
  'auth.login',
  'locks.pair',
  'lock.harden',
  'keys.export',
  'locks.pair',
  'auth.login',
  'system.setup',
];
const SHED_PAIRED = {
  seq: 6,
  time: Math.floor(Date.now() / 1000) - 86400,
  source: 'web',
  method: 'locks.pair',
  target: SHED,
  result: 'ok',
};

async function fingerprint(request) {
  await request.post('/api/rpc', {
    data: { id: 1, method: 'auth.login', params: { password: 'owner-pass', totp: '123456' } },
  });
  const response = await request.post('/api/rpc', { data: { id: 2, method: 'system.info', params: {} } });
  return (await response.json()).result.certFingerprint;
}

function isAuditList(request) {
  return request.url().endsWith('/api/rpc') && request.postDataJSON().method === 'audit.list';
}

async function holdAuditList(page, request, trigger) {
  const listing = page.waitForRequest(isAuditList);
  await mock(request, { delay: { method: 'audit.list', ms: HOLD_MS } });
  await trigger();
  await listing;
}

function announce(request, ...entries) {
  return mock(request, { emit: entries.map((data) => ({ event: 'audit.appended', data })) });
}

async function unlockShed(page) {
  const response = await page.request.post('/api/rpc', {
    data: { id: 1, method: 'lock.unlock', params: { lock: SHED } },
  });
  expect((await response.json()).result.state).toBe('unlocked');
}

function auditActions(page) {
  return page.getByRole('table', { name: 'Audit log' }).locator('tbody td:nth-child(3)');
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

test('entries announced while the audit log loads are listed once, newest first', async ({ page, request }) => {
  await login(page);
  await holdAuditList(page, request, () => page.getByRole('link', { name: 'Security', exact: true }).click());
  await announce(request, SHED_PAIRED);
  await unlockShed(page);
  await settled(page);
  await expect(auditActions(page)).toHaveText(['lock.unlock', ...ACTIONS_AFTER_SIGN_IN]);
});

test('a live audit entry that is already listed is not added again', async ({ page, request }) => {
  await login(page, '#/security');
  const reboot = {
    seq: 9,
    time: Math.floor(Date.now() / 1000),
    source: 'serial',
    method: 'system.reboot',
    result: 'ok',
  };
  await announce(request, SHED_PAIRED, reboot);
  await expect(auditActions(page)).toHaveText(['system.reboot', ...ACTIONS_AFTER_SIGN_IN]);
});

test('after the event socket reconnects, the audit log lists each entry once', async ({ page, request }) => {
  await login(page, '#/security');
  await holdAuditList(page, request, () => mock(request, { dropSockets: true }));
  await unlockShed(page);
  await settled(page);
  await expect(auditActions(page)).toHaveText(['lock.unlock', ...ACTIONS_AFTER_SIGN_IN]);
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

test('a new password needs 12 characters, like the board', async ({ page }) => {
  await login(page, '#/security');
  const form = page.getByRole('form', { name: 'Change password' });
  await expect(form.getByLabel('New password', { exact: true })).toHaveAttribute('minlength', '12');
  await expect(form).toContainText('At least 12 characters');
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
