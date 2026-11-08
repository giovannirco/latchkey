// SPDX-License-Identifier: GPL-3.0-or-later
const { test, expect, mock, login, PASSWORD, TOTP } = require('./support.cjs');

async function signIn(page, password, code) {
  await page.getByLabel('Password').fill(password);
  await page.getByLabel('Authenticator code').fill(code);
  await page.getByRole('button', { name: 'Sign in' }).click();
}

test('the app stays behind the password and authenticator code', async ({ page, request }) => {
  const anonymous = await request.post('/api/rpc', { data: { id: 1, method: 'locks.list', params: {} } });
  expect((await anonymous.json()).error.code).toBe('unauthorized');

  await page.goto('/#/security');
  await expect(page.getByRole('heading', { level: 1, name: 'Sign in' })).toBeVisible();
  await expect(page.getByRole('navigation')).toHaveCount(0);

  await signIn(page, PASSWORD, '000000');
  await expect(page.getByRole('alert')).toContainText('Wrong password or code');
  await expect(page.getByLabel('Authenticator code')).toHaveValue('');

  await signIn(page, PASSWORD, TOTP);
  await expect(page.getByRole('heading', { level: 1, name: 'Security' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Locks', exact: true })).toBeVisible();
});

test('the login form only accepts six digits as the code', async ({ page }) => {
  await page.goto('/');
  const code = page.getByLabel('Authenticator code');
  await expect(code).toHaveAttribute('inputmode', 'numeric');
  await expect(code).toHaveAttribute('autocomplete', 'one-time-code');
  await page.getByLabel('Password').fill(PASSWORD);
  await code.fill('12ab');
  await page.getByRole('button', { name: 'Sign in' }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Sign in' })).toBeVisible();
  expect(await code.evaluate((input) => input.validity.valid)).toBe(false);
});

test('repeated failures show the rate limit', async ({ page }) => {
  await page.goto('/');
  for (let attempt = 0; attempt < 5; attempt += 1) {
    await signIn(page, 'wrong-pass', TOTP);
    await expect(page.getByRole('alert')).toContainText('Wrong password or code');
  }
  await signIn(page, PASSWORD, TOTP);
  await expect(page.getByRole('alert')).toContainText('Too many attempts');
  await expect(page.getByRole('alert')).toContainText(/Wait \d+ s/);
});

test('an unsynced board clock is explained at login', async ({ page, request }) => {
  await mock(request, { timeSynced: false });
  await page.goto('/');
  await signIn(page, PASSWORD, TOTP);
  await expect(page.getByRole('alert')).toContainText("board's clock is not set");
});

test('a session the board ends returns to the login screen without a click', async ({ page, request }) => {
  await login(page, '#/system');
  await mock(request, { expireSessions: true });
  await expect(page.getByRole('heading', { level: 1, name: 'Sign in' })).toBeVisible();
  await expect(page.getByText('Your session ended. Sign in again.')).toBeVisible();

  await signIn(page, PASSWORD, TOTP);
  await expect(page.getByRole('heading', { level: 1, name: 'System' })).toBeVisible();
});

test('an unauthorized answer mid-session returns to the login screen', async ({ page, request }) => {
  await login(page);
  await mock(request, { failNext: { method: 'system.info', code: 'unauthorized', message: 'session expired' } });
  await page.getByRole('link', { name: 'System', exact: true }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Sign in' })).toBeVisible();
  await expect(page.getByText('Your session ended. Sign in again.')).toBeVisible();

  await signIn(page, PASSWORD, TOTP);
  await expect(page.getByRole('heading', { level: 1, name: 'System' })).toBeVisible();
});

test('signing out ends the session on the board', async ({ page }) => {
  await login(page);
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  await expect(page.getByRole('heading', { level: 1, name: 'Sign in' })).toBeVisible();
  const code = await page.evaluate(async () => {
    const response = await fetch('/api/rpc', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: 1, method: 'locks.list', params: {} }),
    });
    return (await response.json()).error.code;
  });
  expect(code).toBe('unauthorized');
});
