// SPDX-License-Identifier: GPL-3.0-or-later
const { test, expect, mock, login, boardButton, openLock, FRONT_DOOR } = require('./support.cjs');

async function rotateTotp(page) {
  await page.getByRole('link', { name: 'Security', exact: true }).click();
  await page.getByRole('button', { name: 'Replace authenticator secret' }).click();
  await page
    .getByRole('dialog', { name: 'Replace authenticator secret?' })
    .getByRole('button', { name: 'Replace' })
    .click();
}

test('the board-button modal names the action and counts down', async ({ page, request }) => {
  await login(page);
  await mock(request, { confirm: 'never', confirmTimeoutMs: 4000 });
  await rotateTotp(page);
  const modal = boardButton(page);
  await expect(modal).toBeVisible();
  await expect(modal).toContainText('Replace the authenticator secret');
  await expect(modal.getByRole('timer')).toHaveText(/^[34] s$/);
  await expect(modal.getByRole('timer')).toHaveText(/^[12] s$/);
});

test('an unpressed board button times out with an error toast', async ({ page, request }) => {
  await login(page);
  await mock(request, { confirm: 'never', confirmTimeoutMs: 1500 });
  await rotateTotp(page);
  const modal = boardButton(page);
  await expect(modal).toBeVisible();
  await expect(modal).toBeHidden({ timeout: 6000 });
  const error = page.locator('#toasts [role="alert"]');
  await expect(error).toContainText('The button on the board was not pressed in time');
  await expect(error).toContainText('Nothing was changed');
});

test('the modal takes focus, keeps it inside, and Escape hides it', async ({ page, request }) => {
  await login(page);
  await mock(request, { confirm: 'never', confirmTimeoutMs: 5000 });
  await rotateTotp(page);
  const modal = boardButton(page);
  await expect(modal).toBeVisible();
  const hide = modal.getByRole('button', { name: 'Hide' });
  await expect(hide).toBeFocused();
  await page.keyboard.press('Tab');
  expect(await modal.evaluate((dialog) => dialog.contains(document.activeElement))).toBe(true);
  await page.keyboard.press('Escape');
  await expect(modal).toBeHidden();
  await expect(page.locator('#toasts [role="alert"]')).toContainText('not pressed in time', { timeout: 8000 });
});

test('a confirmed press shows the confirmation then the result', async ({ page }) => {
  await login(page);
  await rotateTotp(page);
  const modal = boardButton(page);
  await expect(modal).toBeVisible();
  await expect(modal).toBeHidden();
  const secret = page.getByRole('dialog', { name: 'New authenticator secret' });
  await expect(secret).toContainText('will not be shown again');
  await expect(secret.getByRole('link', { name: 'Open in authenticator app' })).toHaveAttribute(
    'href',
    /^otpauth:\/\/totp\//,
  );
  await secret.getByRole('button', { name: 'Done' }).click();
  await expect(secret).toBeHidden();
});

for (const backedUp of [false, true]) {
  test(`switch writes refuse without a prompt or mutation when backedUp is ${backedUp}`, async ({ page, request }) => {
    await mock(request, { setLock: { id: FRONT_DOOR, backedUp, resetButton: true, privacyLock: false, tamperAlert: true } });
    await login(page);
    await openLock(page, 'Front door', 'Settings');
    await expect(page.getByRole('switch', { name: 'Physical reset button' })).toBeChecked();
    await page.evaluate(() => {
      window.__switchEvents = [];
      const socket = new WebSocket(`ws://${location.host}/api/events`);
      window.__switchSocket = socket;
      return new Promise((resolve) => {
        socket.addEventListener('message', (event) => window.__switchEvents.push(JSON.parse(event.data)));
        socket.addEventListener('open', resolve);
      });
    });

    async function switchRequest(method, params = {}) {
      const response = await page.request.post('/api/rpc', {
        data: { id: 1, method, params: { lock: FRONT_DOOR, ...params } },
      });
      const reply = await response.json();
      if (reply.error || !reply.result.job) return reply;
      const outcome = () => page.evaluate((job) => window.__switchEvents.find(
        (event) => event.event === 'job.done' && event.data.job === job,
      )?.data, reply.result.job);
      await expect.poll(outcome).toBeTruthy();
      return outcome();
    }

    for (const [setting, original] of [['resetButton', true], ['privacyLock', false], ['tamperAlert', true]]) {
      for (const enabled of [true, false]) {
        const reply = await switchRequest(`lock.${setting}.set`, { enabled });
        expect(reply.error.code).toBe(setting === 'resetButton' && !enabled && !backedUp ? 'backup_required' : 'unverified');
        expect((await switchRequest(`lock.${setting}.get`)).result.enabled).toBe(original);
      }
    }
    expect(
      await page.evaluate(() => window.__switchEvents.filter((event) => event.event === 'confirm.required')),
    ).toEqual([]);
    await expect(boardButton(page)).toBeHidden();
  });
}
