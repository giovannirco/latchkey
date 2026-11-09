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

test('unverified switch writes refuse before a button prompt even with a backup', async ({ page }) => {
  await login(page);
  await openLock(page, 'Front door', 'Settings');
  const reset = page.getByRole('switch', { name: 'Physical reset button' });
  await expect(reset).not.toBeChecked();
  await page.evaluate(() => {
    window.__switchEvents = [];
    const socket = new WebSocket(`ws://${location.host}/api/events`);
    window.__switchSocket = socket;
    return new Promise((resolve) => {
      socket.addEventListener('message', (event) => window.__switchEvents.push(JSON.parse(event.data)));
      socket.addEventListener('open', resolve);
    });
  });
  for (const method of ['lock.resetButton.set', 'lock.privacyLock.set', 'lock.tamperAlert.set']) {
    for (const enabled of [true, false]) {
      const result = await page.evaluate(
        async ({ method, enabled, lock }) => {
          const response = await fetch('/api/rpc', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id: 1, method, params: { lock, enabled } }),
          });
          return response.json();
        },
        { method, enabled, lock: FRONT_DOOR },
      );
      await expect
        .poll(async () =>
          page.evaluate((reply) => {
            if (reply.error) return reply.error.code;
            return window.__switchEvents.find(
              (event) => event.event === 'job.done' && event.data.job === reply.result.job,
            )?.data.error?.code;
          }, result),
        )
        .toBe('unverified');
    }
  }
  expect(
    await page.evaluate(() => window.__switchEvents.filter((event) => event.event === 'confirm.required')),
  ).toEqual([]);
  await expect(boardButton(page)).toBeHidden();
});
