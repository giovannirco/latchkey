// SPDX-License-Identifier: GPL-3.0-or-later
const { test, expect, mock, login, boardButton, openLock } = require('./support.cjs');

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

test('enabling the reset button needs the board button, disabling does not', async ({ page }) => {
  await login(page);
  await openLock(page, 'Front door', 'Settings');
  const reset = page.getByRole('switch', { name: 'Physical reset button' });
  await expect(reset).not.toBeChecked();
  await reset.check();
  await expect(boardButton(page)).toBeVisible();
  await expect(boardButton(page)).toContainText('Enable the reset button');
  await expect(boardButton(page)).toBeHidden();
  await expect(reset).toBeChecked();

  await reset.uncheck();
  await expect(page.locator('#toasts')).toContainText('Reset button turned off');
  await expect(boardButton(page)).toBeHidden();
  await expect(reset).not.toBeChecked();
});
