// SPDX-License-Identifier: GPL-3.0-or-later
const { test, expect, login, lockCard, toast, boardButton, PASSWORD, TOTP } = require('./support.cjs');

for (const signInAgain of [false, true]) {
  test(`a completed job from a signed-out session cannot reveal a secret${signInAgain ? ' after signing in again' : ''}`, async ({ page }) => {
    await page.addInitScript(() => {
      const NativeSocket = window.WebSocket;
      window.completedJobs = [];
      window.WebSocket = class extends NativeSocket {
        constructor(...args) {
          super(...args);
          this.addEventListener('message', (message) => {
            const event = JSON.parse(message.data);
            if (event.event === 'job.done') window.completedJobs.push(event.data.job);
          });
        }
      };
    });
    await login(page, '#/security');
    let held;
    await page.route('**/api/rpc', async (route) => {
      if (route.request().postDataJSON().method !== 'auth.rotateTotp') return route.continue();
      const response = await route.fetch();
      const reply = await response.json();
      held = { route, response, job: reply.result.job };
    });
    await page.getByRole('button', { name: 'Replace authenticator secret', exact: true }).click();
    await page.getByRole('dialog', { name: 'Replace authenticator secret?' }).getByRole('button', { name: 'Replace', exact: true }).click();
    await boardButton(page).getByRole('button', { name: 'Hide' }).click();
    await expect.poll(() => Boolean(held)).toBe(true);
    await page.waitForFunction((job) => window.completedJobs.includes(job), held.job);
    await page.getByRole('button', { name: 'Sign out', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Sign in', exact: true })).toBeVisible();
    if (signInAgain) {
      await page.getByLabel('Password').fill(PASSWORD);
      await page.getByLabel('Authenticator code').fill(TOTP);
      await page.getByRole('button', { name: 'Sign in', exact: true }).click();
      await expect(page.getByRole('heading', { name: 'Security', exact: true })).toBeVisible();
    }
    const reply = page.waitForResponse((response) => response.url().endsWith('/api/rpc') && response.request().postDataJSON().method === 'auth.rotateTotp');
    await held.route.fulfill({ response: held.response });
    await reply;
    await expect(toast(page, /The session that started this action ended/)).toBeVisible();
    await expect(page.getByRole('dialog', { name: 'New authenticator secret' })).toHaveCount(0);
    await expect(page.getByRole('heading', { name: signInAgain ? 'Security' : 'Sign in', exact: true })).toBeVisible();
  });
}

test('a late unauthorized reply cannot end a newer session', async ({ page }) => {
  await login(page);
  let held;
  await page.route('**/api/rpc', (route) => {
    if (route.request().postDataJSON().method !== 'lock.unlock') return route.continue();
    held = route;
  });
  await lockCard(page, 'Front door').getByRole('button', { name: 'Unlock' }).click();
  await expect.poll(() => Boolean(held)).toBe(true);
  await page.getByRole('button', { name: 'Sign out', exact: true }).click();
  await page.getByLabel('Password').fill(PASSWORD);
  await page.getByLabel('Authenticator code').fill(TOTP);
  await page.getByRole('button', { name: 'Sign in', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Locks', exact: true })).toBeVisible();
  await held.fulfill({
    json: { id: held.request().postDataJSON().id, error: { code: 'unauthorized', message: 'session expired' } },
  });
  await expect(toast(page, /The session that started this action ended/)).toBeVisible();
  await expect(page.getByRole('heading', { name: 'Locks', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Sign out', exact: true })).toBeVisible();
});
