// SPDX-License-Identifier: GPL-3.0-or-later
const { test, expect, login, lockCard, toast } = require('./support.cjs');

async function streamUnlockReply(page, delayMs, body = '{"result":{"state":"unlocked"}}') {
  await page.evaluate(({ delayMs, body }) => {
    const fetch = window.fetch;
    window.fetch = async (input, options) => {
      if (input !== '/api/rpc' || JSON.parse(options.body).method !== 'lock.unlock') {
        return fetch(input, options);
      }
      const stream = new ReadableStream({
        start(controller) {
          const timer = setTimeout(() => {
            options.signal.removeEventListener('abort', abort);
            controller.enqueue(new TextEncoder().encode(body));
            controller.close();
          }, delayMs);
          function abort() {
            clearTimeout(timer);
            controller.error(options.signal.reason);
          }
          options.signal.addEventListener('abort', abort, { once: true });
        },
      });
      return new Response(stream, { headers: { 'Content-Type': 'application/json' } });
    };
  }, { delayMs, body });
}

test('an RPC response body must finish within the request timeout', async ({ page }) => {
  await page.clock.install();
  await login(page);
  await streamUnlockReply(page, 600_000);
  const unlock = lockCard(page, 'Front door').getByRole('button', { name: 'Unlock' });
  await unlock.click();
  await page.clock.fastForward(95_000);
  await expect(unlock).toBeDisabled();
  await page.clock.fastForward(10_000);
  await expect(toast(page, /The board did not answer in time/)).toBeVisible();
  await expect(unlock).toBeEnabled();
  await expect(toast(page, 'Front door unlocked')).toHaveCount(0);
});

test('an RPC response body arriving before the deadline completes the action', async ({ page }) => {
  await page.clock.install();
  await login(page);
  await streamUnlockReply(page, 20_000);
  const front = lockCard(page, 'Front door');
  await front.getByRole('button', { name: 'Unlock' }).click();
  await page.clock.fastForward(20_000);
  await expect(toast(page, 'Front door unlocked')).toBeVisible();
  await expect(front.getByText('Unlocked', { exact: true })).toBeVisible();
});

test('an unreadable RPC response body reports an error without claiming success', async ({ page }) => {
  await page.clock.install();
  await login(page);
  await streamUnlockReply(page, 1000, 'not json');
  await lockCard(page, 'Front door').getByRole('button', { name: 'Unlock' }).click();
  await page.clock.fastForward(1000);
  await expect(toast(page, 'The board answered with an error.')).toBeVisible();
  await expect(toast(page, 'Front door unlocked')).toHaveCount(0);
});
