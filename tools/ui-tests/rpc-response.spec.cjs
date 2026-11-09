// SPDX-License-Identifier: GPL-3.0-or-later
const { test, expect, mock, login, lockCard, toast } = require('./support.cjs');

async function streamUnlockReply(page, delayMs, body = null) {
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
            const reply = body ?? JSON.stringify({ id: JSON.parse(options.body).id, result: { state: 'unlocked' } });
            controller.enqueue(new TextEncoder().encode(reply));
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

for (const [name, reply] of [
  ['missing result', {}],
  ['null result', { result: null }],
  ['array result', { result: [] }],
  ['mismatched request id', { id: -1, result: { state: 'unlocked' } }],
]) {
  test(`an RPC reply with ${name} cannot report an unlock`, async ({ page }) => {
    await login(page);
    await page.route('**/api/rpc', (route) => {
      const request = route.request().postDataJSON();
      if (request.method !== 'lock.unlock') return route.continue();
      return route.fulfill({ json: { id: request.id, ...reply } });
    });
    const front = lockCard(page, 'Front door');
    await front.getByRole('button', { name: 'Unlock' }).click();
    await expect(toast(page, 'The board answered with an error.')).toBeVisible();
    await expect(toast(page, 'Front door unlocked')).toHaveCount(0);
    await expect(front.getByText('Locked', { exact: true })).toBeVisible();
  });
}

for (const [name, reply] of [
  ['missing result', {}],
  ['null result', { result: null }],
  ['array result', { result: [] }],
]) {
  test(`a completed job with ${name} cannot report an unlock`, async ({ page, request }) => {
    await login(page);
    await page.route('**/api/rpc', (route) => {
      const request = route.request().postDataJSON();
      if (request.method !== 'lock.unlock') return route.continue();
      return route.fulfill({ json: { id: request.id, result: { job: 'invalid-unlock' } } });
    });
    const front = lockCard(page, 'Front door');
    await front.getByRole('button', { name: 'Unlock' }).click();
    await mock(request, { emit: [{ event: 'job.done', data: { job: 'invalid-unlock', ...reply } }] });
    await expect(toast(page, 'The board answered with an error.')).toBeVisible();
    await expect(toast(page, 'Front door unlocked')).toHaveCount(0);
    await expect(front.getByText('Locked', { exact: true })).toBeVisible();
  });
}
