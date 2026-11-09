// SPDX-License-Identifier: GPL-3.0-or-later
const { test, expect, mock, calls, login, toast } = require('./support.cjs');

function logs(page) {
  return page.getByRole('region', { name: 'Logs' });
}

function remote(page) {
  return page.getByRole('region', { name: 'Remote logging (syslog)' });
}

test('the Logs view lists the recent lines, newest first', async ({ page }) => {
  await login(page, '#/system');
  const view = logs(page);
  const rows = view.getByRole('row');
  await expect(view.getByRole('table', { name: 'Recent log lines' })).toBeVisible();
  await expect(view).toContainText('SNTP synced');
  await expect(view).toContainText('disconnected, reason 8');
  await expect(rows.nth(1)).toContainText('HTTPS on port 443, redirect on port 80');
  await expect(view.getByRole('cell', { name: 'warn', exact: true })).toBeVisible();
});

test('the level filter keeps the more severe lines', async ({ page }) => {
  await login(page, '#/system');
  const view = logs(page);
  await expect(view).toContainText('SNTP synced');
  await view.getByLabel('Show').selectOption('warn');
  await expect(view).not.toContainText('SNTP synced');
  await expect(view).toContainText('disconnected, reason 8');
  const call = (await calls(page.request)).filter((entry) => entry.method === 'system.logs').pop();
  expect(call.params.level).toBe('warn');
});

test('new lines appear while the view refreshes itself', async ({ page, request }) => {
  await login(page, '#/system');
  const view = logs(page);
  await expect(view).toContainText('SNTP synced');
  await mock(request, { logLines: [{ level: 'error', tag: 'test', message: 'a line from the test' }] });
  await expect(view.getByRole('row').nth(1)).toContainText('a line from the test');
  const polled = (await calls(request)).filter((entry) => entry.method === 'system.logs');
  expect(polled.some((entry) => typeof entry.params.since === 'number')).toBe(true);
});

test('turning the refresh off stops asking the board', async ({ page, request }) => {
  await login(page, '#/system');
  const view = logs(page);
  await expect(view).toContainText('SNTP synced');
  await view.getByLabel('Refresh every few seconds').uncheck();
  const before = (await calls(request)).filter((entry) => entry.method === 'system.logs').length;
  await mock(request, { logLines: [{ level: 'info', tag: 'test', message: 'nobody asked for this line' }] });
  await page.waitForTimeout(4000);
  const after = (await calls(request)).filter((entry) => entry.method === 'system.logs').length;
  expect(after).toBe(before);
  await expect(view).not.toContainText('nobody asked for this line');
  await view.getByLabel('Refresh every few seconds').check();
  await expect(view).toContainText('nobody asked for this line');
});

for (const phase of ['initial read', 'scheduled refresh', 'paged read']) {
  test(`leaving System during its ${phase} stops polling`, async ({ page }) => {
    const scheduled = phase === 'scheduled refresh';
    await login(page, scheduled ? '#/system' : '#/');
    if (scheduled) await expect(logs(page)).toContainText('SNTP synced');
    let held;
    let response;
    let requests = 0;
    await page.route('**/api/rpc', async (route) => {
      if (route.request().postDataJSON().method !== 'system.logs') return route.continue();
      requests += 1;
      if (requests > 1) return route.continue();
      held = route;
      response = await route.fetch();
    });
    if (!scheduled) await page.getByRole('link', { name: 'System', exact: true }).click();
    await expect.poll(() => Boolean(held && response)).toBe(true);
    await page.getByRole('link', { name: 'Locks', exact: true }).click();
    await expect(page.locator('#main h1')).toHaveText('Locks');
    const finished = page.waitForResponse(
      (reply) => reply.request().postDataJSON()?.id === held.request().postDataJSON().id,
    );
    const reply = await response.json();
    if (phase === 'paged read') reply.result.more = true;
    await held.fulfill({ response, json: reply });
    await (await finished).finished();
    await page.waitForTimeout(4000);
    expect(requests).toBe(1);
  });
}

test('Copy puts the shown lines on the clipboard as text', async ({ page, context }) => {
  await context.grantPermissions(['clipboard-read', 'clipboard-write']);
  await login(page, '#/system');
  const view = logs(page);
  await expect(view).toContainText('SNTP synced');
  await view.getByRole('button', { name: 'Copy' }).click();
  await expect(toast(page, 'Copied')).toBeVisible();
  const text = await page.evaluate(() => navigator.clipboard.readText());
  const lines = text.trim().split('\n');
  expect(lines[0]).toMatch(/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z info latchkey 0\.1\.0 board=esp32s3-atom/);
  expect(text).toContain(' warn wifi: disconnected, reason 8');
  expect(lines.at(-1)).toContain('HTTPS on port 443, redirect on port 80');
});

test('the remote logging form saves a collector and shows what it sends', async ({ page, request }) => {
  await login(page, '#/system');
  const form = remote(page);
  await expect(form.getByText('Remote logging is off.')).toBeVisible();
  await form.getByLabel('Send log lines to a syslog collector').check();
  await form.getByLabel('Collector host').fill('logs.example.net');
  await form.getByLabel('Port', { exact: true }).fill('6514');
  await form.getByLabel('Transport').selectOption('tcp');
  await form.getByLabel('Lines to send').selectOption('warn');
  await form.getByRole('button', { name: 'Save remote logging' }).click();
  await expect(toast(page, 'Remote logging saved')).toBeVisible();
  await expect(form.getByText('Sending to logs.example.net:6514 over TCP')).toBeVisible();
  const call = (await calls(request)).find((entry) => entry.method === 'system.syslog.set');
  expect(call.params).toEqual({
    enabled: true,
    host: 'logs.example.net',
    port: 6514,
    transport: 'tcp',
    appName: 'latchkey',
    level: 'warn',
  });
});

test('a collector host the board refuses is reported', async ({ page }) => {
  await login(page, '#/system');
  const form = remote(page);
  await form.getByLabel('Send log lines to a syslog collector').check();
  await form.getByLabel('Collector host').fill('not a host');
  await form.getByRole('button', { name: 'Save remote logging' }).click();
  await expect(page.locator('#toasts')).toContainText(/host must be a host name or an IPv4 address/i);
  await expect(form.getByText('Remote logging is off.')).toBeVisible();
});
