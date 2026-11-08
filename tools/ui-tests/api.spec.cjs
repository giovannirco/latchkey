// SPDX-License-Identifier: GPL-3.0-or-later
const { test, expect, login, PASSWORD, TOTP } = require('./support.cjs');

function rpc(request, method, params = {}, options = {}) {
  return request.post('/api/rpc', { data: { id: 7, method, params }, ...options });
}

async function signIn(request) {
  const response = await rpc(request, 'auth.login', { password: PASSWORD, totp: TOTP });
  const cookie = response.headers()['set-cookie'];
  expect(cookie).toMatch(/^lk_session=[^;]+;/);
  expect(cookie).toMatch(/HttpOnly/i);
  expect(cookie).toMatch(/SameSite=Strict/i);
  return response;
}

test.beforeEach(async ({ request }) => {
  await request.post('/__mock/control', { data: { reset: true } });
});

test('rpc answers with the request id and an error object', async ({ request }) => {
  const response = await rpc(request, 'locks.list');
  expect(await response.json()).toEqual({ id: 7, error: { code: 'unauthorized', message: expect.any(String) } });
});

test('login sets an HttpOnly SameSite=Strict session cookie and never returns a token', async ({ request }) => {
  const response = await signIn(request);
  const body = await response.json();
  expect(body.id).toBe(7);
  expect(JSON.stringify(body)).not.toMatch(/token|lk_session/i);
  const list = await (await rpc(request, 'locks.list')).json();
  expect(list.result.locks.map((lock) => lock.name)).toEqual(['Front door', 'Shed']);
});

test('changing the password needs 12 characters, like the board', async ({ request }) => {
  await signIn(request);
  const short = await (await rpc(request, 'auth.changePassword', { current: PASSWORD, new: 'eleven char' })).json();
  expect(short.error.code).toBe('invalid_argument');
  const enough = await (await rpc(request, 'auth.changePassword', { current: PASSWORD, new: 'twelve chars' })).json();
  expect(enough).toEqual({ id: 7, result: {} });
});

test('mqtt.set refuses a host or prefix the board refuses and never returns the password', async ({ request }) => {
  await signIn(request);
  for (const params of [
    { enabled: true, host: 'bad host' },
    { enabled: true, host: 'mqtt://broker.example' },
    { enabled: true, host: 'broker.example:1883' },
    { enabled: true, host: 'broker.example', prefix: 'home/assistant' },
    { enabled: true, host: 'broker.example', prefix: 'a+b' },
  ]) {
    const refused = await (await rpc(request, 'mqtt.set', params)).json();
    expect(refused.error.code).toBe('invalid_argument');
  }
  const saved = await (
    await rpc(request, 'mqtt.set', { enabled: true, host: ' broker.example ', password: 'broker secret' })
  ).json();
  expect(saved.result).toEqual({
    enabled: true,
    host: 'broker.example',
    port: 1883,
    username: '',
    prefix: 'homeassistant',
    passwordSet: true,
    connected: true,
    problem: null,
  });
  expect(JSON.stringify(await (await rpc(request, 'mqtt.get')).json())).not.toContain('broker secret');
});

test('mqtt.set keeps the stored password only for the same broker, like the board', async ({ request }) => {
  await signIn(request);
  const broker = { enabled: true, host: 'broker.example', port: 1883, username: 'latchkey' };
  const first = await (await rpc(request, 'mqtt.set', { ...broker, password: 'broker secret' })).json();
  expect(first.result).toMatchObject({ passwordSet: true, connected: true, problem: null });
  const same = await (await rpc(request, 'mqtt.set', { ...broker, prefix: 'other_prefix' })).json();
  expect(same.result.passwordSet).toBe(true);
  for (const change of [{ host: 'elsewhere.example' }, { port: 8883 }, { username: 'someone' }]) {
    await rpc(request, 'mqtt.set', { ...broker, password: 'broker secret' });
    const moved = await (await rpc(request, 'mqtt.set', { ...broker, ...change })).json();
    expect(moved.result.passwordSet).toBe(false);
  }
  const off = await (await rpc(request, 'mqtt.set', { ...broker, enabled: false })).json();
  expect(off.result).toMatchObject({ enabled: false, connected: false, problem: null });
});

test('mqtt.set counts the password in bytes and refuses control characters in the username', async ({ request }) => {
  await signIn(request);
  const broker = { enabled: false, host: 'broker.example' };
  const accented = await (await rpc(request, 'mqtt.set', { ...broker, password: 'é'.repeat(33) })).json();
  expect(accented.error.code).toBe('invalid_argument');
  const fits = await (await rpc(request, 'mqtt.set', { ...broker, password: 'é'.repeat(32) })).json();
  expect(fits.result.passwordSet).toBe(true);
  const tab = await (await rpc(request, 'mqtt.set', { ...broker, username: 'tab\there' })).json();
  expect(tab.error.code).toBe('invalid_argument');
});

test('rpc refuses other content types and foreign origins', async ({ request }) => {
  await signIn(request);
  const text = await request.post('/api/rpc', {
    headers: { 'Content-Type': 'text/plain' },
    data: JSON.stringify({ id: 1, method: 'locks.list', params: {} }),
  });
  expect(text.status()).toBe(415);
  const foreign = await rpc(request, 'locks.list', {}, { headers: { Origin: 'http://evil.example' } });
  expect(foreign.status()).toBe(403);
});

test('unsupported features answer unsupported', async ({ request }) => {
  await signIn(request);
  const body = await (await rpc(request, 'lock.fingerprints.list', { lock: '00:00:5E:00:53:02' })).json();
  expect(body.error.code).toBe('unsupported');
});

test('responses never carry lock keys or passcodes from lists', async ({ request }) => {
  await signIn(request);
  const lock = '00:00:5E:00:53:01';
  const bodies = await Promise.all(
    ['locks.list', 'lock.info', 'lock.passcodes.list', 'lock.cards.list', 'system.info'].map(async (method) =>
      JSON.stringify(await (await rpc(request, method, { lock })).json()),
    ),
  );
  for (const body of bodies) expect(body).not.toMatch(/aesKey|adminPs|unlockKey|"code"\s*:\s*"\d/);
});

test('the events socket needs a session', async ({ page }) => {
  await page.goto('/');
  const before = await page.evaluate(
    () =>
      new Promise((resolve) => {
        const socket = new WebSocket(`ws://${location.host}/api/events`);
        socket.onopen = () => resolve('open');
        socket.onerror = () => resolve('refused');
      }),
  );
  expect(before).toBe('refused');
});

test('the page is served gzipped with a hash-based CSP and no-store caching', async ({ request }) => {
  const response = await request.get('/', { headers: { 'Accept-Encoding': 'gzip' } });
  expect(response.headers()['content-encoding']).toBe('gzip');
  expect(response.headers()['cache-control']).toBe('no-store');
  expect(response.headers()['x-content-type-options']).toBe('nosniff');
  const html = await response.text();
  expect(html).toMatch(/http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'sha256-/);
  expect(html).not.toMatch(/\ssrc="app\.js"|href="style\.css"/);
});

test('the page also sends its policy as a header, with frame-ancestors', async ({ request }) => {
  const response = await request.get('/');
  const meta = (await response.text()).match(/http-equiv="Content-Security-Policy" content="([^"]+)"/)[1];
  expect(response.headers()['content-security-policy']).toBe(`${meta}; frame-ancestors 'none'`);
  expect(response.headers()['x-frame-options']).toBe('DENY');
  expect(response.headers()['referrer-policy']).toBe('no-referrer');
});

test('locks.pair answers with a job id and reports the outcome as job.done', async ({ page }) => {
  await login(page);
  const outcome = await page.evaluate(async () => {
    const socket = new WebSocket(`ws://${location.host}/api/events`);
    await new Promise((resolve) => socket.addEventListener('open', resolve));
    const done = new Promise((resolve) =>
      socket.addEventListener('message', (message) => {
        const parsed = JSON.parse(message.data);
        if (parsed.event === 'job.done') resolve(parsed.data);
      }),
    );
    const response = await fetch('/api/rpc', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: 9, method: 'locks.pair', params: { mac: '00:00:5E:00:53:21', name: 'Porch' } }),
    });
    const reply = await response.json();
    const data = await done;
    socket.close();
    return { reply, data };
  });
  expect(outcome.reply).toEqual({ id: 9, result: { job: expect.any(String) } });
  expect(outcome.data.job).toBe(outcome.reply.result.job);
  expect(outcome.data.result.lock).toMatchObject({ id: '00:00:5E:00:53:21', name: 'Porch', hardened: false });
});

async function recordEvents(page) {
  await page.evaluate(
    () =>
      new Promise((resolve) => {
        window.__events = [];
        const socket = new WebSocket(`ws://${location.host}/api/events`);
        socket.addEventListener('message', (message) => window.__events.push(JSON.parse(message.data)));
        socket.addEventListener('open', resolve);
      }),
  );
}

function sawJobDone(page, job) {
  return page.evaluate(
    (id) => window.__events.some((event) => event.event === 'job.done' && event.data.job === id),
    job,
  );
}

test('lock methods answer with a job whose job.done reaches only the session that asked', async ({ page, browser }) => {
  await login(page);
  const otherContext = await browser.newContext();
  const other = await otherContext.newPage();
  await login(other);
  await recordEvents(page);
  await recordEvents(other);
  const reply = await page.evaluate(async () => {
    const response = await fetch('/api/rpc', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id: 3, method: 'lock.unlock', params: { lock: '00:00:5E:00:53:02' } }),
    });
    return response.json();
  });
  expect(reply).toEqual({ id: 3, result: { job: expect.any(String) } });
  await expect.poll(() => sawJobDone(page, reply.result.job)).toBe(true);
  expect(await sawJobDone(other, reply.result.job)).toBe(false);
  await otherContext.close();
});
