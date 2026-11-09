// SPDX-License-Identifier: GPL-3.0-or-later
const http = require('node:http');
const { once } = require('node:events');

const { test, expect, PASSWORD, TOTP } = require('./support.cjs');

test('signing out during the first event handshake preserves the login screen', async ({ page, baseURL }) => {
  const sockets = new Set();
  let handshakeStarted = false;
  const proxy = http.createServer((request, response) => {
    const upstream = http.request(new URL(request.url, baseURL), {
      method: request.method,
      headers: request.headers,
    }, (reply) => {
      response.writeHead(reply.statusCode, reply.headers);
      reply.pipe(response);
    });
    upstream.on('error', () => response.destroy());
    request.pipe(upstream);
  });
  proxy.on('connection', (socket) => {
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
  });
  proxy.on('upgrade', () => { handshakeStarted = true; });
  proxy.listen(0, '127.0.0.1');
  await once(proxy, 'listening');
  try {
    await page.addInitScript(() => {
      const NativeSocket = window.WebSocket;
      window.eventSocketClosed = false;
      window.WebSocket = class extends NativeSocket {
        constructor(...args) {
          super(...args);
          this.addEventListener('close', () => { window.eventSocketClosed = true; });
        }
      };
    });
    await page.goto(`http://127.0.0.1:${proxy.address().port}/`);
    await page.getByLabel('Password').fill(PASSWORD);
    await page.getByLabel('Authenticator code').fill(TOTP);
    await page.getByRole('button', { name: 'Sign in' }).click();
    await expect.poll(() => handshakeStarted).toBe(true);
    await page.getByRole('button', { name: 'Sign out', exact: true }).click();
    await page.waitForFunction(() => window.eventSocketClosed);
    await expect(page.getByRole('heading', { name: 'Sign in', exact: true })).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Cannot reach the board' })).toHaveCount(0);
  } finally {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => proxy.close(resolve));
  }
});
