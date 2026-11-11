// SPDX-License-Identifier: GPL-3.0-or-later
const { test, expect } = require('playwright/test');

async function start(page, { claimed = false, supported = true, missingRelease = false, importError = '', setupReply = null, ready = true, bootOnProbe = false, delayPort = false } = {}) {
  await page.route('https://unpkg.com/**', route => route.fulfill({
    contentType: 'text/javascript',
    body: `customElements.define('esp-web-install-button', class extends HTMLElement {
      constructor() { super(); this.attachShadow({mode: 'open'}).innerHTML = '<slot name="activate"></slot>'; }
    });`,
  }));
  await page.route('**/index.html', async route => {
    const response = await route.fetch();
    let html = await response.text();
    if (!missingRelease) html = html.replace('name="latchkey-version" content=""', 'name="latchkey-version" content="0.7.0"');
    html = html.replace(/ integrity="[^"]+"/g, '');
    html = html.replace(/<script type="importmap">[\s\S]*?<\/script>/, '');
    await route.fulfill({ response, body: html });
  });
  await page.addInitScript(({ claimed, supported, importError, setupReply, ready, bootOnProbe, delayPort }) => {
    window.sent = [];
    let owner = claimed;
    let controller;
    const encoder = new TextEncoder();
    const decoder = new TextDecoder();
    let input = '';
    const info = () => ({
      firmware: '0.7.0', board: 'esp32s3', claimed: owner,
      wifi: { configured: owner, connected: owner && ready, ip: '192.0.2.50' },
      certFingerprint: owner ? 'ab'.repeat(32) : '', time: { synced: true }, timezone: 'UTC0',
    });
    const port = {
      addEventListener() {},
      removeEventListener() {},
      async open() {
        this.readable = new ReadableStream({ start(value) { controller = value; } });
        this.writable = new WritableStream({ write(data) {
          input += decoder.decode(data, { stream: true });
          while (input.includes('\n')) {
            const end = input.indexOf('\n');
            const request = JSON.parse(input.slice(0, end));
            input = input.slice(end + 1);
            window.sent.push(request);
            let result;
            if (request.method === 'system.info') {
              if (bootOnProbe) {
                controller.enqueue(encoder.encode('# latchkey 0.7.0 board=esp32s3 chip=esp32s3\n'));
                bootOnProbe = false;
              }
              result = info();
            }
            else if (request.method === 'system.setup') {
              owner = true;
              result = setupReply || { otpauth: 'otpauth://totp/Latchkey:test?secret=JBSWY3DPEHPK3PXP&issuer=Latchkey' };
            } else if (request.method === 'keys.import') result = { imported: ['00:00:5E:00:53:01'] };
            else if (request.method === 'locks.list') result = [];
            else result = {};
            const reply = request.method === 'keys.import' && importError
              ? { id: request.id, error: { code: importError, message: 'untrusted response text' } }
              : { id: request.id, result };
            controller.enqueue(encoder.encode('# log ignored\n' + JSON.stringify(reply) + '\n'));
          }
        } });
      },
      async close() {},
    };
    Object.defineProperty(navigator, 'serial', {
      value: supported ? {
        requestPort: () => delayPort ? new Promise(resolve => { window.finishPort = () => resolve(port); }) : Promise.resolve(port),
        addEventListener() {}, removeEventListener() {},
      } : undefined,
      configurable: true,
    });
  }, { claimed, supported, importError, setupReply, ready, bootOnProbe, delayPort });
  await page.goto('/index.html');
}

async function connect(page) {
  await page.getByRole('button', { name: 'Connect for setup' }).click();
}

async function claim(page, password = 'example-owner-password') {
  await connect(page);
  await page.getByLabel('Wi-Fi name').fill('example-network');
  await page.getByLabel('Wi-Fi password', { exact: true }).fill('example-wifi-password');
  await page.getByLabel('Board IP address').fill('192.0.2.50');
  await page.getByLabel('Gateway').fill('192.0.2.1');
  await page.getByLabel('DNS server').fill('192.0.2.1');
  await page.getByLabel('Owner password', { exact: true }).fill(password);
  await page.getByLabel('Confirm owner password').fill(password);
  await page.getByRole('button', { name: 'Create owner access' }).click();
}

test('new board install requires explicit erase acknowledgement and follows board selection', async ({ page }) => {
  await start(page);
  await expect(page.getByRole('heading', { name: 'Set up your Latchkey.' })).toBeVisible();
  const install = page.getByRole('button', { name: 'Install firmware' });
  await expect(install).toBeDisabled();
  await page.getByLabel('ESP32-S3', { exact: false }).check();
  await page.getByLabel('This board has no lock keys or settings I need to keep.').check();
  await expect(install).toBeEnabled();
  await expect(page.locator('esp-web-install-button')).toHaveAttribute('manifest', 'firmware/0.7.0/manifest-esp32s3.json');
  await expect(page.getByRole('link', { name: 'Factory image' })).toHaveAttribute('href', 'firmware/0.7.0/latchkey-0.7.0-esp32s3-factory.bin');
});

test('unsupported browser offers downloads without usable serial actions', async ({ page }) => {
  await start(page, { supported: false });
  await expect(page.getByText('Open this page in a desktop browser with Web Serial, such as Chrome or Edge.')).toBeVisible();
  await expect(page.getByRole('button', { name: 'Connect for setup' })).toBeDisabled();
  await expect(page.getByRole('link', { name: 'Factory image' })).toBeVisible();
});

test('missing release blocks flashing but allows setup of installed firmware', async ({ page }) => {
  await start(page, { missingRelease: true });
  await page.getByLabel('This board has no lock keys or settings I need to keep.').check();
  await expect(page.getByRole('button', { name: 'Install firmware' })).toBeDisabled();
  await expect(page.getByRole('button', { name: 'Connect for setup' })).toBeEnabled();
});

test('claimed board bypasses owner creation and hides destructive installation', async ({ page }) => {
  await start(page, { claimed: true });
  await connect(page);
  await expect(page.getByRole('heading', { name: 'Bring your lock keys.' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Install firmware' })).toBeHidden();
  await expect(page.getByRole('button', { name: 'Create owner access' })).toBeHidden();
  expect(await page.evaluate(() => window.sent.map(item => item.method))).toEqual(['system.info']);
});

test('first boot setup keeps one-time authenticator visible until explicitly saved', async ({ page }) => {
  await start(page);
  await claim(page);
  await expect(page.getByRole('heading', { name: 'Save your authenticator.' })).toBeVisible();
  await expect(page.getByLabel('Authenticator secret')).toHaveValue('JBSWY3DPEHPK3PXP');
  await expect(page.getByRole('button', { name: 'Continue to backup' })).toBeDisabled();
  await expect(page.getByLabel('Owner password', { exact: true })).toHaveValue('');
  await page.getByLabel('I saved this account in my authenticator.').check();
  await page.getByRole('button', { name: 'Continue to backup' }).click();
  await expect(page.getByLabel('Authenticator secret')).toHaveValue('');
  expect(await page.evaluate(() => [localStorage.length, sessionStorage.length])).toEqual([0, 0]);
  const calls = await page.evaluate(() => window.sent.map(item => item.method));
  expect(calls.filter(item => item === 'system.setup')).toHaveLength(1);
});

test('backup file and passphrase go only through USB and are cleared after restore', async ({ page }) => {
  await start(page, { claimed: true });
  await connect(page);
  const backup = Buffer.alloc(56);
  backup.write('LKB2'); backup[4] = 1; backup[5] = 1; backup.writeUInt32BE(100000, 6);
  await page.getByLabel('Encrypted lock backup').setInputFiles({ name: 'example.lkb', mimeType: 'application/octet-stream', buffer: backup });
  await page.getByLabel('Backup passphrase').fill('example-backup-passphrase');
  const outbound = [];
  page.on('request', request => { if (request.method() === 'POST') outbound.push(request.url()); });
  await page.getByRole('button', { name: 'Restore lock keys' }).click();
  await expect(page.getByText('Restored 1 lock.')).toBeVisible();
  await expect(page.getByLabel('Backup passphrase')).toHaveValue('');
  const calls = await page.evaluate(() => window.sent.filter(item => item.method === 'keys.import'));
  expect(calls).toHaveLength(1);
  expect(calls[0].params.backup).toBe(backup.toString('base64'));
  expect(outbound).toEqual([]);
});

test('invalid backup is rejected before USB import', async ({ page }) => {
  await start(page, { claimed: true });
  await connect(page);
  await page.getByLabel('Encrypted lock backup').setInputFiles({ name: 'bad.lkb', mimeType: 'application/octet-stream', buffer: Buffer.from('not a backup') });
  await page.getByLabel('Backup passphrase').fill('example-backup-passphrase');
  await page.getByRole('button', { name: 'Restore lock keys' }).click();
  await expect(page.getByRole('alert')).toContainText('valid Latchkey');
  expect(await page.evaluate(() => window.sent.filter(item => item.method === 'keys.import'))).toEqual([]);
});

test('readiness shows the local address and fingerprint without claiming lock operation was tested', async ({ page }) => {
  await start(page, { claimed: true });
  await connect(page);
  await page.getByRole('button', { name: 'Continue without a backup' }).click();
  await expect(page.getByRole('heading', { name: 'Open your Latchkey.' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'Open board' })).toHaveAttribute('href', 'https://192.0.2.50');
  await expect(page.locator('#fingerprint')).toContainText('ab'.repeat(32));
  await expect(page.getByText('Test lock access with the door open before relying on this board.')).toBeVisible();
});

for (const width of [390, 1440]) {
  test(`layout has no horizontal overflow at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 1000 });
    await start(page);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
    await connect(page);
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  });
}

test('capture installer and setup at desktop and mobile sizes', async ({ page }) => {
  test.skip(!process.env.LK_PAGES_SCREENSHOTS, 'visual review only');
  for (const [name, width] of [['desktop', 1440], ['mobile', 390]]) {
    await page.setViewportSize({ width, height: 1000 });
    await start(page);
    await page.screenshot({ path: `/tmp/latchkey-pages-review/${name}.png`, fullPage: true, animations: 'disabled' });
    await connect(page);
    await page.evaluate(() => scrollTo(0, 0));
    await page.screenshot({ path: `/tmp/latchkey-pages-review/${name}-setup.png`, fullPage: true, animations: 'disabled' });
  }
});

test('owner password length is measured in UTF-8 bytes rather than characters', async ({ page }) => {
  await start(page);
  await claim(page, '界'.repeat(4));
  await expect(page.getByRole('heading', { name: 'Save your authenticator.' })).toBeVisible();
});

test('mobile progress markers retain a circular shape', async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await start(page);
  const box = await page.locator('.step-number').first().boundingBox();
  expect(box.width).toBe(box.height);
});

test('malformed setup success never advances or repeats owner creation', async ({ page }) => {
  await start(page, { setupReply: {} });
  await claim(page);
  await expect(page.getByRole('alert')).toContainText('Owner setup could not be confirmed');
  await expect(page.getByRole('heading', { name: 'Save your authenticator.' })).toBeHidden();
  expect(await page.evaluate(() => window.sent.filter(item => item.method === 'system.setup').length)).toBe(1);
});

test('backup conflict is explicit and never becomes a successful restore', async ({ page }) => {
  await start(page, { claimed: true, importError: 'conflict' });
  await connect(page);
  const backup = Buffer.alloc(56);
  backup.write('LKB2'); backup[4] = 1; backup[5] = 1; backup.writeUInt32BE(100000, 6);
  await page.getByLabel('Encrypted lock backup').setInputFiles({ name: 'example.lkb', mimeType: 'application/octet-stream', buffer: backup });
  await page.getByLabel('Backup passphrase').fill('example-backup-passphrase');
  await page.getByRole('button', { name: 'Restore lock keys' }).click();
  await expect(page.getByRole('alert')).toContainText('Nothing was overwritten');
  await expect(page.locator('#restore-result')).toBeHidden();
  await expect(page.getByLabel('Backup passphrase')).toHaveValue('');
});

test('disconnected Wi-Fi never produces a usable board link', async ({ page }) => {
  await start(page, { claimed: true, ready: false });
  await connect(page);
  await page.getByRole('button', { name: 'Continue without a backup' }).click();
  await expect(page.getByRole('link', { name: 'Open board' })).toBeHidden();
  await expect(page.locator('#board-wifi')).toContainText('Not connected');
});

test('uncertain owner setup remains blocked across USB reconnect until login recovery is acknowledged', async ({ page }) => {
  await start(page, { setupReply: {} });
  await claim(page);
  await expect(page.getByRole('alert')).toContainText('Owner setup could not be confirmed');
  await page.getByRole('button', { name: 'Disconnect', exact: true }).click();
  await connect(page);
  await expect(page.getByRole('heading', { name: 'Recover your owner login.' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'USB owner recovery guide' })).toHaveAttribute('href', /#recovering-a-lost-setup-reply$/);
  await expect(page.getByRole('button', { name: 'Continue after recovery' })).toBeDisabled();
  await page.getByLabel('I recovered and verified this board’s owner login.').check();
  await page.getByRole('button', { name: 'Continue after recovery' }).click();
  await expect(page.getByRole('heading', { name: 'Bring your lock keys.' })).toBeVisible();
  expect(await page.evaluate(() => window.sent.some(item => item.method === 'auth.rotateTotp'))).toBe(false);
});

test('a board startup banner during connection does not strand first boot setup', async ({ page }) => {
  await start(page, { bootOnProbe: true });
  await connect(page);
  await expect(page.getByRole('heading', { name: 'Make this board yours.' })).toBeVisible();
  expect(await page.evaluate(() => window.sent.every(item => item.method === 'system.info'))).toBe(true);
});

test('returning from the page cache requires reconnect and preserves lost-authenticator recovery', async ({ page }) => {
  await start(page);
  await claim(page);
  await expect(page.getByLabel('Authenticator secret')).not.toHaveValue('');
  await page.evaluate(() => {
    dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true }));
    dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true }));
  });
  await expect(page.getByRole('button', { name: 'Connect for setup' })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Connect for setup' })).toBeEnabled();
  await expect(page.getByLabel('Authenticator secret')).toHaveValue('');
  await connect(page);
  await expect(page.getByRole('heading', { name: 'Recover your owner login.' })).toBeVisible();
});

test('a late USB picker result after navigation cannot connect the old page', async ({ page }) => {
  await start(page, { claimed: true, delayPort: true });
  await connect(page);
  await page.evaluate(async () => {
    dispatchEvent(new PageTransitionEvent('pagehide', { persisted: true }));
    dispatchEvent(new PageTransitionEvent('pageshow', { persisted: true }));
    window.finishPort();
    await new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve)));
  });
  expect(await page.evaluate(() => window.sent)).toEqual([]);
  await expect(page.getByRole('button', { name: 'Connect for setup' })).toBeEnabled();
});
