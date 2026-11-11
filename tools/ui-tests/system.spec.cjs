// SPDX-License-Identifier: GPL-3.0-or-later
const { test, expect, mock, calls, login } = require('./support.cjs');

test.use({ timezoneId: 'Asia/Kathmandu' });

test('time zone starts from the board and saves explicit daylight rules across reloads', async ({ page, request }) => {
  await login(page, '#/system');
  const zone = page.getByRole('region', { name: 'Time zone', exact: true });
  await expect(zone.getByLabel('POSIX time zone')).toHaveValue('UTC0');
  await expect(zone).toContainText('Browser time zone:');
  await expect(zone).toContainText('UTC+05:45');
  await expect(zone).toContainText('does not adjust for daylight saving');
  const tz = 'EST5EDT,M3.2.0,M11.1.0';
  await zone.getByLabel('POSIX time zone').fill(tz);
  expect((await calls(request)).filter((call) => call.method === 'system.timezone.set')).toHaveLength(0);
  await zone.getByRole('button', { name: 'Save time zone' }).click();
  await expect(page.locator('#toasts')).toContainText('Time zone saved');
  expect((await calls(request)).find((call) => call.method === 'system.timezone.set').params).toEqual({ tz });
  await page.reload();
  await expect(zone.getByLabel('POSIX time zone')).toHaveValue(tz);
});

test('time zone rejects IANA names and preserves the saved value', async ({ page }) => {
  await login(page, '#/system');
  const zone = page.getByRole('region', { name: 'Time zone', exact: true });
  await zone.getByLabel('POSIX time zone').fill('America/New_York');
  await zone.getByRole('button', { name: 'Save time zone' }).click();
  await expect(page.locator('#toasts')).toContainText('Some values are not valid');
  await expect(page.locator('#toasts')).not.toContainText('Time zone saved');
  await page.reload();
  await expect(zone.getByLabel('POSIX time zone')).toHaveValue('UTC0');
});

test('browser offset fills an explicit fixed-offset suggestion without saving it', async ({ page, request }) => {
  await login(page, '#/system');
  const zone = page.getByRole('region', { name: 'Time zone', exact: true });
  await zone.getByRole('button', { name: 'Use current browser offset' }).click();
  await expect(zone.getByLabel('POSIX time zone')).toHaveValue('UTC-5:45');
  expect((await calls(request)).filter((call) => call.method === 'system.timezone.set')).toHaveLength(0);
  await zone.getByRole('button', { name: 'Save time zone' }).click();
  await expect(zone).toContainText('Current board offset: UTC+05:45');
  await expect(zone).toContainText('Sync time');
});

test('time zone storage errors retain the edit for retry without claiming success', async ({ page, request }) => {
  await login(page, '#/system');
  await mock(request, { failNext: { method: 'system.timezone.set', code: 'internal', message: 'cannot save time zone' } });
  const zone = page.getByRole('region', { name: 'Time zone', exact: true });
  await zone.getByLabel('POSIX time zone').fill('<-03>3');
  await zone.getByRole('button', { name: 'Save time zone' }).click();
  await expect(page.locator('#toasts')).toContainText('Cannot save time zone');
  await expect(page.locator('#toasts')).not.toContainText('Time zone saved');
  await expect(zone.getByLabel('POSIX time zone')).toHaveValue('<-03>3');
  await expect(zone.getByRole('button', { name: 'Save time zone' })).toBeEnabled();
});

test('released firmware does not offer an unsupported update upload', async ({ page }) => {
  await login(page, '#/system');
  await expect(page.getByRole('region', { name: 'Firmware update' })).toHaveCount(0);
  await expect(page.getByLabel('Firmware image (.bin)')).toHaveCount(0);
});

test('the system page shows board, Wi-Fi and clock details', async ({ page }) => {
  await login(page, '#/system');
  const board = page.getByRole('region', { name: 'Board' });
  await expect(board).toContainText('esp32s3');
  await expect(board).toContainText('192.0.2.10');
  await expect(board).toContainText('Synced');
});

test('Wi-Fi settings never echo the password', async ({ page, request }) => {
  await login(page, '#/system');
  const wifi = page.getByRole('form', { name: 'Wi-Fi' });
  await expect(wifi.getByLabel('Password')).toHaveValue('');
  await wifi.getByLabel('Network name (SSID)').fill('lab-iot-2');
  await wifi.getByLabel('Password').fill('a wifi secret');
  await wifi.getByRole('button', { name: 'Save Wi-Fi' }).click();
  await expect(page.locator('#toasts')).toContainText('The board is joining lab-iot-2');
  await expect(wifi.getByLabel('Password')).toHaveValue('');
  const call = (await calls(request)).find((entry) => entry.method === 'system.wifi.set');
  expect(call.params).toEqual({
    ssid: 'lab-iot-2',
    password: '***',
    ip: '192.0.2.10',
    gateway: '192.0.2.1',
    netmask: '255.255.255.0',
    dns: '192.0.2.53',
  });
});

test('the Wi-Fi form starts from the static address the board reports', async ({ page }) => {
  await login(page, '#/system');
  const wifi = page.getByRole('form', { name: 'Wi-Fi' });
  await expect(wifi.getByLabel('Network name (SSID)')).toHaveValue('lab-iot');
  await expect(wifi.getByLabel('IP address')).toHaveValue('192.0.2.10');
  await expect(wifi.getByLabel('Gateway')).toHaveValue('192.0.2.1');
  await expect(wifi.getByLabel('Netmask')).toHaveValue('255.255.255.0');
  await expect(wifi.getByLabel('DNS server')).toHaveValue('192.0.2.53');
});

test('a new static address is sent whole and kept by the board', async ({ page }) => {
  await login(page, '#/system');
  const wifi = page.getByRole('form', { name: 'Wi-Fi' });
  await wifi.getByLabel('IP address').fill('198.51.100.20');
  await wifi.getByLabel('Gateway').fill('198.51.100.1');
  await wifi.getByLabel('DNS server').fill('198.51.100.53');
  await wifi.getByRole('button', { name: 'Save Wi-Fi' }).click();
  await expect(page.locator('#toasts')).toContainText('The board is joining lab-iot');
  const reply = await page.request.post('/api/rpc', { data: { id: 1, method: 'system.info', params: {} } });
  const info = await reply.json();
  expect(info.result.wifi).toMatchObject({
    ip: '198.51.100.20',
    gateway: '198.51.100.1',
    netmask: '255.255.255.0',
    dns: '198.51.100.53',
  });
});

test('an address outside the gateway network is refused like the board refuses it', async ({ page }) => {
  await login(page, '#/system');
  const wifi = page.getByRole('form', { name: 'Wi-Fi' });
  await wifi.getByLabel('IP address').fill('198.51.100.20');
  await wifi.getByRole('button', { name: 'Save Wi-Fi' }).click();
  await expect(page.locator('#toasts')).toContainText(/wifi needs ssid, password, ip, gateway, netmask and dns/i);
  await expect(page.locator('#toasts')).not.toContainText('The board is joining');
});

test('the MQTT section shows the connection and says when the password must be given again', async ({ page }) => {
  await login(page, '#/system');
  const section = page.getByRole('region', { name: 'Home Assistant (MQTT)' });
  await expect(section.getByText('MQTT is off.')).toBeVisible();
  await expect(section.getByText('A new host, port or username clears the saved password')).toBeVisible();
  await section.getByLabel('Publish to an MQTT broker').check();
  await section.getByLabel('Broker host').fill('broker.example');
  await section.getByLabel('Password').fill('broker secret');
  await section.getByRole('button', { name: 'Save MQTT' }).click();
  await expect(section.getByText('Connected to the broker.')).toBeVisible();
});
