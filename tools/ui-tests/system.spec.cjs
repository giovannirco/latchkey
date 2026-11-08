// SPDX-License-Identifier: GPL-3.0-or-later
const { test, expect, mock, calls, login, boardButton, toast } = require('./support.cjs');

function firmware(size) {
  const image = Buffer.alloc(size, 0);
  image[0] = 0xe9;
  return image;
}

test('the system page shows board, Wi-Fi and clock details', async ({ page }) => {
  await login(page, '#/system');
  const board = page.getByRole('region', { name: 'Board' });
  await expect(board).toContainText('esp32s3-atom');
  await expect(board).toContainText('192.0.2.10');
  await expect(board).toContainText('Synced');
});

async function uploadFirmware(page) {
  const ota = page.getByRole('region', { name: 'Firmware update' });
  await ota.getByLabel('Firmware image (.bin)').setInputFiles({
    name: 'latchkey-esp32s3.bin',
    mimeType: 'application/octet-stream',
    buffer: firmware(300_000),
  });
  await ota.getByRole('button', { name: 'Upload' }).click();
  return ota;
}

test('a firmware upload shows progress, asks for the board button, then restarts', async ({ page, request }) => {
  await login(page, '#/system');
  const ota = await uploadFirmware(page);
  await expect(ota.getByRole('progressbar')).toBeVisible();
  await expect(boardButton(page)).toBeVisible();
  await expect(boardButton(page)).toContainText('Install new firmware');
  await expect(boardButton(page)).toBeHidden();
  await expect(toast(page, 'Firmware uploaded. The board is restarting')).toBeVisible();
  const audit = await (await request.get('/__mock/calls')).json();
  expect(audit.calls.filter((call) => call.method === 'ota')).toHaveLength(1);
});

test('firmware is not installed when nobody presses the board button', async ({ page, request }) => {
  await login(page, '#/system');
  await mock(request, { confirm: 'never', confirmTimeoutMs: 1500 });
  const ota = await uploadFirmware(page);
  await expect(boardButton(page)).toBeVisible();
  await expect(ota.getByRole('alert')).toContainText('The button on the board was not pressed in time');
  await expect(boardButton(page)).toBeHidden();
  await expect(page.locator('#toasts')).not.toContainText('Firmware uploaded');
});

test('a file that is not an ESP32 app image is refused before upload', async ({ page, request }) => {
  await login(page, '#/system');
  const ota = page.getByRole('region', { name: 'Firmware update' });
  await ota.getByLabel('Firmware image (.bin)').setInputFiles({
    name: 'notes.bin',
    mimeType: 'application/octet-stream',
    buffer: Buffer.from('PK\u0003\u0004 not firmware'),
  });
  await ota.getByRole('button', { name: 'Upload' }).click();
  await expect(ota.getByRole('alert')).toContainText('not an ESP32 firmware image');
  expect((await calls(request)).some((call) => call.method === 'ota')).toBe(false);
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
