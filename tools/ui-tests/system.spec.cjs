// SPDX-License-Identifier: GPL-3.0-or-later
const { test, expect, calls, login } = require('./support.cjs');

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

test('a firmware upload shows progress and the restart', async ({ page }) => {
  await login(page, '#/system');
  const ota = page.getByRole('region', { name: 'Firmware update' });
  await ota.getByLabel('Firmware image (.bin)').setInputFiles({
    name: 'latchkey-esp32s3.bin',
    mimeType: 'application/octet-stream',
    buffer: firmware(300_000),
  });
  await ota.getByRole('button', { name: 'Upload' }).click();
  await expect(ota.getByRole('progressbar')).toBeVisible();
  await expect(ota).toContainText('Upload complete. The board is restarting');
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
  expect(call.params).toEqual({ ssid: 'lab-iot-2', password: '***' });
});
