// SPDX-License-Identifier: GPL-3.0-or-later
import { RpcError, SerialRpc } from './installer-serial.mjs';

const byId = id => document.getElementById(id);
const version = document.querySelector('meta[name="latchkey-version"]').content;
const hasRelease = /^\d+\.\d+\.\d+$/.test(version);
const hasSerial = Boolean(window.isSecureContext && navigator.serial);
const panels = ['install', 'setup', 'auth', 'recovery', 'backup', 'ready'];
let rpc = null;
let busy = false;
let authUri = '';
let currentPanel = 'install';
let restored = false;
let needsOwnerRecovery = false;
let generation = 0;
let connectingRpc = null;

class InactivePage extends Error {}

async function pageResult(promise) {
  const started = generation;
  try {
    const result = await promise;
    if (started !== generation) throw new InactivePage();
    return result;
  } catch (error) {
    if (started !== generation) throw new InactivePage();
    throw error;
  }
}

function message(id, text) {
  byId(id).textContent = text;
  byId(id).hidden = !text;
}

function problem(text) {
  message('error', text);
  byId('error').focus();
}

function showPanel(name) {
  currentPanel = name;
  for (const panel of panels) byId(`${panel}-panel`).hidden = panel !== name;
  const step = { install: 0, setup: 1, auth: 1, recovery: 1, backup: 2, ready: 3 }[name];
  document.querySelectorAll('.steps li').forEach((item, index) => {
    item.classList.toggle('complete', index < step);
    if (index === step) item.setAttribute('aria-current', 'step');
    else item.removeAttribute('aria-current');
  });
  byId(`${name}-title`).focus({ preventScroll: true });
  byId('workspace').scrollIntoView({ block: 'start' });
  updateControls();
}

function updateControls() {
  byId('connect').disabled = !hasSerial || busy || Boolean(rpc);
  byId('disconnect').hidden = !rpc;
  byId('disconnect').disabled = busy;
  byId('install-button').disabled = !hasRelease || !hasSerial || busy || Boolean(rpc) ||
    !byId('erase-ack').checked || !customElements.get('esp-web-install-button');
  for (const element of document.querySelectorAll('#setup-form input, #setup-form button, #backup-form input, #backup-form button')) {
    element.disabled = busy || !rpc || (restored && element.closest('#backup-form') !== null);
  }
  byId('auth-next').disabled = busy || !byId('auth-saved').checked;
  byId('recovery-next').disabled = busy || !rpc || !byId('recovery-ack').checked;
  byId('skip-backup').disabled = busy || !rpc;
  byId('refresh').disabled = busy || !rpc;
  byId('sync-clock').disabled = busy || !rpc;
}

function showBoard() {
  const board = document.querySelector('input[name="board"]:checked').value;
  byId('erase-ack').checked = false;
  if (hasRelease) {
    const base = `firmware/${version}/`;
    document.querySelector('esp-web-install-button').setAttribute('manifest', `${base}manifest-${board}.json`);
    byId('download-factory').href = `${base}latchkey-${version}-${board}-factory.bin`;
    byId('download-ota').href = `${base}latchkey-${version}-${board}-ota.bin`;
  }
  updateControls();
}

function clearPasswords() {
  for (const input of document.querySelectorAll('input[type="password"]')) input.value = '';
  byId('backup-file').value = '';
}

function connectionLost() {
  rpc = null;
  clearPasswords();
  byId('connection-status').textContent = 'USB disconnected';
  document.querySelector('.connection').classList.remove('connected');
  byId('open-board').hidden = true;
  if (currentPanel !== 'auth') showPanel('install');
  problem('USB disconnected. Reconnect to check the board before continuing. A request already sent may have completed.');
  updateControls();
}

async function run(action) {
  if (busy) return;
  const started = generation;
  busy = true;
  message('error', '');
  updateControls();
  try { await action(); }
  catch (error) {
    if (started === generation) problem(error instanceof RpcError ? error.message : 'This step could not be completed. Check the connection and try again.');
  } finally {
    if (started === generation) {
      busy = false;
      message('status', '');
      updateControls();
    }
  }
}

function ipv4(value) {
  if (typeof value !== 'string' || !/^(0|[1-9]\d{0,2})(\.(0|[1-9]\d{0,2})){3}$/.test(value)) return false;
  return value.split('.').every(part => Number(part) <= 255);
}

function validInfo(info) {
  if (!info || typeof info.claimed !== 'boolean' || typeof info.firmware !== 'string' ||
      !info.wifi || typeof info.wifi.connected !== 'boolean') throw new RpcError('bad_response');
  return info;
}

function byteLength(value) {
  return new TextEncoder().encode(value).length;
}

function validPassword(value) {
  return !value.includes('\0') && byteLength(value) >= 12 && byteLength(value) <= 128;
}

async function connect() {
  let next = null;
  const started = generation;
  try {
    const port = await pageResult(navigator.serial.requestPort());
    next = new SerialRpc(port, { onDisconnect: () => { if (started === generation) connectionLost(); } });
    connectingRpc = next;
    message('status', 'Opening USB and reading the board…');
    await pageResult(next.open());
    const info = validInfo(await pageResult(next.waitReady()));
    rpc = next;
    byId('connection-status').textContent = `Connected · firmware ${/^\d+\.\d+\.\d+$/.test(info.firmware) ? info.firmware : 'unknown'}`;
    document.querySelector('.connection').classList.add('connected');
    restored = false;
    message('restore-result', '');
    byId('skip-backup').textContent = 'Continue without a backup';
    if (!info.claimed) needsOwnerRecovery = false;
    byId('recovery-ack').checked = false;
    showPanel(info.claimed ? (needsOwnerRecovery ? 'recovery' : 'backup') : 'setup');
  } catch (error) {
    if (next) await next.close().catch(() => {});
    if (started !== generation) return;
    rpc = null;
    if (error?.name === 'NotFoundError') {
      message('status', '');
      return;
    }
    throw error instanceof RpcError ? error : new RpcError('connect_failed');
  } finally {
    if (connectingRpc === next) connectingRpc = null;
  }
}

function setupParams() {
  const form = byId('setup-form');
  const get = name => form.elements.namedItem(name).value;
  const wifi = { ssid: get('ssid'), password: get('wifi-password') };
  const password = get('password');
  for (const key of ['ip', 'gateway', 'netmask', 'dns']) {
    wifi[key] = get(key).trim();
    if (!ipv4(wifi[key])) throw new Error('Enter valid IPv4 addresses for the board, gateway, subnet mask and DNS server.');
  }
  if (wifi.ssid.includes('\0') || byteLength(wifi.ssid) < 1 || byteLength(wifi.ssid) > 32) {
    throw new Error('The Wi-Fi name must contain 1–32 UTF-8 bytes.');
  }
  if (wifi.password.includes('\0') || (wifi.password && (byteLength(wifi.password) < 8 || byteLength(wifi.password) > 63))) {
    throw new Error('The Wi-Fi password must contain 8–63 UTF-8 bytes, or be empty for an open network.');
  }
  if (!validPassword(password)) throw new Error('The owner password must contain 12–128 UTF-8 bytes and no NUL character.');
  if (password !== get('confirm-password')) throw new Error('The owner passwords do not match.');
  return { wifi, password };
}

async function setup(params) {
  const started = generation;
  needsOwnerRecovery = true;
  try {
    message('status', 'Creating owner access. Keep USB connected and this tab open…');
    const result = await pageResult(rpc.call('system.setup', params, 60000));
    const uri = new URL(result?.otpauth);
    const secret = uri.searchParams.get('secret');
    if (uri.protocol !== 'otpauth:' || uri.hostname !== 'totp' || !secret || !/^[A-Z2-7]{16,128}$/.test(secret)) {
      throw new RpcError('bad_response');
    }
    authUri = uri.href;
    needsOwnerRecovery = false;
    byId('totp-secret').value = secret;
    byId('auth-saved').checked = false;
    showPanel('auth');
  } catch (error) {
    if (error instanceof InactivePage) return;
    if (error.code === 'invalid_argument') needsOwnerRecovery = false;
    const known = {
      invalid_argument: 'The board rejected the setup values. Check the Wi-Fi and static network settings, and the password length.',
      already_claimed: 'This board already has an owner. Disconnect and reconnect to continue without changing its login.',
    };
    problem(known[error.code] || 'Owner setup could not be confirmed. Do not reflash. Reconnect to check whether the board is claimed. If it is claimed and you did not receive the authenticator secret, stop and consult the USB recovery instructions.');
  } finally {
    params.password = '';
    params.wifi.password = '';
    if (started === generation) clearPasswords();
  }
}

async function restore(file, passphrase) {
  const started = generation;
  let bytes = null;
  const params = { passphrase, backup: '' };
  try {
    if (!validPassword(passphrase)) {
      problem('The backup passphrase must contain 12–128 UTF-8 bytes and no NUL character.');
      return;
    }
    if (!file || file.size < 56 || file.size > 8246) {
      problem('Choose a valid Latchkey .lkb backup, no larger than 8,246 bytes.');
      return;
    }
    bytes = new Uint8Array(await pageResult(file.arrayBuffer()));
    const header = new DataView(bytes.buffer);
    if (String.fromCharCode(...bytes.subarray(0, 4)) !== 'LKB2' || bytes[4] !== 1 || bytes[5] !== 1 || header.getUint32(6) !== 100000) {
      problem('Choose a valid Latchkey LKB2 backup. This file has an unsupported or damaged header.');
      return;
    }
    params.backup = btoa(String.fromCharCode(...bytes));
    bytes.fill(0);
    message('status', 'Authenticating and restoring the backup on the board. Keep USB connected…');
    const result = await pageResult(rpc.call('keys.import', params, 240000));
    if (!Array.isArray(result?.imported) || result.imported.length < 1 || result.imported.length > 8 ||
        !result.imported.every(id => typeof id === 'string' && /^([0-9A-F]{2}:){5}[0-9A-F]{2}$/.test(id)) ||
        new Set(result.imported).size !== result.imported.length) throw new RpcError('bad_response');
    restored = true;
    message('restore-result', `Restored ${result.imported.length} ${result.imported.length === 1 ? 'lock' : 'locks'}.`);
    byId('skip-backup').textContent = 'Continue to connection check';
  } catch (error) {
    if (error instanceof InactivePage) return;
    const known = {
      invalid_argument: 'The board could not authenticate or validate this backup. Check the file and passphrase.',
      conflict: 'This backup contains a lock already stored on the board. Nothing was overwritten. Check the board’s existing locks.',
      storage_full: 'The board has insufficient space for this backup. No locks were imported.',
      recovery_required: 'Lock storage needs recovery. Restart the board and inspect its status before another import.',
    };
    problem(known[error.code] || 'Restore could not be confirmed. Reconnect and inspect the board’s locks before trying again; the import may have completed.');
  } finally {
    if (bytes) bytes.fill(0);
    params.passphrase = '';
    params.backup = '';
    if (started === generation) clearPasswords();
  }
}

async function readiness() {
  message('status', 'Reading connection status over USB…');
  const info = validInfo(await pageResult(rpc.call('system.info')));
  byId('board-firmware').textContent = /^\d+\.\d+\.\d+$/.test(info.firmware) ? info.firmware : 'Unknown version';
  byId('board-wifi').textContent = info.wifi.connected && ipv4(info.wifi.ip) ? `Connected · ${info.wifi.ip}` : 'Not connected — check network settings';
  byId('board-owner').textContent = info.claimed ? 'Configured' : 'Not configured';
  byId('board-clock').textContent = info.time?.synced === true ? 'Synchronized' : 'Not synchronized — login codes need an accurate clock';
  const fingerprint = info.certFingerprint;
  const hasFingerprint = typeof fingerprint === 'string' && /^(?:[a-f0-9]{64}|(?:[a-f0-9]{2}:){31}[a-f0-9]{2})$/i.test(fingerprint);
  byId('fingerprint').textContent = hasFingerprint ? fingerprint : 'Not available yet. Wait for Wi-Fi, then check again.';
  const ready = info.claimed && info.wifi.connected && ipv4(info.wifi.ip) && hasFingerprint && info.time?.synced === true;
  byId('open-board').hidden = !ready;
  byId('open-board').removeAttribute('href');
  if (ready) byId('open-board').href = `https://${info.wifi.ip}`;
  byId('sync-clock').hidden = info.time?.synced === true;
  byId('ready-description').textContent = ready
    ? 'The board reports a local connection and configured owner access. Verify its certificate, then sign in.'
    : 'The board is not ready for login yet. Resolve the items below, then check again. Use the USB configuration guide if network settings need correcting.';
  showPanel('ready');
}

if (hasRelease) {
  byId('release-version').textContent = `v${version}`;
  byId('release-link').href = `https://github.com/giovannirco/latchkey/releases/tag/v${version}`;
  byId('download-release').href = byId('release-link').href;
  byId('download-sums').href = `firmware/${version}/SHA256SUMS`;
  byId('release-downloads').hidden = false;
  byId('download-fallback').hidden = true;
} else byId('release-none').hidden = false;
byId('browser-support').hidden = hasSerial;
for (const input of document.querySelectorAll('input[name="board"]')) input.addEventListener('change', showBoard);
byId('erase-ack').addEventListener('change', updateControls);
byId('connect').addEventListener('click', () => run(connect));
byId('disconnect').addEventListener('click', () => run(async () => {
  const current = rpc;
  rpc = null;
  clearPasswords();
  await pageResult(current.close());
  byId('connection-status').textContent = 'USB not connected';
  document.querySelector('.connection').classList.remove('connected');
  if (!authUri) showPanel('install');
}));
byId('setup-form').addEventListener('submit', event => {
  event.preventDefault();
  if (busy || !rpc) return;
  let params;
  try { params = setupParams(); }
  catch (error) { problem(error.message); return; }
  void run(() => setup(params));
});
byId('copy-auth').addEventListener('click', async () => {
  try {
    await pageResult(navigator.clipboard.writeText(authUri));
    message('status', 'Authenticator URI copied. Paste it into your password manager, then clear your clipboard.');
  } catch (error) {
    if (!(error instanceof InactivePage)) problem('Clipboard access was refused. Copy the displayed secret manually.');
  }
});
byId('auth-saved').addEventListener('change', updateControls);
byId('recovery-ack').addEventListener('change', updateControls);
byId('recovery-next').addEventListener('click', () => {
  if (!byId('recovery-ack').checked || busy || !rpc) return;
  needsOwnerRecovery = false;
  message('error', '');
  showPanel('backup');
});
byId('auth-next').addEventListener('click', () => {
  if (!byId('auth-saved').checked || busy) return;
  authUri = '';
  byId('totp-secret').value = '';
  message('status', '');
  showPanel(rpc ? 'backup' : 'install');
});
byId('backup-form').addEventListener('submit', event => {
  event.preventDefault();
  if (busy || !rpc || restored) return;
  const file = byId('backup-file').files[0];
  const passphrase = byId('backup-passphrase').value;
  void run(() => restore(file, passphrase));
});
byId('skip-backup').addEventListener('click', () => run(readiness));
byId('refresh').addEventListener('click', () => run(readiness));
byId('sync-clock').addEventListener('click', () => run(async () => {
  await pageResult(rpc.call('system.time.set', { utc: Math.floor(Date.now() / 1000) }));
  await readiness();
}));
window.addEventListener('beforeunload', event => {
  if (!busy && !authUri) return;
  event.preventDefault();
  event.returnValue = '';
});
window.addEventListener('pagehide', () => {
  generation += 1;
  busy = false;
  needsOwnerRecovery ||= Boolean(authUri);
  clearPasswords();
  authUri = '';
  byId('totp-secret').value = '';
  if (rpc) void rpc.close().catch(() => {});
  if (connectingRpc && connectingRpc !== rpc) void connectingRpc.close().catch(() => {});
  rpc = null;
  connectingRpc = null;
  byId('connection-status').textContent = 'USB not connected';
  document.querySelector('.connection').classList.remove('connected');
  byId('open-board').hidden = true;
  byId('open-board').removeAttribute('href');
  byId('erase-ack').checked = false;
  message('status', '');
  showPanel('install');
});
window.addEventListener('pageshow', event => {
  if (event.persisted) problem('The previous USB session ended. Connect again to read the board’s current state before continuing.');
});
customElements.whenDefined('esp-web-install-button').then(() => {
  byId('flasher-unavailable').hidden = true;
  updateControls();
});
setTimeout(() => {
  if (!customElements.get('esp-web-install-button')) byId('flasher-unavailable').hidden = false;
}, 10000);
showBoard();
