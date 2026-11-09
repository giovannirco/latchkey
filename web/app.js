// SPDX-License-Identifier: GPL-3.0-or-later
const CHAINED_TIMEOUT_MS = 240000;
const LOCK_TIMEOUT_MS = 100000;
const BUTTON_TIMEOUT_MS = 45000;
const SHORT_TIMEOUT_MS = 15000;
const OTA_TIMEOUT_MS = 300000;
const JOB_MEMORY_MS = 300000;
const LOG_ROUNDS = 5;
const TOAST_MS = 6000;
const ERROR_TOAST_MS = 12000;
const SVG_NS = 'http://www.w3.org/2000/svg';
const FIRMWARE_MAGIC = 0xe9;
const LOG_REFRESH_MS = 3000;
const LOG_KEEP = 500;
const LOG_LEVELS = [
  ['verbose', 'All lines'],
  ['debug', 'Debug and more severe'],
  ['info', 'Info and more severe'],
  ['warn', 'Warnings and errors'],
  ['error', 'Errors only'],
];

const ERROR_TEXT = {
  session_changed: 'The session that started this action ended. Check its result before retrying.',
  unauthorized: 'Your session ended. Sign in again.',
  rate_limited: 'Too many attempts. Wait a moment and try again.',
  time_unsynced:
    "The board's clock is not set yet, so it cannot check codes or set the lock's time. It sets its clock over the internet (NTP) once it is online.",
  confirm_timeout: 'The button on the board was not pressed in time. Nothing was changed.',
  busy: 'The board is busy with another lock operation. Try again in a moment.',
  unsupported: 'This lock does not support that.',
  not_paired: 'The board has no keys for this lock.',
  pair_incomplete:
    'Pairing stopped before it finished. The board kept the keys it received: factory-reset the lock, then pair it again.',
  timeout: 'The lock did not answer in time. Touch its keypad to wake it, keep the board close, and try again.',
  disconnected: 'The Bluetooth link to the lock dropped. Try again.',
  bad_response: 'The lock sent an answer the board could not read. Try again.',
  bad_crc: 'The lock sent a damaged answer. Try again.',
  lock_error: 'The lock refused the command.',
  invalid_argument: 'Some values are not valid.',
  storage_full:
    "The board's storage is nearly full; it keeps the rest for pairing and the audit log. Remove names, or forget a lock you no longer use.",
  too_large: 'The board does not have enough free memory to show this list.',
  already_claimed: 'This board already has an owner.',
  backup_required:
    "Back up this lock's keys before hardening it or turning its reset button off: with the button off, the backup is the only way back if the board is lost.",
  network: 'Cannot reach the board. Check that this device is on the same network.',
  job_lost:
    'The connection to the board dropped before it reported the result. Check the lock, then try again if needed.',
  no_reply:
    'The board did not answer in time. Check that it is still on the network, then look at the result before retrying.',
  http: 'The board answered with an error.',
};

const ACTION_TEXT = {
  'locks.pair': 'Pair the lock',
  'lock.harden': 'Harden the lock',
  'lock.factoryReset': 'Factory-reset the lock',
  'lock.adminPasscode.set': 'Change the super admin passcode',
  'lock.adminPasscode.get': 'Show the super admin passcode',
  'lock.resetButton.set': 'Turn the reset button on or off',
  'keys.export': 'Export the key backup',
  'keys.import': 'Import a key backup',
  'auth.rotateTotp': 'Replace the authenticator secret',
  'system.factoryReset': 'Factory-reset the board',
  ota: 'Install new firmware',
};

const FEATURE_TEXT = {
  passcode: 'Passcodes',
  ic: 'IC cards',
  finger_print: 'Fingerprints',
  wrist_band: 'Wristbands',
  auto_lock: 'Auto-lock',
  passcode_with_delete_function: 'Passcodes that clear older ones',
  firmware_setting: 'Firmware settings',
  modify_passcode_function: 'Editable passcodes',
  manual_lock: 'Locking from the app',
  password_display_or_hide: 'Passcode display',
  gateway_unlock: 'Gateway unlock',
  freeze_lock: 'Freeze',
  cyclic_password: 'Cyclic passcodes',
  magnetometer: 'Door sensor',
  config_gateway_unlock: 'Remote unlock',
  audio_management: 'Sound',
  nb_lock: 'NB-IoT',
  get_admin_code: 'Readable admin passcode',
  hotel_lock: 'Hotel mode',
  lock_no_clock_chip: 'No clock chip',
  can_not_click_unlock: 'No touch to unlock',
  passage_mode: 'Passage mode',
  passage_mode_and_auto_lock_and_can_close: 'Passage mode with auto-lock',
  wireless_keyboard: 'Wireless keypad',
  lamp: 'Lamp',
  tamper_alert: 'Tamper alert',
  reset_button: 'Reset button',
  privacy_lock: 'Privacy lock',
  dead_lock: 'Deadlock',
  cyclic_ic_or_finger_print: 'Cyclic cards and fingerprints',
  unlock_direction: 'Unlock direction',
  finger_vein: 'Finger vein',
  wireless_key_fob: 'Wireless key fob',
  accessory_battery: 'Accessory battery',
};

const FEATURES_USED = new Set([
  'passcode',
  'ic',
  'finger_print',
  'auto_lock',
  'modify_passcode_function',
  'manual_lock',
  'audio_management',
  'get_admin_code',
  'passage_mode',
  'tamper_alert',
  'reset_button',
  'privacy_lock',
  'cyclic_ic_or_finger_print',
]);

const MQTT_STATUS_DELAY_MS = 5000;

const METHOD_TEXT = {
  app: 'from the app',
  passcode: 'with a passcode',
  fingerprint: 'with a fingerprint',
  card: 'with a card',
  key: 'with the mechanical key',
  auto: 'automatically',
  remote: 'remotely',
  button: 'with the inside button',
};

const LOG_TEXT = {
  1: 'Unlocked from the app',
  4: 'Unlocked with a passcode',
  5: 'Passcode changed on the keypad',
  6: 'Passcode deleted on the keypad',
  7: 'Wrong passcode entered',
  8: 'All passcodes deleted on the keypad',
  9: 'Passcode pushed out by a newer one',
  10: 'Clearing passcode used',
  11: 'Expired passcode entered',
  12: 'Passcode refused: storage full',
  13: 'Blocked passcode entered',
  14: 'Lock powered on',
  15: 'Card added',
  16: 'All cards deleted',
  17: 'Unlocked with a card',
  18: 'Card deleted',
  19: 'Unlocked with a wristband',
  20: 'Unlocked with a fingerprint',
  21: 'Fingerprint added',
  22: 'Fingerprint not recognised',
  23: 'Fingerprint deleted',
  24: 'All fingerprints deleted',
  25: 'Card refused',
  26: 'Locked from the app',
  27: 'Unlocked with the mechanical key',
  28: 'Unlocked through a gateway',
  29: 'Forced open',
  30: 'Door closed',
  31: 'Door opened',
  32: 'Opened from inside',
  33: 'Locked with a fingerprint',
  34: 'Locked with a passcode',
  35: 'Locked with a card',
  36: 'Locked with the mechanical key',
  37: 'Remote control button',
  38: 'Passcode refused, door locked',
  39: 'Card refused, door locked',
  40: 'Fingerprint refused, door locked',
  41: 'App unlock refused, door locked',
  55: 'Wireless key fob',
  56: 'Wireless keypad battery report',
};

const PASSCODE_TYPES = [
  ['permanent', 'Permanent'],
  ['timed', 'Timed'],
  ['one_time', 'One-time'],
  ['cyclic', 'Cyclic'],
];
const TYPE_TEXT = Object.fromEntries(PASSCODE_TYPES);
const WEEKDAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
const WEEKDAY_NAMES = ['Mondays', 'Tuesdays', 'Wednesdays', 'Thursdays', 'Fridays', 'Saturdays', 'Sundays'];

const HARDEN_ITEMS = [
  ['backup', 'Back up the keys to an encrypted file'],
  ['admin_passcode', 'Replace the super admin passcode with a random one'],
  ['passcodes', 'Delete passcodes Latchkey did not create, the factory 123456 included'],
  ['reset_button', 'Turn off the physical reset button'],
  ['time', "Set the lock's clock"],
];
const STATUS_TEXT = {
  pending: 'Pending',
  todo: 'To do',
  running: 'Running',
  done: 'Done',
  skipped: 'Skipped',
  failed: 'Failed',
};

const CREDENTIALS = {
  fingerprint: {
    title: 'Fingerprints',
    icon: 'finger',
    method: 'lock.fingerprints',
    list: 'fingerprints',
    noun: 'fingerprint',
    Noun: 'Fingerprint',
    instruction: 'Place your finger on the sensor, lift it when the lock beeps, and repeat until it is done.',
    name: (item) => item.name || `Fingerprint ${item.id}`,
    number: () => null,
  },
  card: {
    title: 'IC cards',
    icon: 'card',
    method: 'lock.cards',
    list: 'cards',
    noun: 'card',
    Noun: 'Card',
    instruction: 'Hold the card flat against the keypad until the lock beeps.',
    name: (item) => item.name || 'Card',
    number: (item) => `•••• ${String(item.id).slice(-4)}`,
  },
};

const app = document.getElementById('app');
const toasts = document.getElementById('toasts');
const state = { authed: false, info: null, locks: [] };
let cleanups = [];
let renderSeq = 0;
let uidSeq = 0;
let rpcSeq = 0;
let sessionEpoch = 0;

const uid = (prefix) => `${prefix}-${++uidSeq}`;

function append(el, children) {
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    el.append(child instanceof Node ? child : String(child));
  }
  return el;
}

function h(tag, props, ...children) {
  const el = document.createElement(tag);
  append(el, children);
  for (const [key, value] of Object.entries(props || {})) {
    if (value === null || value === undefined || value === false) continue;
    if (key.startsWith('on') && typeof value === 'function') el.addEventListener(key.slice(2), value);
    else if (key === 'class') el.className = value;
    else if (key === 'value') el.value = value;
    else el.setAttribute(key, value === true ? '' : String(value));
  }
  return el;
}

function icon(name) {
  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('class', 'icon');
  svg.setAttribute('aria-hidden', 'true');
  const use = document.createElementNS(SVG_NS, 'use');
  use.setAttribute('href', `#i-${name}`);
  svg.append(use);
  return svg;
}

const dateTime = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'short' });
const relative = new Intl.RelativeTimeFormat(undefined, { numeric: 'auto', style: 'short' });

function formatTime(seconds) {
  return seconds ? dateTime.format(new Date(seconds * 1000)) : '—';
}

function ago(seconds) {
  if (!seconds) return 'never';
  const diff = Math.round(seconds - Date.now() / 1000);
  for (const [unit, size] of [
    ['day', 86400],
    ['hour', 3600],
    ['minute', 60],
  ]) {
    if (Math.abs(diff) >= size) return relative.format(Math.round(diff / size), unit);
  }
  return relative.format(diff, 'second');
}

function duration(seconds) {
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  if (days) return `${days} d ${hours} h`;
  if (hours) return `${hours} h ${minutes} min`;
  return minutes ? `${minutes} min` : `${seconds} s`;
}

const pad = (value) => String(value).padStart(2, '0');
const clockTime = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' });

function toLocalInput(seconds) {
  const d = new Date(seconds * 1000);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function fromLocalInput(value) {
  const time = new Date(value).getTime();
  return value && Number.isFinite(time) ? Math.floor(time / 1000) : null;
}

function localDate() {
  const d = new Date();
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

function capitalize(text) {
  return text ? text[0].toUpperCase() + text.slice(1) : text;
}

class ApiError extends Error {
  constructor(code, message, extra = {}) {
    super(message || code);
    this.code = code;
    this.serverMessage = message || '';
    this.extra = extra;
  }
}

function errorText(error) {
  if (!(error instanceof ApiError)) return error.message || 'Something went wrong.';
  return ERROR_TEXT[error.code] || capitalize(error.serverMessage) || `Error: ${error.code}`;
}

function errorDetail(error) {
  if (!(error instanceof ApiError) || !error.serverMessage) return null;
  const detail = capitalize(error.serverMessage);
  return detail === errorText(error) || error.serverMessage === error.code ? null : detail;
}

function apiError(error) {
  const { code, message, ...extra } = error || {};
  return new ApiError(code || 'http', message, extra);
}

const CHAINED_METHODS = new Set(['locks.pair', 'lock.harden', 'lock.factoryReset']);

function timeoutFor(method) {
  if (CHAINED_METHODS.has(method)) return CHAINED_TIMEOUT_MS;
  if (method.startsWith('lock.') || method.startsWith('locks.')) return LOCK_TIMEOUT_MS;
  if (method in ACTION_TEXT) return BUTTON_TIMEOUT_MS;
  return SHORT_TIMEOUT_MS;
}

async function call(method, params = {}) {
  const sentSession = sessionEpoch;
  const id = ++rpcSeq;
  const budget = timeoutFor(method);
  const started = Date.now();
  const sentEpoch = jobs.epoch();
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), budget);
  let response;
  let body;
  try {
    response = await fetch('/api/rpc', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'same-origin',
      cache: 'no-store',
      body: JSON.stringify({ id, method, params }),
      signal: controller.signal,
    });
    try {
      body = await response.json();
    } catch (failure) {
      if (controller.signal.aborted) throw failure;
      throw new ApiError('http', `HTTP ${response.status}`);
    }
  } catch (failure) {
    if (failure instanceof ApiError) throw failure;
    throw new ApiError(controller.signal.aborted ? 'no_reply' : 'network', failure.message);
  } finally {
    clearTimeout(timer);
  }
  if (sentSession !== sessionEpoch) throw new ApiError('session_changed');
  if (body && body.error) throw apiError(body.error);
  if (!response.ok) throw new ApiError('http', `HTTP ${response.status}`);
  if (!body || body.id !== id || !body.result || typeof body.result !== 'object' || Array.isArray(body.result)) {
    throw new ApiError('http', 'The board sent an invalid response. Check the result before retrying.');
  }
  const result = body.result;
  if (typeof result.job === 'string') {
    return jobs.wait(result.job, Math.max(1000, budget - (Date.now() - started)), sentEpoch);
  }
  return result;
}

async function rpc(method, params) {
  const sentSession = sessionEpoch;
  try {
    const result = await call(method, params);
    if (sentSession !== sessionEpoch) throw new ApiError('session_changed');
    showWarning(result);
    return result;
  } catch (failure) {
    if (sentSession !== sessionEpoch) throw new ApiError('session_changed');
    if (failure.code === 'unauthorized' && state.authed) sessionLost();
    throw failure;
  } finally {
    if (sentSession === sessionEpoch) boardButton.settle(method);
  }
}

const events = (() => {
  const handlers = new Map();
  const watchers = { drop: new Set(), reopen: new Set() };
  let socket = null;
  let wanted = false;
  let opened = false;
  let retry = 0;
  let timer = 0;

  function notify(kind) {
    for (const watcher of [...watchers[kind]]) watcher();
  }

  function setLive(live) {
    const badge = document.getElementById('live');
    if (!badge) return;
    badge.dataset.live = live ? 'on' : 'off';
    badge.lastChild.textContent = live ? 'Live' : 'Offline';
  }

  function dispatch(message) {
    let parsed;
    try {
      parsed = JSON.parse(message.data);
    } catch {
      return;
    }
    for (const handler of [...(handlers.get(parsed.event) || [])]) handler(parsed.data || {});
  }

  async function reconnect() {
    if (!wanted) return;
    try {
      await rpc('system.info');
    } catch (failure) {
      if (failure.code === 'unauthorized') return;
      schedule();
      return;
    }
    connect();
  }

  function schedule() {
    retry = Math.min(retry + 1, 5);
    timer = setTimeout(reconnect, 500 * 2 ** retry);
  }

  function connect() {
    clearTimeout(timer);
    if (!wanted || socket) return;
    const scheme = location.protocol === 'https:' ? 'wss:' : 'ws:';
    const current = new WebSocket(`${scheme}//${location.host}/api/events`);
    socket = current;
    current.addEventListener('open', () => {
      retry = 0;
      setLive(true);
      if (opened) notify('reopen');
      opened = true;
    });
    current.addEventListener('message', (message) => {
      if (socket === current) dispatch(message);
    });
    current.addEventListener('close', () => {
      if (socket !== current) return;
      socket = null;
      setLive(false);
      notify('drop');
      if (wanted) schedule();
    });
  }

  return {
    async start() {
      wanted = true;
      opened = false;
      connect();
      const current = socket;
      if (current.readyState === WebSocket.OPEN) return;
      return new Promise((resolve, reject) => {
        const onOpen = () => finish();
        const onClose = () => finish(new ApiError('network', 'the events connection closed before it was ready'));
        const timer = setTimeout(
          () => finish(new ApiError('no_reply', 'the events connection did not open')),
          SHORT_TIMEOUT_MS,
        );
        function finish(failure) {
          clearTimeout(timer);
          current.removeEventListener('open', onOpen);
          current.removeEventListener('close', onClose);
          if (failure) reject(failure);
          else resolve();
        }
        current.addEventListener('open', onOpen);
        current.addEventListener('close', onClose);
      });
    },
    stop() {
      wanted = false;
      clearTimeout(timer);
      const current = socket;
      socket = null;
      if (current) current.close();
    },
    on(name, handler) {
      if (!handlers.has(name)) handlers.set(name, new Set());
      handlers.get(name).add(handler);
      return () => handlers.get(name).delete(handler);
    },
    watch(kind, watcher) {
      watchers[kind].add(watcher);
      return () => watchers[kind].delete(watcher);
    },
  };
})();

const jobs = (() => {
  const waiting = new Map();
  const early = new Map();
  let epoch = 0;

  const lost = () => new ApiError('job_lost', '');

  function forget() {
    const cutoff = Date.now() - JOB_MEMORY_MS;
    for (const [id, entry] of early) if (entry.at < cutoff) early.delete(id);
  }

  async function outcome(data) {
    if (data.error) throw apiError(data.error);
    if (!data.result || typeof data.result !== 'object' || Array.isArray(data.result)) {
      throw new ApiError('http', 'The board sent an invalid job result. Check the result before retrying.');
    }
    return data.result;
  }

  events.on('job.done', (data) => {
    if (!data || typeof data.job !== 'string') return;
    const waiter = waiting.get(data.job);
    if (!waiter) {
      forget();
      early.set(data.job, { data, at: Date.now() });
      return;
    }
    waiting.delete(data.job);
    clearTimeout(waiter.timer);
    outcome(data).then(waiter.resolve, waiter.reject);
  });

  events.watch('drop', () => {
    epoch += 1;
    for (const waiter of waiting.values()) {
      clearTimeout(waiter.timer);
      waiter.reject(lost());
    }
    waiting.clear();
  });

  return {
    epoch: () => epoch,
    reset() {
      epoch += 1;
      early.clear();
      for (const waiter of waiting.values()) {
        clearTimeout(waiter.timer);
        waiter.reject(new ApiError('session_changed'));
      }
      waiting.clear();
    },
    wait(id, timeoutMs, sentEpoch) {
      const done = early.get(id);
      if (done) {
        early.delete(id);
        return outcome(done.data);
      }
      if (sentEpoch !== epoch) return Promise.reject(lost());
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          waiting.delete(id);
          reject(new ApiError('no_reply', 'the board did not report the result of the job'));
        }, timeoutMs);
        waiting.set(id, { resolve, reject, timer });
      });
    },
  };
})();

function listen(name, handler) {
  cleanups.push(events.on(name, handler));
}

function toast(message, { error = false, warning = false, alarm = false, detail = null } = {}) {
  const kind = alarm ? ' toast-alarm' : error ? ' toast-error' : warning ? ' toast-warning' : '';
  const loud = error || warning || alarm;
  const item = h(
    'div',
    { class: `toast${kind}`, role: loud ? 'alert' : null },
    icon(loud ? 'alert' : 'check'),
    h('div', { class: 'toast-body' }, h('strong', null, message), detail ? h('span', null, detail) : null),
    h(
      'button',
      { class: 'icon-button', type: 'button', 'aria-label': 'Dismiss', onclick: () => item.remove() },
      icon('x'),
    ),
  );
  toasts.append(item);
  if (!warning && !alarm) setTimeout(() => item.remove(), error ? ERROR_TOAST_MS : TOAST_MS);
}

const STORED_WARNING_TEXT = {
  watch_state_unreadable: 'The saved operation-log cursor could not be read. Some events may have been missed.',
  alerts_unreadable: 'Alerts stored before this could not be read and are lost.',
};

function alertText(data) {
  const lock = state.locks.find((item) => item.id === data.lock);
  const name = lock ? lock.name : data.lock;
  if (data.method === 'forced') return `${name} was forced open`;
  const how = METHOD_TEXT[data.method];
  return how ? `${name} was unlocked ${how}, and not by Latchkey` : `${name} was unlocked, and not by Latchkey`;
}

events.on('lock.alert', (data) => {
  if (!data || typeof data.lock !== 'string') return;
  toast(alertText(data), {
    alarm: true,
    detail: `${formatTime(data.time)}, read from the lock's log. Check who can open it.`,
  });
});

function showWarning(result) {
  if (result && typeof result.warning === 'string' && result.warning) {
    toast('Done, with a warning', { warning: true, detail: capitalize(result.warning) });
  }
}

function toastError(failure) {
  toast(errorText(failure), { error: true, detail: errorDetail(failure) });
}

function errorBlock(failure, retry) {
  return h(
    'div',
    { class: 'alert', role: 'alert' },
    h('p', null, errorText(failure)),
    errorDetail(failure) ? h('p', { class: 'detail' }, errorDetail(failure)) : null,
    retry ? h('button', { class: 'button small', type: 'button', onclick: retry }, icon('refresh'), 'Retry') : null,
  );
}

function showError(target, failure) {
  target.replaceChildren(
    h('span', null, errorText(failure)),
    errorDetail(failure) ? h('span', { class: 'detail' }, ` ${errorDetail(failure)}`) : '',
  );
  target.hidden = false;
}

async function pending(button, work) {
  button.disabled = true;
  button.classList.add('is-pending');
  try {
    return await work();
  } finally {
    button.disabled = false;
    button.classList.remove('is-pending');
  }
}

const FOCUSABLE =
  'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled])';

function trapFocus(event) {
  if (event.key !== 'Tab') return;
  const items = [...event.currentTarget.querySelectorAll(FOCUSABLE)].filter((el) => !el.closest('[hidden]'));
  if (!items.length) return;
  const first = items[0];
  const last = items[items.length - 1];
  if (event.shiftKey && document.activeElement === first) {
    event.preventDefault();
    last.focus();
  } else if (!event.shiftKey && document.activeElement === last) {
    event.preventDefault();
    first.focus();
  }
}

function openDialog(title, build, { className = '', onClose, focus = null } = {}) {
  const titleId = uid('dialog');
  const dialog = h(
    'dialog',
    { class: `dialog ${className}`, 'aria-labelledby': titleId },
    h('h2', { id: titleId }, title),
  );
  const restore = document.activeElement;
  dialog.addEventListener('keydown', trapFocus);
  dialog.addEventListener('close', () => {
    dialog.remove();
    if (onClose) onClose();
    if (restore && restore.isConnected && typeof restore.focus === 'function') restore.focus();
  });
  build(dialog);
  document.body.append(dialog);
  dialog.showModal();
  const target = focus || dialog.querySelector(FOCUSABLE);
  if (target) target.focus();
  return dialog;
}

function closeDialogs() {
  for (const dialog of document.querySelectorAll('dialog[open]')) dialog.close();
}

function formDialog(title, { intro, fields = [], submit, danger = false, onSubmit }) {
  return new Promise((resolve) => {
    let finished = false;
    const error = h('p', { class: 'form-error', role: 'alert', hidden: true });
    const submitButton = h('button', { class: `button ${danger ? 'danger' : 'primary'}`, type: 'submit' }, submit);
    let dialog = null;
    const form = h(
      'form',
      { class: 'stack' },
      intro ? h('p', { class: 'muted' }, intro) : null,
      fields,
      error,
      h(
        'div',
        { class: 'actions' },
        h('button', { class: 'button', type: 'button', onclick: () => dialog.close() }, 'Cancel'),
        submitButton,
      ),
    );
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      error.hidden = true;
      try {
        const result = await pending(submitButton, () => onSubmit(form));
        finished = true;
        dialog.close();
        resolve(result === undefined ? true : result);
      } catch (failure) {
        if (!dialog.open) return;
        showError(error, failure);
      }
    });
    dialog = openDialog(title, (box) => box.append(form), {
      onClose: () => {
        if (!finished) resolve(null);
      },
    });
  });
}

function confirmDialog(title, message, action, { danger = true, typed = null } = {}) {
  const fields = [];
  if (typed) {
    const input = h('input', { type: 'text', required: true, autocomplete: 'off', spellcheck: 'false' });
    input.pattern = typed.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    fields.push(field(`Type ${typed} to confirm`, input));
  }
  return formDialog(title, { intro: message, fields, submit: action, danger, onSubmit: async () => true });
}

const ONCE_NOTE = 'It will not be shown again. Write it down or store it in a password manager now.';

function secretDialog(title, { intro, secret, label, extra = null, long = false, note = ONCE_NOTE }) {
  openDialog(title, (dialog) =>
    dialog.append(
      h(
        'div',
        { class: 'stack' },
        intro ? h('p', null, intro) : null,
        h('output', { class: `secret${long ? ' long' : ''}`, 'aria-label': label }, secret),
        extra,
        h('p', { class: 'muted' }, note),
        h(
          'div',
          { class: 'actions' },
          h('button', { class: 'button primary', type: 'button', onclick: () => dialog.close() }, 'Done'),
        ),
      ),
    ),
  );
}

function field(label, control, hint) {
  if (!control.id) control.id = uid('field');
  let hintEl = null;
  if (hint) {
    hintEl = h('p', { class: 'hint', id: `${control.id}-hint` }, hint);
    control.setAttribute('aria-describedby', hintEl.id);
  }
  return h('div', { class: 'field' }, h('label', { for: control.id }, label), control, hintEl);
}

function checkField(label, control) {
  return h('label', { class: 'check' }, control, h('span', null, label));
}

function switchControl(label, checked, onChange) {
  const input = h('input', { type: 'checkbox', role: 'switch', checked });
  input.disabled = !onChange;
  if (onChange) input.addEventListener('change', () => onChange(input.checked, input));
  return h('label', { class: 'switch' }, input, h('span', null, label));
}

function heading(view, text, actions = [], beside = null) {
  const title = h('h1', { tabindex: '-1' }, text);
  view.append(
    h(
      'div',
      { class: 'view-head' },
      h('div', { class: 'view-title' }, title, beside),
      actions.length ? h('div', { class: 'view-actions' }, actions) : null,
    ),
  );
  return title;
}

function section(title, iconName, actions = [], className = '') {
  const id = uid('section');
  const body = h('div', { class: 'section-body stack' });
  const el = h(
    'section',
    { class: `card ${className}`, 'aria-labelledby': id },
    h(
      'div',
      { class: 'section-head' },
      h('h2', { id }, iconName ? icon(iconName) : null, h('span', null, title)),
      actions.length ? h('div', { class: 'section-actions' }, actions) : null,
    ),
    body,
  );
  return { el, body };
}

async function load(target, work) {
  target.setAttribute('aria-busy', 'true');
  target.replaceChildren(h('p', { class: 'muted' }, 'Loading…'));
  try {
    await work();
  } catch (failure) {
    if (failure.code === 'unauthorized') return;
    target.replaceChildren(errorBlock(failure, () => load(target, work)));
  } finally {
    target.removeAttribute('aria-busy');
  }
}

function facts(rows) {
  return h(
    'dl',
    { class: 'facts' },
    rows.filter(Boolean).map(([term, value]) => [h('dt', null, term), h('dd', null, value ?? '—')]),
  );
}

function base64Bytes(text) {
  return Uint8Array.from(atob(text), (char) => char.charCodeAt(0));
}

function bytesBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}

function download(bytes, filename) {
  const url = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }));
  const host = [...document.querySelectorAll('dialog[open]')].pop() || document.body;
  const link = h('a', { href: url, download: filename, hidden: true });
  host.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 30000);
}

const boardButton = (() => {
  let dialog = null;
  let statusLine = null;
  let action = null;
  let ticker = 0;
  let closer = 0;

  function close() {
    clearInterval(ticker);
    clearTimeout(closer);
    const open = dialog;
    dialog = null;
    action = null;
    if (open && open.open) open.close();
  }

  function show(data) {
    close();
    action = data.action;
    const total = Number(data.timeoutMs) > 0 ? Number(data.timeoutMs) : 30000;
    const deadline = Date.now() + total;
    const countdown = h('span', { class: 'countdown', role: 'timer' });
    const meter = h('progress', { max: String(total), value: String(total), 'aria-hidden': 'true' });
    const status = h('p', null, 'Press it within ', countdown, ' to confirm you are next to the board.');
    const hide = h('button', { class: 'button', type: 'button', onclick: () => current.close() }, 'Hide');
    const tick = () => {
      const left = Math.max(0, deadline - Date.now());
      countdown.textContent = `${Math.ceil(left / 1000)} s`;
      meter.value = left;
    };
    const current = openDialog(
      'Press the button on the board',
      (box) =>
        box.append(
          h(
            'div',
            { class: 'stack' },
            h('div', { class: 'press' }, icon('button')),
            h('p', { class: 'press-action' }, ACTION_TEXT[action] || action),
            status,
            meter,
            h(
              'p',
              { class: 'muted small' },
              'Nothing changes until the button is pressed. Hiding this does not cancel the request.',
            ),
            h('div', { class: 'actions' }, hide),
          ),
        ),
      {
        className: 'centered',
        focus: hide,
        onClose: () => {
          if (dialog === current) {
            clearInterval(ticker);
            clearTimeout(closer);
            dialog = null;
            action = null;
          }
        },
      },
    );
    dialog = current;
    statusLine = status;
    tick();
    ticker = setInterval(tick, 250);
  }

  function result(data) {
    if (!dialog || data.action !== action) return;
    if (!data.confirmed) {
      close();
      return;
    }
    clearInterval(ticker);
    dialog.classList.add('confirmed');
    statusLine.replaceChildren('Confirmed. Working on it…');
    closer = setTimeout(close, 700);
  }

  function settle(method) {
    if (dialog && action === method) close();
  }

  events.on('confirm.required', show);
  events.on('confirm.result', result);
  return { settle, close };
})();

function enrolModal(kind, lockId) {
  const info = CREDENTIALS[kind];
  const status = h('p', { 'aria-live': 'polite' }, 'Waiting for the lock…');
  const count = h('p', { class: 'countdown' });
  const bar = h('progress', { max: '1', value: '0', 'aria-label': 'Enrolment progress' });
  const error = h('div', { class: 'alert', role: 'alert', hidden: true });
  let dialog = null;
  const closeButton = h('button', { class: 'button', type: 'button', onclick: () => dialog.close() }, 'Hide');
  dialog = openDialog(
    `Enrolling ${info.noun}`,
    (box) =>
      box.append(
        h(
          'div',
          { class: 'stack' },
          h('div', { class: 'press' }, icon(info.icon)),
          h('p', { class: 'press-action' }, info.instruction),
          bar,
          count,
          status,
          error,
          h('div', { class: 'actions' }, closeButton),
        ),
      ),
    { className: 'centered', onClose: () => off() },
  );
  const off = events.on('enroll.progress', (data) => {
    if (data.lock !== lockId || data.kind !== kind) return;
    if (data.stage === 'waiting') {
      status.textContent =
        kind === 'fingerprint' ? 'Place your finger on the sensor.' : 'Hold the card against the lock.';
    } else if (data.stage === 'progress') {
      bar.max = data.total || 1;
      bar.value = data.scans || 0;
      count.textContent = `Scan ${data.scans} of ${data.total}`;
      status.textContent =
        data.scans < data.total ? 'Lift your finger, then place it again.' : 'Keep still while the lock saves it…';
    } else if (data.stage === 'added') {
      bar.value = bar.max;
      status.textContent = `${info.Noun} added.`;
    }
  });
  return {
    done() {
      off();
      bar.value = bar.max;
      status.textContent = `${info.Noun} added.`;
      dialog.classList.add('confirmed');
      setTimeout(() => {
        if (dialog.open) dialog.close();
      }, 800);
    },
    fail(failure) {
      off();
      status.textContent = 'Enrolment failed.';
      showError(error, failure);
      closeButton.textContent = 'Close';
    },
  };
}

function sessionLost() {
  state.authed = false;
  events.stop();
  showLogin(ERROR_TEXT.unauthorized);
}

function loginErrorText(failure) {
  if (failure.code === 'unauthorized') return 'Wrong password or code.';
  if (failure.code === 'rate_limited') {
    const wait = failure.extra.retryAfter;
    return wait ? `Too many attempts. Wait ${wait} s and try again.` : ERROR_TEXT.rate_limited;
  }
  return errorText(failure);
}

function showLogin(message) {
  sessionEpoch += 1;
  renderSeq += 1;
  state.authed = false;
  state.info = null;
  state.locks = [];
  jobs.reset();
  for (const fn of cleanups.splice(0)) fn();
  closeDialogs();
  const error = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const password = h('input', { type: 'password', name: 'password', autocomplete: 'current-password', required: true });
  const code = h('input', {
    type: 'text',
    name: 'totp',
    inputmode: 'numeric',
    autocomplete: 'one-time-code',
    pattern: '[0-9]{6}',
    maxlength: '6',
    required: true,
  });
  const submit = h('button', { class: 'button primary wide', type: 'submit' }, 'Sign in');
  const form = h(
    'form',
    { class: 'stack' },
    field('Password', password),
    field('Authenticator code', code, 'The six digits from your authenticator app.'),
    error,
    submit,
  );
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    error.hidden = true;
    try {
      await pending(submit, () => call('auth.login', { password: password.value, totp: code.value }));
    } catch (failure) {
      error.textContent = loginErrorText(failure);
      error.hidden = false;
      code.value = '';
      (failure.code === 'unauthorized' ? password : code).focus();
      return;
    }
    password.value = '';
    code.value = '';
    await boot();
  });
  app.replaceChildren(
    h(
      'main',
      { id: 'main', class: 'login', tabindex: '-1' },
      h(
        'div',
        { class: 'login-card' },
        h('div', { class: 'brand' }, icon('key'), h('span', null, 'Latchkey')),
        h('h1', null, 'Sign in'),
        message ? h('p', { class: 'notice' }, message) : null,
        form,
        h(
          'p',
          { class: 'muted small' },
          'Only the owner can sign in. The board was claimed over USB; to recover a lost password or authenticator, reset the board over USB.',
        ),
      ),
    ),
  );
  password.focus();
}

function navLink(href, iconName, text) {
  return h('a', { class: 'nav-link', href, 'data-nav': href }, icon(iconName), h('span', null, text));
}

function renderShell() {
  const main = h('main', { id: 'main', tabindex: '-1' });
  app.replaceChildren(
    h('button', { class: 'button skip', type: 'button', onclick: () => main.focus() }, 'Skip to content'),
    h(
      'header',
      { class: 'topbar' },
      h('a', { class: 'brand', href: '#/locks' }, icon('key'), h('span', null, 'Latchkey')),
      h(
        'nav',
        { class: 'main-nav', 'aria-label': 'Main' },
        navLink('#/locks', 'lock', 'Locks'),
        navLink('#/security', 'shield', 'Security'),
        navLink('#/system', 'chip', 'System'),
      ),
      h(
        'div',
        { class: 'topbar-end' },
        h(
          'span',
          { id: 'live', class: 'live', 'data-live': 'off' },
          h('span', { class: 'dot', 'aria-hidden': 'true' }),
          h('span', null, 'Offline'),
        ),
        h(
          'button',
          { class: 'button ghost small', type: 'button', onclick: () => signOut(false) },
          icon('logout'),
          h('span', null, 'Sign out'),
        ),
      ),
    ),
    main,
  );
}

async function signOut(everywhere) {
  try {
    await call('auth.logout', everywhere ? { all: true } : {});
  } catch (failure) {
    if (failure.code !== 'unauthorized') {
      toastError(failure);
      return;
    }
  }
  state.authed = false;
  events.stop();
  showLogin(everywhere ? 'Every session was signed out.' : 'Signed out.');
}

async function startApp() {
  state.info = await call('system.info');
  state.authed = true;
  renderShell();
  await events.start();
  await route();
}

const ROUTES = [
  [/^#\/locks$/, viewLocks],
  [/^#\/pair$/, viewPair],
  [/^#\/lock\/([^/]+)(?:\/(access|settings|log|device))?$/, viewLock],
  [/^#\/security$/, viewSecurity],
  [/^#\/system$/, viewSystem],
];

async function route({ keepDialogs = false } = {}) {
  if (!state.authed) return;
  for (const fn of cleanups.splice(0)) fn();
  if (!keepDialogs) closeDialogs();
  const hash = location.hash || '#/locks';
  const found = ROUTES.map(([pattern, view]) => [hash.match(pattern), view]).find(([match]) => match);
  if (!found) {
    location.replace('#/locks');
    return;
  }
  const [match, view] = found;
  const seq = ++renderSeq;
  const top = `#/${hash.split('/')[1]}`;
  for (const link of document.querySelectorAll('[data-nav]')) {
    const current =
      link.dataset.nav === top ||
      (top === '#/lock' && link.dataset.nav === '#/locks') ||
      (top === '#/pair' && link.dataset.nav === '#/locks');
    if (current) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  }
  const main = document.getElementById('main');
  const container = h('div', { class: 'view' });
  main.replaceChildren(container);
  const work = view(container, ...match.slice(1).map((part) => (part ? decodeURIComponent(part) : part)));
  const title = container.querySelector('h1');
  if (title) title.focus({ preventScroll: true });
  try {
    await work;
  } catch (failure) {
    if (seq !== renderSeq || failure.code === 'unauthorized') return;
    if (!(failure instanceof ApiError)) throw failure;
    container.append(errorBlock(failure, () => route()));
  }
}

function lockStateText(value) {
  return value === 'locked' ? 'Locked' : value === 'unlocked' ? 'Unlocked' : 'Unknown';
}

function eventText(event) {
  const verb =
    event.action === 'unlock' ? 'Unlocked' : event.action === 'lock' ? 'Locked' : capitalize(event.action || 'Event');
  const how = METHOD_TEXT[event.method] || (event.method ? `by ${event.method}` : '');
  return [verb, how, event.name ? `(${event.name})` : ''].filter(Boolean).join(' ');
}

function lockControls(lock, onChange) {
  const pill = h('span', { class: 'pill' });
  const glyph = h('span', { class: 'glyph' });
  const battery = h('span', { class: 'battery' });
  const unlock = h('button', { class: 'button big', type: 'button' }, icon('unlock'), 'Unlock');
  const relock = h('button', { class: 'button big', type: 'button' }, icon('lock'), 'Lock');
  const last = h('p', { class: 'muted small' });
  let heardAt = 0;

  function paint() {
    pill.className = `pill ${lock.state || 'unknown'}`;
    pill.textContent = lockStateText(lock.state);
    glyph.className = `glyph ${lock.state || 'unknown'}`;
    glyph.replaceChildren(icon(lock.state === 'unlocked' ? 'unlock' : 'lock'));
    battery.textContent =
      typeof lock.battery === 'number' && lock.battery >= 0 ? `${lock.battery}%` : 'battery unknown';
    battery.classList.toggle('low', lock.battery >= 0 && lock.battery < 20);
    unlock.className = `button big${lock.state === 'unlocked' ? '' : ' primary'}`;
    relock.className = `button big${lock.state === 'unlocked' ? ' primary' : ''}`;
    last.textContent = lock.lastEvent ? `${eventText(lock.lastEvent)} · ${ago(lock.lastEvent.time)}` : 'No events yet';
    if (onChange) onChange(lock);
  }

  async function operate(action, button) {
    const sentAt = performance.now();
    try {
      const result = await pending(button, () => rpc(`lock.${action}`, { lock: lock.id }));
      if (heardAt < sentAt) {
        lock.state = result.state || (action === 'unlock' ? 'unlocked' : 'locked');
        if (typeof result.battery === 'number') lock.battery = result.battery;
        paint();
      }
      toast(`${lock.name} ${action === 'unlock' ? 'unlocked' : 'locked'}`);
    } catch (failure) {
      toastError(failure);
    }
  }

  unlock.addEventListener('click', () => operate('unlock', unlock));
  relock.addEventListener('click', () => operate('lock', relock));
  listen('lock.state', (data) => {
    if (data.lock !== lock.id) return;
    heardAt = performance.now();
    if (data.state) lock.state = data.state;
    if (typeof data.battery === 'number') lock.battery = data.battery;
    paint();
  });
  listen('lock.event', (data) => {
    if (data.lock !== lock.id) return;
    lock.lastEvent = { ...data, time: data.time || Math.floor(Date.now() / 1000) };
    paint();
  });
  paint();
  return { pill, glyph, battery, last, actions: h('div', { class: 'lock-actions' }, unlock, relock) };
}

async function viewLocks(view) {
  heading(view, 'Locks', [h('a', { class: 'button primary', href: '#/pair' }, icon('plus'), 'Add lock')]);
  const grid = h('div', { class: 'lock-grid', 'aria-busy': 'true' }, h('p', { class: 'muted' }, 'Loading…'));
  view.append(grid);
  let locks;
  try {
    ({ locks = [] } = await rpc('locks.list'));
  } finally {
    grid.removeAttribute('aria-busy');
  }
  state.locks = locks;
  if (!locks.length) {
    grid.replaceChildren(
      h(
        'div',
        { class: 'card empty' },
        h('p', null, 'No locks yet. Pair a factory-fresh lock to start.'),
        h('p', null, h('a', { class: 'button primary', href: '#/pair' }, icon('plus'), 'Add lock')),
      ),
    );
    return;
  }
  grid.replaceChildren(...locks.map(lockCard));
}

function lockCard(lock) {
  const nameId = uid('lock');
  const controls = lockControls(lock);
  const warnings = h('p', { class: 'warnings' });
  if (!lock.hardened) warnings.append(h('span', { class: 'badge warn' }, icon('alert'), 'Not hardened'));
  if (!lock.backedUp) warnings.append(h('span', { class: 'badge warn' }, icon('download'), 'No key backup'));
  if (lock.warnings.length) {
    warnings.append(
      h('span', { class: 'badge warn', title: lock.warnings.join(' ') }, icon('alert'), 'Monitoring warning'),
    );
  }
  const alerts = h('span', { class: 'badge warn' });
  warnings.append(alerts);
  function showAlertCount(count) {
    lock.alertCount = count;
    alerts.textContent = `${count} ${count === 1 ? 'alert' : 'alerts'}`;
    alerts.hidden = count === 0;
    warnings.hidden = lock.hardened && lock.backedUp && count === 0 && !lock.warnings.length;
  }
  showAlertCount(lock.alertCount);
  let alertGeneration = 0;
  async function reloadAlertCount() {
    const requested = ++alertGeneration;
    const result = await rpc('lock.alerts.list', { lock: lock.id });
    if (requested === alertGeneration) showAlertCount(result.alerts.length);
  }
  for (const name of ['lock.alert', 'lock.alerts.changed']) {
    listen(name, (data) => {
      if (data.lock === lock.id) reloadAlertCount().catch(toastError);
    });
  }
  return h(
    'article',
    { class: 'card lock-card', 'aria-labelledby': nameId },
    h(
      'div',
      { class: 'lock-card-head' },
      controls.glyph,
      h(
        'div',
        { class: 'lock-title' },
        h('h2', { id: nameId }, lock.name),
        h('p', { class: 'muted small' }, lock.model || 'Lock'),
      ),
      controls.pill,
    ),
    h('p', { class: 'muted small' }, 'Battery ', controls.battery, ` · seen ${ago(lock.lastSeen)}`),
    controls.last,
    warnings.childNodes.length ? warnings : null,
    controls.actions,
    h('a', { class: 'details', href: `#/lock/${encodeURIComponent(lock.id)}` }, 'Details', icon('next')),
  );
}

async function viewPair(view) {
  heading(view, 'Add a lock');
  const steps = ['Scan', 'Pair', 'Harden'].map((text) => h('li', null, text));
  const panel = h('section', { class: 'card stack', 'aria-label': 'Add a lock' });
  view.append(h('ol', { class: 'stepper' }, steps), panel);
  const setStep = (index) =>
    steps.forEach((item, i) => {
      item.classList.toggle('done', i < index);
      if (i === index) item.setAttribute('aria-current', 'step');
      else item.removeAttribute('aria-current');
    });
  setStep(0);
  try {
    ({ locks: state.locks = [] } = await rpc('locks.list'));
  } catch (failure) {
    if (failure.code === 'unauthorized') return;
  }

  const found = new Map();
  const legend = h('legend', null, 'Locks nearby');
  const none = h('p', { class: 'muted' }, 'No locks found yet.');
  const results = h('fieldset', { class: 'scan-results' }, legend, none);
  const status = h('p', { class: 'muted', 'aria-live': 'polite' }, 'Not scanning.');
  const scan = h('button', { class: 'button', type: 'button' }, icon('bluetooth'), 'Scan');
  const name = h('input', {
    type: 'text',
    maxlength: '32',
    required: true,
    autocomplete: 'off',
    placeholder: 'Front door',
  });
  const adminPasscode = codeInput();
  const pair = h('button', { class: 'button primary', type: 'submit', disabled: true }, 'Pair');
  const error = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const form = h(
    'form',
    { class: 'stack' },
    h(
      'p',
      null,
      "Touch the lock's keypad to wake it, keep the board within a few metres, then scan. Only a factory-fresh lock can be paired.",
    ),
    h('div', { class: 'row' }, scan, status),
    results,
    field('Name', name, 'Shown on the dashboard. You can change it later.'),
    field(
      'Super admin passcode (optional)',
      adminPasscode,
      'Four to nine digits that always open the lock from its keypad. Leave empty and the lock gets a random seven-digit code; you can show or change it later.',
    ),
    error,
    h('div', { class: 'actions' }, pair),
  );
  panel.append(form);

  function addResult(device) {
    if (!device || !device.mac) return;
    const known = state.locks.find((lock) => lock.id === device.lock || lock.mac === device.mac);
    const previous = found.get(device.mac);
    const input = h('input', { type: 'radio', name: 'device', value: device.mac, disabled: Boolean(device.paired) });
    const note = known
      ? `already added as ${known.name}`
      : device.paired
        ? 'paired to other keys: factory-reset it first'
        : 'factory-fresh, ready to pair';
    const item = h(
      'label',
      { class: `scan-item${device.paired ? ' is-disabled' : ''}` },
      input,
      h(
        'span',
        { class: 'scan-main' },
        h('strong', null, device.name || 'Unnamed lock'),
        h('span', { class: 'muted small' }, `${device.mac} · ${device.rssi ?? '?'} dBm · ${note}`),
      ),
    );
    input.addEventListener('change', () => {
      pair.disabled = false;
    });
    if (previous) {
      input.checked = previous.input.checked;
      previous.item.replaceWith(item);
    } else {
      results.append(item);
    }
    found.set(device.mac, { input, item });
    none.hidden = true;
  }

  listen('scan.result', addResult);
  let countdown = 0;
  cleanups.push(() => clearInterval(countdown));
  scan.addEventListener('click', async () => {
    error.hidden = true;
    try {
      const { seconds = 10 } = await pending(scan, () => rpc('locks.scan', { seconds: 10 }));
      let left = seconds;
      status.textContent = `Scanning, ${left} s left…`;
      clearInterval(countdown);
      countdown = setInterval(() => {
        left -= 1;
        status.textContent =
          left > 0
            ? `Scanning, ${left} s left…`
            : 'Scan finished. Touch the keypad and scan again if your lock is missing.';
        if (left <= 0) clearInterval(countdown);
      }, 1000);
    } catch (failure) {
      showError(error, failure);
    }
  });

  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    error.hidden = true;
    const chosen = form.querySelector('input[name="device"]:checked');
    const mac = chosen ? chosen.value : '';
    if (!mac) {
      showError(error, new Error('Pick a lock first.'));
      return;
    }
    setStep(1);
    try {
      const params = { mac, name: name.value.trim() };
      if (adminPasscode.value) params.adminPasscode = adminPasscode.value;
      const { lock } = await pending(pair, () => rpc('locks.pair', params));
      adminPasscode.value = '';
      state.locks.push(lock);
      setStep(2);
      panel.replaceChildren(hardeningPanel(lock, { title: `Harden ${lock.name}`, finish: true }));
    } catch (failure) {
      setStep(0);
      showError(error, failure);
    }
  });
}

function hardeningPanel(lock, { title, finish = false, onDone } = {}) {
  const rows = new Map();
  const items = HARDEN_ITEMS.map(([key, text]) => {
    const badge = h('span', { class: 'badge' }, STATUS_TEXT.pending);
    const detail = h('span', { class: 'muted small' });
    const item = h('li', { 'data-status': 'pending' }, h('span', { class: 'step-text' }, text, ' ', detail), badge);
    rows.set(key, { item, badge, detail });
    return item;
  });
  const mark = (key, status, text) => {
    const row = rows.get(key);
    if (!row) return;
    row.item.dataset.status = status;
    row.badge.textContent = STATUS_TEXT[status];
    if (text !== undefined) row.detail.textContent = text ? `(${text})` : '';
  };
  const markStep = (step) => mark(step.step, step.skipped ? 'skipped' : step.ok ? 'done' : 'failed', step.detail || '');
  if (lock.backedUp) mark('backup', 'done');

  const alert = h('div', { class: 'alert', role: 'alert', hidden: true });
  const exportButton = h('button', { class: 'button', type: 'button' }, icon('download'), 'Export keys…');
  const hardenButton = h('button', { class: 'button primary', type: 'button' }, icon('shield'), 'Harden lock');
  const done = h(
    'div',
    { class: 'success', hidden: true },
    icon('check'),
    h('p', null, h('strong', null, 'Lock hardened.'), ' Only Latchkey and the credentials you add here open it now.'),
    finish ? h('a', { class: 'button primary', href: '#/locks' }, 'Go to the locks') : null,
  );

  async function runExport() {
    const result = await exportKeysDialog(lock);
    if (!result) return;
    lock.backedUp = true;
    mark('backup', 'done');
    alert.hidden = true;
  }

  async function runHarden() {
    alert.hidden = true;
    for (const [key] of HARDEN_ITEMS) if (key !== 'backup') mark(key, 'pending', '');
    const off = events.on('harden.step', (data) => {
      if (data.lock === lock.id) markStep(data);
    });
    try {
      const { steps = [] } = await pending(hardenButton, () => rpc('lock.harden', { lock: lock.id }));
      for (const step of steps) markStep(step);
      lock.hardened = true;
      exportButton.hidden = true;
      hardenButton.hidden = true;
      done.hidden = false;
      if (onDone) onDone(lock);
    } catch (failure) {
      if (failure.code !== 'backup_required') {
        toastError(failure);
        return;
      }
      mark('backup', 'todo');
      alert.replaceChildren(
        h('p', null, errorText(failure)),
        h(
          'button',
          { class: 'button primary', type: 'button', onclick: runExport },
          icon('download'),
          'Export keys now',
        ),
      );
      alert.hidden = false;
    } finally {
      off();
    }
  }

  exportButton.addEventListener('click', runExport);
  hardenButton.addEventListener('click', runHarden);
  return h(
    'div',
    { class: 'stack' },
    title ? h('h2', null, title) : null,
    h(
      'p',
      null,
      'Hardening closes the doors a factory lock leaves open. The board asks for its button once, then runs every step.',
    ),
    h('ol', { class: 'checklist', 'aria-label': 'Hardening steps' }, items),
    alert,
    done,
    h('div', { class: 'row' }, exportButton, hardenButton),
  );
}

function exportKeysDialog(lock) {
  const passphrase = h('input', {
    type: 'password',
    minlength: '12',
    maxlength: '128',
    required: true,
    autocomplete: 'new-password',
  });
  const repeat = h('input', { type: 'password', required: true, autocomplete: 'new-password' });
  return formDialog('Export keys', {
    intro: lock
      ? `Saves the keys of ${lock.name} to a file encrypted with this passphrase. The board asks for its button.`
      : 'Saves the keys of every lock to a file encrypted with this passphrase. The board asks for its button.',
    fields: [
      field('Passphrase', passphrase, 'At least 12 characters. Without it nobody can open the file, you included.'),
      field('Repeat passphrase', repeat),
    ],
    submit: 'Export',
    onSubmit: async () => {
      if (passphrase.value !== repeat.value) throw new Error('The passphrases do not match.');
      const params = { passphrase: passphrase.value };
      if (lock) params.lock = lock.id;
      const result = await rpc('keys.export', params);
      passphrase.value = '';
      repeat.value = '';
      download(base64Bytes(result.backup || ''), `latchkey-backup-${localDate()}.lkb`);
      toast('Key backup saved', { detail: 'Keep the file and its passphrase in different places.' });
      return result;
    },
  });
}

function importKeysDialog() {
  const file = h('input', { type: 'file', accept: '.lkb,application/octet-stream', required: true });
  const passphrase = h('input', { type: 'password', required: true, autocomplete: 'off' });
  return formDialog('Import keys', {
    intro:
      'Restores locks from a backup made by keys.export, on this board or another one. The board asks for its button.',
    fields: [field('Backup file (.lkb)', file), field('Passphrase', passphrase)],
    submit: 'Import',
    onSubmit: async () => {
      const bytes = new Uint8Array(await file.files[0].arrayBuffer());
      const result = await rpc('keys.import', { passphrase: passphrase.value, backup: bytesBase64(bytes) });
      passphrase.value = '';
      const count = (result.imported || []).length;
      toast(count === 1 ? 'Imported 1 lock' : `Imported ${count} locks`);
      return result;
    },
  });
}

async function viewLock(view, lockId, tab = 'access') {
  view.append(h('a', { class: 'back', href: '#/locks' }, icon('back'), 'All locks'));
  const rename = h(
    'button',
    { class: 'icon-button', type: 'button', 'aria-label': 'Rename', disabled: true },
    icon('edit'),
  );
  const title = heading(view, 'Lock', [], rename);
  const head = h('div', { class: 'card lock-head', 'aria-busy': 'true' }, h('p', { class: 'muted' }, 'Loading…'));
  view.append(head);
  let lock;
  let features;
  try {
    const [list, reported] = await Promise.all([rpc('locks.list'), rpc('lock.features', { lock: lockId })]);
    state.locks = list.locks || [];
    lock = state.locks.find((item) => item.id === lockId);
    features = new Set(reported.features || []);
  } catch (failure) {
    if (failure.code === 'unauthorized') return;
    head.replaceChildren(errorBlock(failure), h('a', { class: 'button', href: '#/locks' }, 'Back to the locks'));
    return;
  } finally {
    head.removeAttribute('aria-busy');
  }
  if (!lock) {
    head.replaceChildren(h('p', null, 'This lock is not paired with the board.'));
    return;
  }
  title.textContent = lock.name;
  rename.disabled = false;
  rename.addEventListener('click', async () => {
    const input = h('input', { type: 'text', maxlength: '32', required: true, value: lock.name, autocomplete: 'off' });
    const result = await formDialog('Rename lock', {
      fields: [field('Name', input)],
      submit: 'Save',
      onSubmit: () => rpc('locks.rename', { lock: lock.id, name: input.value.trim() }),
    });
    if (result && result.lock) {
      lock.name = result.lock.name;
      title.textContent = lock.name;
      toast('Lock renamed');
    }
  });

  const controls = lockControls(lock);
  head.replaceChildren(
    controls.glyph,
    h(
      'div',
      { class: 'lock-facts' },
      h('p', null, controls.pill, ' ', h('span', { class: 'muted' }, 'Battery '), controls.battery),
      controls.last,
      h('p', { class: 'muted small' }, `${lock.model || 'Lock'} · ${lock.mac} · seen ${ago(lock.lastSeen)}`),
    ),
    controls.actions,
  );
  await renderAlerts(view, lock);
  const base = `#/lock/${encodeURIComponent(lock.id)}`;
  const tabs = [
    ['access', 'Access'],
    ['settings', 'Settings'],
    ['log', 'Log'],
    ['device', 'Device'],
  ];
  view.append(
    h(
      'nav',
      { class: 'tabs', 'aria-label': 'Lock sections' },
      tabs.map(([key, text]) =>
        h('a', { class: 'tab', href: `${base}/${key}`, 'aria-current': key === tab ? 'page' : null }, text),
      ),
    ),
  );
  const panel = h('div', { class: 'panel' });
  view.append(panel);
  const has = (name) => features.has(name);
  if (tab === 'access') await renderAccess(panel, lock, has);
  else if (tab === 'settings') await renderSettings(panel, lock, has);
  else if (tab === 'log') await renderLog(panel, lock);
  else await renderDevice(panel, lock, features);
}

async function renderAlerts(view, lock) {
  const acknowledge = h('button', { class: 'button small', type: 'button', disabled: true }, 'Acknowledge alerts');
  const part = section('Alerts', 'alert', [acknowledge]);
  part.el.setAttribute('aria-busy', 'true');
  view.append(part.el);
  let through = 0;
  let generation = 0;
  async function load() {
    const requested = ++generation;
    const result = await rpc('lock.alerts.list', { lock: lock.id });
    if (requested !== generation || !part.el.isConnected) return;
    through = Math.max(0, ...result.alerts.map((alert) => alert.id));
    acknowledge.disabled = through === 0;
    part.body.replaceChildren(
      ...result.warnings.map((warning) => h('p', { class: 'notice', role: 'status' }, warning)),
      result.alerts.length
        ? h(
            'ul',
            null,
            result.alerts.map((alert) =>
              h(
                'li',
                null,
                STORED_WARNING_TEXT[alert.kind] ||
                  `${alertText({ ...alert, lock: lock.id })} - ${formatTime(alert.time)}`,
              ),
            ),
          )
        : h('p', { class: 'muted' }, 'No unacknowledged alerts.'),
    );
  }
  acknowledge.addEventListener('click', async () => {
    acknowledge.disabled = true;
    try {
      await rpc('lock.alerts.ack', { lock: lock.id, through });
      await load();
    } catch (failure) {
      toastError(failure);
      acknowledge.disabled = through === 0;
    }
  });
  for (const event of ['lock.alert', 'lock.alerts.changed']) {
    listen(event, (data) => {
      if (data.lock === lock.id) load().catch(toastError);
    });
  }
  try {
    await load();
  } catch (failure) {
    part.body.replaceChildren(errorBlock(failure));
  } finally {
    part.el.removeAttribute('aria-busy');
  }
}

function validityText(validity) {
  if (!validity) return 'Permanent';
  return `${formatTime(validity.start)} to ${formatTime(validity.end)}`;
}

function dayNames(days) {
  const key = [...days].sort((a, b) => a - b).join(',');
  if (key === '1,2,3,4,5') return 'Weekdays';
  if (key === '6,7') return 'Weekends';
  if (key === '1,2,3,4,5,6,7') return 'Every day';
  return [...days]
    .sort((a, b) => a - b)
    .map((day) => WEEKDAYS[day - 1])
    .join(', ');
}

function scheduleText(days, start, end) {
  return days.length ? `${dayNames(days)} ${start}-${end}` : 'No day picked yet';
}

function cycleText(cycle) {
  return scheduleText(cycle.days || [], cycle.start, cycle.end);
}

function zoneLabel(offsetMinutes) {
  const magnitude = Math.abs(offsetMinutes);
  return `UTC${offsetMinutes < 0 ? '-' : '+'}${pad(Math.floor(magnitude / 60))}:${pad(magnitude % 60)}`;
}

function zoneHint() {
  const here = zoneLabel(-new Date().getTimezoneOffset());
  const local = state.info && typeof state.info.localTime === 'string' ? state.info.localTime : '';
  const board = /[+-]\d\d:\d\d$/.test(local) ? `UTC${local.slice(-6)}` : null;
  const named = state.info && state.info.timezone ? ` (${state.info.timezone})` : '';
  if (!board) return `Dates and times are in this device's time zone, ${here}.`;
  if (board === here)
    return `Dates and times are in this device's time zone, ${here}, the same as the board's${named}.`;
  return `Dates and times are in this device's time zone, ${here}. The board keeps ${board}${named}, and the lock follows the board.`;
}

function codeInput(props = {}) {
  return h('input', {
    type: 'text',
    class: 'masked',
    inputmode: 'numeric',
    pattern: '[0-9]{4,9}',
    maxlength: '9',
    autocomplete: 'off',
    autocorrect: 'off',
    autocapitalize: 'off',
    spellcheck: 'false',
    'data-1p-ignore': true,
    'data-lpignore': 'true',
    ...props,
  });
}

function readWindow(from, until) {
  const start = fromLocalInput(from.value);
  const end = fromLocalInput(until.value);
  if (start === null || end === null) throw new Error('Set both the start and the end.');
  if (end <= start) throw new Error('The end must be after the start.');
  return { start, end };
}

function windowFields(validity, defaultHours) {
  const now = Math.floor(Date.now() / 1000 / 60) * 60;
  const from = h('input', { type: 'datetime-local', value: toLocalInput(validity ? validity.start : now) });
  const until = h('input', {
    type: 'datetime-local',
    value: toLocalInput(validity ? validity.end : now + defaultHours * 3600),
  });
  return {
    from,
    until,
    group: h(
      'div',
      { class: 'stack' },
      h('div', { class: 'field-group' }, field('Valid from', from), field('Valid until', until)),
      h('p', { class: 'hint' }, zoneHint()),
    ),
  };
}

function weeklyEditor(cycle) {
  const selected = new Set(cycle ? cycle.days : [1, 2, 3, 4, 5]);
  const from = h('input', { type: 'time', value: cycle ? cycle.start : '08:00', required: true });
  const until = h('input', { type: 'time', value: cycle ? cycle.end : '18:00', required: true });
  const summary = h('p', { class: 'summary', 'aria-live': 'polite' });
  const toggles = WEEKDAYS.map((day, index) =>
    h('button', { class: 'day-toggle', type: 'button', 'aria-label': WEEKDAY_NAMES[index] }, day),
  );
  function refresh() {
    toggles.forEach((button, index) => button.setAttribute('aria-pressed', String(selected.has(index + 1))));
    summary.textContent = scheduleText([...selected], from.value, until.value);
  }
  function pick(days) {
    selected.clear();
    days.forEach((day) => selected.add(day));
    refresh();
  }
  toggles.forEach((button, index) =>
    button.addEventListener('click', () => {
      if (selected.has(index + 1)) selected.delete(index + 1);
      else selected.add(index + 1);
      refresh();
    }),
  );
  const weekdays = h(
    'button',
    { class: 'button small', type: 'button', onclick: () => pick([1, 2, 3, 4, 5]) },
    'Weekdays',
  );
  const everyDay = h(
    'button',
    { class: 'button small', type: 'button', onclick: () => pick([1, 2, 3, 4, 5, 6, 7]) },
    'Every day',
  );
  from.addEventListener('input', refresh);
  until.addEventListener('input', refresh);
  refresh();
  return {
    el: h(
      'div',
      { class: 'stack weekly' },
      h('div', { class: 'day-toggles', role: 'group', 'aria-label': 'Days' }, toggles),
      h('div', { class: 'row' }, weekdays, everyDay),
      h('div', { class: 'field-group' }, field('From', from), field('Until', until)),
      summary,
    ),
    read() {
      const days = [...selected].sort((a, b) => a - b);
      if (!days.length) throw new Error('Pick at least one day.');
      if (until.value <= from.value) throw new Error('The daily window must end after it starts.');
      return { days, start: from.value, end: until.value };
    },
  };
}

function scheduleEditor(entry, weeklyAllowed) {
  const current = entry.cycle && weeklyAllowed ? 'weekly' : entry.validity ? 'dates' : 'always';
  const group = uid('when');
  const choices = [
    ['always', 'Always'],
    ['dates', 'Between dates'],
  ];
  if (weeklyAllowed) choices.push(['weekly', 'Weekly schedule']);
  const radios = choices.map(([value, text]) => {
    const input = h('input', { type: 'radio', name: group, value, checked: value === current });
    return { input, label: h('label', { class: 'choice' }, input, h('span', null, text)) };
  });
  const period = windowFields(entry.validity, 24 * 30);
  const weekly = weeklyAllowed ? weeklyEditor(entry.cycle) : null;
  const chosen = () => radios.find(({ input }) => input.checked).input.value;
  const sync = () => {
    period.group.hidden = chosen() !== 'dates';
    if (weekly) weekly.el.hidden = chosen() !== 'weekly';
  };
  radios.forEach(({ input }) => input.addEventListener('change', sync));
  sync();
  return {
    el: [
      h(
        'fieldset',
        { class: 'choices' },
        h('legend', null, 'When it opens the lock'),
        radios.map((r) => r.label),
      ),
      period.group,
      weekly ? weekly.el : null,
    ],
    read() {
      const mode = chosen();
      const plan = { validity: mode === 'dates' ? readWindow(period.from, period.until) : null };
      if (weeklyAllowed) plan.cycle = mode === 'weekly' ? weekly.read() : null;
      return plan;
    },
  };
}

function weekdayChecks(selected = []) {
  const boxes = WEEKDAYS.map((day, index) =>
    h('input', { type: 'checkbox', value: String(index + 1), checked: selected.includes(index + 1) }),
  );
  return {
    el: h(
      'div',
      { class: 'days' },
      boxes.map((box, index) => checkField(WEEKDAYS[index], box)),
    ),
    values: () => boxes.filter((box) => box.checked).map((box) => Number(box.value)),
  };
}

function renderItems(part, items, emptyText) {
  part.body.replaceChildren(items.length ? h('ul', { class: 'items' }, items) : h('p', { class: 'empty' }, emptyText));
}

async function renderAccess(panel, lock, has) {
  const parts = [];
  if (has('passcode')) parts.push(passcodeSection(lock, has));
  if (has('finger_print')) parts.push(credentialSection(lock, 'fingerprint', has));
  if (has('ic')) parts.push(credentialSection(lock, 'card', has));
  if (!parts.length) {
    panel.append(h('p', { class: 'card empty' }, 'This lock reports no passcodes, cards or fingerprints.'));
    return;
  }
  for (const part of parts) panel.append(part.el);
  for (const part of parts) await part.reload();
}

function passcodeSection(lock, has) {
  const add = h('button', { class: 'button small primary', type: 'button' }, icon('plus'), 'Add passcode');
  const clear = h('button', { class: 'button small', type: 'button' }, icon('trash'), 'Delete all');
  const part = section('Passcodes', 'keypad', [add, clear]);
  part.el.insertBefore(
    h(
      'p',
      { class: 'hint' },
      'The lock opens when a code appears anywhere among the digits typed, so others can hide it in a longer string. Use 7 to 9 digits, and avoid runs like 123456 or one repeated digit.',
    ),
    part.body,
  );

  function item(entry) {
    const label = entry.name || 'Passcode';
    const actions = [];
    if (has('modify_passcode_function')) {
      actions.push(
        h(
          'button',
          { class: 'button small', type: 'button', 'aria-label': `Edit ${label}`, onclick: () => editPasscode(entry) },
          icon('edit'),
          'Edit',
        ),
      );
    }
    actions.push(
      h(
        'button',
        {
          class: 'button small',
          type: 'button',
          'aria-label': `Delete ${label}`,
          onclick: () => deletePasscode(entry),
        },
        icon('trash'),
        'Delete',
      ),
    );
    const details = [TYPE_TEXT[entry.type] || entry.type];
    if (entry.type !== 'permanent' && entry.validity) details.push(validityText(entry.validity));
    if (entry.cycle) details.push(cycleText(entry.cycle));
    return h(
      'li',
      { class: 'item' },
      icon('keypad'),
      h(
        'div',
        { class: 'item-main' },
        h('strong', null, label),
        ' ',
        h('span', { class: 'mask', 'aria-hidden': 'true' }, '••••••'),
        h('span', { class: 'visually-hidden' }, 'digits hidden'),
        h('p', { class: 'muted small' }, details.join(' · ')),
        entry.managed === false ? h('span', { class: 'badge warn' }, 'Not created by Latchkey') : null,
      ),
      h('div', { class: 'item-actions' }, actions),
    );
  }

  part.reload = () =>
    load(part.body, async () => {
      const { passcodes = [] } = await rpc('lock.passcodes.list', { lock: lock.id });
      renderItems(part, passcodes.map(item), 'No passcodes on this lock.');
    });

  async function deletePasscode(entry) {
    const done = await formDialog('Delete passcode', {
      intro: `The passcode “${entry.name || 'Passcode'}” stops working on the lock right away.`,
      submit: 'Delete',
      danger: true,
      onSubmit: () => rpc('lock.passcodes.delete', { lock: lock.id, id: entry.id }),
    });
    if (done) await part.reload();
  }

  async function editPasscode(entry) {
    const name = h('input', { type: 'text', maxlength: '24', value: entry.name || '', autocomplete: 'off' });
    const code = codeInput();
    const period = entry.type === 'permanent' ? null : windowFields(entry.validity, 24);
    const done = await formDialog('Edit passcode', {
      fields: [
        field('Name', name),
        field('New code (optional)', code, 'Four to nine digits. Leave empty to keep the current code.'),
        period ? period.group : null,
      ],
      submit: 'Save',
      onSubmit: async () => {
        const params = { lock: lock.id, id: entry.id, name: name.value.trim() };
        if (code.value) params.code = code.value;
        if (period) params.validity = readWindow(period.from, period.until);
        await rpc('lock.passcodes.update', params);
        code.value = '';
      },
    });
    if (done) await part.reload();
  }

  add.addEventListener('click', async () => {
    const name = h('input', { type: 'text', maxlength: '24', autocomplete: 'off' });
    const type = h(
      'select',
      null,
      PASSCODE_TYPES.filter(([key]) => key !== 'cyclic').map(([key, text]) => h('option', { value: key }, text)),
    );
    const code = codeInput({ placeholder: 'Random' });
    const period = windowFields(null, 24);
    const sync = () => {
      period.group.hidden = type.value === 'permanent';
      if (type.value === 'one_time') {
        const start = fromLocalInput(period.from.value) || Math.floor(Date.now() / 1000);
        period.until.value = toLocalInput(start + 6 * 3600);
      }
    };
    type.addEventListener('change', sync);
    sync();
    const created = await formDialog('Add passcode', {
      fields: [
        field('Name', name, 'Kept on the board to tell passcodes apart.'),
        field('Type', type),
        field(
          'Code (optional)',
          code,
          'Four to nine digits; seven to nine are safer. Leave empty and the board picks a random six-digit code.',
        ),
        period.group,
      ],
      submit: 'Add',
      onSubmit: async () => {
        const params = { lock: lock.id, type: type.value, name: name.value.trim() };
        if (code.value) params.code = code.value;
        if (type.value !== 'permanent') params.validity = readWindow(period.from, period.until);
        const result = await rpc('lock.passcodes.add', params);
        code.value = '';
        return result.passcode || {};
      },
    });
    if (!created) return;
    if (created.code) {
      secretDialog('New passcode', {
        intro: `${created.name || 'The new passcode'} works on the keypad now.`,
        secret: created.code,
        label: 'New passcode',
      });
    }
    await part.reload();
  });

  clear.addEventListener('click', async () => {
    const done = await formDialog('Delete every passcode?', {
      intro: `Every passcode on ${lock.name} stops working, including ones Latchkey did not create. The super admin passcode stays.`,
      submit: 'Delete all',
      danger: true,
      onSubmit: () => rpc('lock.passcodes.clear', { lock: lock.id }),
    });
    if (done) await part.reload();
  });
  return part;
}

function credentialSection(lock, kind, has) {
  const info = CREDENTIALS[kind];
  const add = h('button', { class: 'button small primary', type: 'button' }, icon('plus'), `Add ${info.noun}`);
  const clear = h('button', { class: 'button small', type: 'button' }, icon('trash'), 'Delete all');
  const part = section(info.title, info.icon, [add, clear]);

  function item(entry) {
    const label = info.name(entry);
    const number = info.number(entry);
    return h(
      'li',
      { class: 'item' },
      icon(info.icon),
      h(
        'div',
        { class: 'item-main' },
        h('strong', null, label),
        number ? [' ', h('span', { class: 'mask' }, number)] : null,
        h(
          'p',
          { class: 'muted small' },
          [validityText(entry.validity), entry.cycle ? cycleText(entry.cycle) : null].filter(Boolean).join(' · '),
        ),
      ),
      h(
        'div',
        { class: 'item-actions' },
        h(
          'button',
          {
            class: 'button small',
            type: 'button',
            'aria-label': `Validity of ${label}`,
            onclick: () => editValidity(entry),
          },
          icon('clock'),
          'Validity',
        ),
        h(
          'button',
          { class: 'button small', type: 'button', 'aria-label': `Delete ${label}`, onclick: () => remove(entry) },
          icon('trash'),
          'Delete',
        ),
      ),
    );
  }

  part.reload = () =>
    load(part.body, async () => {
      const result = await rpc(`${info.method}.list`, { lock: lock.id });
      renderItems(part, (result[info.list] || []).map(item), `No ${info.list} on this lock.`);
    });

  async function editValidity(entry) {
    const schedule = scheduleEditor(entry, has('cyclic_ic_or_finger_print'));
    const done = await formDialog(`${info.Noun} validity`, {
      fields: schedule.el,
      submit: 'Save',
      onSubmit: () => rpc(`${info.method}.setValidity`, { lock: lock.id, id: entry.id, ...schedule.read() }),
    });
    if (done) await part.reload();
  }

  async function remove(entry) {
    const done = await formDialog(`Delete ${info.noun}`, {
      intro: `${info.name(entry)} stops opening ${lock.name} right away.`,
      submit: 'Delete',
      danger: true,
      onSubmit: () => rpc(`${info.method}.delete`, { lock: lock.id, id: entry.id }),
    });
    if (done) await part.reload();
  }

  add.addEventListener('click', async () => {
    const name = h('input', { type: 'text', maxlength: '24', autocomplete: 'off' });
    const values = await formDialog(`Add ${info.noun}`, {
      intro: `The lock waits for the ${info.noun} after you press Start.`,
      fields: [field('Name', name, `Kept on the board to tell ${info.list} apart.`)],
      submit: 'Start',
      onSubmit: async () => ({ name: name.value.trim() }),
    });
    if (!values) return;
    const modal = enrolModal(kind, lock.id);
    try {
      await rpc(`${info.method}.enroll`, { lock: lock.id, name: values.name });
      modal.done();
      toast(`${info.Noun} added`);
      await part.reload();
    } catch (failure) {
      modal.fail(failure);
    }
  });

  clear.addEventListener('click', async () => {
    const done = await formDialog(`Delete every ${info.noun}?`, {
      intro: `No ${info.noun} will open ${lock.name} until you add one again.`,
      submit: 'Delete all',
      danger: true,
      onSubmit: () => rpc(`${info.method}.clear`, { lock: lock.id }),
    });
    if (done) await part.reload();
  });
  return part;
}

function settingSwitch(label, initial, onSet) {
  return switchControl(label, initial, async (checked, input) => {
    input.disabled = true;
    try {
      const result = await onSet(checked);
      input.checked = result && typeof result.enabled === 'boolean' ? result.enabled : checked;
    } catch (failure) {
      input.checked = !checked;
      toastError(failure);
    } finally {
      input.disabled = false;
    }
  });
}

async function renderSettings(panel, lock, has) {
  const parts = [];
  const target = { lock: lock.id };

  if (has('auto_lock')) {
    const part = section('Auto-lock', 'clock');
    part.load = async () => {
      const setting = await rpc('lock.autolock.get', target);
      const lowest = setting.min || 1;
      const highest = setting.max || 65535;
      const enabled = h('input', { type: 'checkbox', checked: setting.seconds > 0 });
      const delay = h('input', {
        type: 'number',
        min: String(lowest),
        max: String(highest),
        value: String(setting.seconds || Math.max(lowest, 5)),
        required: true,
      });
      const save = h('button', { class: 'button small primary', type: 'submit' }, 'Save');
      const form = h(
        'form',
        { class: 'stack' },
        checkField('Lock automatically', enabled),
        field('Delay in seconds', delay, `From ${lowest} to ${highest} s after unlocking.`),
        h('div', { class: 'row' }, save),
      );
      form.addEventListener('submit', async (event) => {
        event.preventDefault();
        try {
          await pending(save, () =>
            rpc('lock.autolock.set', { ...target, seconds: enabled.checked ? Number(delay.value) : 0 }),
          );
          toast(enabled.checked ? `Auto-lock after ${delay.value} s` : 'Auto-lock turned off');
        } catch (failure) {
          toastError(failure);
        }
      });
      part.body.replaceChildren(form);
    };
    parts.push(part);
  }

  if (has('passage_mode')) parts.push(passageSection(lock));

  if (has('audio_management')) {
    const part = section('Sound', 'sound');
    part.load = async () => {
      const sound = await rpc('lock.sound.get', target);
      const levels = sound.levels || 5;
      const hasVolume = typeof sound.volume === 'number';
      const volume = h(
        'select',
        null,
        Array.from({ length: levels }, (_, index) =>
          h('option', { value: String(index + 1), selected: sound.volume === index + 1 }, String(index + 1)),
        ),
      );
      const apply = (enabled) =>
        rpc(
          'lock.sound.set',
          hasVolume ? { ...target, enabled, volume: Number(volume.value) } : { ...target, enabled },
        );
      const toggle = settingSwitch('Keypad sounds', sound.enabled, apply);
      volume.addEventListener('change', async () => {
        try {
          await apply(toggle.querySelector('input').checked);
          toast(`Volume set to ${volume.value}`);
        } catch (failure) {
          toastError(failure);
        }
      });
      part.body.replaceChildren(toggle, hasVolume ? field('Volume', volume) : null);
    };
    parts.push(part);
  }

  if (has('reset_button')) {
    const part = section('Reset button', 'power');
    part.load = async () => {
      const { enabled } = await rpc('lock.resetButton.get', target);
      part.body.replaceChildren(
        switchControl('Physical reset button', enabled),
        h(
          'p',
          { class: 'hint' },
          'When on, anyone holding the reset button inside the lock can wipe it and pair it to their own app. This switch is read-only until its write command is verified on a real lock.',
        ),
      );
    };
    parts.push(part);
  }

  const switches = [
    [
      'privacy_lock',
      'Privacy lock',
      'lock.privacyLock',
      'When on, a lock closed from inside ignores passcodes, cards and fingerprints until it is opened from inside.',
    ],
    [
      'tamper_alert',
      'Tamper alert',
      'lock.tamperAlert',
      'When on, the lock sounds an alarm when someone tries to force it.',
    ],
  ];
  for (const [feature, title, method, hint] of switches) {
    if (!has(feature)) continue;
    const part = section(title, 'shield', [h('span', { class: 'badge' }, 'Read-only')]);
    part.load = async () => {
      const { enabled } = await rpc(`${method}.get`, target);
      part.body.replaceChildren(
        switchControl(title, enabled),
        h(
          'p',
          { class: 'hint' },
          `${hint} This switch is read-only until its write command is verified on a real lock.`,
        ),
      );
    };
    parts.push(part);
  }

  if (has('passcode')) {
    const part = section('Super admin passcode', 'key');
    part.load = async () => {
      const show = h('button', { class: 'button small', type: 'button' }, 'Show admin passcode');
      const change = h('button', { class: 'button small', type: 'button' }, 'Change admin passcode');
      show.addEventListener('click', async () => {
        try {
          const result = await pending(show, () => rpc('lock.adminPasscode.get', target));
          const where =
            result.source === 'lock'
              ? result.matchesBoard === false
                ? 'Read from the lock. It differs from the copy the board kept, so it was changed outside Latchkey.'
                : 'Read from the lock.'
              : 'The lock does not hand out its code, so this is the copy the board kept when it set it.';
          secretDialog('Super admin passcode', {
            intro: `${where} It always opens ${lock.name} from the keypad.`,
            secret: result.code,
            label: 'Super admin passcode',
            note: 'Keep it private. Close this window when you are done.',
          });
        } catch (failure) {
          toastError(failure);
        }
      });
      change.addEventListener('click', async () => {
        const code = codeInput();
        const result = await formDialog('Change the super admin passcode', {
          intro: 'The board asks for its button before the lock gets the new code.',
          fields: [
            field(
              'New super admin passcode (optional)',
              code,
              'Four to nine digits; seven to nine are safer. Leave empty and the board picks a random seven-digit code.',
            ),
          ],
          submit: 'Save',
          onSubmit: async () => {
            const params = code.value ? { ...target, code: code.value } : target;
            const outcome = await rpc('lock.adminPasscode.set', params);
            code.value = '';
            return outcome || {};
          },
        });
        if (!result) return;
        if (result.code) {
          secretDialog('New super admin passcode', {
            intro: `This passcode always opens ${lock.name} from the keypad.`,
            secret: result.code,
            label: 'New super admin passcode',
          });
        } else {
          toast('Super admin passcode changed');
        }
      });
      part.body.replaceChildren(
        h(
          'p',
          { class: 'hint' },
          'This passcode always opens the lock from the keypad. Hardening replaces it with a random one.',
        ),
        h('div', { class: 'row' }, show, change),
      );
    };
    parts.push(part);
  }

  const clock = section('Clock', 'clock');
  clock.load = async () => {
    const sync = h('button', { class: 'button small', type: 'button' }, icon('refresh'), "Set the lock's clock");
    sync.addEventListener('click', async () => {
      try {
        const result = await pending(sync, () => rpc('lock.time.sync', target));
        toast(`Lock clock set to ${formatTime(result.time)}`);
      } catch (failure) {
        toastError(failure);
      }
    });
    clock.body.replaceChildren(
      h(
        'p',
        { class: 'hint' },
        'The lock keeps its own clock for timed passcodes and its log. This copies the board clock to it.',
      ),
      sync,
    );
  };
  parts.push(clock);

  for (const item of parts) panel.append(item.el);
  for (const item of parts) await load(item.body, item.load);
}

const PASSAGE_ADD_STOPPED =
  'Adding did not finish, so some windows may have been added. The list shows what the lock holds now.';

function passageSection(lock) {
  const clear = h('button', { class: 'button small', type: 'button' }, 'Turn off all');
  const item = section('Passage mode', 'unlock', [clear]);
  const target = { lock: lock.id };
  let notice = null;

  const describe = (mode) => {
    const day = mode.day === 0 ? 'Every day' : WEEKDAY_NAMES[mode.day - 1] || `Day ${mode.day}`;
    return `${mode.type === 'monthly' ? `Day ${mode.day} of the month` : day}, ${mode.start} to ${mode.end}`;
  };

  function render(modes) {
    const list = modes.length
      ? h(
          'ul',
          { class: 'items' },
          modes.map((mode) =>
            h(
              'li',
              { class: 'item' },
              h('div', { class: 'item-main' }, describe(mode)),
              h(
                'button',
                {
                  class: 'button small',
                  type: 'button',
                  'aria-label': `Delete ${describe(mode)}`,
                  onclick: async (event) => {
                    try {
                      const result = await pending(event.currentTarget, () =>
                        rpc('lock.passage.delete', { ...target, ...mode }),
                      );
                      render(result.modes || []);
                    } catch (failure) {
                      toastError(failure);
                    }
                  },
                },
                icon('trash'),
                'Delete',
              ),
            ),
          ),
        )
      : h('p', { class: 'empty' }, 'Off. The lock locks again after every opening.');
    const days = weekdayChecks([1, 2, 3, 4, 5]);
    const from = h('input', { type: 'time', value: '08:00', required: true });
    const until = h('input', { type: 'time', value: '18:00', required: true });
    const add = h('button', { class: 'button small primary', type: 'submit' }, icon('plus'), 'Add passage window');
    const form = h(
      'form',
      { class: 'stack' },
      h(
        'fieldset',
        { class: 'field-group' },
        h('legend', null, 'New window'),
        days.el,
        field('From', from),
        field('Until', until),
      ),
      h('div', { class: 'row' }, add),
    );
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const selected = days.values();
      if (!selected.length || until.value <= from.value) {
        toastError(new Error(selected.length ? 'The window must end after it starts.' : 'Pick at least one day.'));
        return;
      }
      try {
        const result = await pending(add, () =>
          rpc('lock.passage.add', {
            ...target,
            type: 'weekly',
            days: selected.length === 7 ? [0] : selected,
            start: from.value,
            end: until.value,
          }),
        );
        render(result.modes || []);
        toast('Passage window added');
      } catch (failure) {
        toastError(failure);
        if (failure.code === 'unauthorized') return;
        notice = PASSAGE_ADD_STOPPED;
        await load(item.body, item.load);
      }
    });
    item.body.replaceChildren(
      ...[
        h('p', { class: 'hint' }, 'During a passage window the lock stays open after it is unlocked.'),
        notice && h('p', { class: 'notice', role: 'status' }, notice),
        list,
        form,
      ].filter(Boolean),
    );
    notice = null;
  }

  item.load = async () => {
    const { modes = [] } = await rpc('lock.passage.list', target);
    render(modes);
  };

  clear.addEventListener('click', async () => {
    const done = await formDialog('Turn off passage mode?', {
      intro: `Every passage window on ${lock.name} is removed.`,
      submit: 'Turn off all',
      danger: true,
      onSubmit: () => rpc('lock.passage.clear', target),
    });
    if (done) await load(item.body, item.load);
  });
  return item;
}

async function renderLog(panel, lock) {
  const fetchNew = h('button', { class: 'button small', type: 'button' }, icon('refresh'), 'Fetch new entries');
  const item = section('Operation log', 'list', [fetchNew]);
  const rows = h('tbody');
  let last = 0;
  const row = (entry) =>
    h(
      'tr',
      null,
      h('td', { class: 'nowrap' }, formatTime(entry.time)),
      h('td', null, entry.name || LOG_TEXT[entry.type] || `Event ${entry.type}`),
      h('td', null, typeof entry.battery === 'number' ? `${entry.battery}%` : '—'),
    );
  const table = h(
    'div',
    { class: 'table-wrap' },
    h(
      'table',
      null,
      h('caption', { class: 'visually-hidden' }, 'Operation log'),
      h(
        'thead',
        null,
        h(
          'tr',
          null,
          h('th', { scope: 'col' }, 'When'),
          h('th', { scope: 'col' }, 'Event'),
          h('th', { scope: 'col' }, 'Battery'),
        ),
      ),
      rows,
    ),
  );
  const show = (entries) => {
    const fresh = entries.filter((entry) => entry.seq > last || !rows.childNodes.length);
    rows.prepend(...[...fresh].sort((a, b) => b.seq - a.seq).map(row));
    for (const entry of fresh) last = Math.max(last, entry.seq);
    return fresh.length;
  };
  const readOn = async (first) => {
    let result = first;
    let added = show(result.entries || []);
    for (let round = 0; result.more && round < LOG_ROUNDS; round += 1) {
      result = await rpc('lock.log.fetch', { lock: lock.id, since: last });
      added += show(result.entries || []);
    }
    return added;
  };
  fetchNew.addEventListener('click', async () => {
    try {
      const added = await pending(fetchNew, async () =>
        readOn(await rpc('lock.log.fetch', { lock: lock.id, since: last })),
      );
      toast(added ? `${added} new entries` : 'No new entries');
    } catch (failure) {
      toastError(failure);
    }
  });
  panel.append(item.el);
  await load(item.body, async () => {
    await readOn(await rpc('lock.log.fetch', { lock: lock.id }));
    item.body.replaceChildren(
      rows.childNodes.length ? table : h('p', { class: 'empty' }, 'The lock has no log entries.'),
      h('p', { class: 'hint' }, 'Entries come from the lock itself, with the time on its own clock.'),
    );
  });
}

async function renderDevice(panel, lock, features) {
  const device = section('Device', 'info');
  const reported = section('Features', 'list');
  const used = [...features].filter((name) => FEATURES_USED.has(name));
  const unused = [...features].filter((name) => !FEATURES_USED.has(name));
  const chips = (label, names) =>
    h(
      'ul',
      { class: 'chips', 'aria-label': label },
      names.map((name) => h('li', null, FEATURE_TEXT[name] || name)),
    );
  reported.body.append(
    features.size ? chips('Reported features', used) : h('p', { class: 'muted' }, 'The lock reported no features.'),
    unused.length
      ? h(
          'div',
          { class: 'stack' },
          h('p', { class: 'hint' }, 'The lock also reports these, which Latchkey does not use yet:'),
          chips('Reported, not used by Latchkey', unused),
        )
      : null,
  );
  const hardening = section('Hardening', 'shield');
  hardening.body.append(
    lock.hardened
      ? h(
          'p',
          null,
          h('span', { class: 'badge ok' }, icon('check'), 'Hardened'),
          ' Default passcodes are gone and the reset button is off.',
        )
      : hardeningPanel(lock, {}),
  );
  const forget = h('button', { class: 'button small', type: 'button' }, icon('trash'), 'Forget lock');
  const reset = h('button', { class: 'button small danger', type: 'button' }, icon('power'), 'Factory-reset lock');
  const danger = section('Danger zone', 'alert', [], 'danger-zone');
  danger.body.append(
    h(
      'p',
      { class: 'hint' },
      'Forget drops the keys from this board only: the lock stays paired, and without a backup nothing can manage it again.',
    ),
    h(
      'p',
      { class: 'hint' },
      'Factory reset wipes the lock back to its factory state, credentials included. It needs the button on the board.',
    ),
    h('div', { class: 'row' }, forget, reset),
  );
  forget.addEventListener('click', async () => {
    const done = await formDialog(`Forget ${lock.name}?`, {
      intro: lock.backedUp
        ? 'The board deletes its keys for this lock. You can bring them back from your key backup.'
        : 'There is no key backup for this lock. Once forgotten, only a factory reset at the lock makes it usable again.',
      fields: [
        field(
          'Type forget to confirm',
          h('input', { type: 'text', required: true, pattern: 'forget', autocomplete: 'off' }),
        ),
      ],
      submit: 'Forget',
      danger: true,
      onSubmit: () => rpc('locks.forget', { lock: lock.id }),
    });
    if (done) {
      toast(`${lock.name} forgotten`);
      location.hash = '#/locks';
    }
  });
  reset.addEventListener('click', async () => {
    const ok = await confirmDialog(
      `Factory-reset ${lock.name}?`,
      'Every passcode, card and fingerprint is erased and the lock opens with its factory defaults until you pair it again.',
      'Factory reset',
      { typed: 'reset' },
    );
    if (!ok) return;
    try {
      await pending(reset, () => rpc('lock.factoryReset', { lock: lock.id }));
      toast(`${lock.name} is back to factory state`);
      location.hash = '#/locks';
    } catch (failure) {
      toastError(failure);
    }
  });
  panel.append(h('div', { class: 'grid' }, device.el, reported.el), hardening.el, danger.el);
  await load(device.body, async () => {
    const info = await rpc('lock.info', { lock: lock.id });
    device.body.replaceChildren(
      facts([
        ['Model', info.model],
        ['Hardware', info.hardware],
        ['Firmware', info.firmware],
        ['Made', info.manufactureDate],
        ['Bluetooth address', info.mac || lock.mac],
        ['Protocol', info.protocol],
      ]),
    );
  });
}

async function viewSecurity(view) {
  heading(view, 'Security');
  try {
    ({ locks: state.locks = [] } = await rpc('locks.list'));
  } catch (failure) {
    if (failure.code === 'unauthorized') return;
  }
  const cert = section('Board certificate', 'shield');
  const session = section('Session', 'key');
  const password = section('Password', 'key');
  const authenticator = section('Authenticator', 'clock');
  const backup = section('Key backup', 'download');
  const loadOlder = h('button', { class: 'button small', type: 'button', hidden: true }, 'Load older');
  const audit = section('Audit log', 'list', [loadOlder]);

  session.body.append(
    h('p', null, 'You are signed in. Sessions end after a few minutes without activity, and when the board restarts.'),
    h(
      'div',
      { class: 'row' },
      h(
        'button',
        { class: 'button small', type: 'button', onclick: () => signOut(true) },
        icon('logout'),
        'Sign out everywhere',
      ),
    ),
  );

  const current = h('input', { type: 'password', required: true, autocomplete: 'current-password' });
  const next = h('input', {
    type: 'password',
    required: true,
    minlength: '12',
    maxlength: '128',
    autocomplete: 'new-password',
  });
  const repeat = h('input', { type: 'password', required: true, autocomplete: 'new-password' });
  const passwordError = h('p', { class: 'form-error', role: 'alert', hidden: true });
  const change = h('button', { class: 'button small primary', type: 'submit' }, 'Change password');
  const passwordForm = h(
    'form',
    { class: 'stack', 'aria-label': 'Change password' },
    field('Current password', current),
    field('New password', next, 'At least 12 characters. Other sessions are signed out.'),
    field('Repeat new password', repeat),
    passwordError,
    h('div', { class: 'row' }, change),
  );
  passwordForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    passwordError.hidden = true;
    if (next.value !== repeat.value) {
      showError(passwordError, new Error('The new passwords do not match.'));
      return;
    }
    try {
      await pending(change, () => rpc('auth.changePassword', { current: current.value, new: next.value }));
      passwordForm.reset();
      toast('Password changed');
    } catch (failure) {
      showError(passwordError, failure);
    }
  });
  password.body.append(passwordForm);

  const rotate = h('button', { class: 'button small', type: 'button' }, 'Replace authenticator secret');
  rotate.addEventListener('click', async () => {
    const ok = await confirmDialog(
      'Replace authenticator secret?',
      'The codes from your current authenticator entry stop working. The board shows the new secret once and asks for its button.',
      'Replace',
      { danger: false },
    );
    if (!ok) return;
    try {
      const { otpauth } = await pending(rotate, () => rpc('auth.rotateTotp'));
      const secret = new URL(otpauth).searchParams.get('secret') || '';
      secretDialog('New authenticator secret', {
        intro: 'Add this secret to your authenticator app, then sign in with the new codes.',
        secret,
        long: true,
        label: 'New authenticator secret',
        extra: h('p', null, h('a', { class: 'button primary', href: otpauth }, 'Open in authenticator app')),
      });
    } catch (failure) {
      toastError(failure);
    }
  });
  authenticator.body.append(
    h(
      'p',
      { class: 'hint' },
      'Sign-in needs your password and a six-digit code. Replace the secret if a device holding it was lost.',
    ),
    rotate,
  );

  const exportAll = h(
    'button',
    { class: 'button small', type: 'button', onclick: () => exportKeysDialog(null) },
    icon('download'),
    'Export keys…',
  );
  const importAll = h(
    'button',
    { class: 'button small', type: 'button', onclick: () => importKeysDialog() },
    icon('upload'),
    'Import keys…',
  );
  backup.body.append(
    h(
      'p',
      { class: 'hint' },
      'The backup holds every lock key, encrypted with your passphrase. Import it on a new board to move your locks.',
    ),
    h('div', { class: 'row' }, exportAll, importAll),
  );

  const rows = h('tbody');
  const shown = new Set();
  const nameOf = (id) => (state.locks.find((lock) => lock.id === id) || {}).name || id;
  const auditRow = (entry) =>
    h(
      'tr',
      { 'data-seq': entry.seq },
      h('td', { class: 'nowrap' }, formatTime(entry.time)),
      h('td', null, entry.source || '—'),
      h('td', null, h('code', null, entry.method)),
      h('td', null, entry.target ? nameOf(entry.target) : '—'),
      h('td', { class: entry.result === 'ok' ? null : 'result-bad' }, entry.result === 'ok' ? 'OK' : entry.result),
    );
  const showEntry = (entry) => {
    if (shown.has(entry.seq)) return;
    shown.add(entry.seq);
    const older = [...rows.rows].find((row) => Number(row.dataset.seq) < entry.seq);
    rows.insertBefore(auditRow(entry), older || null);
  };
  const table = h(
    'div',
    { class: 'table-wrap' },
    h(
      'table',
      null,
      h('caption', { class: 'visually-hidden' }, 'Audit log'),
      h(
        'thead',
        null,
        h(
          'tr',
          null,
          ['When', 'Source', 'Action', 'Target', 'Result'].map((text) => h('th', { scope: 'col' }, text)),
        ),
      ),
      rows,
    ),
  );
  let oldest = null;
  const fetchAudit = async () => {
    const result = await rpc('audit.list', oldest ? { before: oldest, limit: 50 } : { limit: 50 });
    for (const entry of result.entries || []) {
      showEntry(entry);
      oldest = oldest === null ? entry.seq : Math.min(oldest, entry.seq);
    }
    loadOlder.hidden = !result.more;
  };
  loadOlder.addEventListener('click', async () => {
    try {
      await pending(loadOlder, fetchAudit);
    } catch (failure) {
      toastError(failure);
    }
  });
  listen('audit.appended', (entry) => {
    if (entry && entry.method) showEntry(entry);
  });

  view.append(h('div', { class: 'grid' }, cert.el, session.el, password.el, authenticator.el), backup.el, audit.el);
  await load(cert.body, async () => {
    state.info = await rpc('system.info');
    cert.body.replaceChildren(
      h(
        'p',
        { class: 'hint' },
        "SHA-256 fingerprint of the board's HTTPS certificate. It must match the one the board printed on its USB console.",
      ),
      h('code', { class: 'fingerprint' }, state.info.certFingerprint || 'Not reported'),
    );
  });
  await load(audit.body, async () => {
    await fetchAudit();
    audit.body.replaceChildren(
      table,
      h('p', { class: 'hint' }, 'Every action on the board, newest first. Secrets are never recorded.'),
    );
  });
}

function levelSelect(value) {
  const select = h(
    'select',
    null,
    LOG_LEVELS.map(([level, text]) => h('option', { value: level }, text)),
  );
  select.value = value;
  return select;
}

function logTime(line) {
  if (typeof line.utcMs !== 'number') return `${(line.uptimeMs / 1000).toFixed(1)} s after start`;
  const when = new Date(line.utcMs);
  return `${clockTime.format(when)}.${String(when.getMilliseconds()).padStart(3, '0')}`;
}

function logLineText(line) {
  const when = typeof line.utcMs === 'number' ? new Date(line.utcMs).toISOString() : `+${line.uptimeMs}ms`;
  return `${when} ${line.level} ${line.tag ? `${line.tag}: ` : ''}${line.message}`;
}

function logsSection() {
  const copy = h('button', { class: 'button small', type: 'button' }, 'Copy');
  const part = section('Logs', 'list', [copy]);
  const level = levelSelect('info');
  const auto = h('input', { type: 'checkbox', checked: true });
  const status = h('p', { class: 'muted small', 'aria-live': 'polite' });
  const note = h('p', { class: 'hint', hidden: true });
  const rows = h('tbody');
  let lines = [];
  let next = null;
  let timer = 0;
  let busy = false;
  let again = false;
  let generation = 0;
  let stopped = false;

  const row = (line) =>
    h(
      'tr',
      null,
      h('td', { class: 'nowrap' }, logTime(line)),
      h('td', { class: `log-level log-${line.level}` }, line.level),
      h('td', null, line.tag || '—'),
      h('td', { class: 'log-message' }, line.message),
    );

  async function pull(since) {
    const fresh = [];
    let missed = 0;
    let cursor = since;
    for (;;) {
      if (stopped) return null;
      const params = cursor === null ? { level: level.value } : { level: level.value, since: cursor };
      const page = await rpc('system.logs', params);
      if (stopped) return null;
      if (cursor !== null && page.next < cursor) return null;
      fresh.push(...page.lines);
      missed += page.missed || 0;
      cursor = page.next;
      if (!page.more) return { fresh, missed, next: cursor };
    }
  }

  async function refresh() {
    if (stopped) return;
    if (busy) {
      again = true;
      return;
    }
    busy = true;
    const mine = generation;
    try {
      let result = await pull(next);
      if (stopped) return;
      if (result === null) {
        lines = [];
        result = await pull(null);
      }
      if (mine !== generation) return;
      lines = [...lines, ...result.fresh].slice(-LOG_KEEP);
      next = result.next;
      rows.replaceChildren(...[...lines].reverse().map(row));
      status.textContent = lines.length ? '' : 'No lines at this level yet.';
      if (result.missed) {
        note.hidden = false;
        note.textContent = `${result.missed} lines were overwritten on the board before this page could show them.`;
      }
    } catch (failure) {
      if (!stopped && failure.code !== 'unauthorized')
        status.textContent = `Cannot refresh the lines: ${errorText(failure)}`;
    } finally {
      busy = false;
      if (again && !stopped) {
        again = false;
        refresh();
      }
    }
  }

  function schedule() {
    clearTimeout(timer);
    if (stopped || !auto.checked) return;
    timer = setTimeout(async () => {
      if (!document.hidden) await refresh();
      schedule();
    }, LOG_REFRESH_MS);
  }

  level.addEventListener('change', () => {
    generation += 1;
    lines = [];
    next = null;
    note.hidden = true;
    rows.replaceChildren();
    refresh();
  });
  auto.addEventListener('change', () => {
    if (auto.checked) refresh();
    schedule();
  });
  copy.addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(`${lines.map(logLineText).join('\n')}\n`);
      toast(`Copied ${lines.length} lines`);
    } catch {
      toastError(new Error('The browser did not allow copying. Select the lines and copy them by hand.'));
    }
  });
  cleanups.push(() => {
    stopped = true;
    again = false;
    clearTimeout(timer);
    generation += 1;
  });

  part.body.append(
    h('div', { class: 'row log-controls' }, field('Show', level), checkField('Refresh every few seconds', auto)),
    status,
    h(
      'div',
      { class: 'table-wrap log-wrap' },
      h(
        'table',
        { class: 'log-table' },
        h('caption', { class: 'visually-hidden' }, 'Recent log lines'),
        h(
          'thead',
          null,
          h(
            'tr',
            null,
            ['Time', 'Level', 'Tag', 'Message'].map((text) => h('th', { scope: 'col' }, text)),
          ),
        ),
        rows,
      ),
    ),
    note,
    h(
      'p',
      { class: 'hint' },
      'The board keeps its latest log lines in memory until it restarts, newest first here. Secrets never appear in them.',
    ),
  );
  return {
    el: part.el,
    start: async () => {
      await refresh();
      schedule();
    },
  };
}

async function remoteLogging(part) {
  const settings = await rpc('system.syslog.get');
  const enabled = h('input', { type: 'checkbox', checked: settings.enabled });
  const host = h('input', {
    type: 'text',
    maxlength: '64',
    value: settings.host || '',
    autocomplete: 'off',
    spellcheck: 'false',
  });
  const port = h('input', { type: 'number', min: '1', max: '65535', value: String(settings.port || 514) });
  const transport = h('select', null, h('option', { value: 'udp' }, 'UDP'), h('option', { value: 'tcp' }, 'TCP'));
  transport.value = settings.transport || 'udp';
  const appName = h('input', {
    type: 'text',
    maxlength: '48',
    value: settings.appName || 'latchkey',
    autocomplete: 'off',
    spellcheck: 'false',
  });
  const level = levelSelect(settings.level || 'info');
  const save = h('button', { class: 'button small primary', type: 'submit' }, 'Save remote logging');
  const status = h('p', { class: 'muted small', 'aria-live': 'polite' });
  const show = (view) => {
    const where = `${view.host}:${view.port} over ${view.transport.toUpperCase()}`;
    const errors = view.errors ? `, ${view.errors} errors so far` : '';
    status.textContent = !view.enabled
      ? 'Remote logging is off.'
      : view.connected
        ? `Sending to ${where}: ${view.sent} lines sent, ${view.dropped} dropped.`
        : `Not connected to ${where} yet${errors}.`;
  };
  show(settings);
  const form = h(
    'form',
    { class: 'stack', 'aria-label': 'Remote logging' },
    checkField('Send log lines to a syslog collector', enabled),
    h(
      'div',
      { class: 'field-group' },
      field('Collector host', host),
      field('Port', port),
      field('Transport', transport),
      field('App name', appName),
      field('Lines to send', level),
    ),
    h('div', { class: 'row' }, save),
  );
  form.addEventListener('submit', async (event) => {
    event.preventDefault();
    const params = {
      enabled: enabled.checked,
      host: host.value.trim(),
      port: Number(port.value),
      transport: transport.value,
      appName: appName.value.trim(),
      level: level.value,
    };
    try {
      show(await pending(save, () => rpc('system.syslog.set', params)));
      toast('Remote logging saved');
    } catch (failure) {
      toastError(failure);
    }
  });
  part.body.replaceChildren(
    h(
      'p',
      { class: 'hint' },
      'Off by default. The board sends each log line as RFC 5424 syslog over plain UDP or TCP, so anyone on the network path can read them: use a collector on your own network. On the classic ESP32, UDP needs less memory.',
    ),
    status,
    form,
  );
}

async function viewSystem(view) {
  heading(view, 'System');
  const board = section('Board', 'chip');
  const wifi = section('Wi-Fi', 'wifi');
  const ota = section('Firmware update', 'upload');
  const mqtt = section('Home Assistant (MQTT)', 'wifi');
  const remote = section('Remote logging (syslog)', 'upload');
  const logs = logsSection();
  const restart = section('Restart', 'refresh');
  const danger = section('Danger zone', 'alert', [], 'danger-zone');

  const ssid = h('input', { type: 'text', maxlength: '32', required: true, autocomplete: 'off', spellcheck: 'false' });
  const wifiPassword = h('input', { type: 'password', maxlength: '63', autocomplete: 'new-password' });
  const saveWifi = h('button', { class: 'button small primary', type: 'submit' }, 'Save Wi-Fi');
  const addressInput = () =>
    h('input', {
      type: 'text',
      inputmode: 'decimal',
      maxlength: '15',
      required: true,
      autocomplete: 'off',
      spellcheck: 'false',
    });
  const address = addressInput();
  const gateway = addressInput();
  const netmask = addressInput();
  const dns = addressInput();
  const wifiForm = h(
    'form',
    { class: 'stack', 'aria-label': 'Wi-Fi' },
    field('Network name (SSID)', ssid),
    field('Password', wifiPassword, 'Leave empty for an open network. The board never shows a saved password.'),
    h(
      'div',
      { class: 'field-group' },
      field('IP address', address),
      field('Gateway', gateway),
      field('Netmask', netmask),
      field('DNS server', dns),
    ),
    h(
      'p',
      { class: 'hint' },
      'The board keeps a fixed address on your network. If you change it, open the board at its new address.',
    ),
    h('div', { class: 'row' }, saveWifi),
  );
  wifiForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const params = {
      ssid: ssid.value.trim(),
      password: wifiPassword.value,
      ip: address.value.trim(),
      gateway: gateway.value.trim(),
      netmask: netmask.value.trim(),
      dns: dns.value.trim(),
    };
    try {
      await pending(saveWifi, () => rpc('system.wifi.set', params));
      wifiPassword.value = '';
      toast(`The board is joining ${ssid.value.trim()}`, { detail: 'If its address changes, open the new one.' });
    } catch (failure) {
      toastError(failure);
    }
  });
  wifi.body.append(wifiForm);

  const image = h('input', { type: 'file', accept: '.bin,application/octet-stream' });
  const upload = h('button', { class: 'button small primary', type: 'button' }, icon('upload'), 'Upload');
  const progress = h('progress', { max: '1', value: '0', hidden: true });
  const otaStatus = h('p', { 'aria-live': 'polite' });
  const otaError = h('p', { class: 'form-error', role: 'alert', hidden: true });
  upload.addEventListener('click', async () => {
    otaError.hidden = true;
    otaStatus.textContent = '';
    const file = image.files[0];
    if (!file) {
      showError(otaError, new Error('Choose a firmware image first.'));
      return;
    }
    const first = new Uint8Array(await file.slice(0, 1).arrayBuffer())[0];
    if (first !== FIRMWARE_MAGIC) {
      showError(otaError, new Error('This file is not an ESP32 firmware image. Use the .bin from a Latchkey release.'));
      return;
    }
    progress.hidden = false;
    progress.max = file.size;
    progress.value = 0;
    const sent = () => {
      otaStatus.textContent = 'Uploaded. Press the button on the board to install it.';
    };
    try {
      await pending(upload, () => sendFirmware(file, progress, sent));
      progress.value = progress.max;
      otaStatus.textContent = 'Upload complete. The board is restarting into the new firmware.';
      toast('Firmware uploaded. The board is restarting', { detail: 'This page reconnects when it is back.' });
    } catch (failure) {
      otaStatus.textContent = '';
      showError(otaError, failure);
    } finally {
      boardButton.settle('ota');
    }
  });
  ota.body.append(
    h(
      'p',
      { class: 'hint' },
      'The board keeps the running firmware in its other slot and rolls back if the new one fails to start.',
    ),
    field('Firmware image (.bin)', image),
    h('div', { class: 'row' }, upload),
    progress,
    otaStatus,
    otaError,
  );

  const reboot = h('button', { class: 'button small', type: 'button' }, icon('refresh'), 'Restart the board');
  reboot.addEventListener('click', async () => {
    const ok = await confirmDialog(
      'Restart the board?',
      'Lock operations stop for a few seconds while it restarts.',
      'Restart',
      { danger: false },
    );
    if (!ok) return;
    try {
      await pending(reboot, () => rpc('system.reboot'));
      toast('The board is restarting');
    } catch (failure) {
      toastError(failure);
    }
  });
  restart.body.append(reboot);

  const wipe = h('button', { class: 'button small danger', type: 'button' }, icon('power'), 'Factory-reset the board');
  wipe.addEventListener('click', async () => {
    const ok = await confirmDialog(
      'Factory-reset the board?',
      'The board forgets its owner, Wi-Fi and every lock key. Locks stay paired to keys that no longer exist unless you have a backup. It needs the button on the board.',
      'Factory reset',
      { typed: 'erase' },
    );
    if (!ok) return;
    try {
      await pending(wipe, () => rpc('system.factoryReset'));
      state.authed = false;
      events.stop();
      showLogin('The board was reset. Claim it again over USB.');
    } catch (failure) {
      toastError(failure);
    }
  });
  danger.body.append(h('p', { class: 'hint' }, 'Erases everything on the board. Claiming it again needs USB.'), wipe);

  view.append(
    h('div', { class: 'grid' }, board.el, wifi.el),
    ota.el,
    mqtt.el,
    remote.el,
    logs.el,
    h('div', { class: 'grid' }, restart.el, danger.el),
  );
  logs.start();
  await load(board.body, async () => {
    const info = await rpc('system.info');
    state.info = info;
    const heap = info.heap || {};
    const clock = info.time || {};
    const net = info.wifi || {};
    if (!ssid.value) ssid.value = net.ssid || '';
    for (const [input, value] of [
      [address, net.ip],
      [gateway, net.gateway],
      [netmask, net.netmask],
      [dns, net.dns],
    ]) {
      if (!input.value) input.value = value || '';
    }
    board.body.replaceChildren(
      facts([
        ['Firmware', info.firmware],
        ['Board', info.board],
        ['Chip', info.chip],
        ['ESP-IDF', info.idf],
        ['Uptime', typeof info.uptime === 'number' ? duration(info.uptime) : null],
        [
          'Free memory',
          typeof heap.free === 'number'
            ? `${Math.round(heap.free / 1024)} KiB (lowest ${Math.round((heap.minFree || 0) / 1024)} KiB)`
            : null,
        ],
        ['Clock', clock.synced ? `Synced · ${formatTime(clock.utc)}` : 'Not synced yet'],
        ['Wi-Fi', net.connected ? `${net.ssid} · ${net.ip} · ${net.rssi} dBm` : 'Not connected'],
      ]),
    );
  });
  await load(mqtt.body, async () => {
    const settings = await rpc('mqtt.get');
    const enabled = h('input', { type: 'checkbox', checked: settings.enabled });
    const host = h('input', {
      type: 'text',
      maxlength: '64',
      value: settings.host || '',
      autocomplete: 'off',
      spellcheck: 'false',
    });
    const port = h('input', { type: 'number', min: '1', max: '65535', value: String(settings.port || 1883) });
    const username = h('input', { type: 'text', maxlength: '64', value: settings.username || '', autocomplete: 'off' });
    const secret = h('input', {
      type: 'password',
      maxlength: '64',
      autocomplete: 'new-password',
      placeholder: settings.passwordSet ? 'Unchanged' : '',
    });
    const prefix = h('input', {
      type: 'text',
      maxlength: '32',
      value: settings.prefix || 'homeassistant',
      autocomplete: 'off',
    });
    const save = h('button', { class: 'button small primary', type: 'submit' }, 'Save MQTT');
    const status = h('p', { class: 'muted small', 'aria-live': 'polite' });
    const showStatus = (view) => {
      status.textContent = !view.enabled
        ? 'MQTT is off.'
        : view.connected
          ? 'Connected to the broker.'
          : `Not connected: ${view.problem || 'connecting'}.`;
    };
    showStatus(settings);
    const form = h(
      'form',
      { class: 'stack', 'aria-label': 'MQTT' },
      checkField('Publish to an MQTT broker', enabled),
      h(
        'div',
        { class: 'field-group' },
        field('Broker host', host),
        field('Port', port),
        field('Username', username),
        field(
          'Password',
          secret,
          'A new host, port or username clears the saved password: enter it again when you change them.',
        ),
        field('Discovery prefix', prefix),
      ),
      h('div', { class: 'row' }, save),
    );
    form.addEventListener('submit', async (event) => {
      event.preventDefault();
      const params = {
        enabled: enabled.checked,
        host: host.value.trim(),
        port: Number(port.value),
        username: username.value.trim(),
        prefix: prefix.value.trim(),
      };
      if (secret.value) params.password = secret.value;
      try {
        const view = await pending(save, () => rpc('mqtt.set', params));
        secret.value = '';
        secret.placeholder = view.passwordSet ? 'Unchanged' : '';
        showStatus(view);
        toast('MQTT settings saved');
        setTimeout(() => {
          rpc('mqtt.get').then(showStatus, toastError);
        }, MQTT_STATUS_DELAY_MS);
      } catch (failure) {
        toastError(failure);
      }
    });
    mqtt.body.replaceChildren(
      h(
        'p',
        { class: 'hint' },
        'Off by default. When on, the board announces each lock to Home Assistant and takes lock commands through the same queue.',
      ),
      status,
      form,
    );
  });
  await load(remote.body, () => remoteLogging(remote));
}

function sendFirmware(file, progress, onSent) {
  return new Promise((resolve, reject) => {
    const request = new XMLHttpRequest();
    request.open('POST', '/api/ota');
    request.timeout = OTA_TIMEOUT_MS;
    request.setRequestHeader('Content-Type', 'application/octet-stream');
    request.upload.addEventListener('progress', (event) => {
      if (event.lengthComputable) {
        progress.max = event.total;
        progress.value = event.loaded;
      }
    });
    request.upload.addEventListener('load', onSent);
    request.addEventListener('load', () => {
      let body = null;
      try {
        body = JSON.parse(request.responseText);
      } catch {
        body = null;
      }
      if (body && body.error) {
        const failure = new ApiError(body.error.code, body.error.message);
        if (failure.code === 'unauthorized') sessionLost();
        reject(failure);
      } else if (request.status >= 200 && request.status < 300) {
        resolve((body && body.result) || {});
      } else {
        reject(new ApiError('http', `HTTP ${request.status}`));
      }
    });
    request.addEventListener('error', () => reject(new ApiError('network', 'the upload was interrupted')));
    request.addEventListener('timeout', () => reject(new ApiError('no_reply', 'the upload took too long')));
    request.send(file);
  });
}

async function boot() {
  const startedSession = sessionEpoch;
  try {
    await startApp();
  } catch (failure) {
    if (startedSession !== sessionEpoch || failure.code === 'session_changed') return;
    state.authed = false;
    events.stop();
    if (failure.code === 'unauthorized') {
      showLogin();
      return;
    }
    app.replaceChildren(
      h(
        'main',
        { id: 'main', class: 'login' },
        h(
          'div',
          { class: 'login-card' },
          h('h1', null, 'Cannot reach the board'),
          errorBlock(failure),
          h('button', { class: 'button primary', type: 'button', onclick: () => boot() }, 'Try again'),
        ),
      ),
    );
  }
}

function resync() {
  if (!state.authed || location.hash === '#/pair') return;
  route({ keepDialogs: true });
}

window.addEventListener('hashchange', () => route());
events.watch('reopen', resync);
boot();
