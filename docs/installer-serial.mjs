// SPDX-License-Identifier: GPL-3.0-or-later
const BOARD_ERRORS = new Set([
  'already_claimed', 'bad_request', 'busy', 'conflict', 'internal', 'invalid_argument',
  'not_claimed', 'not_paired', 'recovery_required', 'storage_error', 'storage_full',
  'time_unsynced', 'too_large', 'unauthorized', 'unavailable', 'unknown_method', 'unsupported',
]);

const ERRORS = {
  bad_response: 'The board returned an invalid reply. Reconnect and check its state before continuing.',
  board_error: 'The board rejected the request.',
  board_restarted: 'The board restarted. The request may have completed; reconnect and check its state.',
  busy: 'Wait for the current request to finish.',
  close_failed: 'The USB connection could not close. Unplug and reconnect the board.',
  connect_failed: 'Cannot open the USB connection. Close other serial tools and reconnect the board.',
  disconnected: 'The USB connection ended. Reconnect and check the board before continuing.',
  invalid_request: 'The request is invalid.',
  not_ready: 'The board is still starting.',
  request_too_large: 'The request exceeds the board’s USB limit.',
  response_too_large: 'The board sent an oversized reply. Reconnect before continuing.',
  timeout: 'The board did not reply in time. The request may have completed; reconnect and check its state.',
  write_failed: 'The USB write failed. The request may have completed; reconnect and check its state.',
};

export class RpcError extends Error {
  constructor(code) {
    const safe = Object.hasOwn(ERRORS, code) || BOARD_ERRORS.has(code) ? code : 'board_error';
    super(ERRORS[safe] || ERRORS.board_error);
    this.name = 'RpcError';
    this.code = safe;
  }
}

function within(promise, milliseconds) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new RpcError('close_failed')), milliseconds);
    Promise.resolve(promise).then(
      value => { clearTimeout(timer); resolve(value); },
      error => { clearTimeout(timer); reject(error); },
    );
  });
}

export class SerialRpc {
  #port;
  #onDisconnect;
  #state = 'new';
  #reader = null;
  #writer = null;
  #pending = null;
  #nextId = 1;
  #line = new Uint8Array(32768);
  #length = 0;
  #closing = null;
  #opening = null;
  #opened = false;
  #waitingReady = false;
  #disconnected = () => this.#fail(new RpcError('disconnected'));

  constructor(port, { onDisconnect = () => {} } = {}) {
    this.#port = port;
    this.#onDisconnect = onDisconnect;
  }

  async open() {
    if (this.#state !== 'new') throw new RpcError('disconnected');
    this.#state = 'opening';
    try {
      this.#opening = this.#port.open({ baudRate: 115200 }).then(() => { this.#opened = true; });
      await this.#opening;
      if (this.#state !== 'opening') throw new RpcError('disconnected');
      this.#reader = this.#port.readable.getReader();
      this.#writer = this.#port.writable.getWriter();
      this.#port.addEventListener('disconnect', this.#disconnected);
      this.#state = 'open';
      void this.#read();
    } catch {
      const code = this.#state === 'closed' ? 'disconnected' : 'connect_failed';
      this.#state = 'closed';
      await this.#shutdown().catch(() => {});
      throw new RpcError(code);
    }
  }

  async call(method, params = {}, timeoutMs = 15000) {
    if (this.#waitingReady) throw new RpcError('busy');
    return this.#request(method, params, timeoutMs, false);
  }

  async waitReady(timeoutMs = 45000) {
    if (this.#state !== 'open') throw new RpcError('disconnected');
    if (this.#waitingReady || this.#pending) throw new RpcError('busy');
    if (!Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > 2147483647) {
      throw new RpcError('invalid_request');
    }
    this.#waitingReady = true;
    const deadline = performance.now() + timeoutMs;
    try {
      while (true) {
        const remaining = deadline - performance.now();
        if (remaining <= 0) break;
        try {
          return await this.#request('system.info', {}, Math.min(2000, remaining), true);
        } catch (error) {
          if (error.code !== 'not_ready') throw error;
        }
      }
      const error = new RpcError('timeout');
      this.#fail(error);
      throw error;
    } finally {
      this.#waitingReady = false;
    }
  }

  async #request(method, params, timeoutMs, probe) {
    if (this.#state !== 'open') throw new RpcError('disconnected');
    if (this.#pending) throw new RpcError('busy');
    if (typeof method !== 'string' || !method || !params || typeof params !== 'object' ||
        Array.isArray(params) || !Number.isFinite(timeoutMs) || timeoutMs <= 0 || timeoutMs > 2147483647) {
      throw new RpcError('invalid_request');
    }
    const id = this.#nextId++;
    let bytes;
    try {
      bytes = new TextEncoder().encode(JSON.stringify({ id, method, params }) + '\n');
    } catch {
      throw new RpcError('invalid_request');
    }
    if (bytes.length - 1 > 16384) {
      bytes.fill(0);
      throw new RpcError('request_too_large');
    }
    return new Promise((resolve, reject) => {
      const pending = { id, resolve, reject, written: false, reply: null, probe };
      pending.timer = setTimeout(() => {
        if (pending.probe && pending.written) this.#reject(new RpcError('not_ready'));
        else this.#fail(new RpcError('timeout'));
      }, timeoutMs);
      this.#pending = pending;
      this.#writer.write(bytes).then(() => {
        bytes.fill(0);
        pending.written = true;
        this.#settle(pending);
      }, () => {
        bytes.fill(0);
        this.#fail(new RpcError('write_failed'));
      });
    });
  }

  async close() {
    this.#state = 'closed';
    this.#reject(new RpcError('disconnected'));
    await this.#shutdown();
  }

  #reject(error) {
    const pending = this.#pending;
    this.#pending = null;
    if (!pending) return;
    clearTimeout(pending.timer);
    pending.reply = null;
    pending.reject(error);
  }

  #fail(error) {
    if (this.#state !== 'open') return;
    this.#state = 'closed';
    this.#reject(error);
    void this.#shutdown().catch(() => {});
    try { this.#onDisconnect(error); } catch {}
  }

  #settle(pending) {
    if (this.#pending !== pending || !pending.written || !pending.reply) return;
    this.#pending = null;
    clearTimeout(pending.timer);
    const reply = pending.reply;
    pending.reply = null;
    if (reply.error) pending.reject(reply.error);
    else pending.resolve(reply.result);
  }

  #accept(text) {
    if (this.#pending && /^#.*\blatchkey \S+ board=/.test(text)) {
      if (this.#pending.probe) {
        this.#pending.reply = { error: new RpcError('not_ready') };
        this.#settle(this.#pending);
        return;
      }
      this.#fail(new RpcError('board_restarted'));
      return;
    }
    if (!this.#pending || !text.startsWith('{')) return;
    let message;
    try { message = JSON.parse(text); } catch { return; }
    if (!message || typeof message !== 'object' || Object.hasOwn(message, 'event') || message.id !== this.#pending.id) return;
    const result = Object.hasOwn(message, 'result');
    const error = Object.hasOwn(message, 'error');
    if (result === error || (error && (!message.error || typeof message.error !== 'object'))) {
      this.#fail(new RpcError('bad_response'));
      return;
    }
    this.#pending.reply = error
      ? { error: new RpcError(BOARD_ERRORS.has(message.error.code) ? message.error.code : 'board_error') }
      : { result: message.result };
    this.#settle(this.#pending);
  }

  async #read() {
    const reader = this.#reader;
    const decoder = new TextDecoder('utf-8', { fatal: true });
    try {
      while (this.#state === 'open') {
        const { value, done } = await reader.read();
        if (done) {
          this.#fail(new RpcError('disconnected'));
          return;
        }
        for (const byte of value) {
          if (this.#state !== 'open') return;
          if (byte === 10) {
            let text = '';
            try { text = decoder.decode(this.#line.subarray(0, this.#length)).replace(/\r$/, ''); } catch {}
            this.#line.fill(0, 0, this.#length);
            this.#length = 0;
            this.#accept(text);
          } else {
            if (this.#length === this.#line.length) {
              this.#fail(new RpcError('response_too_large'));
              return;
            }
            this.#line[this.#length++] = byte;
          }
        }
      }
    } catch {
      this.#fail(new RpcError('disconnected'));
    } finally {
      reader.releaseLock();
      if (this.#reader === reader) this.#reader = null;
      this.#line.fill(0);
      this.#length = 0;
    }
  }

  #shutdown() {
    if (this.#closing) return this.#closing;
    this.#closing = this.#release();
    return this.#closing;
  }

  async #release() {
    if (this.#opening) await this.#opening.catch(() => {});
    this.#port.removeEventListener('disconnect', this.#disconnected);
    const reader = this.#reader;
    const writer = this.#writer;
    this.#writer = null;
    if (writer) {
      void writer.abort().catch(() => {});
      writer.releaseLock();
    }
    if (reader) {
      await within(reader.cancel(), 2000).catch(() => {});
      reader.releaseLock();
      if (this.#reader === reader) this.#reader = null;
    }
    this.#line.fill(0);
    this.#length = 0;
    if (!this.#opened) return;
    this.#opened = false;
    try { await within(this.#port.close(), 2000); } catch { throw new RpcError('close_failed'); }
  }
}
