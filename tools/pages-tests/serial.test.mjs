// SPDX-License-Identifier: GPL-3.0-or-later
import assert from 'node:assert/strict';
import { setImmediate } from 'node:timers/promises';
import test from 'node:test';

import { RpcError, SerialRpc } from '../../docs/installer-serial.mjs';

class Port extends EventTarget {
  writes = [];
  closes = 0;
  options = null;
  onWrite = () => {};
  readable = new ReadableStream({ start: controller => { this.input = controller; } });
  writable = new WritableStream({
    write: bytes => {
      const request = JSON.parse(new TextDecoder().decode(bytes));
      this.writes.push(request);
      return this.onWrite(request);
    },
  });

  async open(options) { this.options = options; }
  async close() { this.closes++; }
  push(text) { this.input.enqueue(new TextEncoder().encode(text)); }
  reply(id, result) { this.push(JSON.stringify({ id, result }) + '\n'); }
}

async function connected(t, options = {}) {
  const port = new Port();
  const client = new SerialRpc(port, options);
  await client.open();
  t.after(() => client.close());
  return { port, client };
}

test('opens at the firmware baud rate and returns only the matching response', async t => {
  const { port, client } = await connected(t);
  port.onWrite = ({ id }) => {
    port.push('# diagnostic\r\nnot json\n[1,2]\n');
    port.push(JSON.stringify({ event: 'lock.state', id, result: 'ignore' }) + '\n');
    port.reply(id + 1, 'wrong request');
    port.push(`{"id":${id},"res`);
    port.push('ult":{"claimed":false}}\r\n');
  };
  assert.deepEqual(port.options, { baudRate: 115200 });
  assert.deepEqual(await client.call('system.info'), { claimed: false });
  assert.deepEqual(port.writes, [{ id: 1, method: 'system.info', params: {} }]);
});

test('accepts UTF-8 split across serial chunks', async t => {
  const { port, client } = await connected(t);
  port.onWrite = ({ id }) => {
    const bytes = new TextEncoder().encode(JSON.stringify({ id, result: 'São' }) + '\n');
    for (const byte of bytes) port.input.enqueue(Uint8Array.of(byte));
  };
  assert.equal(await client.call('system.info'), 'São');
});

test('rejects simultaneous calls without writing a second request', async t => {
  const { port, client } = await connected(t);
  const pending = client.call('system.info');
  await assert.rejects(client.call('system.info'), error => error.code === 'busy');
  await setImmediate();
  port.reply(1, {});
  await pending;
  assert.equal(port.writes.length, 1);
});

test('known board errors retain their code but discard arbitrary message and data', async t => {
  const { port, client } = await connected(t);
  port.onWrite = ({ id }) => port.push(JSON.stringify({
    id, error: { code: 'already_claimed', message: 'fixture-sensitive-value', extra: 'fixture-sensitive-value' },
  }) + '\n');
  await assert.rejects(client.call('system.setup'), error => {
    assert.ok(error instanceof RpcError);
    assert.equal(error.code, 'already_claimed');
    assert.ok(!String(error).includes('fixture-sensitive-value'));
    assert.ok(!JSON.stringify(error).includes('fixture-sensitive-value'));
    return true;
  });
  port.onWrite = ({ id }) => port.reply(id, { claimed: true });
  assert.deepEqual(await client.call('system.info'), { claimed: true });
});

test('unknown board error codes are not echoed', async t => {
  const { port, client } = await connected(t);
  port.onWrite = ({ id }) => port.push(JSON.stringify({ id, error: { code: 'fixture_sensitive_value' } }) + '\n');
  await assert.rejects(client.call('keys.import'), error => error.code === 'board_error');
});

test('response timeout closes the connection and never retries a mutation', async t => {
  const events = [];
  const { port, client } = await connected(t, { onDisconnect: error => events.push(error.code) });
  await assert.rejects(client.call('system.setup', { password: 'fixture-password' }, 10), error => error.code === 'timeout');
  await assert.rejects(client.call('system.setup'), error => error.code === 'disconnected');
  await client.close();
  assert.equal(port.writes.length, 1);
  assert.equal(port.closes, 1);
  assert.deepEqual(events, ['timeout']);
  assert.equal(port.readable.locked, false);
  assert.equal(port.writable.locked, false);
});

test('write failures expose no driver detail and poison the connection', async t => {
  const { port, client } = await connected(t);
  port.onWrite = () => { throw new Error('fixture-sensitive-driver-detail'); };
  await assert.rejects(client.call('keys.import'), error => {
    assert.equal(error.code, 'write_failed');
    assert.ok(!String(error).includes('fixture-sensitive-driver-detail'));
    return true;
  });
  await assert.rejects(client.call('system.info'), error => error.code === 'disconnected');
});

test('a stalled write is bounded by the request deadline', async t => {
  const { port, client } = await connected(t);
  port.onWrite = () => new Promise(() => {});
  await assert.rejects(client.call('keys.import', {}, 10), error => error.code === 'timeout');
  await client.close();
  assert.equal(port.writes.length, 1);
  assert.equal(port.writable.locked, false);
});

test('read failure rejects the pending call and notifies once', async t => {
  const events = [];
  const { port, client } = await connected(t, { onDisconnect: error => events.push(error.code) });
  port.onWrite = () => port.input.error(new Error('fixture-sensitive-driver-detail'));
  await assert.rejects(client.call('keys.import'), error => error.code === 'disconnected');
  await client.close();
  assert.deepEqual(events, ['disconnected']);
  assert.equal(port.closes, 1);
});

test('end of stream closes an idle connection', async t => {
  const events = [];
  const { port, client } = await connected(t, { onDisconnect: error => events.push(error.code) });
  port.input.close();
  await setImmediate();
  await assert.rejects(client.call('system.info'), error => error.code === 'disconnected');
  assert.deepEqual(events, ['disconnected']);
});

test('a port disconnect event rejects a call even before the stream ends', async t => {
  const { port, client } = await connected(t);
  port.onWrite = () => port.dispatchEvent(new Event('disconnect'));
  await assert.rejects(client.call('keys.import', {}, 100), error => error.code === 'disconnected');
});

test('a boot banner during a mutation makes its result uncertain', async t => {
  const { port, client } = await connected(t);
  port.onWrite = () => port.push('# I (150) main: latchkey 0.7.0 board=esp32 chip=ESP32\n');
  await assert.rejects(client.call('keys.import'), error => error.code === 'board_restarted');
  await assert.rejects(client.call('system.info'), error => error.code === 'disconnected');
});

test('oversized incoming lines fail clearly without storing unbounded input', async t => {
  const { port, client } = await connected(t);
  port.onWrite = () => port.push('x'.repeat(32769));
  await assert.rejects(client.call('system.info'), error => error.code === 'response_too_large');
});

test('the 32 KiB bound applies per line, not per read chunk', async t => {
  const { port, client } = await connected(t);
  port.onWrite = ({ id }) => {
    port.push(('# ' + 'x'.repeat(254) + '\n').repeat(130) + JSON.stringify({ id, result: {} }) + '\n');
  };
  assert.deepEqual(await client.call('system.info'), {});
});

test('oversized UTF-8 requests are rejected before writing and leave the connection usable', async t => {
  const { port, client } = await connected(t);
  await assert.rejects(client.call('keys.import', { backup: 'é'.repeat(8192) }), error => error.code === 'request_too_large');
  assert.equal(port.writes.length, 0);
  port.onWrite = ({ id }) => port.reply(id, {});
  assert.deepEqual(await client.call('system.info'), {});
});

test('invalid request inputs fail without leaking serialization details', async t => {
  const { port, client } = await connected(t);
  const params = {};
  params['fixture-sensitive-value'] = params;
  for (const args of [['system.info', params], ['', {}], ['system.info', []], ['system.info', {}, 0]]) {
    await assert.rejects(client.call(...args), error => {
      assert.equal(error.code, 'invalid_request');
      assert.ok(!String(error).includes('fixture-sensitive-value'));
      return true;
    });
  }
  assert.equal(port.writes.length, 0);
});

test('malformed matching replies close the connection instead of claiming success', async t => {
  const { port, client } = await connected(t);
  port.onWrite = ({ id }) => port.push(JSON.stringify({ id }) + '\n');
  await assert.rejects(client.call('system.setup'), error => error.code === 'bad_response');
});

test('explicit close cancels a pending call, releases locks, and is idempotent', async t => {
  const events = [];
  const { port, client } = await connected(t, { onDisconnect: error => events.push(error.code) });
  const pending = client.call('system.info');
  const rejected = assert.rejects(pending, error => error.code === 'disconnected');
  await client.close();
  await rejected;
  await client.close();
  assert.equal(port.closes, 1);
  assert.equal(port.readable.locked, false);
  assert.equal(port.writable.locked, false);
  assert.deepEqual(events, []);
});

test('open errors are safe and a closed instance cannot reopen', async () => {
  const port = new Port();
  port.open = async () => { throw new Error('fixture-sensitive-driver-detail'); };
  const client = new SerialRpc(port);
  await assert.rejects(client.open(), error => error.code === 'connect_failed' && !String(error).includes('fixture-sensitive'));
  await assert.rejects(client.open(), error => error.code === 'disconnected');
  await client.close();
});

test('closing during open prevents a late connection from becoming usable', async () => {
  const port = new Port();
  let finish;
  port.open = () => new Promise(resolve => { finish = resolve; });
  const client = new SerialRpc(port);
  const opened = assert.rejects(client.open(), error => error.code === 'disconnected');
  const closed = client.close();
  finish();
  await Promise.all([opened, closed]);
  assert.equal(port.closes, 1);
  await assert.rejects(client.call('system.info'), error => error.code === 'disconnected');
});

test('waitReady survives startup banners on the same open port using only system.info', async t => {
  const events = [];
  const { port, client } = await connected(t, { onDisconnect: error => events.push(error.code) });
  port.onWrite = ({ id }) => {
    if (port.writes.length === 1) port.push('# I (150) main: latchkey 0.7.0 board=esp32 chip=ESP32\n');
    else port.reply(id, { claimed: false });
  };
  assert.deepEqual(await client.waitReady(), { claimed: false });
  assert.deepEqual(port.writes, [
    { id: 1, method: 'system.info', params: {} },
    { id: 2, method: 'system.info', params: {} },
  ]);
  assert.deepEqual(events, []);
  assert.equal(port.closes, 0);
});

test('waitReady retries a fully written unanswered probe and ignores its late reply', async t => {
  const { port, client } = await connected(t);
  port.onWrite = ({ id }) => {
    if (port.writes.length === 1) return;
    port.reply(id - 1, { stale: true });
    port.reply(id, { claimed: false });
  };
  assert.deepEqual(await client.waitReady(4000), { claimed: false });
  assert.equal(port.writes.length, 2);
  assert.equal(port.closes, 0);
});

test('waitReady overall timeout closes the connection and reports once', async t => {
  const events = [];
  const { port, client } = await connected(t, { onDisconnect: error => events.push(error.code) });
  await assert.rejects(client.waitReady(20), error => error.code === 'timeout');
  await client.close();
  assert.ok(port.writes.every(request => request.method === 'system.info'));
  assert.equal(port.closes, 1);
  assert.deepEqual(events, ['timeout']);
});

test('waitReady never overlaps a probe whose write is still pending', async t => {
  const { port, client } = await connected(t);
  let finish;
  port.onWrite = ({ id }) => {
    if (port.writes.length > 1) { port.reply(id, {}); return; }
    port.push('# latchkey 0.7.0 board=esp32\n');
    return new Promise(resolve => { finish = resolve; });
  };
  const ready = client.waitReady();
  await setImmediate();
  await assert.rejects(client.call('system.setup'), error => error.code === 'busy');
  await assert.rejects(client.waitReady(), error => error.code === 'busy');
  assert.equal(port.writes.length, 1);
  finish();
  assert.deepEqual(await ready, {});
  assert.equal(port.writes.length, 2);
});

test('waitReady does not retry a stalled write', async t => {
  const { port, client } = await connected(t);
  port.onWrite = () => new Promise(() => {});
  await assert.rejects(client.waitReady(20), error => error.code === 'timeout');
  await assert.rejects(client.waitReady(), error => error.code === 'disconnected');
  assert.equal(port.writes.length, 1);
});

test('waitReady does not retry a write failure or disconnect', async t => {
  for (const disconnected of [false, true]) {
    const { port, client } = await connected(t);
    port.onWrite = () => {
      if (disconnected) port.dispatchEvent(new Event('disconnect'));
      else throw new Error('fixture-driver-failure');
    };
    const code = disconnected ? 'disconnected' : 'write_failed';
    await assert.rejects(client.waitReady(), error => error.code === code);
    assert.equal(port.writes.length, 1);
  }
});

test('waitReady rejects invalid deadlines without making requests', async t => {
  const { port, client } = await connected(t);
  for (const timeout of [0, -1, NaN, Infinity, 2147483648]) {
    await assert.rejects(client.waitReady(timeout), error => error.code === 'invalid_request');
  }
  assert.equal(port.writes.length, 0);
});

test('waitReady reports timeout when the deadline passes between probes', async t => {
  const { client } = await connected(t);
  const readings = [0, 0.5, 2];
  t.mock.method(performance, 'now', () => readings.length ? readings.shift() : 2);
  await assert.rejects(client.waitReady(1), error => error.code === 'timeout');
});

test('a mutation after waitReady still fails on a restart without retrying', async t => {
  const { port, client } = await connected(t);
  port.onWrite = ({ id, method }) => {
    if (method === 'system.info') port.reply(id, {});
    else port.push('# latchkey 0.7.0 board=esp32\n');
  };
  await client.waitReady();
  await assert.rejects(client.call('system.setup'), error => error.code === 'board_restarted');
  assert.deepEqual(port.writes.map(request => request.method), ['system.info', 'system.setup']);
});
