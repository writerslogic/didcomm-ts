/** Protocol-level checks for the dependency-free HTTP and WebSocket receivers. */
import { request } from 'node:http';
import { connect as netConnect, type Socket } from 'node:net';
import { randomBytes } from 'node:crypto';
import { listenHttp } from '../src/transport/http.js';
import { listen as listenWs, connect as connectWs } from '../src/transport/websocket.js';

function clientFrame(opcode: number, payload: Uint8Array, { fin = true, mask = true } = {}): Buffer {
  const len = payload.length;
  const lenBytes = len < 126 ? [len] : len < 65536 ? [126, len >> 8, len & 0xff] : [127, 0, 0, 0, 0, (len >>> 24) & 0xff, (len >> 16) & 0xff, (len >> 8) & 0xff, len & 0xff];
  const head = Buffer.from([(fin ? 0x80 : 0) | opcode, (mask ? 0x80 : 0) | lenBytes[0], ...lenBytes.slice(1)]);
  if (!mask) return Buffer.concat([head, payload]);
  const key = randomBytes(4);
  const body = Buffer.from(payload).map((b, i) => b ^ key[i & 3]);
  return Buffer.concat([head, key, body]);
}

async function rawWs(port: number): Promise<{ socket: Socket; received: () => Buffer }> {
  const socket = netConnect(port, '127.0.0.1');
  let data = Buffer.alloc(0);
  socket.on('data', (chunk) => (data = Buffer.concat([data, chunk])));
  await new Promise((r) => socket.once('connect', r));
  socket.write(
    'GET / HTTP/1.1\r\nHost: x\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n' +
      `Sec-WebSocket-Key: ${randomBytes(16).toString('base64')}\r\nSec-WebSocket-Version: 13\r\n\r\n`,
  );
  await waitFor(() => data.includes('\r\n\r\n'));
  expect(data.toString()).toContain('101 Switching Protocols');
  const headerEnd = data.indexOf('\r\n\r\n') + 4;
  return { socket, received: () => data.subarray(headerEnd) };
}

async function waitFor(check: () => boolean, ms = 2000): Promise<void> {
  const deadline = Date.now() + ms;
  while (!check()) {
    if (Date.now() > deadline) throw new Error('timed out');
    await new Promise((r) => setTimeout(r, 10));
  }
}

describe('WebSocket server', () => {
  test('reassembles fragmented messages and answers pings', async () => {
    const messages: Uint8Array[] = [];
    const server = await listenWs(0, (bytes) => void messages.push(bytes));
    const { socket, received } = await rawWs(server.port);
    socket.write(clientFrame(0x2, Buffer.from('hel'), { fin: false }));
    socket.write(clientFrame(0x9, Buffer.from('p')));
    socket.write(clientFrame(0x0, Buffer.from('lo')));
    await waitFor(() => messages.length === 1);
    expect(Buffer.from(messages[0]).toString()).toBe('hello');
    expect(received().subarray(0, 3)).toEqual(Buffer.from([0x8a, 0x01, 0x70]));
    socket.destroy();
    await server.close();
  });

  test.each([
    ['unmasked client frame', clientFrame(0x2, Buffer.from('x'), { mask: false }), 1002],
    ['continuation without a start frame', clientFrame(0x0, Buffer.from('x')), 1002],
    ['message over the size limit', clientFrame(0x2, randomBytes(2000)), 1009],
  ])('closes on %s', async (_name, bytes, code) => {
    const messages: Uint8Array[] = [];
    const server = await listenWs(0, (b) => void messages.push(b), { maxMessageBytes: 1024 });
    const { socket, received } = await rawWs(server.port);
    socket.write(bytes);
    await waitFor(() => received().length >= 4);
    expect(received()[0]).toBe(0x88);
    expect(received().readUInt16BE(2)).toBe(code);
    expect(messages).toHaveLength(0);
    socket.destroy();
    await server.close();
  });

  test('large binary messages round-trip through the built-in client', async () => {
    const messages: Uint8Array[] = [];
    const server = await listenWs(0, (b) => void messages.push(b));
    const client = await connectWs(`ws://127.0.0.1:${server.port}`);
    const payload = randomBytes(300_000);
    client.send(payload);
    await waitFor(() => messages.length === 1);
    expect(Buffer.from(messages[0]).equals(payload)).toBe(true);
    await client.close();
    await server.close();
  });
});

describe('HTTP receiver', () => {
  test('enforces method, path and body limits', async () => {
    const { port, close } = await listenHttp(0, () => {}, { maxBodyBytes: 1024 });
    const url = `http://127.0.0.1:${port}/`;
    const ct = { 'content-type': 'application/didcomm-encrypted+json' };
    expect((await fetch(url)).status).toBe(405);
    expect((await fetch(`${url}other`, { method: 'POST', headers: ct, body: 'x' })).status).toBe(404);
    expect((await fetch(url, { method: 'POST', headers: ct, body: randomBytes(2048) })).status).toBe(413);
    expect((await fetch(url, { method: 'POST', headers: ct, body: '' })).status).toBe(400);
    expect((await fetch(url, { method: 'POST', headers: { 'content-type': 'text/plain' }, body: 'x' })).status).toBe(415);
    expect((await fetch(url, { method: 'POST', headers: ct, body: '{}' })).status).toBe(202);
    await close();
  });

  test('rejects an oversized chunked upload mid-stream and closes the connection', async () => {
    let called = false;
    const { port, close } = await listenHttp(0, () => void (called = true), { maxBodyBytes: 1024 });
    const status = await new Promise<number>((resolve, reject) => {
      const req = request({ port, method: 'POST', path: '/', headers: { 'content-type': 'application/didcomm-encrypted+json' } }, (res) => {
        res.resume();
        resolve(res.statusCode ?? 0);
      });
      req.on('error', reject);
      for (let i = 0; i < 4; i++) req.write(randomBytes(512));
      req.end();
    });
    expect(status).toBe(413);
    expect(called).toBe(false);
    await close();
  });
});
