#!/usr/bin/env node
/**
 * Captures README screenshots of the `serve` web chat UI: starts two local
 * chat servers (Alice and Bob) with fresh identities, exchanges a few real
 * authcrypted messages through their APIs, then renders each UI in headless
 * Chrome over the DevTools protocol (seeding the API token the UI would
 * otherwise prompt for).
 *
 * Usage: npm run build && node scripts/screenshots.mjs [--chrome <path>] [--out docs/images]
 */
import { spawn } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..');
const { values: args } = parseArgs({
  options: {
    chrome: { type: 'string', default: '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome' },
    out: { type: 'string', default: join(REPO, 'docs/images') },
  },
});
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const children = [];
const dirs = [];

function startServer(name, port) {
  const cwd = mkdtempSync(join(tmpdir(), `didcomm-ts-shot-${name}-`));
  dirs.push(cwd);
  const child = spawn(process.execPath, [join(REPO, 'dist/chat/cli.js'), 'serve', String(port)], { cwd, stdio: ['ignore', 'pipe', 'pipe'] });
  children.push(child);
  return new Promise((resolveToken, reject) => {
    let stderr = '';
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
      const match = stderr.match(/API token: ([0-9a-f]{64})/);
      if (match) resolveToken({ port, token: match[1] });
    });
    child.once('exit', (code) => reject(new Error(`${name} server exited ${code}: ${stderr}`)));
  });
}

async function api(server, path, body) {
  const res = await fetch(`http://127.0.0.1:${server.port}${path}`, {
    method: body ? 'POST' : 'GET',
    headers: { authorization: `Bearer ${server.token}`, 'content-type': 'application/json' },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
  if (!res.ok) throw new Error(`${path} -> HTTP ${res.status}: ${await res.text()}`);
  return res.json();
}

async function cdpSession(port) {
  for (let i = 0; i < 50; i++) {
    try {
      const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
      const page = targets.find((t) => t.type === 'page');
      if (page) {
        const ws = new WebSocket(page.webSocketDebuggerUrl);
        await new Promise((r, j) => ((ws.onopen = r), (ws.onerror = j)));
        let id = 0;
        const pending = new Map();
        ws.onmessage = (event) => {
          const msg = JSON.parse(event.data);
          if (msg.id && pending.has(msg.id)) {
            const { res, rej } = pending.get(msg.id);
            pending.delete(msg.id);
            msg.error ? rej(new Error(msg.error.message)) : res(msg.result);
          }
        };
        const send = (method, params = {}) =>
          new Promise((res, rej) => {
            pending.set(++id, { res, rej });
            ws.send(JSON.stringify({ id, method, params }));
          });
        return { send, close: () => ws.close() };
      }
    } catch {
      // Chrome not ready yet.
    }
    await sleep(100);
  }
  throw new Error('Chrome DevTools endpoint did not come up');
}

async function capture(server, file) {
  const debugPort = 9300 + Math.floor(Math.random() * 500);
  const profile = mkdtempSync(join(tmpdir(), 'didcomm-ts-chrome-'));
  dirs.push(profile);
  const chrome = spawn(args.chrome, [
    '--headless=new',
    `--remote-debugging-port=${debugPort}`,
    `--user-data-dir=${profile}`,
    '--hide-scrollbars',
    '--force-device-scale-factor=2',
    'about:blank',
  ]);
  children.push(chrome);
  const cdp = await cdpSession(debugPort);
  await cdp.send('Emulation.setDeviceMetricsOverride', { width: 900, height: 760, deviceScaleFactor: 2, mobile: false });
  await cdp.send('Page.enable');
  await cdp.send('Page.addScriptToEvaluateOnNewDocument', {
    source: `sessionStorage.setItem('didcomm-ts-api-token', ${JSON.stringify(server.token)});`,
  });
  await cdp.send('Page.navigate', { url: `http://127.0.0.1:${server.port}/` });
  await sleep(2500);
  const { data } = await cdp.send('Page.captureScreenshot', { format: 'png' });
  writeFileSync(file, Buffer.from(data, 'base64'));
  cdp.close();
  chrome.kill();
}

try {
  mkdirSync(resolve(args.out), { recursive: true });
  const [alice, bob] = await Promise.all([startServer('alice', 8701), startServer('bob', 8702)]);
  const aliceDid = (await api(alice, '/api/identity')).did;
  const bobDid = (await api(bob, '/api/identity')).did;
  const toBob = { peerDid: bobDid, endpoint: `http://127.0.0.1:${bob.port}/` };
  const toAlice = { peerDid: aliceDid, endpoint: `http://127.0.0.1:${alice.port}/` };
  await api(alice, '/api/send', { ...toBob, text: 'Hi Bob, this message is authcrypted end to end (ECDH-1PU + A256KW, A256CBC-HS512).' });
  await sleep(300);
  await api(bob, '/api/send', { ...toAlice, text: 'Got it, and decrypted with zero runtime dependencies.' });
  await sleep(300);
  await api(alice, '/api/send', { ...toBob, text: 'Same envelopes interoperate with didcomm-rust and didcomm-python.' });
  await sleep(500);
  await capture(alice, join(resolve(args.out), 'chat-alice.png'));
  await capture(bob, join(resolve(args.out), 'chat-bob.png'));
  console.log(`wrote ${join(args.out, 'chat-alice.png')} and chat-bob.png`);
} finally {
  for (const child of children) child.kill();
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
}
