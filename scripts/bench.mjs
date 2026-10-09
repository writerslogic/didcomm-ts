#!/usr/bin/env node
/**
 * Throughput benchmark: didcomm-ts vs didcomm-rust (the `didcomm` WASM
 * package, a dev dependency) on identical keys, DID Docs and messages.
 *
 * Usage: npm run build && node scripts/bench.mjs [--seconds 0.25] [--samples 15] [--size 1024]
 * Prints a JSON report: per-operation median/min/max ops/s over `samples`
 * interleaved timed windows.
 */
import { generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { cpus, platform, arch } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseArgs } from 'node:util';
import { Message } from 'didcomm';

const DIST = join(dirname(fileURLToPath(import.meta.url)), '..', 'dist');
const ours = await import(join(DIST, 'core/index.js'));
const { values: args } = parseArgs({
  options: {
    seconds: { type: 'string', default: '0.25' },
    samples: { type: 'string', default: '15' },
    size: { type: 'string', default: '1024' },
  },
});
const WINDOW_MS = Number(args.seconds) * 1000;
const SAMPLES = Number(args.samples);

function party(name, curve) {
  const did = `did:example:${name}`;
  const kid = `${did}#key-1`;
  const { publicKey, privateKey } =
    curve === 'X25519' ? generateKeyPairSync('x25519') : generateKeyPairSync('ec', { namedCurve: curve });
  return {
    did,
    doc: {
      id: did,
      keyAgreement: [kid],
      authentication: [],
      verificationMethod: [{ id: kid, type: 'JsonWebKey2020', controller: did, publicKeyJwk: publicKey.export({ format: 'jwk' }) }],
      service: [],
    },
    secret: { id: kid, type: 'JsonWebKey2020', privateKeyJwk: privateKey.export({ format: 'jwk' }) },
  };
}

function resolvers(docs, secrets) {
  return {
    did: { resolve: async (did) => docs.find((d) => d.id === did) ?? null },
    secrets: {
      get_secret: async (id) => secrets.find((s) => s.id === id) ?? null,
      find_secrets: async (ids) => ids.filter((id) => secrets.some((s) => s.id === id)),
    },
  };
}

const rust = {
  async pack(msg, to, from, r) {
    const m = new Message(msg);
    try {
      const [packed] = await m.pack_encrypted(to, from, null, r.did, r.secrets, { forward: false });
      return packed;
    } finally {
      m.free();
    }
  },
  async unpack(envelope, r) {
    const [m] = await Message.unpack(envelope, r.did, r.secrets, { expect_decrypt_by_all_keys: false, unwrap_re_wrapping_forward: false });
    m.free();
  },
};
const ts = {
  pack: (msg, to, from, r) => (from ? ours.packAuthcrypt(msg, [to], from, r) : ours.packAnoncrypt(msg, [to], r)),
  unpack: (envelope, r) => ours.unpack(envelope, r),
};

async function window(fn) {
  let ops = 0;
  const start = performance.now();
  while (performance.now() - start < WINDOW_MS) {
    await fn();
    ops++;
  }
  return (ops * 1000) / (performance.now() - start);
}

const median = (xs) => Math.round([...xs].sort((a, b) => a - b)[Math.floor(xs.length / 2)]);

/**
 * Interleaves timed windows of every operation so drift (thermal, GC, JIT)
 * hits all implementations alike; reports the median and min/max per op.
 */
async function compare(ops) {
  for (const fn of Object.values(ops)) for (let i = 0; i < 50; i++) await fn();
  const samples = Object.fromEntries(Object.keys(ops).map((k) => [k, []]));
  for (let s = 0; s < SAMPLES; s++) {
    for (const [name, fn] of Object.entries(ops)) samples[name].push(await window(fn));
  }
  return Object.fromEntries(
    Object.entries(samples).map(([k, xs]) => [k, { median: median(xs), min: Math.round(Math.min(...xs)), max: Math.round(Math.max(...xs)) }]),
  );
}

const results = [];
for (const curve of ['X25519', 'P-256']) {
  const alice = party('alice', curve);
  const bob = party('bob', curve);
  const docs = [alice.doc, bob.doc];
  const sender = resolvers(docs, [alice.secret]);
  const recipient = resolvers(docs, [bob.secret]);
  for (const mode of ['authcrypt', 'anoncrypt']) {
    const from = mode === 'authcrypt' ? alice.did : null;
    const msg = {
      id: randomUUID(),
      typ: 'application/didcomm-plain+json',
      type: 'https://didcomm.org/basicmessage/2.0/message',
      ...(from ? { from } : {}),
      to: [bob.did],
      body: { content: randomBytes(Number(args.size) / 2).toString('hex') },
    };
    const tsEnvelope = await ts.pack(msg, bob.did, from, sender);
    const rustEnvelope = await rust.pack(msg, bob.did, from, sender);
    const measured = await compare({
      tsPack: () => ts.pack(msg, bob.did, from, sender),
      rustPack: () => rust.pack(msg, bob.did, from, sender),
      tsUnpack: () => ts.unpack(tsEnvelope, recipient),
      rustUnpack: () => rust.unpack(rustEnvelope, recipient),
    });
    results.push({ curve, mode, opsPerSec: measured });
  }
}

console.log(
  JSON.stringify(
    {
      node: process.version,
      platform: `${platform()} ${arch()}`,
      cpu: cpus()[0]?.model,
      messageBytes: Number(args.size),
      windowMs: WINDOW_MS,
      samples: SAMPLES,
      results,
    },
    null,
    2,
  ),
);
