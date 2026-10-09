// Probes interop with aviarytech/didcomm (@aviarytech/didcomm-core 0.1.35, the
// only published version), which supports anoncrypt over X25519 only. Runs
// both directions against the pure backend and, as a control, against
// didcomm-rust (WASM), and prints one JSON result per cell.
// Usage (after `npm run build` at the repo root): node test/interop/aviary/probe.mjs
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const here = dirname(fileURLToPath(import.meta.url));
const require = createRequire(join(here, 'package.json'));
const { DIDCommCore } = require('@aviarytech/didcomm-core');
// @aviarytech/did-core's DIDDocument is unusable at runtime for JsonWebKey2020
// methods (its crypto-interfaces module exports no JsonWebKey constructor), so
// key agreement keys are wrapped directly with crypto-core's JsonWebKey, the
// same class @aviarytech/did-secrets uses.
const { JsonWebKey } = require('@aviarytech/crypto-core');
const { Secret } = require('@aviarytech/did-secrets');
const repo = join(here, '../../..');
const pure = await import(join(repo, 'dist/core/pure/index.js'));
const wasm = await import(join(repo, 'dist/core/envelope.js'));

const did = `did:example:bob${randomUUID().replace(/-/g, '')}`;
const kid = `${did}#ka-1`;
const { publicKey, privateKey } = generateKeyPairSync('x25519');
const publicKeyJwk = publicKey.export({ format: 'jwk' });
const privateKeyJwk = privateKey.export({ format: 'jwk' });
const vm = { id: kid, type: 'JsonWebKey2020', controller: did, publicKeyJwk };

const aviary = new DIDCommCore(
  {
    resolve: async () => ({
      getAllKeyAgreements: () => [{ id: kid, asJsonWebKey: async () => new JsonWebKey(kid, did, publicKeyJwk, null) }],
    }),
  },
  { resolve: async (id) => (id === kid ? new Secret({ id: kid, type: 'JsonWebKey2020', publicKeyJwk, privateKeyJwk }) : null) },
);
const ours = {
  did: {
    resolve: async (d) =>
      d === did ? { id: did, keyAgreement: [kid], authentication: [], verificationMethod: [vm], service: [] } : null,
  },
  secrets: {
    get_secret: async (id) => (id === kid ? { id: kid, type: 'JsonWebKey2020', privateKeyJwk } : null),
    find_secrets: async (ids) => ids.filter((id) => id === kid),
  },
};
const message = () => ({
  id: randomUUID(),
  typ: 'application/didcomm-plain+json',
  type: 'https://didcomm.org/basicmessage/2.0/message',
  to: [did],
  body: { content: 'hello' },
});

async function cell(name, run) {
  try {
    const detail = await run();
    console.log(JSON.stringify({ cell: name, ok: true, detail }));
  } catch (err) {
    console.log(JSON.stringify({ cell: name, ok: false, error: String(err?.message ?? err).slice(0, 200) }));
  }
}

const aviaryEnvelope = await aviary.packMessage(did, message());
const aviaryHeader = JSON.parse(Buffer.from(aviaryEnvelope.protected, 'base64url').toString());
console.log(JSON.stringify({ aviaryProtectedHeader: aviaryHeader, aviaryRecipientHeader: Object.keys(aviaryEnvelope.recipients[0].header) }));

for (const [name, backend] of [['pure', pure], ['wasm', wasm]]) {
  await cell(`aviary -> ${name}`, async () => (await backend.unpack(JSON.stringify(aviaryEnvelope), ours)).message.id);
  await cell(`${name} -> aviary`, async () => {
    const packed = await backend.packAnoncrypt(message(), [did], { ...ours, anoncryptEnc: 'XC20P' });
    const result = await aviary.unpackMessage(JSON.parse(packed), 'application/didcomm-encrypted+json');
    if (!result) throw new Error('aviary unpackMessage returned no payload');
    return result.id;
  });
}
