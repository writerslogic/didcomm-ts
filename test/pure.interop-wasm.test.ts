/**
 * Cross-implementation matrix: envelopes packed by the pure backend must
 * unpack in didcomm-rust (WASM) and vice versa, for every curve and
 * algorithm combination didcomm-rust supports (X25519 and P-256 key
 * agreement; EdDSA signing).
 */
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import * as wasm from './support/wasmBackend.js';
import * as pure from '../src/core/pure/index.js';
import type { DIDDoc, PlaintextMessage, Secret } from '../src/core/types.js';
import { encryptJwe } from '../src/core/pure/jwe.js';
import { privateKeyFromJwk, publicKeyFromJwk, type Jwk } from '../src/core/pure/keys.js';

type KeyCurve = 'X25519' | 'P-256';

function keyPair(curve: KeyCurve | 'Ed25519') {
  const { publicKey, privateKey } =
    curve === 'P-256'
      ? generateKeyPairSync('ec', { namedCurve: 'P-256' })
      : generateKeyPairSync(curve === 'X25519' ? 'x25519' : 'ed25519');
  return { publicKeyJwk: publicKey.export({ format: 'jwk' }), privateKeyJwk: privateKey.export({ format: 'jwk' }) };
}

function party(name: string, curve: KeyCurve, keyAgreementCount = 1) {
  const did = `did:example:${name}-${randomUUID()}`;
  const secrets: Secret[] = [];
  const doc: DIDDoc = { id: did, keyAgreement: [], authentication: [], verificationMethod: [], service: [] };
  for (let i = 1; i <= keyAgreementCount; i++) {
    const kid = `${did}#ka-${i}`;
    const { publicKeyJwk, privateKeyJwk } = keyPair(curve);
    doc.keyAgreement.push(kid);
    doc.verificationMethod.push({ id: kid, type: 'JsonWebKey2020', controller: did, publicKeyJwk });
    secrets.push({ id: kid, type: 'JsonWebKey2020', privateKeyJwk });
  }
  const signKid = `${did}#sign-1`;
  const signing = keyPair('Ed25519');
  doc.authentication.push(signKid);
  doc.verificationMethod.push({ id: signKid, type: 'JsonWebKey2020', controller: did, publicKeyJwk: signing.publicKeyJwk });
  secrets.push({ id: signKid, type: 'JsonWebKey2020', privateKeyJwk: signing.privateKeyJwk });
  return { did, doc, secrets };
}

function resolversFor(docs: DIDDoc[], secrets: Secret[]) {
  return {
    did: { resolve: async (did: string) => docs.find((d) => d.id === did) ?? null },
    secrets: {
      get_secret: async (id: string) => secrets.find((s) => s.id === id) ?? null,
      find_secrets: async (ids: string[]) => ids.filter((id) => secrets.some((s) => s.id === id)),
    },
  };
}

function message(from: string | undefined, to: string): PlaintextMessage {
  return {
    id: randomUUID(),
    typ: 'application/didcomm-plain+json',
    type: 'https://didcomm.org/basicmessage/2.0/message',
    ...(from ? { from } : {}),
    to: [to],
    body: { content: `hello ${randomUUID()}` },
  };
}

const backends = { pure, wasm } as const;
type BackendName = keyof typeof backends;
const directions: Array<[BackendName, BackendName]> = [
  ['pure', 'wasm'],
  ['wasm', 'pure'],
  ['pure', 'pure'],
];

describe.each(['X25519', 'P-256'] as KeyCurve[])('%s', (curve) => {
  const alice = party('alice', curve);
  const bob = party('bob', curve);
  const docs = [alice.doc, bob.doc];
  const sender = resolversFor(docs, alice.secrets);
  const recipient = resolversFor(docs, bob.secrets);

  test.each(directions)('authcrypt %s -> %s', async (packer, unpacker) => {
    const msg = message(alice.did, bob.did);
    const packed = await backends[packer].packAuthcrypt(msg, [bob.did], alice.did, sender);
    const result = await backends[unpacker].unpack(packed, recipient);
    expect(result.message).toEqual(msg);
    expect(result.senderKey).toBe(alice.doc.keyAgreement[0]);
    expect(result.recipientKey).toBe(bob.doc.keyAgreement[0]);
  });

  test.each(directions)('anoncrypt %s -> %s', async (packer, unpacker) => {
    const msg = message(undefined, bob.did);
    const packed = await backends[packer].packAnoncrypt(msg, [bob.did], sender);
    const result = await backends[unpacker].unpack(packed, recipient);
    expect(result.message).toEqual(msg);
    expect(result.senderKey).toBeNull();
  });

  test.each(['A256CBC-HS512', 'A256GCM', 'XC20P'] as const)('pure anoncrypt %s -> wasm', async (enc) => {
    const msg = message(undefined, bob.did);
    const packed = await pure.packAnoncrypt(msg, [bob.did], { ...sender, anoncryptEnc: enc });
    expect(JSON.parse(Buffer.from((packed as string).split('"protected":"')[1].split('"')[0], 'base64url').toString()).enc).toBe(enc);
    expect((await wasm.unpack(packed, recipient)).message).toEqual(msg);
  });

  test.each(directions)('authcrypt + EdDSA signature %s -> %s', async (packer, unpacker) => {
    const msg = message(alice.did, bob.did);
    const packed = await backends[packer].packAuthcrypt(msg, [bob.did], alice.did, { ...sender, signBy: alice.did });
    const result = await backends[unpacker].unpack(packed, recipient);
    expect(result.message).toEqual(msg);
    if (unpacker === 'pure') expect((result as pure.PureUnpackResult).signedBy).toBe(`${alice.did}#sign-1`);
  });

  test.each(directions)('CBOR authcrypt %s -> %s', async (packer, unpacker) => {
    const msg = message(alice.did, bob.did);
    const packed = await backends[packer].packAuthcrypt(msg, [bob.did], alice.did, { ...sender, encoding: 'cbor' });
    expect(packed).toBeInstanceOf(Uint8Array);
    expect((await backends[unpacker].unpack(packed, recipient)).message).toEqual(msg);
  });
});

test('pure multi-recipient authcrypt shares one envelope that every member decrypts in wasm', async () => {
  const alice = party('alice', 'X25519');
  const group = party('group', 'X25519', 3);
  const docs = [alice.doc, group.doc];
  const msg = message(alice.did, group.did);
  const packed = (await pure.packAuthcrypt(msg, [group.did], alice.did, resolversFor(docs, alice.secrets))) as string;
  expect(JSON.parse(packed).recipients).toHaveLength(3);
  for (const kid of group.doc.keyAgreement) {
    const memberSecrets = group.secrets.filter((s) => s.id === kid);
    const result = await wasm.unpack(packed, resolversFor(docs, memberSecrets));
    expect(result.message).toEqual(msg);
    expect(result.recipientKey).toBe(kid);
  }
});

test('authcrypt whose plaintext "from" names a DID other than the sender key is refused on pack and unpack', async () => {
  const alice = party('alice', 'X25519');
  const mallory = party('mallory', 'X25519');
  const bob = party('bob', 'X25519');
  const docs = [alice.doc, mallory.doc, bob.doc];
  const forged = message(alice.did, bob.did);
  await expect(
    pure.packAuthcrypt(forged, [bob.did], mallory.did, resolversFor(docs, mallory.secrets)),
  ).rejects.toThrow('does not match the sender DID');

  // Bypass the pack-side check by building the JWE directly with mallory's key.
  const malloryKid = mallory.doc.keyAgreement[0];
  const jwe = encryptJwe(
    new TextEncoder().encode(JSON.stringify(forged)),
    'A256CBC-HS512',
    [{ kid: bob.doc.keyAgreement[0], key: publicKeyFromJwk(bob.doc.verificationMethod[0].publicKeyJwk as Jwk) }],
    { kid: malloryKid, key: privateKeyFromJwk(mallory.secrets[0].privateKeyJwk as Jwk) },
  );
  await expect(pure.unpack(JSON.stringify(jwe), resolversFor(docs, bob.secrets))).rejects.toThrow(
    'does not match the sender DID',
  );
});

test('the attestation gate is shared: pure packing refuses an unattested recipient key', async () => {
  const alice = party('alice', 'X25519');
  const bob = party('bob', 'X25519');
  const attestation = { verify: async () => false };
  await expect(
    pure.packAuthcrypt(message(alice.did, bob.did), [bob.did], alice.did, {
      ...resolversFor([alice.doc, bob.doc], alice.secrets),
      attestation,
    }),
  ).rejects.toThrow('Recipient key failed attestation');
});
