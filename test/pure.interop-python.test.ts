/**
 * Cross-implementation matrix against didcomm-python (sicpa-dlab, 0.3.2),
 * driven through test/interop/python/driver.py with uv. Skipped when uv is
 * not installed; set DIDCOMM_TS_REQUIRE_INTEROP=1 to make that a failure.
 */
import { spawnSync } from 'node:child_process';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { join } from 'node:path';
import * as pure from '../src/core/pure/index.js';
import type { DIDDoc, PlaintextMessage, Secret } from '../src/core/types.js';

const PROJECT = join(process.cwd(), 'test/interop/python');
const uvAvailable = spawnSync('uv', ['--version']).status === 0;
if (!uvAvailable && process.env.DIDCOMM_TS_REQUIRE_INTEROP === '1') {
  throw new Error('uv is required for the didcomm-python interop matrix');
}
const describeIfUv = uvAvailable ? describe : describe.skip;

function python(request: Record<string, unknown>): Record<string, any> {
  const run = spawnSync('uv', ['run', '--frozen', '--project', PROJECT, 'python', '-I', join(PROJECT, 'driver.py')], {
    input: JSON.stringify(request),
    encoding: 'utf8',
    timeout: 60_000,
  });
  if (run.status !== 0) throw new Error(`driver.py exited ${run.status}: ${run.stderr}`);
  const response = JSON.parse(run.stdout);
  if (response.error) throw new Error(`didcomm-python: ${response.error}`);
  return response;
}

type Curve = 'X25519' | 'P-256' | 'P-384' | 'P-521';
const NODE_CURVE = { 'P-256': 'P-256', 'P-384': 'P-384', 'P-521': 'P-521' } as const;

function keyPair(curve: Curve | 'Ed25519') {
  const { publicKey, privateKey } =
    curve === 'X25519' || curve === 'Ed25519'
      ? generateKeyPairSync(curve === 'X25519' ? 'x25519' : 'ed25519')
      : generateKeyPairSync('ec', { namedCurve: NODE_CURVE[curve] });
  return { publicKeyJwk: publicKey.export({ format: 'jwk' }), privateKeyJwk: privateKey.export({ format: 'jwk' }) };
}

function party(name: string, curve: Curve) {
  const did = `did:example:${name}${randomUUID().replace(/-/g, '')}`;
  const ka = keyPair(curve);
  const sign = keyPair('Ed25519');
  const doc: DIDDoc = {
    id: did,
    keyAgreement: [`${did}#ka-1`],
    authentication: [`${did}#sign-1`],
    verificationMethod: [
      { id: `${did}#ka-1`, type: 'JsonWebKey2020', controller: did, publicKeyJwk: ka.publicKeyJwk },
      { id: `${did}#sign-1`, type: 'JsonWebKey2020', controller: did, publicKeyJwk: sign.publicKeyJwk },
    ],
    service: [],
  };
  const secrets: Secret[] = [
    { id: `${did}#ka-1`, type: 'JsonWebKey2020', privateKeyJwk: ka.privateKeyJwk },
    { id: `${did}#sign-1`, type: 'JsonWebKey2020', privateKeyJwk: sign.privateKeyJwk },
  ];
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

describeIfUv('didcomm-python interop', () => {
  describe.each(['X25519', 'P-256', 'P-384', 'P-521'] as Curve[])('%s', (curve) => {
    const alice = party('alice', curve);
    const bob = party('bob', curve);
    const docs = [alice.doc, bob.doc];

    test('authcrypt pure -> python', async () => {
      const msg = message(alice.did, bob.did);
      const envelope = await pure.packAuthcrypt(msg, [bob.did], alice.did, resolversFor(docs, alice.secrets));
      const result = python({ op: 'unpack', didDocs: docs, secrets: bob.secrets, envelope });
      expect(result.message).toMatchObject(msg);
      expect(result.authenticated).toBe(true);
      expect(result.encryptedFrom).toBe(`${alice.did}#ka-1`);
    });

    test('authcrypt python -> pure', async () => {
      const msg = message(alice.did, bob.did);
      const { envelope } = python({ op: 'pack', didDocs: docs, secrets: alice.secrets, message: msg, to: bob.did, from: alice.did });
      const result = await pure.unpack(envelope, resolversFor(docs, bob.secrets));
      expect(result.message).toMatchObject(msg);
      expect(result.senderKey).toBe(`${alice.did}#ka-1`);
    });

    test.each(['A256CBC-HS512', 'A256GCM', 'XC20P'] as const)('anoncrypt %s both directions', async (enc) => {
      const msg = message(undefined, bob.did);
      const ours = await pure.packAnoncrypt(msg, [bob.did], { ...resolversFor(docs, []), anoncryptEnc: enc });
      expect(python({ op: 'unpack', didDocs: docs, secrets: bob.secrets, envelope: ours }).message).toMatchObject(msg);

      const { envelope } = python({ op: 'pack', didDocs: docs, secrets: [], message: msg, to: bob.did, from: null, enc });
      expect((await pure.unpack(envelope, resolversFor(docs, bob.secrets))).message).toMatchObject(msg);
    });
  });

  test('authcrypt + EdDSA signature, protected sender: python -> pure', async () => {
    const alice = party('alice', 'X25519');
    const bob = party('bob', 'X25519');
    const docs = [alice.doc, bob.doc];
    const msg = message(alice.did, bob.did);
    const { envelope } = python({
      op: 'pack',
      didDocs: docs,
      secrets: alice.secrets,
      message: msg,
      to: bob.did,
      from: alice.did,
      signBy: alice.did,
      protectSender: true,
    });
    const result = await pure.unpack(envelope, resolversFor(docs, bob.secrets));
    expect(result.message).toMatchObject(msg);
    expect(result.senderKey).toBe(`${alice.did}#ka-1`);
    expect(result.signedBy).toBe(`${alice.did}#sign-1`);
  });

  test('authcrypt + EdDSA signature: pure -> python', async () => {
    const alice = party('alice', 'X25519');
    const bob = party('bob', 'X25519');
    const docs = [alice.doc, bob.doc];
    const msg = message(alice.did, bob.did);
    const envelope = await pure.packAuthcrypt(msg, [bob.did], alice.did, {
      ...resolversFor(docs, alice.secrets),
      signBy: alice.did,
    });
    const result = python({ op: 'unpack', didDocs: docs, secrets: bob.secrets, envelope });
    expect(result.message).toMatchObject(msg);
    expect(result.nonRepudiation).toBe(true);
    expect(result.signFrom).toBe(`${alice.did}#sign-1`);
  });
});
