/** DID rotation (`from_prior`) and plaintext messages, checked against didcomm-rust (vectors and WASM). */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { FromPrior as RustFromPrior, Message } from 'didcomm';
import {
  packAuthcrypt,
  packFromPrior,
  packPlaintext,
  unpack,
  unpackFromPrior,
  unpackPlaintext,
  type DIDDoc,
  type PlaintextMessage,
  type Secret,
} from '../src/index.js';
import { b64urlEncode, utf8 } from '../src/core/pure/bytes.js';
import { privateKeyFromJwk, sign, type Jwk } from '../src/core/pure/keys.js';

const vectors = JSON.parse(readFileSync(join(process.cwd(), 'test/fixtures/didcomm-rust-vectors.json'), 'utf8')) as {
  didDocs: Record<string, DIDDoc>;
  secrets: Secret[];
  fromPriorJwts: Record<string, string>;
  plaintextFromPrior: PlaintextMessage;
};
const vectorDid = { resolve: async (id: string) => vectors.didDocs[id] ?? null };

describe('didcomm-rust from_prior vectors', () => {
  test('FROM_PRIOR_JWT_FULL verifies (times skipped: the vector has exp < nbf)', async () => {
    const { fromPrior, issuerKid } = await unpackFromPrior(vectors.fromPriorJwts.FROM_PRIOR_JWT_FULL, vectorDid, null);
    expect(fromPrior.iss).toBe('did:example:charlie');
    expect(fromPrior.sub).toBe('did:example:alice');
    expect(issuerKid).toBe('did:example:charlie#key-1');
  });

  test('its expired exp is enforced by default', async () => {
    await expect(unpackFromPrior(vectors.fromPriorJwts.FROM_PRIOR_JWT_FULL, vectorDid)).rejects.toThrow('expired');
    await expect(unpackPlaintext(JSON.stringify(vectors.plaintextFromPrior), { did: vectorDid })).rejects.toThrow('expired');
  });

  test.each(['FROM_PRIOR_JWT_INVALID', 'FROM_PRIOR_JWT_INVALID_SIGNATURE'])('rejects %s', async (name) => {
    await expect(unpackFromPrior(vectors.fromPriorJwts[name], vectorDid, null)).rejects.toThrow();
  });
});

function party(name: string) {
  const id = `did:example:${name}-${randomUUID()}`;
  const ka = generateKeyPairSync('x25519');
  const auth = generateKeyPairSync('ed25519');
  const doc: DIDDoc = {
    id,
    keyAgreement: [`${id}#ka`],
    authentication: [`${id}#auth`],
    verificationMethod: [
      { id: `${id}#ka`, type: 'JsonWebKey2020', controller: id, publicKeyJwk: ka.publicKey.export({ format: 'jwk' }) },
      { id: `${id}#auth`, type: 'JsonWebKey2020', controller: id, publicKeyJwk: auth.publicKey.export({ format: 'jwk' }) },
    ],
    service: [],
  };
  const secrets: Secret[] = [
    { id: `${id}#ka`, type: 'JsonWebKey2020', privateKeyJwk: ka.privateKey.export({ format: 'jwk' }) },
    { id: `${id}#auth`, type: 'JsonWebKey2020', privateKeyJwk: auth.privateKey.export({ format: 'jwk' }) },
  ];
  return { id, doc, secrets };
}

const oldAlice = party('old-alice');
const alice = party('alice');
const bob = party('bob');
const mallory = party('mallory');
const docs = [oldAlice.doc, alice.doc, bob.doc, mallory.doc];
const resolvers = (secrets: Secret[]) => ({
  did: { resolve: async (id: string) => docs.find((d) => d.id === id) ?? null },
  secrets: {
    get_secret: async (id: string) => secrets.find((s) => s.id === id) ?? null,
    find_secrets: async (ids: string[]) => ids.filter((id) => secrets.some((s) => s.id === id)),
  },
});
const message = (fromPrior?: string): PlaintextMessage => ({
  id: randomUUID(),
  typ: 'application/didcomm-plain+json',
  type: 'https://didcomm.org/basicmessage/2.0/message',
  from: alice.id,
  to: [bob.id],
  ...(fromPrior ? { from_prior: fromPrior } : {}),
  body: {},
});
const now = Math.floor(Date.now() / 1000);

describe('from_prior round trips', () => {
  test('didcomm-ts packs, didcomm-ts and didcomm-rust unpack', async () => {
    const { jwt, issuerKid } = await packFromPrior(
      { iss: oldAlice.id, sub: alice.id, iat: now, exp: now + 3600 },
      null,
      resolvers(oldAlice.secrets),
    );
    expect(issuerKid).toBe(`${oldAlice.id}#auth`);
    const envelope = (await packAuthcrypt(message(jwt), [bob.id], alice.id, resolvers(alice.secrets))) as string;

    const ours = await unpack(envelope, resolvers(bob.secrets));
    expect(ours.fromPrior).toMatchObject({ iss: oldAlice.id, sub: alice.id });
    expect(ours.fromPriorIssuerKid).toBe(`${oldAlice.id}#auth`);

    const r = resolvers(bob.secrets);
    const [m, metadata] = await Message.unpack(envelope, r.did, r.secrets, {});
    m.free();
    expect(metadata.from_prior_issuer_kid).toBe(`${oldAlice.id}#auth`);
  });

  test('didcomm-rust packs, didcomm-ts verifies', async () => {
    const value = new RustFromPrior({ iss: oldAlice.id, sub: alice.id, iat: now, exp: now + 3600 });
    const r = resolvers(oldAlice.secrets);
    const [jwt, kid] = await value.pack(null, r.did, r.secrets);
    value.free();
    const { fromPrior, issuerKid } = await unpackFromPrior(jwt, r.did);
    expect(fromPrior).toMatchObject({ iss: oldAlice.id, sub: alice.id });
    expect(issuerKid).toBe(kid);
  });

  test('rejects a from_prior signed by a key that does not belong to `iss`', async () => {
    // Mallory signs with her own key but claims to be rotating away from old Alice's DID.
    const key = privateKeyFromJwk(mallory.secrets[1].privateKeyJwk as Jwk);
    const header = b64urlEncode(utf8(JSON.stringify({ typ: 'JWT', alg: 'EdDSA', kid: `${mallory.id}#auth` })));
    const payload = b64urlEncode(utf8(JSON.stringify({ iss: oldAlice.id, sub: alice.id })));
    const forged = `${header}.${payload}.${b64urlEncode(sign(key, utf8(`${header}.${payload}`)))}`;
    await expect(unpackFromPrior(forged, resolvers([]).did)).rejects.toThrow('not the DID of its signing key');
  });

  test('rejects a from_prior whose `sub` is not the message `from`', async () => {
    const { jwt } = await packFromPrior({ iss: oldAlice.id, sub: bob.id }, null, resolvers(oldAlice.secrets));
    await expect(unpackPlaintext(packPlaintext(message(jwt)), resolvers([]))).rejects.toThrow('does not match the message `from`');
  });

  test('rejects a from_prior that is not yet valid', async () => {
    const { jwt } = await packFromPrior({ iss: oldAlice.id, sub: alice.id, nbf: now + 3600 }, null, resolvers(oldAlice.secrets));
    await expect(unpackFromPrior(jwt, resolvers([]).did)).rejects.toThrow('not yet valid');
  });
});

describe('plaintext messages', () => {
  test('pack and unpack, with from_prior', async () => {
    const { jwt } = await packFromPrior({ iss: oldAlice.id, sub: alice.id }, null, resolvers(oldAlice.secrets));
    const { message: out, fromPrior } = await unpackPlaintext(packPlaintext(message(jwt)), resolvers([]));
    expect(out.typ).toBe('application/didcomm-plain+json');
    expect(fromPrior?.sub).toBe(alice.id);
  });

  test('didcomm-rust reads our plaintext', async () => {
    const plaintext = packPlaintext(message());
    const r = resolvers([]);
    const [m, metadata] = await Message.unpack(plaintext, r.did, r.secrets, {});
    expect(m.as_value().id).toBe(JSON.parse(plaintext).id);
    m.free();
    expect(metadata.encrypted).toBe(false);
  });

  test('unpackPlaintext refuses encrypted envelopes, and unpack refuses plaintext', async () => {
    const envelope = await packAuthcrypt(message(), [bob.id], alice.id, resolvers(alice.secrets));
    await expect(unpackPlaintext(envelope, resolvers([]))).rejects.toThrow('use unpack');
    await expect(unpack(packPlaintext(message()), resolvers(bob.secrets))).rejects.toThrow('not encrypted');
  });
});
