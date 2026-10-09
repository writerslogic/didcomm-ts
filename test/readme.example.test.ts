/**
 * Runs every README usage example (with fixtures for their free variables)
 * so the snippets stay correct. Keep each "README snippet" block in sync.
 */
import { generateKeyPairSync } from 'node:crypto';
import {
  anoncryptProvider,
  packAnoncrypt,
  packAuthcrypt,
  packSigned,
  routing,
  unpack,
  unpackSigned,
  type DIDDoc,
  type PlaintextMessage,
  type Secret,
} from '../src/index.js';

/** A DID with one X25519 keyAgreement key and one Ed25519 authentication key. */
function party(name: string): { doc: DIDDoc; secrets: Secret[] } {
  const id = `did:example:${name}`;
  const ka = generateKeyPairSync('x25519');
  const auth = generateKeyPairSync('ed25519');
  return {
    doc: {
      id,
      keyAgreement: [`${id}#key-x25519-1`],
      authentication: [`${id}#key-ed25519-1`],
      verificationMethod: [
        { id: `${id}#key-x25519-1`, type: 'JsonWebKey2020', controller: id, publicKeyJwk: ka.publicKey.export({ format: 'jwk' }) },
        { id: `${id}#key-ed25519-1`, type: 'JsonWebKey2020', controller: id, publicKeyJwk: auth.publicKey.export({ format: 'jwk' }) },
      ],
      service: [],
    },
    secrets: [
      { id: `${id}#key-x25519-1`, type: 'JsonWebKey2020', privateKeyJwk: ka.privateKey.export({ format: 'jwk' }) },
      { id: `${id}#key-ed25519-1`, type: 'JsonWebKey2020', privateKeyJwk: auth.privateKey.export({ format: 'jwk' }) },
    ],
  };
}

const { doc: alice, secrets: aliceSecrets } = party('alice');
const { doc: bob, secrets: bobSecrets } = party('bob');
const { doc: mediator, secrets: mediatorSecrets } = party('mediator');

// --- README snippet: resolvers ---
const docs = new Map<string, DIDDoc>([[alice.id, alice], [bob.id, bob], [mediator.id, mediator]]);
const did = { resolve: async (id: string) => docs.get(id) ?? null };
const secretsFor = (owned: Secret[]) => ({
  get_secret: async (id: string) => owned.find((s) => s.id === id) ?? null,
  find_secrets: async (ids: string[]) => ids.filter((id) => owned.some((s) => s.id === id)),
});
// --- end snippet ---

const message = (): PlaintextMessage => ({
  id: crypto.randomUUID(),
  typ: 'application/didcomm-plain+json',
  type: 'https://didcomm.org/basicmessage/2.0/message',
  from: alice.id,
  to: [bob.id],
  body: { content: 'hello' },
});

test('README: authcrypt', async () => {
  // --- README snippet: authcrypt ---
  const envelope = await packAuthcrypt(message(), [bob.id], alice.id, { did, secrets: secretsFor(aliceSecrets) });
  const { message: received, senderKey, recipientKey } = await unpack(envelope, { did, secrets: secretsFor(bobSecrets) });
  // senderKey === 'did:example:alice#key-x25519-1', recipientKey === 'did:example:bob#key-x25519-1'
  // --- end snippet ---
  expect(received.body).toEqual({ content: 'hello' });
  expect(senderKey).toBe('did:example:alice#key-x25519-1');
  expect(recipientKey).toBe('did:example:bob#key-x25519-1');
});

test('README: authcrypt with a signature', async () => {
  // --- README snippet: authcrypt + signature ---
  const envelope = await packAuthcrypt(message(), [bob.id], alice.id, {
    did,
    secrets: secretsFor(aliceSecrets),
    signBy: alice.id,
  });
  const { signedBy } = await unpack(envelope, { did, secrets: secretsFor(bobSecrets) });
  // signedBy === 'did:example:alice#key-ed25519-1'
  // --- end snippet ---
  expect(signedBy).toBe('did:example:alice#key-ed25519-1');
});

test('README: anoncrypt', async () => {
  // --- README snippet: anoncrypt ---
  const { from, ...anonymous } = message();
  const envelope = await packAnoncrypt(anonymous, [bob.id], { did, secrets: secretsFor([]), anoncryptEnc: 'XC20P' });
  const { senderKey } = await unpack(envelope, { did, secrets: secretsFor(bobSecrets) });
  // senderKey === null
  // --- end snippet ---
  expect(senderKey).toBeNull();
});

test('README: signed only', async () => {
  // --- README snippet: signed ---
  const jws = await packSigned(message(), alice.id, { did, secrets: secretsFor(aliceSecrets) });
  const { message: verified, signedBy } = await unpackSigned(jws, { did, secrets: secretsFor([]) });
  // --- end snippet ---
  expect(verified.body).toEqual({ content: 'hello' });
  expect(signedBy).toBe('did:example:alice#key-ed25519-1');
});

test('README: forward through a mediator', async () => {
  const envelope = await packAuthcrypt(message(), [bob.id], alice.id, { did, secrets: secretsFor(aliceSecrets) });
  // --- README snippet: forward ---
  const forwarded = await routing.wrapForwardChain(
    JSON.parse(envelope as string),
    ['did:example:mediator#key-x25519-1'],
    bob.id,
    anoncryptProvider({ did, secrets: secretsFor([]) }),
  );
  // POST JSON.stringify(forwarded) to the mediator's endpoint.
  // --- end snippet ---

  // The mediator unwraps the forward and finds Bob's untouched envelope inside.
  const { message: forward } = await unpack(JSON.stringify(forwarded), { did, secrets: secretsFor(mediatorSecrets) });
  const { next, attachedMessage } = routing.unwrapForward(forward as unknown as routing.PlaintextMessage);
  expect(next).toBe(bob.id);
  const { message: received } = await unpack(JSON.stringify(attachedMessage), { did, secrets: secretsFor(bobSecrets) });
  expect(received.body).toEqual({ content: 'hello' });
});
