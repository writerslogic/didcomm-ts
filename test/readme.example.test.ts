/** Runs the README's usage example (with fixtures for its free variables) so the snippet stays correct. */
import { generateKeyPairSync } from 'node:crypto';
import { packAuthcrypt, unpack, type DIDDoc, type Secret } from '../src/index.js';

function party(name: string): { doc: DIDDoc; secrets: Secret[] } {
  const id = `did:example:${name}`;
  const { publicKey, privateKey } = generateKeyPairSync('x25519');
  return {
    doc: {
      id,
      keyAgreement: [`${id}#key-1`],
      authentication: [],
      verificationMethod: [{ id: `${id}#key-1`, type: 'JsonWebKey2020', controller: id, publicKeyJwk: publicKey.export({ format: 'jwk' }) }],
      service: [],
    },
    secrets: [{ id: `${id}#key-1`, type: 'JsonWebKey2020', privateKeyJwk: privateKey.export({ format: 'jwk' }) }],
  };
}

test('README usage example', async () => {
  const { doc: alice, secrets: aliceSecrets } = party('alice');
  const { doc: bob, secrets: bobSecrets } = party('bob');

  // --- README snippet (imports above) ---
  const docs = new Map<string, DIDDoc>([[alice.id, alice], [bob.id, bob]]);
  const did = { resolve: async (id: string) => docs.get(id) ?? null };
  const secretsFor = (owned: Secret[]) => ({
    get_secret: async (id: string) => owned.find((s) => s.id === id) ?? null,
    find_secrets: async (ids: string[]) => ids.filter((id) => owned.some((s) => s.id === id)),
  });

  const envelope = await packAuthcrypt(
    {
      id: crypto.randomUUID(),
      typ: 'application/didcomm-plain+json',
      type: 'https://didcomm.org/basicmessage/2.0/message',
      from: alice.id,
      to: [bob.id],
      body: { content: 'hello' },
    },
    [bob.id],
    alice.id,
    { did, secrets: secretsFor(aliceSecrets) },
  );

  const { message, senderKey, recipientKey } = await unpack(envelope, { did, secrets: secretsFor(bobSecrets) });
  // --- end snippet ---

  expect(message.body).toEqual({ content: 'hello' });
  expect(senderKey).toBe(`${alice.id}#key-1`);
  expect(recipientKey).toBe(`${bob.id}#key-1`);
});
