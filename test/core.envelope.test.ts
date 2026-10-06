import { generateKeyPairSync, randomUUID } from 'node:crypto';
import {
  packAuthcrypt,
  packAnoncrypt,
  unpack,
  detectEnvelopeEncoding,
  type DIDDoc,
  type DidResolver,
  type Secret,
  type SecretsResolver,
  type PlaintextMessage,
} from '../src/core/index.js';

// ---------------------------------------------------------------------------
// Test fixtures: in-memory DID Docs / secrets backed by real X25519 keys.
// ---------------------------------------------------------------------------

function generateX25519KeyAgreement(did: string): {
  did: string;
  kid: string;
  doc: DIDDoc;
  secret: Secret;
} {
  const kid = `${did}#key-1`;
  const { publicKey, privateKey } = generateKeyPairSync('x25519');
  const publicKeyJwk = publicKey.export({ format: 'jwk' });
  const privateKeyJwk = privateKey.export({ format: 'jwk' });

  const doc: DIDDoc = {
    id: did,
    keyAgreement: [kid],
    authentication: [],
    verificationMethod: [
      {
        id: kid,
        type: 'JsonWebKey2020',
        controller: did,
        publicKeyJwk,
      },
    ],
    service: [],
  };

  const secret: Secret = {
    id: kid,
    type: 'JsonWebKey2020',
    privateKeyJwk,
  };

  return { did, kid, doc, secret };
}

/**
 * didcomm-rust's pack_encrypted only shares one CEK across keyAgreement keys
 * that belong to a single DID Doc (verified empirically: a cross-DID key set
 * throws `DIDCommMalformed: Recipient keys are outside of one did`). So "3
 * distinct recipients sharing one envelope" is modeled here the way DIDComm
 * itself models it — as one group/multi-device DID Doc listing one
 * keyAgreement key per member — with each member holding only their own
 * secret and decrypting independently.
 */
function generateGroupKeyAgreement(
  did: string,
  memberCount: number,
): { did: string; doc: DIDDoc; members: Array<{ kid: string; secret: Secret }> } {
  const members: Array<{ kid: string; secret: Secret }> = [];
  const verificationMethod: DIDDoc['verificationMethod'] = [];

  for (let i = 0; i < memberCount; i++) {
    const kid = `${did}#key-${i + 1}`;
    const { publicKey, privateKey } = generateKeyPairSync('x25519');
    verificationMethod.push({
      id: kid,
      type: 'JsonWebKey2020',
      controller: did,
      publicKeyJwk: publicKey.export({ format: 'jwk' }),
    });
    members.push({
      kid,
      secret: { id: kid, type: 'JsonWebKey2020', privateKeyJwk: privateKey.export({ format: 'jwk' }) },
    });
  }

  const doc: DIDDoc = {
    id: did,
    keyAgreement: members.map((m) => m.kid),
    authentication: [],
    verificationMethod,
    service: [],
  };

  return { did, doc, members };
}

class MapDidResolver implements DidResolver {
  constructor(private readonly docs: Map<string, DIDDoc>) {}
  async resolve(did: string): Promise<DIDDoc | null> {
    return this.docs.get(did) ?? null;
  }
}

class MapSecretsResolver implements SecretsResolver {
  constructor(private readonly secrets: Map<string, Secret>) {}
  async get_secret(secretId: string): Promise<Secret | null> {
    return this.secrets.get(secretId) ?? null;
  }
  async find_secrets(secretIds: string[]): Promise<string[]> {
    return secretIds.filter((id) => this.secrets.has(id));
  }
}

function makePlaintextMessage(body: Record<string, unknown>): PlaintextMessage {
  return {
    id: randomUUID(),
    typ: 'application/didcomm-plain+json',
    type: 'https://didcomm.org/basicmessage/2.0/message',
    body,
  };
}

describe('core/envelope', () => {
  test('multi-recipient authcrypt produces one shared-CEK envelope decryptable by each of 3 distinct recipients independently', async () => {
    const alice = generateX25519KeyAgreement('did:example:alice');
    const group = generateGroupKeyAgreement('did:example:group', 3);
    const [member1, member2, member3] = group.members;

    const allDocs = new Map<string, DIDDoc>([
      [alice.did, alice.doc],
      [group.did, group.doc],
    ]);
    const sharedDidResolver = new MapDidResolver(allDocs);
    const aliceSecrets = new MapSecretsResolver(new Map([[alice.kid, alice.secret]]));

    const plaintext = makePlaintextMessage({ hello: 'world' });

    const envelope = await packAuthcrypt(plaintext, [group.did], alice.did, {
      did: sharedDidResolver,
      secrets: aliceSecrets,
    });

    expect(typeof envelope).toBe('string');

    // One envelope, one shared CEK: JWE general JSON serialization carries a
    // single protected/iv/ciphertext/tag alongside a recipients array with one
    // entry per recipient key, rather than N separate envelopes.
    const jwe = JSON.parse(envelope as string);
    expect(Array.isArray(jwe.recipients)).toBe(true);
    expect(jwe.recipients).toHaveLength(3);
    expect(typeof jwe.ciphertext).toBe('string');
    expect(typeof jwe.iv).toBe('string');
    expect(typeof jwe.tag).toBe('string');

    for (const member of [member1, member2, member3]) {
      // Each recipient's resolver holds only its own secret, proving the
      // other two recipient entries are not needed to decrypt this one.
      const memberSecrets = new MapSecretsResolver(new Map([[member.kid, member.secret]]));
      const result = await unpack(envelope, { did: sharedDidResolver, secrets: memberSecrets });
      expect(result.message.body).toEqual({ hello: 'world' });
      expect(result.senderKey).toBe(alice.kid);
      expect(result.recipientKey).toBe(member.kid);
    }
  });

  // Regression: a plaintext `to` header naming the real recipient DID (as
  // the chat CLI's `send` sets) must round-trip. didcomm-rust's
  // pack_encrypted rejects a `to` argument that the plaintext's own `to`
  // header does not list, so packing must resolve the real recipient DID as
  // its `to` target, not a synthetic one.
  test('authcrypt with a plaintext `to` header naming the recipient DID round-trips', async () => {
    const alice = generateX25519KeyAgreement('did:example:alice-to');
    const bob = generateX25519KeyAgreement('did:example:bob-to');

    const allDocs = new Map<string, DIDDoc>([
      [alice.did, alice.doc],
      [bob.did, bob.doc],
    ]);
    const sharedDidResolver = new MapDidResolver(allDocs);
    const aliceSecrets = new MapSecretsResolver(new Map([[alice.kid, alice.secret]]));
    const bobSecrets = new MapSecretsResolver(new Map([[bob.kid, bob.secret]]));

    const plaintext: PlaintextMessage = {
      ...makePlaintextMessage({ content: 'hello bob' }),
      from: alice.did,
      to: [bob.did],
    };

    const envelope = await packAuthcrypt(plaintext, [bob.did], alice.did, {
      did: sharedDidResolver,
      secrets: aliceSecrets,
    });

    const { message } = await unpack(envelope, { did: sharedDidResolver, secrets: bobSecrets });
    expect((message.body as { content: string }).content).toBe('hello bob');
  });

  // Regression: a sender device packing to OTHER devices of its own
  // multi-device DID (an explicit-key-ID subset of that DID's
  // `keyAgreement`, excluding the sender's own key) must still resolve the
  // sender's key through the real resolver, not the resolver override
  // narrowed to the requested recipient keys.
  test('authcrypt from one device of a multi-device DID to its other devices round-trips', async () => {
    const devices = generateGroupKeyAgreement('did:example:devices', 3);
    const [deviceA, deviceB, deviceC] = devices.members;

    const sharedDidResolver = new MapDidResolver(new Map([[devices.did, devices.doc]]));
    const senderSecrets = new MapSecretsResolver(new Map([[deviceA.kid, deviceA.secret]]));
    const recipientSecrets = new MapSecretsResolver(new Map([[deviceB.kid, deviceB.secret]]));

    const plaintext = makePlaintextMessage({ content: 'hello other devices' });

    const envelope = await packAuthcrypt(plaintext, [deviceB.kid, deviceC.kid], deviceA.kid, {
      did: sharedDidResolver,
      secrets: senderSecrets,
    });

    const { message } = await unpack(envelope, { did: sharedDidResolver, secrets: recipientSecrets });
    expect((message.body as { content: string }).content).toBe('hello other devices');
  });

  test('envelope encoding auto-detection round-trips JSON and CBOR', async () => {
    const alice = generateX25519KeyAgreement('did:example:alice2');
    const bob = generateX25519KeyAgreement('did:example:bob4');

    const docs = new Map<string, DIDDoc>([
      [alice.did, alice.doc],
      [bob.did, bob.doc],
    ]);
    const didResolver = new MapDidResolver(docs);
    const aliceSecrets = new MapSecretsResolver(new Map([[alice.kid, alice.secret]]));
    const bobSecrets = new MapSecretsResolver(new Map([[bob.kid, bob.secret]]));

    const plaintext = makePlaintextMessage({ encoding: 'check' });

    const jsonEnvelope = await packAnoncrypt(plaintext, [bob.did], {
      did: didResolver,
      secrets: aliceSecrets,
      encoding: 'json',
    });
    expect(typeof jsonEnvelope).toBe('string');
    expect(detectEnvelopeEncoding(jsonEnvelope)).toBe('json');

    const cborEnvelope = await packAnoncrypt(plaintext, [bob.did], {
      did: didResolver,
      secrets: aliceSecrets,
      encoding: 'cbor',
    });
    expect(cborEnvelope).toBeInstanceOf(Uint8Array);
    expect(detectEnvelopeEncoding(cborEnvelope as Uint8Array)).toBe('cbor');

    const fromJson = await unpack(jsonEnvelope, { did: didResolver, secrets: bobSecrets });
    expect(fromJson.message.body).toEqual({ encoding: 'check' });
    expect(fromJson.senderKey).toBeNull();

    const fromCbor = await unpack(cborEnvelope, { did: didResolver, secrets: bobSecrets });
    expect(fromCbor.message.body).toEqual({ encoding: 'check' });
    expect(fromCbor.senderKey).toBeNull();
  });
});
