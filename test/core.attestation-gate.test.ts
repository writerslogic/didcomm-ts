import { generateKeyPairSync, randomUUID } from 'node:crypto';
import {
  packAuthcrypt,
  unpack,
  type DIDDoc,
  type DidResolver,
  type Secret,
  type SecretsResolver,
  type PlaintextMessage,
  type RecipientKeyAttestation,
  type VerificationMethod,
} from '../src/core/index.js';

// ---------------------------------------------------------------------------
// Minimal fixtures (deliberately not imported from core.envelope.test.ts, to
// avoid re-registering its describe/test blocks).
// ---------------------------------------------------------------------------

function generateX25519KeyAgreement(did: string): {
  did: string;
  kid: string;
  doc: DIDDoc;
  secret: Secret;
} {
  const kid = `${did}#key-1`;
  const { publicKey, privateKey } = generateKeyPairSync('x25519');
  const doc: DIDDoc = {
    id: did,
    keyAgreement: [kid],
    authentication: [],
    verificationMethod: [
      {
        id: kid,
        type: 'JsonWebKey2020',
        controller: did,
        publicKeyJwk: publicKey.export({ format: 'jwk' }),
      },
    ],
    service: [],
  };
  const secret: Secret = {
    id: kid,
    type: 'JsonWebKey2020',
    privateKeyJwk: privateKey.export({ format: 'jwk' }),
  };
  return { did, kid, doc, secret };
}

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

describe('core/envelope attestation gate', () => {
  test('packAuthcrypt to 2 keys under one DID succeeds when the attestation callback approves both', async () => {
    const alice = generateX25519KeyAgreement('did:example:attest-alice-1');
    const group = generateGroupKeyAgreement('did:example:attest-group-1', 2);
    const [member1, member2] = group.members;

    const allDocs = new Map<string, DIDDoc>([
      [alice.did, alice.doc],
      [group.did, group.doc],
    ]);
    const didResolver = new MapDidResolver(allDocs);
    const aliceSecrets = new MapSecretsResolver(new Map([[alice.kid, alice.secret]]));

    const calls: Array<[string, string]> = [];
    const attestation: RecipientKeyAttestation = {
      async verify(keyId: string, vm: VerificationMethod): Promise<boolean> {
        calls.push([keyId, vm.id]);
        return true;
      },
    };

    const plaintext = makePlaintextMessage({ hello: 'world' });

    const envelope = await packAuthcrypt(plaintext, [group.did], alice.did, {
      did: didResolver,
      secrets: aliceSecrets,
      attestation,
    });

    expect(calls).toHaveLength(2);
    expect(calls.map((c) => c[0])).toEqual([member1.kid, member2.kid]);
    expect(calls.map((c) => c[1])).toEqual([member1.kid, member2.kid]);

    const jwe = JSON.parse(envelope as string);
    expect(Array.isArray(jwe.recipients)).toBe(true);
    expect(jwe.recipients).toHaveLength(2);

    for (const member of [member1, member2]) {
      const memberSecrets = new MapSecretsResolver(new Map([[member.kid, member.secret]]));
      const result = await unpack(envelope, { did: didResolver, secrets: memberSecrets });
      expect(result.message.body).toEqual({ hello: 'world' });
      expect(result.recipientKey).toBe(member.kid);
    }
  });

  test('packAuthcrypt throws and names the specific rejected key id when the callback rejects one of two keys', async () => {
    const alice = generateX25519KeyAgreement('did:example:attest-alice-2');
    const group = generateGroupKeyAgreement('did:example:attest-group-2', 2);
    const [member1, member2] = group.members;

    const allDocs = new Map<string, DIDDoc>([
      [alice.did, alice.doc],
      [group.did, group.doc],
    ]);
    const didResolver = new MapDidResolver(allDocs);
    const aliceSecrets = new MapSecretsResolver(new Map([[alice.kid, alice.secret]]));

    const attestation: RecipientKeyAttestation = {
      async verify(keyId: string): Promise<boolean> {
        // Reject the second key specifically, not just "the first" one, so an
        // implementation that always names keyIds[0] cannot pass this test.
        return keyId !== member2.kid;
      },
    };

    const plaintext = makePlaintextMessage({ hello: 'world' });

    await expect(
      packAuthcrypt(plaintext, [group.did], alice.did, {
        did: didResolver,
        secrets: aliceSecrets,
        attestation,
      }),
    ).rejects.toThrow(member2.kid);

    await expect(
      packAuthcrypt(plaintext, [group.did], alice.did, {
        did: didResolver,
        secrets: aliceSecrets,
        attestation,
      }),
    ).rejects.not.toThrow(member1.kid);
  });

  test('packAuthcrypt with no `attestation` option behaves exactly as before (backward compatible, no gating)', async () => {
    const alice = generateX25519KeyAgreement('did:example:attest-alice-3');
    const group = generateGroupKeyAgreement('did:example:attest-group-3', 2);
    const [member1, member2] = group.members;

    const allDocs = new Map<string, DIDDoc>([
      [alice.did, alice.doc],
      [group.did, group.doc],
    ]);
    const didResolver = new MapDidResolver(allDocs);
    const aliceSecrets = new MapSecretsResolver(new Map([[alice.kid, alice.secret]]));

    const plaintext = makePlaintextMessage({ hello: 'world' });

    const envelope = await packAuthcrypt(plaintext, [group.did], alice.did, {
      did: didResolver,
      secrets: aliceSecrets,
    });

    const jwe = JSON.parse(envelope as string);
    expect(jwe.recipients).toHaveLength(2);

    for (const member of [member1, member2]) {
      const memberSecrets = new MapSecretsResolver(new Map([[member.kid, member.secret]]));
      const result = await unpack(envelope, { did: didResolver, secrets: memberSecrets });
      expect(result.message.body).toEqual({ hello: 'world' });
      expect(result.recipientKey).toBe(member.kid);
    }
  });
});
