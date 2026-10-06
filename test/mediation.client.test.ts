import { jest } from '@jest/globals';
import { generateKeyPairSync, randomUUID, type JsonWebKey } from 'node:crypto';
import {
  packAuthcrypt,
  unpack,
  type DIDDoc,
  type DidResolver,
  type PlaintextMessage,
  type Secret,
  type SecretsResolver,
} from '../src/core/index.js';
import { requestMediation, updateKeylist } from '../src/chat/mediation.js';

function generateX25519(did: string): { did: string; kid: string; doc: DIDDoc; secret: Secret } {
  const { publicKey, privateKey } = generateKeyPairSync('x25519');
  const publicJwk = publicKey.export({ format: 'jwk' }) as JsonWebKey;
  const kid = `${did}#key-1`;
  return {
    did,
    kid,
    doc: {
      id: did,
      keyAgreement: [kid],
      authentication: [],
      verificationMethod: [
        { id: kid, type: 'JsonWebKey2020', controller: did, publicKeyJwk: publicJwk },
      ],
      service: [{ id: `${did}#service-1`, type: 'DIDCommMessaging', serviceEndpoint: { uri: 'https://mediator.example/' } }],
    },
    secret: { id: kid, type: 'JsonWebKey2020', privateKeyJwk: privateKey.export({ format: 'jwk' }) as JsonWebKey },
  };
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

describe('mediation client (coordinate-mediation 2.0)', () => {
  const client = generateX25519('did:example:client');
  const mediator = generateX25519('did:example:mediator');
  const sharedDocs = new Map([[client.did, client.doc], [mediator.did, mediator.doc]]);
  const clientDid = new MapDidResolver(sharedDocs);
  const clientSecrets = new MapSecretsResolver(new Map([[client.kid, client.secret]]));
  const mediatorDid = new MapDidResolver(sharedDocs);
  const mediatorSecrets = new MapSecretsResolver(new Map([[mediator.kid, mediator.secret]]));

  const ctx = { selfDid: client.did, did: clientDid, secrets: clientSecrets };

  /** Mocks `fetch` to decrypt the client's request and respond with `reply`. */
  function mockMediatorReply(buildReply: (request: PlaintextMessage) => PlaintextMessage) {
    (global as { fetch?: typeof fetch }).fetch = jest.fn(async (_url: string, init: { body: Uint8Array }) => {
      const { message } = await unpack(init.body, { did: mediatorDid, secrets: mediatorSecrets });
      const reply = buildReply(message);
      const packedReply = await packAuthcrypt(reply, [client.did], mediator.did, {
        did: mediatorDid,
        secrets: mediatorSecrets,
      });
      const bytes = typeof packedReply === 'string' ? new TextEncoder().encode(packedReply) : packedReply;
      return new Response(bytes, { status: 200 });
    }) as unknown as typeof fetch;
  }

  afterEach(() => {
    delete (global as { fetch?: typeof fetch }).fetch;
  });

  test('requestMediation returns the granted routing_did', async () => {
    mockMediatorReply((request) => ({
      id: randomUUID(),
      typ: 'application/didcomm-plain+json',
      type: 'https://didcomm.org/coordinate-mediation/2.0/mediate-grant',
      body: { routing_did: 'did:example:mediator-routing' },
      from: mediator.did,
      to: [request.from as string],
    }));

    const grant = await requestMediation(mediator.did, ctx);
    expect(grant.routingDid).toBe('did:example:mediator-routing');
  });

  test('requestMediation throws on mediate-deny', async () => {
    mockMediatorReply((request) => ({
      id: randomUUID(),
      typ: 'application/didcomm-plain+json',
      type: 'https://didcomm.org/coordinate-mediation/2.0/mediate-deny',
      body: {},
      from: mediator.did,
      to: [request.from as string],
    }));

    await expect(requestMediation(mediator.did, ctx)).rejects.toThrow(/denied/);
  });

  test('updateKeylist resolves on a successful keylist-update-response', async () => {
    mockMediatorReply((request) => ({
      id: randomUUID(),
      typ: 'application/didcomm-plain+json',
      type: 'https://didcomm.org/coordinate-mediation/2.0/keylist-update-response',
      body: {
        updated: [{ recipient_did: client.did, action: 'add', result: 'success' }],
      },
      from: mediator.did,
      to: [request.from as string],
    }));

    const result = await updateKeylist(mediator.did, client.did, 'add', ctx);
    expect(result).toEqual({ recipientDid: client.did, action: 'add', result: 'success' });
  });

  test('updateKeylist throws on a client_error result', async () => {
    mockMediatorReply((request) => ({
      id: randomUUID(),
      typ: 'application/didcomm-plain+json',
      type: 'https://didcomm.org/coordinate-mediation/2.0/keylist-update-response',
      body: {
        updated: [{ recipient_did: client.did, action: 'add', result: 'client_error' }],
      },
      from: mediator.did,
      to: [request.from as string],
    }));

    await expect(updateKeylist(mediator.did, client.did, 'add', ctx)).rejects.toThrow(/client_error/);
  });
});
