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
import { discoverMediationVersion, requestMediation, updateRecipient } from '../src/chat/mediation.js';

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

describe('mediation client (coordinate-mediation 2.0 / 3.0)', () => {
  const client = generateX25519('did:example:client');
  const mediator = generateX25519('did:example:mediator');
  const sharedDocs = new Map([[client.did, client.doc], [mediator.did, mediator.doc]]);
  const clientDid = new MapDidResolver(sharedDocs);
  const clientSecrets = new MapSecretsResolver(new Map([[client.kid, client.secret]]));
  const mediatorDid = new MapDidResolver(sharedDocs);
  const mediatorSecrets = new MapSecretsResolver(new Map([[mediator.kid, mediator.secret]]));

  const ctx = { selfDid: client.did, did: clientDid, secrets: clientSecrets };

  /** Mocks `fetch` to decrypt the client's request and respond with `buildReply(request)`, per-call via a map keyed by request type. */
  function mockMediatorReplies(repliesByRequestType: Record<string, (request: PlaintextMessage) => PlaintextMessage>) {
    (global as { fetch?: typeof fetch }).fetch = jest.fn(async (_url: string, init: { body: Uint8Array }) => {
      const { message } = await unpack(init.body, { did: mediatorDid, secrets: mediatorSecrets });
      const buildReply = repliesByRequestType[message.type];
      if (!buildReply) throw new Error(`test mock has no reply configured for request type ${message.type}`);
      const reply = buildReply(message);
      const packedReply = await packAuthcrypt(reply, [client.did], mediator.did, {
        did: mediatorDid,
        secrets: mediatorSecrets,
      });
      const bytes = typeof packedReply === 'string' ? new TextEncoder().encode(packedReply) : packedReply;
      return new Response(bytes, { status: 200 });
    }) as unknown as typeof fetch;
  }

  function discloseReply(protocolIds: string[]) {
    return (request: PlaintextMessage): PlaintextMessage => ({
      id: randomUUID(),
      typ: 'application/didcomm-plain+json',
      type: 'https://didcomm.org/discover-features/2.0/disclose',
      body: { disclosures: protocolIds.map((id) => ({ 'feature-type': 'protocol', id })) },
      from: mediator.did,
      to: [request.from as string],
    });
  }

  afterEach(() => {
    delete (global as { fetch?: typeof fetch }).fetch;
  });

  test('discoverMediationVersion prefers 3.0 when both are disclosed', async () => {
    mockMediatorReplies({
      'https://didcomm.org/discover-features/2.0/queries': discloseReply([
        'https://didcomm.org/coordinate-mediation/2.0',
        'https://didcomm.org/coordinate-mediation/3.0',
      ]),
    });

    await expect(discoverMediationVersion(mediator.did, ctx)).resolves.toBe('3.0');
  });

  test('discoverMediationVersion falls back to 2.0 when only 2.0 is disclosed', async () => {
    mockMediatorReplies({
      'https://didcomm.org/discover-features/2.0/queries': discloseReply([
        'https://didcomm.org/coordinate-mediation/2.0',
      ]),
    });

    await expect(discoverMediationVersion(mediator.did, ctx)).resolves.toBe('2.0');
  });

  test('discoverMediationVersion throws when neither version is disclosed', async () => {
    mockMediatorReplies({
      'https://didcomm.org/discover-features/2.0/queries': discloseReply([
        'https://didcomm.org/trust-ping/2.0',
      ]),
    });

    await expect(discoverMediationVersion(mediator.did, ctx)).rejects.toThrow(/did not disclose/);
  });

  describe.each(['2.0', '3.0'] as const)('protocol version %s', (version) => {
    test('requestMediation returns the granted routing_did(s)', async () => {
      const routingDidBody = version === '2.0' ? 'did:example:mediator-routing' : ['did:example:mediator-routing'];
      mockMediatorReplies({
        [`https://didcomm.org/coordinate-mediation/${version}/mediate-request`]: (request) => ({
          id: randomUUID(),
          typ: 'application/didcomm-plain+json',
          type: `https://didcomm.org/coordinate-mediation/${version}/mediate-grant`,
          body: { routing_did: routingDidBody },
          from: mediator.did,
          to: [request.from as string],
        }),
      });

      const grant = await requestMediation(mediator.did, ctx, version);
      expect(grant.routingDids).toEqual(['did:example:mediator-routing']);
    });

    test('requestMediation throws on mediate-deny', async () => {
      mockMediatorReplies({
        [`https://didcomm.org/coordinate-mediation/${version}/mediate-request`]: (request) => ({
          id: randomUUID(),
          typ: 'application/didcomm-plain+json',
          type: `https://didcomm.org/coordinate-mediation/${version}/mediate-deny`,
          body: {},
          from: mediator.did,
          to: [request.from as string],
        }),
      });

      await expect(requestMediation(mediator.did, ctx, version)).rejects.toThrow(/denied/);
    });

    test('updateRecipient resolves on a successful update response', async () => {
      const requestType =
        version === '2.0'
          ? 'https://didcomm.org/coordinate-mediation/2.0/keylist-update'
          : 'https://didcomm.org/coordinate-mediation/3.0/recipient-update';
      const responseType =
        version === '2.0'
          ? 'https://didcomm.org/coordinate-mediation/2.0/keylist-update-response'
          : 'https://didcomm.org/coordinate-mediation/3.0/recipient-update-response';
      mockMediatorReplies({
        [requestType]: (request) => ({
          id: randomUUID(),
          typ: 'application/didcomm-plain+json',
          type: responseType,
          body: { updated: [{ recipient_did: client.did, action: 'add', result: 'success' }] },
          from: mediator.did,
          to: [request.from as string],
        }),
      });

      const result = await updateRecipient(mediator.did, client.did, 'add', ctx, version);
      expect(result).toEqual({ recipientDid: client.did, action: 'add', result: 'success' });
    });

    test('updateRecipient throws on a client_error result', async () => {
      const requestType =
        version === '2.0'
          ? 'https://didcomm.org/coordinate-mediation/2.0/keylist-update'
          : 'https://didcomm.org/coordinate-mediation/3.0/recipient-update';
      const responseType =
        version === '2.0'
          ? 'https://didcomm.org/coordinate-mediation/2.0/keylist-update-response'
          : 'https://didcomm.org/coordinate-mediation/3.0/recipient-update-response';
      mockMediatorReplies({
        [requestType]: (request) => ({
          id: randomUUID(),
          typ: 'application/didcomm-plain+json',
          type: responseType,
          body: { updated: [{ recipient_did: client.did, action: 'add', result: 'client_error' }] },
          from: mediator.did,
          to: [request.from as string],
        }),
      });

      await expect(updateRecipient(mediator.did, client.did, 'add', ctx, version)).rejects.toThrow(/client_error/);
    });
  });
});
