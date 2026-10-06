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
import { requestStatus, requestDelivery, acknowledgeReceived } from '../src/chat/pickup.js';

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
      verificationMethod: [{ id: kid, type: 'JsonWebKey2020', controller: did, publicKeyJwk: publicJwk }],
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

describe('pickup client (messagepickup 3.0)', () => {
  const client = generateX25519('did:example:client');
  const mediator = generateX25519('did:example:mediator');
  const sharedDocs = new Map([[client.did, client.doc], [mediator.did, mediator.doc]]);
  const clientDid = new MapDidResolver(sharedDocs);
  const clientSecrets = new MapSecretsResolver(new Map([[client.kid, client.secret]]));
  const mediatorDid = new MapDidResolver(sharedDocs);
  const mediatorSecrets = new MapSecretsResolver(new Map([[mediator.kid, mediator.secret]]));
  const ctx = { selfDid: client.did, did: clientDid, secrets: clientSecrets };

  function mockMediatorReplies(repliesByRequestType: Record<string, (request: PlaintextMessage) => PlaintextMessage>) {
    (global as { fetch?: typeof fetch }).fetch = jest.fn(async (_url: string, init: { body: Uint8Array }) => {
      const { message } = await unpack(init.body, { did: mediatorDid, secrets: mediatorSecrets });
      const buildReply = repliesByRequestType[message.type];
      if (!buildReply) throw new Error(`test mock has no reply configured for request type ${message.type}`);
      const reply = buildReply(message);
      const packedReply = await packAuthcrypt(reply, [client.did], mediator.did, { did: mediatorDid, secrets: mediatorSecrets });
      const bytes = typeof packedReply === 'string' ? new TextEncoder().encode(packedReply) : packedReply;
      return new Response(bytes, { status: 200 });
    }) as unknown as typeof fetch;
  }

  afterEach(() => {
    delete (global as { fetch?: typeof fetch }).fetch;
  });

  test('requestStatus returns the queued message count', async () => {
    mockMediatorReplies({
      'https://didcomm.org/messagepickup/3.0/status-request': (request) => ({
        id: randomUUID(),
        typ: 'application/didcomm-plain+json',
        type: 'https://didcomm.org/messagepickup/3.0/status',
        body: { message_count: 2, live_delivery: false },
        from: mediator.did,
        to: [request.from as string],
      }),
    });

    const status = await requestStatus(mediator.did, ctx);
    expect(status).toMatchObject({ messageCount: 2, liveDelivery: false });
  });

  test('requestDelivery decodes base64 attachments to raw envelope bytes', async () => {
    const queuedBytes = new TextEncoder().encode('{"fake":"envelope"}');
    mockMediatorReplies({
      'https://didcomm.org/messagepickup/3.0/delivery-request': (request) => ({
        id: randomUUID(),
        thid: request.id,
        typ: 'application/didcomm-plain+json',
        type: 'https://didcomm.org/messagepickup/3.0/delivery',
        body: {},
        from: mediator.did,
        to: [request.from as string],
        attachments: [{ id: 'msg-1', data: { base64: Buffer.from(queuedBytes).toString('base64') } }],
      }),
    });

    const delivered = await requestDelivery(mediator.did, ctx, 10);
    expect(delivered).toHaveLength(1);
    expect(delivered[0].attachmentId).toBe('msg-1');
    expect(new TextDecoder().decode(delivered[0].envelopeBytes)).toBe('{"fake":"envelope"}');
  });

  test('acknowledgeReceived returns the updated queue count', async () => {
    mockMediatorReplies({
      'https://didcomm.org/messagepickup/3.0/messages-received': (request) => ({
        id: randomUUID(),
        typ: 'application/didcomm-plain+json',
        type: 'https://didcomm.org/messagepickup/3.0/status',
        body: { message_count: 0 },
        from: mediator.did,
        to: [request.from as string],
      }),
    });

    const result = await acknowledgeReceived(mediator.did, ctx, ['msg-1']);
    expect(result).toEqual({ messageCount: 0 });
  });
});
