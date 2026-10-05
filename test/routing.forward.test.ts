import {
  AnoncryptProvider,
  EncryptedMessage,
  PlaintextMessage,
  FORWARD_MESSAGE_TYPE,
  wrapInForward,
  wrapForwardChain,
  unwrapForward,
} from '../src/routing/forward.js';
import { DIDDoc, selectRoutingPath } from '../src/routing/index.js';

/**
 * A fake anoncrypt provider for tests: "encryption" tags the plaintext
 * with the recipient key id and JSON-serializes it, so round trips are
 * verifiable without a real crypto stack. It still faithfully exercises
 * the wrap/unwrap contract (plaintext in, opaque envelope out, and back).
 */
function fakeAnoncryptProvider(): AnoncryptProvider {
  return {
    encrypt(message: PlaintextMessage, recipientKeyId: string): EncryptedMessage {
      return {
        anoncrypted: true,
        recipientKeyId,
        ciphertext: JSON.stringify(message),
      };
    },
    decrypt(message: EncryptedMessage): PlaintextMessage {
      if (message.anoncrypted !== true || typeof message.ciphertext !== 'string') {
        throw new Error('not a message produced by fakeAnoncryptProvider');
      }
      return JSON.parse(message.ciphertext) as PlaintextMessage;
    },
  };
}

function samplePlaintextMessage(): PlaintextMessage {
  return {
    id: 'msg-1',
    type: 'https://example.com/protocols/example/1.0/hello',
    to: ['did:example:recipient'],
    from: 'did:example:sender',
    body: { greeting: 'hello' },
  };
}

describe('wrapInForward / unwrapForward', () => {
  it('round trips a single-hop forward wrap/unwrap', async () => {
    const crypto = fakeAnoncryptProvider();
    const innerPlaintext = samplePlaintextMessage();
    const innerEncrypted = await crypto.encrypt(innerPlaintext, 'did:example:recipient#key-1');

    const forwardEncrypted = await wrapInForward(
      innerEncrypted,
      'did:example:recipient',
      'did:example:mediator1#key-1',
      crypto,
    );

    // The mediator receives forwardEncrypted and anondecrypts it.
    const forwardPlaintext = await crypto.decrypt(forwardEncrypted);
    expect(forwardPlaintext.type).toBe(FORWARD_MESSAGE_TYPE);

    const { next, attachedMessage } = unwrapForward(forwardPlaintext);
    expect(next).toBe('did:example:recipient');
    expect(attachedMessage).toEqual(innerEncrypted);

    // The mediator forwards attachedMessage on; the final recipient
    // anondecrypts it and recovers the original plaintext.
    const recovered = await crypto.decrypt(attachedMessage);
    expect(recovered).toEqual(innerPlaintext);
  });

  it('rejects unwrapping a non-forward message', () => {
    const notForward: PlaintextMessage = {
      id: 'x',
      type: 'https://example.com/not-forward',
      body: {},
    };
    expect(() => unwrapForward(notForward)).toThrow(/expected message type/i);
  });

  it('round trips a multi-hop (2 mediator) forward wrap/unwrap', async () => {
    const crypto = fakeAnoncryptProvider();
    const innerPlaintext = samplePlaintextMessage();
    const innerEncrypted = await crypto.encrypt(innerPlaintext, 'did:example:recipient#key-1');

    const finalRecipient = 'did:example:recipient';
    const mediator1 = 'did:example:mediator1#key-1'; // closest to recipient
    const mediator2 = 'did:example:mediator2#key-1'; // closest to sender, entry point

    const wireMessage = await wrapForwardChain(
      innerEncrypted,
      [mediator1, mediator2],
      finalRecipient,
      crypto,
    );

    // --- Hop at mediator2 (entry point, closest to sender) ---
    const atMediator2 = await crypto.decrypt(wireMessage);
    const unwrapped2 = unwrapForward(atMediator2);
    expect(unwrapped2.next).toBe(mediator1);

    // --- Hop at mediator1 (closest to recipient) ---
    const atMediator1 = await crypto.decrypt(unwrapped2.attachedMessage);
    const unwrapped1 = unwrapForward(atMediator1);
    expect(unwrapped1.next).toBe(finalRecipient);
    expect(unwrapped1.attachedMessage).toEqual(innerEncrypted);

    // --- Final recipient ---
    const recovered = await crypto.decrypt(unwrapped1.attachedMessage);
    expect(recovered).toEqual(innerPlaintext);
  });
});

describe('selectRoutingPath', () => {
  function multiDeviceDidDoc(): DIDDoc {
    return {
      id: 'did:example:recipient',
      service: [
        {
          id: 'did:example:recipient#mobile',
          type: 'DIDCommMessaging',
          serviceEndpoint: {
            uri: 'https://mobile-mediator.example.com/didcomm',
            accept: ['didcomm/v2'],
            routingKeys: ['did:example:mobileMediator#key-1'],
          },
        },
        {
          id: 'did:example:recipient#desktop',
          type: 'DIDCommMessaging',
          serviceEndpoint: {
            uri: 'https://entry-mediator.example.com/didcomm',
            accept: ['didcomm/v2'],
            // Two-hop chain for the desktop device: closest-to-recipient first.
            routingKeys: [
              'did:example:desktopInnerMediator#key-1',
              'did:example:desktopEntryMediator#key-1',
            ],
          },
        },
        {
          id: 'did:example:recipient#watch',
          type: 'DIDCommMessaging',
          serviceEndpoint: {
            uri: 'https://watch-mediator.example.com/didcomm',
            accept: ['didcomm/v2'],
            routingKeys: ['did:example:watchMediator#key-1'],
          },
        },
      ],
    };
  }

  it('picks the right path among 3 service entries for a given device hint', () => {
    const didDoc = multiDeviceDidDoc();

    const desktopPath = selectRoutingPath(didDoc, 'desktop');
    expect(desktopPath.deviceId).toBe('desktop');
    expect(desktopPath.endpoint).toBe('https://entry-mediator.example.com/didcomm');
    expect(desktopPath.mediators).toEqual([
      'did:example:desktopInnerMediator',
      'did:example:desktopEntryMediator',
    ]);

    const mobilePath = selectRoutingPath(didDoc, 'mobile');
    expect(mobilePath.deviceId).toBe('mobile');
    expect(mobilePath.mediators).toEqual(['did:example:mobileMediator']);
  });

  it('returns all device paths when no device hint is given', () => {
    const didDoc = multiDeviceDidDoc();
    const paths = selectRoutingPath(didDoc);

    expect(paths).toHaveLength(3);
    expect(paths.map((p) => p.deviceId).sort()).toEqual(['desktop', 'mobile', 'watch']);
  });

  it('throws for an unknown device hint', () => {
    const didDoc = multiDeviceDidDoc();
    expect(() => selectRoutingPath(didDoc, 'tv')).toThrow(/no DIDCommMessaging service entry/i);
  });
});
