import { resolveDidPeer } from '../src/chat/didPeer.js';

describe('resolveDidPeer', () => {
  test('resolves a numalgo-2 DID with authentication and key-agreement keys (spec worked example)', () => {
    const did =
      'did:peer:2.Vz6Mkj3PUd1WjvaDhNZhhhXQdz5UnZXmS7ehtx8bsPpD47kKc.Ez6LSg8zQom395jKLrGiBNruB9MM6V8PWuf2FpEy4uRFiqQBR';

    const doc = resolveDidPeer(did);

    expect(doc.id).toBe(did);
    expect(doc.authentication).toEqual([`${did}#key-1`]);
    expect(doc.keyAgreement).toEqual([`${did}#key-2`]);
    expect(doc.verificationMethod).toHaveLength(2);
    expect(doc.verificationMethod[0].type).toBe('Ed25519VerificationKey2020');
    expect(doc.verificationMethod[1].type).toBe('X25519KeyAgreementKey2020');
    expect(doc.service).toEqual([]);
  });

  test('decodes a DIDCommMessaging service segment with routingKeys', () => {
    const serviceJson = JSON.stringify({
      t: 'dm',
      s: 'https://example.com/endpoint',
      r: ['did:example:somemediator#somekey'],
    });
    const encoded = Buffer.from(serviceJson, 'utf8').toString('base64url').replace(/=+$/, '');
    const did = `did:peer:2.Ez6LSg8zQom395jKLrGiBNruB9MM6V8PWuf2FpEy4uRFiqQBR.S${encoded}`;

    const doc = resolveDidPeer(did);

    expect(doc.service).toHaveLength(1);
    expect(doc.service[0].type).toBe('DIDCommMessaging');
    expect(doc.service[0].serviceEndpoint).toEqual({
      uri: 'https://example.com/endpoint',
      routingKeys: ['did:example:somemediator#somekey'],
      accept: undefined,
    });
  });

  test('rejects did:peer numalgo other than 2', () => {
    expect(() => resolveDidPeer('did:peer:0z6Mkj3PUd1')).toThrow(/numalgo 2/);
  });

  test('rejects an unsupported purpose code', () => {
    expect(() =>
      resolveDidPeer('did:peer:2.Xz6Mkj3PUd1WjvaDhNZhhhXQdz5UnZXmS7ehtx8bsPpD47kKc'),
    ).toThrow(/purpose code/);
  });
});
