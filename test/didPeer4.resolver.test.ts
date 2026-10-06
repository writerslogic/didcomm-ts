import { resolveDidPeer4 } from '../src/chat/didPeer.js';

// Real long-form did:peer:4 captured from mediator.wyvrn.app's own did:web
// document (its `alsoKnownAs` field) — a genuine production test vector.
// It decodes to the same keys and DIDCommMessaging service endpoint as that
// did:web document, confirming both represent the same mediator identity.
const WYVRN_MEDIATOR_PEER4 =
  'did:peer:4zQmWH3zTUYqKHCcUBqvaYapaiefiw8sZmiCHKYYaoRjmWGy:z7zA6ozDv3XcqLdU2SUa1bPXVevbmhsekT4ULDkJbKtzotRoKM39CzoNzntNzucR6t5ML2FZ8gnY7CLyboHk6g1guPcypdcfCGKSp1Vtrs859hgmfZGRexgdNQAtTEihWy9wUXMjkQG2WHTiCqf5vreRZcvNzdNGuCc56MDYAyzsd9vH8QHNB9AuH2daPE2ybEEaWZX2zq7nPeUu64gpMuojPqRrcXmXrYuKm8N8feYXH9snA4ogvR7DudMLY4iZ2SS2xZKZPsvKoVcdrziDgrCeu3cDEWPh1Emkpd82ZKLjLmww3WJ6z5dkQFyF6U9vJdcPixmuBN8DhJZ5KtXmwW4NLGuRboU9gBy6QURGE5Hm1oKGygfgV1qc7j6vcupNwwuPtPEmLpfbwdHo5FubzNrQsvdUHq3o1gdVF9ERtYDbiYukJbrUmrLksKVdodRS2YDEEXHGnVS3uDWzQZT9ewQDMDQ28YEPvMQqkPMxH45JrzecfpAa3VgHaYkG23gspK6qeB5er5wiXzaHmvpjVgVFkxNbnBjzk4q8MZBheYFPT5BLTeQP29HGhBTnHncvami5VRZ83xZSXKw92Ri8Wo6EuCYjCR2VuDGewxzD3GDuTXbK4Zyh8LhuiV81SBxYJms3RnV5c39BoEZDARDgohynUabqehviHbSqxtRwACww5XY1MGqZtsx24TWKVHjuU5t4s53VwQpUKDSzjRNyy14TLRe76Zom7pjofvkqShS';

describe('resolveDidPeer4', () => {
  test('resolves a real long-form did:peer:4 (mediator.wyvrn.app)', () => {
    const doc = resolveDidPeer4(WYVRN_MEDIATOR_PEER4);

    expect(doc.id).toBe(WYVRN_MEDIATOR_PEER4);
    expect(doc.verificationMethod).toHaveLength(2);
    expect(doc.verificationMethod[0]).toMatchObject({
      id: `${WYVRN_MEDIATOR_PEER4}#key-1`,
      type: 'JsonWebKey2020',
      controller: WYVRN_MEDIATOR_PEER4,
    });
    expect(doc.verificationMethod[0].publicKeyJwk).toMatchObject({ kty: 'OKP', crv: 'Ed25519' });
    expect(doc.verificationMethod[1].publicKeyJwk).toMatchObject({ kty: 'OKP', crv: 'X25519' });
    expect(doc.authentication).toEqual([`${WYVRN_MEDIATOR_PEER4}#key-1`]);
    expect(doc.keyAgreement).toEqual([`${WYVRN_MEDIATOR_PEER4}#key-2`]);
    expect(doc.service).toHaveLength(1);
    expect(doc.service[0]).toMatchObject({
      id: `${WYVRN_MEDIATOR_PEER4}#service`,
      type: 'DIDCommMessaging',
      serviceEndpoint: { uri: 'https://mediator.wyvrn.app', accept: ['didcomm/v2', 'didcomm/v2+cbor'], routingKeys: [] },
    });
  });

  test('rejects a tampered long-form DID (hash mismatch)', () => {
    const tampered = WYVRN_MEDIATOR_PEER4.replace(':z7zA', ':z7zB');
    expect(() => resolveDidPeer4(tampered)).toThrow(/hash verification failed/);
  });

  test('rejects a short-form did:peer:4 (no embedded document)', () => {
    expect(() => resolveDidPeer4('did:peer:4zQmWH3zTUYqKHCcUBqvaYapaiefiw8sZmiCHKYYaoRjmWGy')).toThrow(
      /short-form/,
    );
  });

  test('rejects a non-did:peer:4 DID', () => {
    expect(() => resolveDidPeer4('did:peer:2.Vz6Mkj3')).toThrow(/not a did:peer:4/);
  });
});
