import { jest } from '@jest/globals';
import { resolveDidWeb } from '../src/chat/didWeb.js';

function jsonResponse(status: number, body: unknown): Response {
  return {
    ok: status >= 200 && status < 300,
    status,
    async json() {
      return body;
    },
  } as unknown as Response;
}

describe('resolveDidWeb', () => {
  let fetchSpy: ReturnType<typeof jest.spyOn>;

  beforeEach(() => {
    fetchSpy = jest.spyOn(globalThis, 'fetch');
  });

  afterEach(() => {
    fetchSpy.mockRestore();
  });

  it('resolves a did:web DID with a path component from a mocked fetch', async () => {
    const did = 'did:web:example.com:path:to:doc';
    const doc = {
      id: did,
      keyAgreement: ['did:web:example.com:path:to:doc#key-1'],
      authentication: [],
      verificationMethod: [],
      service: [],
    };
    fetchSpy.mockResolvedValue(jsonResponse(200, doc));

    const resolved = await resolveDidWeb(did);

    expect(fetchSpy).toHaveBeenCalledWith('https://example.com/path/to/doc/did.json');
    expect(resolved).toEqual(doc);
  });

  it('resolves a bare did:web DID (no path) against /.well-known/did.json', async () => {
    const did = 'did:web:example.com';
    const doc = { id: did, keyAgreement: [], authentication: [], verificationMethod: [], service: [] };
    fetchSpy.mockResolvedValue(jsonResponse(200, doc));

    const resolved = await resolveDidWeb(did);

    expect(fetchSpy).toHaveBeenCalledWith('https://example.com/.well-known/did.json');
    expect(resolved).toEqual(doc);
  });

  it('rejects a DID document whose id does not match the requested DID', async () => {
    const did = 'did:web:example.com';
    const doc = { id: 'did:web:not-example.com', keyAgreement: [], authentication: [], verificationMethod: [], service: [] };
    fetchSpy.mockResolvedValue(jsonResponse(200, doc));

    await expect(resolveDidWeb(did)).rejects.toThrow(/does not match requested DID/i);
  });

  it('rejects a non-2xx HTTP response', async () => {
    fetchSpy.mockResolvedValue(jsonResponse(404, { error: 'not found' }));

    await expect(resolveDidWeb('did:web:example.com')).rejects.toThrow(/HTTP 404/);
  });

  // Regression: mediator.wyvrn.app's real did:web document uses relative
  // ("#key-N") verification-method/relationship ids and "Multikey"
  // (publicKeyMultibase) verification methods — the installed `didcomm`
  // package's resolver recognizes neither form directly (relative ids don't
  // match pack_encrypted's fully-qualified key-id lookups, and "Multikey" is
  // not one of its recognized verification-method types), so both must be
  // normalized on resolution or real-world interop silently breaks with
  // "No compatible crypto" / an unknown-type deserialization error.
  it('normalizes relative ids and Multikey verification methods (real-world did:web shape)', async () => {
    const did = 'did:web:mediator.wyvrn.app';
    const doc = {
      id: did,
      verificationMethod: [
        { id: '#key-1', type: 'Multikey', publicKeyMultibase: 'z6Mkw5v4p9Jt2hgEL12iCry52AnusRAYH5iAA78pKa3vJjmY', controller: did },
        { id: '#key-2', type: 'Multikey', publicKeyMultibase: 'z6LSjiQT881Hctk4bJAev6GtxPVfVEdyGNG5es9GF757EEKX', controller: did },
      ],
      authentication: ['#key-1'],
      keyAgreement: ['#key-2'],
      service: [{ id: '#service', type: 'DIDCommMessaging', serviceEndpoint: { uri: 'https://mediator.wyvrn.app', accept: ['didcomm/v2'], routingKeys: [] } }],
    };
    fetchSpy.mockResolvedValue(jsonResponse(200, doc));

    const resolved = await resolveDidWeb(did);

    expect(resolved.authentication).toEqual([`${did}#key-1`]);
    expect(resolved.keyAgreement).toEqual([`${did}#key-2`]);
    expect(resolved.verificationMethod[0]).toMatchObject({ id: `${did}#key-1`, type: 'JsonWebKey2020' });
    expect(resolved.verificationMethod[0].publicKeyJwk).toMatchObject({ kty: 'OKP', crv: 'Ed25519' });
    expect(resolved.verificationMethod[1]).toMatchObject({ id: `${did}#key-2`, type: 'JsonWebKey2020' });
    expect(resolved.verificationMethod[1].publicKeyJwk).toMatchObject({ kty: 'OKP', crv: 'X25519' });
    expect(resolved.service[0].id).toBe(`${did}#service`);
  });
});
