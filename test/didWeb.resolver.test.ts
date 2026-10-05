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
});
