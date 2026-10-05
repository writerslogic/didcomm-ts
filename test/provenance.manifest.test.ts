import { attachProvenance, readProvenance, C2paManifestRef } from '../src/provenance/index.js';

function freezeDeep<T>(value: T): T {
  Object.values(value as object).forEach((v) => {
    if (v && typeof v === 'object' && !Object.isFrozen(v)) {
      freezeDeep(v);
    }
  });
  return Object.freeze(value);
}

describe('provenance manifest reference', () => {
  test('attach/read round trip with a url reference', () => {
    const attachment = { id: 'att-1', data: { base64: 'xyz' } };
    const manifestRef: C2paManifestRef = {
      url: 'https://example.com/manifest.c2pa',
      hash: { alg: 'sha256', value: 'deadbeef' },
    };

    const out = attachProvenance(attachment, manifestRef);

    expect(readProvenance(out)).toEqual(manifestRef);
  });

  test('attach/read round trip with an embedded manifest', () => {
    const attachment = { id: 'att-2', data: { json: { foo: 'bar' } } };
    const manifestRef: C2paManifestRef = {
      embedded: new Uint8Array([1, 2, 3, 4]),
      hash: { alg: 'sha256', value: 'cafebabe' },
    };

    const out = attachProvenance(attachment, manifestRef);
    const read = readProvenance(out);

    expect(read).not.toBeNull();
    expect(read?.embedded).toEqual(manifestRef.embedded);
    expect(read?.hash).toEqual(manifestRef.hash);
  });

  test('readProvenance returns null when no c2pa field is present', () => {
    const attachment = { id: 'att-3', data: { links: ['https://example.com/x'] } };

    expect(readProvenance(attachment)).toBeNull();
  });

  test('readProvenance returns null for a malformed c2pa field', () => {
    const attachment = {
      id: 'att-4',
      data: { base64: 'xyz', c2pa: { hash: { alg: 'sha256' } } },
    };

    expect(readProvenance(attachment)).toBeNull();
  });

  test('attachProvenance does not mutate its input', () => {
    const attachment = freezeDeep({ id: 'att-5', data: { base64: 'xyz' } });
    const manifestRef: C2paManifestRef = {
      url: 'https://example.com/manifest.c2pa',
      hash: { alg: 'sha256', value: 'deadbeef' },
    };

    const out = attachProvenance(attachment, manifestRef);

    expect(out).not.toBe(attachment);
    expect(out.data).not.toBe(attachment.data);
    expect('c2pa' in attachment.data).toBe(false);
    expect(readProvenance(out)).toEqual(manifestRef);
  });
});
