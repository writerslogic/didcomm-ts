/**
 * Carries a *reference* to (or an embedded copy of) a C2PA content-provenance
 * manifest alongside a DIDComm attachment. Actual C2PA manifest creation,
 * signing, and validation against the C2PA spec are out of scope here and
 * must use a dedicated C2PA library if/when implemented.
 */

export interface C2paManifestRef {
  url?: string;
  embedded?: Uint8Array;
  hash: { alg: string; value: string };
}

interface AttachmentShape {
  id: string;
  data: {
    base64?: string;
    json?: unknown;
    links?: string[];
  };
}

function isC2paManifestRef(value: unknown): value is C2paManifestRef {
  if (typeof value !== 'object' || value === null) {
    return false;
  }
  const candidate = value as Record<string, unknown>;

  const hash = candidate.hash;
  if (typeof hash !== 'object' || hash === null) {
    return false;
  }
  const { alg, value: hashValue } = hash as Record<string, unknown>;
  if (typeof alg !== 'string' || alg.length === 0) {
    return false;
  }
  if (typeof hashValue !== 'string' || hashValue.length === 0) {
    return false;
  }

  if (candidate.url !== undefined && typeof candidate.url !== 'string') {
    return false;
  }
  if (candidate.embedded !== undefined && !(candidate.embedded instanceof Uint8Array)) {
    return false;
  }

  return true;
}

export function attachProvenance<A extends AttachmentShape>(
  attachment: A,
  manifestRef: C2paManifestRef
): A & { data: A['data'] & { c2pa: C2paManifestRef } } {
  return {
    ...attachment,
    data: {
      ...attachment.data,
      c2pa: manifestRef,
    },
  };
}

export function readProvenance(attachment: AttachmentShape): C2paManifestRef | null {
  const candidate = (attachment.data as { c2pa?: unknown }).c2pa;
  return isC2paManifestRef(candidate) ? candidate : null;
}
