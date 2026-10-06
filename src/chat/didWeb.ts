/**
 * `did:web` resolver, per https://w3c-ccg.github.io/did-method-web/.
 *
 * A DID like `did:web:example.com` maps to
 * `https://example.com/.well-known/did.json`; a DID with a path component,
 * e.g. `did:web:example.com:path:to:doc`, maps to
 * `https://example.com/path/to/doc/did.json` (each `:`-separated path
 * segment after the domain becomes a `/`-separated path segment, and is
 * percent-decoded). The domain segment itself is also percent-decoded,
 * which recovers a `%3A`-encoded port (e.g. `did:web:example.com%3A3000`
 * resolves against `https://example.com:3000/...`).
 */
import type { DIDDoc } from "../core/index.js";
import { normalizeDidDoc } from "./normalizeDidDoc.js";

const DID_WEB_PREFIX = "did:web:";

/** Builds the `https://` URL a `did:web` DID resolves its DID document from. */
function didWebToUrl(did: string): string {
  if (!did.startsWith(DID_WEB_PREFIX)) {
    throw new Error(`not a did:web DID: ${did}`);
  }

  const methodSpecificId = did.slice(DID_WEB_PREFIX.length);
  const segments = methodSpecificId.split(":");
  const [domainSegment, ...pathSegments] = segments;
  if (!domainSegment) {
    throw new Error(`invalid did:web DID (missing domain): ${did}`);
  }

  const domain = decodeURIComponent(domainSegment);
  if (pathSegments.length === 0) {
    return `https://${domain}/.well-known/did.json`;
  }

  const path = pathSegments.map((segment) => decodeURIComponent(segment)).join("/");
  return `https://${domain}/${path}/did.json`;
}

/**
 * Resolves a `did:web` DID by fetching its DID document over HTTPS and
 * validating that the document's `id` matches the requested DID. Throws on
 * a non-2xx HTTP status, a JSON parse failure, a malformed `did:web` DID,
 * or an `id` mismatch.
 */
export async function resolveDidWeb(did: string): Promise<DIDDoc> {
  const url = didWebToUrl(did);

  const response = await fetch(url);
  if (!response.ok) {
    throw new Error(`did:web resolution failed: GET ${url} returned HTTP ${response.status}`);
  }

  let doc: DIDDoc;
  try {
    doc = (await response.json()) as DIDDoc;
  } catch (err) {
    throw new Error(
      `did:web resolution failed: could not parse JSON from ${url}: ${err instanceof Error ? err.message : String(err)}`,
    );
  }

  if (doc.id !== did) {
    throw new Error(`did:web resolution failed: document id "${doc.id}" does not match requested DID "${did}"`);
  }

  return normalizeDidDoc(doc);
}
