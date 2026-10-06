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
import type { DIDDoc, Service, VerificationMethod } from "../core/index.js";
import { multikeyToJwk } from "./multikey.js";

const DID_WEB_PREFIX = "did:web:";

/** Expands a possibly-relative id ("#key-1") to an absolute one (`${did}#key-1`); leaves absolute ids unchanged. */
function absoluteId(did: string, id: string): string {
  return id.startsWith("#") ? `${did}${id}` : id;
}

/**
 * Normalizes a resolved DID document so downstream pack/unpack can use it:
 * - expands relative verification-method/relationship ids to absolute ones
 *   (many real documents, e.g. mediator.wyvrn.app's, use `"#key-1"` style
 *   ids relative to the document's own `id`);
 * - converts `"Multikey"` verification methods (`publicKeyMultibase`) to
 *   `"JsonWebKey2020"` (`publicKeyJwk`) — see multikey.ts's header comment
 *   for why the installed `didcomm` package requires this.
 * Any other verification method type/key representation is passed through
 * unchanged (and will surface its own error from didcomm-rust if
 * unsupported, rather than being silently dropped here).
 */
function normalizeDidDoc(doc: DIDDoc): DIDDoc {
  const verificationMethod: VerificationMethod[] = doc.verificationMethod.map((vm) => {
    const id = absoluteId(doc.id, vm.id);
    const controller = absoluteId(doc.id, vm.controller);
    if (vm.type === "Multikey" && typeof vm.publicKeyMultibase === "string") {
      const { jwk } = multikeyToJwk(vm.publicKeyMultibase);
      return { id, type: "JsonWebKey2020", controller, publicKeyJwk: jwk };
    }
    return { ...vm, id, controller };
  });

  const service: Service[] = (doc.service ?? []).map((svc) => ({
    ...svc,
    id: absoluteId(doc.id, svc.id),
  }));

  return {
    ...doc,
    verificationMethod,
    authentication: doc.authentication.map((id) => absoluteId(doc.id, id)),
    keyAgreement: doc.keyAgreement.map((id) => absoluteId(doc.id, id)),
    service,
  };
}

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
