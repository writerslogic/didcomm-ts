import type { DIDDoc, Service, VerificationMethod } from "../core/index.js";
import { multikeyToJwk } from "./multikey.js";

/** Expands a possibly-relative id ("#key-1") to an absolute one (`${did}#key-1`); leaves absolute ids unchanged. */
export function absoluteId(did: string, id: string): string {
  return id.startsWith("#") ? `${did}${id}` : id;
}

/**
 * Normalizes a resolved DID document so downstream pack/unpack can use it:
 * - expands relative verification-method/relationship/service ids to
 *   absolute ones (many real documents — e.g. mediator.wyvrn.app's did:web
 *   document, and every did:peer:4 embedded document per spec — use
 *   `"#key-1"` style ids relative to the document's own `id`, and
 *   did:peer:4's embedded document omits `controller` entirely when it
 *   equals the document owner);
 * - converts any verification method carrying `publicKeyMultibase` (any
 *   declared `type` — real documents pair this field with both `"Multikey"`
 *   and legacy type strings like `"X25519KeyAgreementKey2020"`) to
 *   `"JsonWebKey2020"` / `publicKeyJwk` — see multikey.ts's header comment
 *   for why the installed `didcomm` package requires exactly that pairing.
 * Any verification method with neither `publicKeyMultibase` nor a
 * `"JsonWebKey2020"` type is passed through unchanged, and will surface its
 * own error from didcomm-rust if unsupported, rather than being silently
 * dropped here.
 */
export function normalizeDidDoc(doc: DIDDoc): DIDDoc {
  const verificationMethod: VerificationMethod[] = doc.verificationMethod.map((vm) => {
    const id = absoluteId(doc.id, vm.id);
    const controller = absoluteId(doc.id, vm.controller || doc.id);
    if (typeof vm.publicKeyMultibase === "string") {
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
