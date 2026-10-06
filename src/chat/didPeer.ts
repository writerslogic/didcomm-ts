import { createHash } from "node:crypto";
import type { DIDDoc, Service, VerificationMethod } from "../core/index.js";
import { multikeyToJwk } from "./multikey.js";
import { base58btcDecode, base58btcEncode } from "./keys.js";

function encodeMultibaseKey(bytes: Uint8Array): string {
  return `z${base58btcEncode(bytes)}`;
}
import { normalizeDidDoc } from "./normalizeDidDoc.js";

// Multicodec varint prefix for raw JSON content (code 0x0200), and multihash
// varint prefixes for sha2-256 (code 0x12) + a 32-byte digest length (0x20) —
// both single-byte varints since 0x12 and 0x20 are each < 0x80. Per
// https://github.com/multiformats/multicodec/blob/master/table.csv and
// https://github.com/multiformats/multihash.
const JSON_MULTICODEC_PREFIX = [0x80, 0x04];
const SHA256_MULTIHASH_PREFIX = [0x12, 0x20];

/** Verification relationship each numalgo-2 purpose code contributes to. */
const PURPOSE_RELATIONSHIP: Record<string, "authentication" | "keyAgreement" | "other"> = {
  V: "authentication",
  E: "keyAgreement",
  A: "other",
  I: "other",
  D: "other",
};

interface AbbreviatedService {
  t?: string;
  s?: unknown;
  r?: string[];
  a?: string[];
}

function expandServiceType(abbreviated: string | undefined): string {
  if (abbreviated === "dm") return "DIDCommMessaging";
  return abbreviated ?? "unknown";
}

function decodeServiceSegment(did: string, encoded: string, index: number): Service {
  const padded = encoded + "=".repeat((4 - (encoded.length % 4)) % 4);
  const parsed = JSON.parse(Buffer.from(padded, "base64url").toString("utf8")) as AbbreviatedService;
  const type = expandServiceType(parsed.t);
  const serviceEndpoint =
    parsed.r || parsed.a
      ? { uri: parsed.s as string, routingKeys: parsed.r, accept: parsed.a }
      : parsed.s;

  return { id: `${did}#didcommmessaging-${index + 1}`, type, serviceEndpoint };
}

/**
 * Resolves a `did:peer:2...` DID purely locally — no network call. Numalgo 2
 * ("Multi-key") encodes the full DID document (keys + services) in the DID
 * string itself, per
 * https://identity.foundation/peer-did-method-spec/#generation-method.
 * Numalgo 4 (long-form, hash-of-document) is implemented separately below
 * as `resolveDidPeer4`.
 */
export function resolveDidPeer(did: string): DIDDoc {
  if (!did.startsWith("did:peer:2.")) {
    throw new Error(`unsupported did:peer form (only numalgo 2 is implemented): ${did}`);
  }

  const segments = did
    .slice("did:peer:2".length)
    .split(".")
    .filter((segment) => segment.length > 0);

  const verificationMethod: VerificationMethod[] = [];
  const authentication: string[] = [];
  const keyAgreement: string[] = [];
  const service: Service[] = [];
  let keyIndex = 0;
  let serviceIndex = 0;

  for (const segment of segments) {
    const purposeCode = segment[0];
    const rest = segment.slice(1);

    if (purposeCode === "S") {
      service.push(decodeServiceSegment(did, rest, serviceIndex));
      serviceIndex++;
      continue;
    }

    const relationship = PURPOSE_RELATIONSHIP[purposeCode];
    if (!relationship) {
      throw new Error(`unsupported did:peer purpose code '${purposeCode}' in ${did}`);
    }

    keyIndex++;
    const { jwk } = multikeyToJwk(rest);
    const kid = `${did}#key-${keyIndex}`;
    verificationMethod.push({
      id: kid,
      // "JsonWebKey2020" (not a curve-specific type string) is what the
      // installed `didcomm` package's resolver actually recognizes for a
      // publicKeyJwk-bearing verification method — confirmed empirically
      // elsewhere in this codebase (see core.envelope.test.ts, cli.ts's
      // didKeyDoc); a curve-specific type here silently breaks pack/unpack
      // with "No compatible crypto: No common keys" despite valid key bytes.
      type: "JsonWebKey2020",
      controller: did,
      publicKeyJwk: jwk,
    });

    if (relationship === "authentication") authentication.push(kid);
    if (relationship === "keyAgreement") keyAgreement.push(kid);
  }

  return { id: did, keyAgreement, authentication, verificationMethod, service };
}

const X25519_PUB_MULTICODEC_PREFIX_BYTES = Uint8Array.from([0xec, 0x01]);

/**
 * Builds a `did:peer:2` string with one `keyAgreement` key (`x25519PublicKeyBase64Url`,
 * this identity's X25519 public key, base64url — the same value as its
 * `secretJwk.x`) and one `DIDCommMessaging` service entry addressed through
 * `mediatorEndpoint` with `routingKeys` (typically a mediator's granted
 * `routing_did`(s) from `mediate-grant` — see mediation.ts).
 */
export function buildDidPeer2(
  x25519PublicKeyBase64Url: string,
  mediatorEndpoint: string,
  routingKeys: string[],
): string {
  const publicKeyBytes = Buffer.from(x25519PublicKeyBase64Url, "base64url");
  const prefixed = new Uint8Array(X25519_PUB_MULTICODEC_PREFIX_BYTES.length + publicKeyBytes.length);
  prefixed.set(X25519_PUB_MULTICODEC_PREFIX_BYTES, 0);
  prefixed.set(publicKeyBytes, X25519_PUB_MULTICODEC_PREFIX_BYTES.length);
  const keyEntry = `E${encodeMultibaseKey(prefixed)}`;

  const serviceJson = JSON.stringify({ t: "dm", s: mediatorEndpoint, r: routingKeys });
  const serviceEntry = `S${Buffer.from(serviceJson, "utf8").toString("base64url").replace(/=+$/, "")}`;

  return `did:peer:2.${keyEntry}.${serviceEntry}`;
}

/** Minimal shape of a did:peer:4 "Input Document" — no root `id`, relative ids/references, omittable `controller`. */
interface PeerInputDocument {
  verificationMethod?: (Omit<VerificationMethod, "controller"> & { controller?: string })[];
  authentication?: string[];
  keyAgreement?: string[];
  service?: Service[];
}

/**
 * Resolves a long-form `did:peer:4{hash}:{encoded document}` DID purely
 * locally — no network call. Per
 * https://identity.foundation/peer-did-method-spec/#method-4-short-form-and-long-form:
 * the encoded document is `base58btc(multicodec-json-prefix + utf8(JSON))`,
 * and the hash is `base58btc(multihash-sha256-prefix + sha256(utf8(encoded
 * document string)))`. Short-form `did:peer:4{hash}` (no embedded document)
 * cannot be resolved without separately having stored its long-form
 * counterpart — not supported here.
 */
export function resolveDidPeer4(did: string): DIDDoc {
  if (!did.startsWith("did:peer:4")) {
    throw new Error(`not a did:peer:4 DID: ${did}`);
  }

  const body = did.slice("did:peer:4".length);
  const separatorIndex = body.indexOf(":");
  if (separatorIndex === -1) {
    throw new Error(
      `short-form did:peer:4 cannot be resolved without its long-form counterpart: ${did}`,
    );
  }

  const hashPart = body.slice(0, separatorIndex);
  const encodedDoc = body.slice(separatorIndex + 1);

  const expectedHashBytes = createHash("sha256").update(Buffer.from(encodedDoc, "utf8")).digest();
  const expectedHash = `z${base58btcEncode(new Uint8Array([...SHA256_MULTIHASH_PREFIX, ...expectedHashBytes]))}`;
  if (hashPart !== expectedHash) {
    throw new Error(`did:peer:4 hash verification failed for ${did} (expected ${expectedHash})`);
  }

  if (!encodedDoc.startsWith("z")) {
    throw new Error(`unsupported multibase transform in did:peer:4 encoded document: ${did}`);
  }
  const decoded = base58btcDecode(encodedDoc.slice(1));
  const hasJsonPrefix = JSON_MULTICODEC_PREFIX.every((byte, i) => decoded[i] === byte);
  if (!hasJsonPrefix) {
    throw new Error(`unsupported multicodec prefix in did:peer:4 encoded document: ${did}`);
  }
  const jsonBytes = decoded.slice(JSON_MULTICODEC_PREFIX.length);
  const input = JSON.parse(Buffer.from(jsonBytes).toString("utf8")) as PeerInputDocument;

  const doc: DIDDoc = {
    id: did,
    authentication: input.authentication ?? [],
    keyAgreement: input.keyAgreement ?? [],
    verificationMethod: (input.verificationMethod ?? []).map((vm) => ({
      ...vm,
      controller: vm.controller ?? did,
    })),
    service: input.service ?? [],
  };

  return normalizeDidDoc(doc);
}
