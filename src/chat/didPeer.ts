import type { DIDDoc, Service, VerificationMethod } from "../core/index.js";
import { base58btcDecode } from "./keys.js";

// Multicodec varint prefixes, per https://github.com/multiformats/multicodec/blob/master/table.csv:
// x25519-pub = 0xec, ed25519-pub = 0xed (both encode as a 2-byte varint: [code | 0x80, 0x01]).
const X25519_PUB_MULTICODEC_PREFIX = [0xec, 0x01];
const ED25519_PUB_MULTICODEC_PREFIX = [0xed, 0x01];

type KeyCodec = "x25519" | "ed25519";

function decodeMultibaseKey(value: string): { codec: KeyCodec; publicKeyBytes: Uint8Array } {
  if (!value.startsWith("z")) {
    throw new Error(`unsupported multibase transform in did:peer key: ${value}`);
  }
  const decoded = base58btcDecode(value.slice(1));
  const matchesPrefix = (prefix: number[]) => prefix.every((byte, i) => decoded[i] === byte);

  if (matchesPrefix(X25519_PUB_MULTICODEC_PREFIX)) {
    return { codec: "x25519", publicKeyBytes: decoded.slice(X25519_PUB_MULTICODEC_PREFIX.length) };
  }
  if (matchesPrefix(ED25519_PUB_MULTICODEC_PREFIX)) {
    return { codec: "ed25519", publicKeyBytes: decoded.slice(ED25519_PUB_MULTICODEC_PREFIX.length) };
  }
  throw new Error(`unsupported multicodec prefix in did:peer key: ${value}`);
}

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
 * Numalgo 4 (hash-of-long-form / long-form) is NOT supported here.
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
    const { codec, publicKeyBytes } = decodeMultibaseKey(rest);
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
      publicKeyJwk:
        codec === "x25519"
          ? { kty: "OKP", crv: "X25519", x: Buffer.from(publicKeyBytes).toString("base64url") }
          : { kty: "OKP", crv: "Ed25519", x: Buffer.from(publicKeyBytes).toString("base64url") },
    });

    if (relationship === "authentication") authentication.push(kid);
    if (relationship === "keyAgreement") keyAgreement.push(kid);
  }

  return { id: did, keyAgreement, authentication, verificationMethod, service };
}
