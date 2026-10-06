import { base58btcDecode } from "./keys.js";

// Multicodec varint prefixes, per https://github.com/multiformats/multicodec/blob/master/table.csv:
// x25519-pub = 0xec, ed25519-pub = 0xed (both encode as a 2-byte varint: [code | 0x80, 0x01]).
const X25519_PUB_MULTICODEC_PREFIX = [0xec, 0x01];
const ED25519_PUB_MULTICODEC_PREFIX = [0xed, 0x01];

export type MultikeyCodec = "x25519" | "ed25519";

/** Decodes a multibase (`z...`) + multicodec-prefixed public key, per the DID Core Multikey spec. */
export function decodeMultibaseKey(value: string): { codec: MultikeyCodec; publicKeyBytes: Uint8Array } {
  if (!value.startsWith("z")) {
    throw new Error(`unsupported multibase transform in multikey value: ${value}`);
  }
  const decoded = base58btcDecode(value.slice(1));
  const matchesPrefix = (prefix: number[]) => prefix.every((byte, i) => decoded[i] === byte);

  if (matchesPrefix(X25519_PUB_MULTICODEC_PREFIX)) {
    return { codec: "x25519", publicKeyBytes: decoded.slice(X25519_PUB_MULTICODEC_PREFIX.length) };
  }
  if (matchesPrefix(ED25519_PUB_MULTICODEC_PREFIX)) {
    return { codec: "ed25519", publicKeyBytes: decoded.slice(ED25519_PUB_MULTICODEC_PREFIX.length) };
  }
  throw new Error(`unsupported multicodec prefix in multikey value: ${value}`);
}

/**
 * Converts a `publicKeyMultibase` value to the equivalent JWK.
 * "JsonWebKey2020" (not a curve-specific type string) is what the installed
 * `didcomm` package's resolver actually recognizes for a publicKeyJwk-bearing
 * verification method — confirmed empirically elsewhere in this codebase
 * (core.envelope.test.ts, cli.ts's didKeyDoc); real-world documents using the
 * modern `"Multikey"` type with `publicKeyMultibase` (e.g.
 * mediator.wyvrn.app's did:web document) must be normalized to this form
 * before being handed to pack/unpack, or didcomm-rust rejects them with
 * "No compatible crypto" / an unknown verification-method-type error.
 */
export function multikeyToJwk(publicKeyMultibase: string): { codec: MultikeyCodec; jwk: Record<string, string> } {
  const { codec, publicKeyBytes } = decodeMultibaseKey(publicKeyMultibase);
  const x = Buffer.from(publicKeyBytes).toString("base64url");
  return {
    codec,
    jwk: codec === "x25519" ? { kty: "OKP", crv: "X25519", x } : { kty: "OKP", crv: "Ed25519", x },
  };
}
