/**
 * Optional extension (not required for core DIDComm interop): IETF RATS (RFC 9334)
 * device-attestation evidence carried as an EAT (RFC 9711) token in its CWT/COSE_Sign1
 * form. Integration point: before a primary device trusts a new device's key for
 * multi-recipient authcrypt, it may request an EatToken proving that key is
 * hardware-backed. This module builds/verifies the token; `eatRecipientAttestation`
 * in ./recipientGate.ts binds it to a recipient key and plugs it into the pack
 * backends' `attestation` gate.
 */

import { encode, decode } from 'cbor-x';

/** Debug status of the device, per the EAT `dbgstat` claim. */
export enum DebugStatus {
  Disabled = 0,
  Enabled = 1,
  DisabledSinceBoot = 2,
  DisabledPermanently = 3,
  DisabledFullyAndPermanently = 4,
}

/**
 * EAT claims relevant to device attestation. CBOR integer claim-keys below follow
 * RFC 9711 / the IANA "CBOR Web Token (CWT) Claims" registry; confirm against the
 * current registry (https://www.iana.org/assignments/cwt/) before relying on exact
 * values across implementations.
 */
export interface EatClaims {
  /** Universal Entity ID, a stable device identifier (claim-key 256). */
  ueid: Uint8Array;
  /** Hardware OEM identifier (claim-key 258). */
  oemid?: number | Uint8Array;
  /** Hardware model identifier (claim-key 259). */
  hwmodel?: Uint8Array;
  /** Name of the software/firmware running on the device (claim-key 270). */
  swname?: string;
  /** Version of the software/firmware running on the device (claim-key 271). */
  swversion?: string;
  /** Debug facility status (claim-key 263). */
  dbgstat?: DebugStatus;
  /** Freshness nonce tying this token to a specific challenge (claim-key 10). */
  nonce: Uint8Array;
}

const CLAIM_KEY = {
  nonce: 10,
  ueid: 256,
  oemid: 258,
  hwmodel: 259,
  swname: 270,
  swversion: 271,
  dbgstat: 263,
} as const;

/** COSE header labels used in the protected header (RFC 8152 §3.1). */
const HEADER_LABEL = {
  alg: 1,
  kid: 4,
} as const;

export interface EatSigner {
  sign(bytes: Uint8Array): Promise<Uint8Array>;
  alg: string;
  kid: string;
}

export interface EatVerifier {
  verify(signedBytes: Uint8Array, signature: Uint8Array, kid: string): Promise<boolean>;
}

function claimsToMap(claims: EatClaims): Map<number, unknown> {
  const map = new Map<number, unknown>();
  map.set(CLAIM_KEY.ueid, claims.ueid);
  map.set(CLAIM_KEY.nonce, claims.nonce);
  if (claims.oemid !== undefined) map.set(CLAIM_KEY.oemid, claims.oemid);
  if (claims.hwmodel !== undefined) map.set(CLAIM_KEY.hwmodel, claims.hwmodel);
  if (claims.swname !== undefined) map.set(CLAIM_KEY.swname, claims.swname);
  if (claims.swversion !== undefined) map.set(CLAIM_KEY.swversion, claims.swversion);
  if (claims.dbgstat !== undefined) map.set(CLAIM_KEY.dbgstat, claims.dbgstat);
  return map;
}

function mapToClaims(map: Map<number, unknown>): EatClaims | null {
  const ueid = map.get(CLAIM_KEY.ueid);
  const nonce = map.get(CLAIM_KEY.nonce);
  if (!(ueid instanceof Uint8Array) || !(nonce instanceof Uint8Array)) return null;

  const claims: EatClaims = { ueid, nonce };
  const oemid = map.get(CLAIM_KEY.oemid);
  if (oemid !== undefined) claims.oemid = oemid as number | Uint8Array;
  const hwmodel = map.get(CLAIM_KEY.hwmodel);
  if (hwmodel instanceof Uint8Array) claims.hwmodel = hwmodel;
  const swname = map.get(CLAIM_KEY.swname);
  if (typeof swname === 'string') claims.swname = swname;
  const swversion = map.get(CLAIM_KEY.swversion);
  if (typeof swversion === 'string') claims.swversion = swversion;
  const dbgstat = map.get(CLAIM_KEY.dbgstat);
  if (typeof dbgstat === 'number') claims.dbgstat = dbgstat as DebugStatus;
  return claims;
}

/**
 * Builds the RFC 8152 §4.4 "Signature1" structure bytes that are actually signed,
 * binding the signature to both the protected header and the payload so a tampered
 * header (e.g. a swapped alg/kid) is detected the same as a tampered payload.
 *
 * Inputs are coerced to Node `Buffer` before encoding: cbor-x tags a plain
 * `Uint8Array` with CBOR tag 64 (RFC 8746) to preserve its exact type across a
 * round trip, but leaves a `Buffer` untagged. `decode()` is not guaranteed to
 * hand back a `Buffer` for a nested byte string, so re-encoding its raw output
 * without normalizing first would silently produce different bytes on the
 * verify side than were actually signed on the build side.
 */
function buildToBeSigned(protectedBytes: Uint8Array, payloadBytes: Uint8Array): Uint8Array {
  return encode(['Signature1', Buffer.from(protectedBytes), Buffer.alloc(0), Buffer.from(payloadBytes)]);
}

/**
 * Builds a COSE_Sign1-wrapped CWT carrying the given EAT claims as its payload
 * (embedded, not detached). The outer CBOR structure is the standard COSE_Sign1
 * array: [protected_header_bytes, unprotected_header_map, payload_bytes, signature_bytes].
 */
export async function buildEatToken(claims: EatClaims, signer: EatSigner): Promise<Uint8Array> {
  const protectedHeader = new Map<number, unknown>([
    [HEADER_LABEL.alg, signer.alg],
    [HEADER_LABEL.kid, signer.kid],
  ]);
  const protectedBytes: Uint8Array = encode(protectedHeader);
  const unprotectedHeader = new Map<number, unknown>();
  const payloadBytes: Uint8Array = encode(claimsToMap(claims));

  const toBeSigned = buildToBeSigned(protectedBytes, payloadBytes);
  const signature = await signer.sign(toBeSigned);

  const coseSign1 = [protectedBytes, unprotectedHeader, payloadBytes, signature];
  return new Uint8Array(encode(coseSign1));
}

/**
 * Verifies a COSE_Sign1-wrapped EAT token and returns its claims, or null if the
 * token is malformed, the signature does not verify, or the payload is tampered.
 */
export async function verifyEatToken(
  token: Uint8Array,
  verifier: EatVerifier,
): Promise<EatClaims | null> {
  let decoded: unknown;
  try {
    decoded = decode(token);
  } catch {
    return null;
  }
  if (!Array.isArray(decoded) || decoded.length !== 4) return null;
  const [protectedBytes, , payloadBytes, signature] = decoded as unknown[];
  if (
    !(protectedBytes instanceof Uint8Array) ||
    !(payloadBytes instanceof Uint8Array) ||
    !(signature instanceof Uint8Array)
  ) {
    return null;
  }

  let protectedHeader: unknown;
  try {
    protectedHeader = decode(protectedBytes);
  } catch {
    return null;
  }
  const kid = protectedHeader instanceof Map ? protectedHeader.get(HEADER_LABEL.kid) : undefined;
  if (typeof kid !== 'string') return null;

  const toBeSigned = buildToBeSigned(protectedBytes, payloadBytes);
  const ok = await verifier.verify(toBeSigned, signature, kid);
  if (!ok) return null;

  let claimsMap: unknown;
  try {
    claimsMap = decode(payloadBytes);
  } catch {
    return null;
  }
  if (!(claimsMap instanceof Map)) return null;
  return mapToClaims(claimsMap);
}
