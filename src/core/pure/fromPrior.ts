/**
 * DID rotation: the `from_prior` header, a compact JWS (`typ: JWT`) signed by
 * a key in the prior DID's `authentication` set, whose claims say the prior
 * DID (`iss`) has rotated to the message's `from` DID (`sub`). Compatible with
 * didcomm-rust's `FromPrior::pack` / `FromPrior::unpack`.
 *
 * Verification requires `iss` to be the DID of the signing key (a rotation
 * claim is only meaningful when the prior DID's own key makes it) and
 * enforces `exp` / `nbf`.
 */

import type { DidResolver, SecretsResolver } from '../types.js';
import { b64urlDecode, b64urlEncode, fromUtf8, utf8 } from './bytes.js';
import { jwsAlgFor, publicKeyFromVerificationMethod, sign, verify } from './keys.js';
import { didOf, findKey, loadSecret, resolveDoc } from './resolve.js';

export interface FromPrior {
  /** The prior DID (no fragment). */
  iss: string;
  /** The new DID (no fragment); must equal the message's `from` DID. */
  sub: string;
  aud?: string;
  exp?: number;
  nbf?: number;
  iat?: number;
  jti?: string;
}

/** Tolerated clock skew, in seconds, when checking `exp` and `nbf`. */
const CLOCK_SKEW_SECONDS = 60;

function isPlainDid(value: unknown): value is string {
  return typeof value === 'string' && /^did:[a-z0-9]+:[^#?/]+$/.test(value);
}

function validateClaims(claims: FromPrior): void {
  if (!isPlainDid(claims.iss)) throw new Error('from_prior `iss` must be a DID without a fragment');
  if (!isPlainDid(claims.sub)) throw new Error('from_prior `sub` must be a DID without a fragment');
  if (claims.iss === claims.sub) throw new Error('from_prior `iss` and `sub` must differ');
  for (const field of ['exp', 'nbf', 'iat'] as const) {
    if (claims[field] !== undefined && !Number.isSafeInteger(claims[field])) {
      throw new Error(`from_prior \`${field}\` must be an integer (seconds)`);
    }
  }
  for (const field of ['aud', 'jti'] as const) {
    if (claims[field] !== undefined && typeof claims[field] !== 'string') {
      throw new Error(`from_prior \`${field}\` must be a string`);
    }
  }
}

/**
 * Signs `fromPrior` as a compact JWT with a key from the prior DID's
 * `authentication` set: `issuerKid` if given, otherwise the first one the
 * secrets resolver holds. Set the returned `jwt` as the message's `from_prior`.
 */
export async function packFromPrior(
  fromPrior: FromPrior,
  issuerKid: string | null,
  resolvers: { did: DidResolver; secrets: SecretsResolver },
): Promise<{ jwt: string; issuerKid: string }> {
  validateClaims(fromPrior);
  if (issuerKid !== null && didOf(issuerKid) !== fromPrior.iss) {
    throw new Error('from_prior issuer kid does not belong to `iss`');
  }
  const doc = await resolveDoc(resolvers.did, fromPrior.iss);
  const candidates = issuerKid
    ? [issuerKid]
    : doc.authentication.map((ref) => (ref.startsWith('#') ? `${fromPrior.iss}${ref}` : ref));
  const [kid] = await resolvers.secrets.find_secrets(candidates);
  if (!kid) throw new Error('No from_prior issuer secret found');
  findKey(doc, kid, 'authentication');
  const key = await loadSecret(resolvers.secrets, kid);

  const header = b64urlEncode(utf8(JSON.stringify({ typ: 'JWT', alg: jwsAlgFor(key.curve), kid })));
  const payload = b64urlEncode(utf8(JSON.stringify(fromPrior)));
  const signature = b64urlEncode(sign(key, utf8(`${header}.${payload}`)));
  return { jwt: `${header}.${payload}.${signature}`, issuerKid: kid };
}

/**
 * Verifies a `from_prior` JWT and returns its claims and the signing key ID.
 * `nowSeconds` is the time `exp` / `nbf` are checked against; pass `null` to
 * skip those checks (e.g. when verifying an archived message).
 */
export async function unpackFromPrior(
  jwt: string,
  did: DidResolver,
  nowSeconds: number | null = Math.floor(Date.now() / 1000),
): Promise<{ fromPrior: FromPrior; issuerKid: string }> {
  const parts = jwt.split('.');
  if (parts.length !== 3) throw new Error('from_prior is not a compact JWS');
  const [headerB64, payloadB64, signatureB64] = parts;
  const header = JSON.parse(fromUtf8(b64urlDecode(headerB64))) as { typ?: unknown; alg?: unknown; kid?: unknown };
  if (header.typ !== 'JWT') throw new Error('from_prior typ is not JWT');
  if (typeof header.kid !== 'string' || !header.kid.includes('#')) throw new Error('from_prior kid is not a DID URL');

  const kid = header.kid;
  const doc = await resolveDoc(did, didOf(kid));
  const key = publicKeyFromVerificationMethod(findKey(doc, kid, 'authentication'));
  // The key's curve dictates the algorithm; the header must agree, never choose.
  if (header.alg !== jwsAlgFor(key.curve)) throw new Error('from_prior alg does not match the issuer key');
  if (!verify(key, utf8(`${headerB64}.${payloadB64}`), b64urlDecode(signatureB64))) {
    throw new Error('from_prior signature verification failed');
  }

  const fromPrior = JSON.parse(fromUtf8(b64urlDecode(payloadB64))) as FromPrior;
  validateClaims(fromPrior);
  if (fromPrior.iss !== didOf(kid)) throw new Error('from_prior `iss` is not the DID of its signing key');
  if (nowSeconds === null) return { fromPrior, issuerKid: kid };
  if (fromPrior.exp !== undefined && nowSeconds > fromPrior.exp + CLOCK_SKEW_SECONDS) {
    throw new Error('from_prior has expired');
  }
  if (fromPrior.nbf !== undefined && nowSeconds + CLOCK_SKEW_SECONDS < fromPrior.nbf) {
    throw new Error('from_prior is not yet valid');
  }
  return { fromPrior, issuerKid: kid };
}
