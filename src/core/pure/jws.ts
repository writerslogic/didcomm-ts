/**
 * DIDComm v2 signed messages: JWS General JSON serialization with one
 * signature, protected header {typ, alg}, unprotected header {kid}
 * (mirroring didcomm-rust's `jws/sign.rs`).
 */

import { b64urlDecode, b64urlEncode, fromUtf8, utf8 } from './bytes.js';
import { jwsAlgFor, sign, verify, type PrivateKey, type PublicKey } from './keys.js';

export const SIGNED_TYP = 'application/didcomm-signed+json';

export interface JwsJson {
  payload: string;
  signatures: { protected: string; signature: string; header: { kid: string } }[];
}

export function isJws(value: unknown): value is JwsJson {
  const v = value as Partial<JwsJson> | null;
  return typeof v === 'object' && v !== null && typeof v.payload === 'string' && Array.isArray(v.signatures);
}

export function signJws(payload: Uint8Array, kid: string, key: PrivateKey): JwsJson {
  const protectedB64 = b64urlEncode(utf8(JSON.stringify({ typ: SIGNED_TYP, alg: jwsAlgFor(key.curve) })));
  const payloadB64 = b64urlEncode(payload);
  const signature = sign(key, utf8(`${protectedB64}.${payloadB64}`));
  return {
    payload: payloadB64,
    signatures: [{ protected: protectedB64, signature: b64urlEncode(signature), header: { kid } }],
  };
}

/** The signer's kid, read before verification so the caller can resolve its key. */
export function jwsSignerKid(jws: JwsJson): string {
  if (jws.signatures.length !== 1) throw new Error('Signed message must carry exactly one signature');
  const kid = jws.signatures[0]?.header?.kid;
  if (typeof kid !== 'string') throw new Error('JWS signature is missing header.kid');
  return kid;
}

export function verifyJws(jws: JwsJson, key: PublicKey): Uint8Array {
  jwsSignerKid(jws);
  const { protected: protectedB64, signature } = jws.signatures[0];
  if (typeof protectedB64 !== 'string' || typeof signature !== 'string') throw new Error('Malformed JWS signature');
  const header = JSON.parse(fromUtf8(b64urlDecode(protectedB64))) as { typ?: unknown; alg?: unknown };
  if (header.typ !== undefined && header.typ !== SIGNED_TYP) throw new Error(`Unexpected JWS typ: ${String(header.typ)}`);
  // The alg must be the one the key's curve dictates; never let the header choose.
  if (header.alg !== jwsAlgFor(key.curve)) throw new Error(`JWS alg ${String(header.alg)} does not match signer key`);
  if (!verify(key, utf8(`${protectedB64}.${jws.payload}`), b64urlDecode(signature))) {
    throw new Error('JWS signature verification failed');
  }
  return b64urlDecode(jws.payload);
}
