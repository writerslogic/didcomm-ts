// Frozen noble-based primitives from before the node:crypto migration; used only by the differential test.
/**
 * Key material for the pure backend: parsing DID Doc verification methods and
 * secrets into raw curve keys, ECDH, ephemeral key generation, and JWK export.
 */

import { ed25519, x25519 } from '@noble/curves/ed25519.js';
import { p256, p384, p521 } from '@noble/curves/nist.js';
import { secp256k1 } from '@noble/curves/secp256k1.js';
import { decodeMultibaseKey } from './multibase.js';
import type { Secret, VerificationMethod } from '../../../src/core/types.js';
import { b64urlDecode, b64urlEncode, bytesEqual } from './bytes.js';

export type Curve = 'X25519' | 'Ed25519' | 'P-256' | 'P-384' | 'P-521' | 'secp256k1';
type WeierstrassCurve = 'P-256' | 'P-384' | 'P-521' | 'secp256k1';

const WEIERSTRASS = { 'P-256': p256, 'P-384': p384, 'P-521': p521, secp256k1 } as const;
const COORDINATE_LENGTH: Record<WeierstrassCurve, number> = {
  'P-256': 32,
  'P-384': 48,
  'P-521': 66,
  secp256k1: 32,
};

/** X25519/Ed25519: the 32-byte encoded point. Weierstrass curves: uncompressed SEC1 (0x04 || x || y). */
export interface PublicKey {
  curve: Curve;
  bytes: Uint8Array;
}

export interface PrivateKey {
  curve: Curve;
  d: Uint8Array;
  publicKey: PublicKey;
}

export interface Jwk {
  kty?: string;
  crv?: string;
  x?: string;
  y?: string;
  d?: string;
}

function isWeierstrass(curve: Curve): curve is WeierstrassCurve {
  return curve in WEIERSTRASS;
}

function parseCurve(crv: unknown): Curve {
  if (crv === 'X25519' || crv === 'Ed25519' || crv === 'P-256' || crv === 'P-384' || crv === 'P-521') {
    return crv;
  }
  if (crv === 'secp256k1') return 'secp256k1';
  throw new Error(`Unsupported JWK curve: ${String(crv)}`);
}

function requireLength(bytes: Uint8Array, length: number, what: string): Uint8Array {
  if (bytes.length !== length) {
    throw new Error(`Invalid ${what}: expected ${length} bytes, got ${bytes.length}`);
  }
  return bytes;
}

/**
 * RFC 7518 §6.2.1.2 requires full-length coordinates, but didcomm-python
 * (authlib) strips leading zero bytes from P-521 epk coordinates. Accepting
 * the shorter form is safe: the point is still validated on the curve.
 */
function leftPadCoordinate(bytes: Uint8Array, length: number, what: string): Uint8Array {
  if (bytes.length === length) return bytes;
  if (bytes.length === 0 || bytes.length > length) return requireLength(bytes, length, what);
  const padded = new Uint8Array(length);
  padded.set(bytes, length - bytes.length);
  return padded;
}

export function publicKeyFromJwk(jwk: Jwk): PublicKey {
  const curve = parseCurve(jwk.crv);
  if (typeof jwk.x !== 'string') throw new Error('JWK is missing x');
  if (!isWeierstrass(curve)) {
    if (jwk.kty !== 'OKP') throw new Error(`JWK for ${curve} must have kty OKP`);
    return { curve, bytes: requireLength(b64urlDecode(jwk.x), 32, `${curve} public key`) };
  }
  if (jwk.kty !== 'EC') throw new Error(`JWK for ${curve} must have kty EC`);
  if (typeof jwk.y !== 'string') throw new Error('EC JWK is missing y');
  const len = COORDINATE_LENGTH[curve];
  const x = leftPadCoordinate(b64urlDecode(jwk.x), len, `${curve} x coordinate`);
  const y = leftPadCoordinate(b64urlDecode(jwk.y), len, `${curve} y coordinate`);
  const bytes = new Uint8Array(1 + 2 * len);
  bytes[0] = 0x04;
  bytes.set(x, 1);
  bytes.set(y, 1 + len);
  // Rejects points not on the curve before they reach ECDH or verification.
  WEIERSTRASS[curve].Point.fromBytes(bytes).assertValidity();
  return { curve, bytes };
}

export function publicKeyToJwk(key: PublicKey): Jwk {
  if (!isWeierstrass(key.curve)) {
    return { kty: 'OKP', crv: key.curve, x: b64urlEncode(key.bytes) };
  }
  const len = COORDINATE_LENGTH[key.curve];
  return {
    kty: 'EC',
    crv: key.curve,
    x: b64urlEncode(key.bytes.subarray(1, 1 + len)),
    y: b64urlEncode(key.bytes.subarray(1 + len)),
  };
}

function derivePublicKey(curve: Curve, d: Uint8Array): PublicKey {
  switch (curve) {
    case 'X25519':
      return { curve, bytes: x25519.getPublicKey(d) };
    case 'Ed25519':
      return { curve, bytes: ed25519.getPublicKey(d) };
    default:
      return { curve, bytes: WEIERSTRASS[curve].getPublicKey(d, false) };
  }
}

export function privateKeyFromJwk(jwk: Jwk): PrivateKey {
  if (typeof jwk.d !== 'string') throw new Error('Private JWK is missing d');
  const publicKey = publicKeyFromJwk(jwk);
  const expectedLength = isWeierstrass(publicKey.curve) ? COORDINATE_LENGTH[publicKey.curve] : 32;
  const d = requireLength(b64urlDecode(jwk.d), expectedLength, `${publicKey.curve} private key`);
  if (!bytesEqual(derivePublicKey(publicKey.curve, d).bytes, publicKey.bytes)) {
    throw new Error('Private JWK d does not match its public key');
  }
  return { curve: publicKey.curve, d, publicKey };
}

export function publicKeyFromVerificationMethod(vm: VerificationMethod): PublicKey {
  if (vm.publicKeyJwk !== undefined) return publicKeyFromJwk(vm.publicKeyJwk as Jwk);
  if (vm.publicKeyMultibase !== undefined) {
    const { codec, publicKeyBytes } = decodeMultibaseKey(vm.publicKeyMultibase);
    return { curve: codec === 'x25519' ? 'X25519' : 'Ed25519', bytes: requireLength(publicKeyBytes, 32, codec) };
  }
  throw new Error(`Unsupported verification method key encoding: ${vm.id}`);
}

export function privateKeyFromSecret(secret: Secret): PrivateKey {
  if (secret.privateKeyJwk !== undefined) return privateKeyFromJwk(secret.privateKeyJwk as Jwk);
  throw new Error(`Unsupported secret encoding (expected privateKeyJwk): ${secret.id}`);
}

/** Maps an Ed25519 key to its X25519 equivalent (RFC 7748 birational map); other keys pass through. */
export function toKeyAgreementPublic(key: PublicKey): PublicKey {
  if (key.curve !== 'Ed25519') return key;
  return { curve: 'X25519', bytes: ed25519.utils.toMontgomery(key.bytes) };
}

export function toKeyAgreementPrivate(key: PrivateKey): PrivateKey {
  if (key.curve !== 'Ed25519') return key;
  const d = ed25519.utils.toMontgomerySecret(key.d);
  return { curve: 'X25519', d, publicKey: derivePublicKey('X25519', d) };
}

export function generateEphemeral(curve: Curve): PrivateKey {
  if (curve === 'Ed25519') throw new Error('Ed25519 is not a key agreement curve');
  const d = curve === 'X25519' ? x25519.utils.randomSecretKey() : WEIERSTRASS[curve].utils.randomSecretKey();
  return { curve, d, publicKey: derivePublicKey(curve, d) };
}

/** Raw ECDH shared secret Z (X25519 output, or the x coordinate for Weierstrass curves). */
export function ecdh(priv: PrivateKey, pub: PublicKey): Uint8Array {
  if (priv.curve !== pub.curve) {
    throw new Error(`ECDH curve mismatch: ${priv.curve} vs ${pub.curve}`);
  }
  if (priv.curve === 'X25519') {
    const z = x25519.getSharedSecret(priv.d, pub.bytes);
    if (z.every((byte) => byte === 0)) throw new Error('X25519 produced an all-zero shared secret');
    return z;
  }
  if (!isWeierstrass(priv.curve)) throw new Error(`${priv.curve} is not a key agreement curve`);
  return WEIERSTRASS[priv.curve].getSharedSecret(priv.d, pub.bytes, true).slice(1);
}

export type JwsAlg = 'EdDSA' | 'ES256' | 'ES256K';

export function jwsAlgFor(curve: Curve): JwsAlg {
  if (curve === 'Ed25519') return 'EdDSA';
  if (curve === 'P-256') return 'ES256';
  if (curve === 'secp256k1') return 'ES256K';
  throw new Error(`No DIDComm JWS algorithm for curve ${curve}`);
}

export function sign(key: PrivateKey, message: Uint8Array): Uint8Array {
  const alg = jwsAlgFor(key.curve);
  if (alg === 'EdDSA') return ed25519.sign(message, key.d);
  return WEIERSTRASS[key.curve as WeierstrassCurve].sign(message, key.d, { prehash: true });
}

export function verify(key: PublicKey, message: Uint8Array, signature: Uint8Array): boolean {
  const alg = jwsAlgFor(key.curve);
  try {
    if (alg === 'EdDSA') return ed25519.verify(signature, message, key.bytes);
    // High-S signatures are valid ECDSA; P-256 signers (e.g. askar) do not normalize S.
    return WEIERSTRASS[key.curve as WeierstrassCurve].verify(signature, message, key.bytes, {
      prehash: true,
      lowS: false,
    });
  } catch {
    return false;
  }
}
