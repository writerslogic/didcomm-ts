/**
 * Key material: parsing DID Doc verification methods and secrets into raw
 * curve keys, ECDH, ephemeral key generation, signatures, and JWK export.
 * Primitives come from `node:crypto` (OpenSSL); DIDComm/JOSE logic is ours.
 */

import {
  createECDH,
  createHash,
  createPrivateKey,
  createPublicKey,
  diffieHellman,
  generateKeyPairSync,
  sign as nodeSign,
  verify as nodeVerify,
  type JsonWebKey as NodeJwk,
  type KeyObject,
} from 'node:crypto';
import { decodeMultibaseKey } from './multibase.js';
import type { Secret, VerificationMethod } from '../types.js';
import { b64urlDecode, b64urlEncode, bytesEqual, concatBytes } from './bytes.js';

export type Curve = 'X25519' | 'Ed25519' | 'P-256' | 'P-384' | 'P-521' | 'secp256k1';
type WeierstrassCurve = 'P-256' | 'P-384' | 'P-521' | 'secp256k1';
type OkpCurve = 'X25519' | 'Ed25519';

const OPENSSL_CURVE: Record<WeierstrassCurve, string> = {
  'P-256': 'prime256v1',
  'P-384': 'secp384r1',
  'P-521': 'secp521r1',
  secp256k1: 'secp256k1',
};
const COORDINATE_LENGTH: Record<WeierstrassCurve, number> = {
  'P-256': 32,
  'P-384': 48,
  'P-521': 66,
  secp256k1: 32,
};

// Fixed DER prefixes wrapping a raw 32-byte OKP key (RFC 8410).
const OKP_DER = {
  X25519: { spki: hex('302a300506032b656e032100'), pkcs8: hex('302e020100300506032b656e04220420') },
  Ed25519: { spki: hex('302a300506032b6570032100'), pkcs8: hex('302e020100300506032b657004220420') },
} as const;

function hex(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, 'hex'));
}

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
  return curve in OPENSSL_CURVE;
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

function leftPad(bytes: Uint8Array, length: number): Uint8Array {
  if (bytes.length === length) return bytes;
  const padded = new Uint8Array(length);
  padded.set(bytes, length - bytes.length);
  return padded;
}

/**
 * RFC 7518 §6.2.1.2 requires full-length coordinates, but didcomm-python
 * (authlib) strips leading zero bytes from P-521 epk coordinates. Accepting
 * the shorter form is safe: the point is still validated on the curve.
 */
function leftPadCoordinate(bytes: Uint8Array, length: number, what: string): Uint8Array {
  if (bytes.length === 0 || bytes.length > length) return requireLength(bytes, length, what);
  return leftPad(bytes, length);
}

function okpPublicKeyObject(curve: OkpCurve, bytes: Uint8Array): KeyObject {
  return createPublicKey({ key: Buffer.from(concatBytes(OKP_DER[curve].spki, bytes)), format: 'der', type: 'spki' });
}

function okpPrivateKeyObject(curve: OkpCurve, d: Uint8Array): KeyObject {
  return createPrivateKey({ key: Buffer.from(concatBytes(OKP_DER[curve].pkcs8, d)), format: 'der', type: 'pkcs8' });
}

/*
 * Importing a key into OpenSSL costs far more than using it, so parsed keys
 * and their native handles are memoized per object. WeakMaps tie each entry's
 * lifetime to the caller's own JWK / our key object; nothing is retained
 * beyond what the caller already holds.
 */
function memoize<K extends object, V>(cache: WeakMap<K, V>, key: K, make: () => V): V {
  let value = cache.get(key);
  if (value === undefined) {
    value = make();
    cache.set(key, value);
  }
  return value;
}

const keyObjects = new WeakMap<PublicKey | PrivateKey, KeyObject>();
const ecdhHandles = new WeakMap<PrivateKey, ReturnType<typeof createECDH>>();

const okpPublicHandle = (key: PublicKey) => memoize(keyObjects, key, () => okpPublicKeyObject(key.curve as OkpCurve, key.bytes));
const okpPrivateHandle = (key: PrivateKey) => memoize(keyObjects, key, () => okpPrivateKeyObject(key.curve as OkpCurve, key.d));

/** Parsed-key caches keyed by the caller's JWK object, revalidated against its members on every hit. */
const parsedPublicJwks = new WeakMap<object, { fingerprint: string; key: PublicKey }>();
const parsedPrivateJwks = new WeakMap<object, { fingerprint: string; key: PrivateKey }>();

function memoizeJwk<T extends PublicKey | PrivateKey>(
  cache: WeakMap<object, { fingerprint: string; key: T }>,
  jwk: Jwk,
  parse: () => T,
): T {
  const fingerprint = `${jwk.kty}|${jwk.crv}|${jwk.x}|${jwk.y}|${jwk.d}`;
  const hit = cache.get(jwk);
  if (hit && hit.fingerprint === fingerprint) return hit.key;
  const key = parse();
  cache.set(jwk, { fingerprint, key });
  return key;
}

function ecJwk(key: PublicKey, d?: Uint8Array): NodeJwk {
  return { ...(publicKeyToJwk(key) as NodeJwk), ...(d ? { d: b64urlEncode(d) } : {}) };
}

export function publicKeyFromJwk(jwk: Jwk): PublicKey {
  return memoizeJwk(parsedPublicJwks, jwk, () => parsePublicJwk(jwk));
}

function parsePublicJwk(jwk: Jwk): PublicKey {
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
  const key: PublicKey = { curve, bytes: concatBytes(new Uint8Array([0x04]), x, y) };
  // Rejects points not on the curve before they reach ECDH or verification.
  createPublicKey({ key: ecJwk(key), format: 'jwk' });
  return key;
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
  if (isWeierstrass(curve)) {
    const ecdh = createECDH(OPENSSL_CURVE[curve]);
    ecdh.setPrivateKey(Buffer.from(d));
    return { curve, bytes: new Uint8Array(ecdh.getPublicKey()) };
  }
  const spki = createPublicKey(okpPrivateKeyObject(curve, d)).export({ format: 'der', type: 'spki' });
  return { curve, bytes: new Uint8Array(spki.subarray(OKP_DER[curve].spki.length)) };
}

export function privateKeyFromJwk(jwk: Jwk): PrivateKey {
  const d = jwk.d;
  if (typeof d !== 'string') throw new Error('Private JWK is missing d');
  return memoizeJwk(parsedPrivateJwks, jwk, () => parsePrivateJwk({ ...jwk, d }));
}

function parsePrivateJwk(jwk: Jwk & { d: string }): PrivateKey {
  const publicKey = parsePublicJwk(jwk);
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

const P25519 = 2n ** 255n - 19n;

function modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
  let result = 1n;
  base %= modulus;
  for (; exponent > 0n; exponent >>= 1n, base = (base * base) % modulus) {
    if (exponent & 1n) result = (result * base) % modulus;
  }
  return result;
}

function littleEndianToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (let i = bytes.length - 1; i >= 0; i--) value = (value << 8n) | BigInt(bytes[i]);
  return value;
}

function bigIntToLittleEndian(value: bigint, length: number): Uint8Array {
  const out = new Uint8Array(length);
  for (let i = 0; i < length; i++, value >>= 8n) out[i] = Number(value & 0xffn);
  return out;
}

/** Maps an Ed25519 key to its X25519 equivalent (RFC 7748 birational map, u = (1+y)/(1-y)); other keys pass through. */
export function toKeyAgreementPublic(key: PublicKey): PublicKey {
  if (key.curve !== 'Ed25519') return key;
  // Validates the encoding is a real Ed25519 point before mapping it.
  okpPublicKeyObject('Ed25519', key.bytes);
  const yBytes = key.bytes.slice();
  yBytes[31] &= 0x7f;
  const y = littleEndianToBigInt(yBytes);
  if (y >= P25519 || y === 1n) throw new Error('Ed25519 public key has no X25519 equivalent');
  const u = ((1n + y) * modPow((1n - y + P25519) % P25519, P25519 - 2n, P25519)) % P25519;
  return { curve: 'X25519', bytes: bigIntToLittleEndian(u, 32) };
}

/** The X25519 scalar for an Ed25519 seed: the first half of SHA-512(seed), as Ed25519 itself uses it. */
export function toKeyAgreementPrivate(key: PrivateKey): PrivateKey {
  if (key.curve !== 'Ed25519') return key;
  const d = new Uint8Array(createHash('sha512').update(key.d).digest().subarray(0, 32));
  d[0] &= 248;
  d[31] &= 127;
  d[31] |= 64;
  return { curve: 'X25519', d, publicKey: derivePublicKey('X25519', d) };
}

export function generateEphemeral(curve: Curve): PrivateKey {
  if (curve === 'Ed25519') throw new Error('Ed25519 is not a key agreement curve');
  if (curve === 'X25519') {
    const pair = generateKeyPairSync('x25519');
    const pkcs8 = pair.privateKey.export({ format: 'der', type: 'pkcs8' });
    const spki = pair.publicKey.export({ format: 'der', type: 'spki' });
    const key: PrivateKey = {
      curve,
      d: new Uint8Array(pkcs8.subarray(OKP_DER.X25519.pkcs8.length)),
      publicKey: { curve, bytes: new Uint8Array(spki.subarray(OKP_DER.X25519.spki.length)) },
    };
    // Reuse the handle that generated the key instead of re-importing it for ECDH.
    keyObjects.set(key, pair.privateKey);
    return key;
  }
  const ecdh = createECDH(OPENSSL_CURVE[curve]);
  const publicKey = { curve, bytes: new Uint8Array(ecdh.generateKeys()) };
  const key: PrivateKey = { curve, d: leftPad(new Uint8Array(ecdh.getPrivateKey()), COORDINATE_LENGTH[curve]), publicKey };
  ecdhHandles.set(key, ecdh);
  return key;
}

/** Raw ECDH shared secret Z (X25519 output, or the x coordinate for Weierstrass curves). */
export function ecdh(priv: PrivateKey, pub: PublicKey): Uint8Array {
  if (priv.curve !== pub.curve) {
    throw new Error(`ECDH curve mismatch: ${priv.curve} vs ${pub.curve}`);
  }
  if (priv.curve === 'X25519') {
    let z: Uint8Array;
    try {
      z = diffieHellman({ privateKey: okpPrivateHandle(priv), publicKey: okpPublicHandle(pub) });
    } catch {
      // OpenSSL refuses low-order points, which would yield an all-zero secret.
      throw new Error('X25519 key agreement failed (low-order or invalid public key)');
    }
    if (z.every((byte) => byte === 0)) throw new Error('X25519 produced an all-zero shared secret');
    return new Uint8Array(z);
  }
  if (!isWeierstrass(priv.curve)) throw new Error(`${priv.curve} is not a key agreement curve`);
  const curveName = OPENSSL_CURVE[priv.curve];
  const agreement = memoize(ecdhHandles, priv, () => {
    const ecdh = createECDH(curveName);
    ecdh.setPrivateKey(Buffer.from(priv.d));
    return ecdh;
  });
  return leftPad(new Uint8Array(agreement.computeSecret(Buffer.from(pub.bytes))), COORDINATE_LENGTH[priv.curve]);
}

export type JwsAlg = 'EdDSA' | 'ES256' | 'ES256K';

export function jwsAlgFor(curve: Curve): JwsAlg {
  if (curve === 'Ed25519') return 'EdDSA';
  if (curve === 'P-256') return 'ES256';
  if (curve === 'secp256k1') return 'ES256K';
  throw new Error(`No DIDComm JWS algorithm for curve ${curve}`);
}

export function sign(key: PrivateKey, message: Uint8Array): Uint8Array {
  if (jwsAlgFor(key.curve) === 'EdDSA') {
    return new Uint8Array(nodeSign(null, message, okpPrivateHandle(key)));
  }
  const privateKey = memoize(keyObjects, key, () => createPrivateKey({ key: ecJwk(key.publicKey, key.d), format: 'jwk' }));
  return new Uint8Array(nodeSign('sha256', message, { key: privateKey, dsaEncoding: 'ieee-p1363' }));
}

export function verify(key: PublicKey, message: Uint8Array, signature: Uint8Array): boolean {
  const alg = jwsAlgFor(key.curve);
  try {
    if (alg === 'EdDSA') return nodeVerify(null, message, okpPublicHandle(key), signature);
    // P1363 signatures are fixed-length r || s; reject anything else outright.
    if (signature.length !== 2 * COORDINATE_LENGTH[key.curve as WeierstrassCurve]) return false;
    const publicKey = memoize(keyObjects, key, () => createPublicKey({ key: ecJwk(key), format: 'jwk' }));
    // OpenSSL accepts high-S signatures, which are valid ECDSA (askar's P-256 signer does not normalize S).
    return nodeVerify('sha256', message, { key: publicKey, dsaEncoding: 'ieee-p1363' }, signature);
  } catch {
    return false;
  }
}
