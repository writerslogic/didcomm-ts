/**
 * JWE content encryption: A256CBC-HS512 (RFC 7518 §5.2.5), A256GCM, and XC20P
 * (XChaCha20-Poly1305). The AAD is the ASCII of the base64url protected header.
 */

import { cbc, gcm } from '@noble/ciphers/aes.js';
import { xchacha20poly1305 } from '@noble/ciphers/chacha.js';
import { hmac } from '@noble/hashes/hmac.js';
import { sha512 } from '@noble/hashes/sha2.js';
import { bytesEqual, concatBytes } from './bytes.js';

export type ContentEnc = 'A256CBC-HS512' | 'A256GCM' | 'XC20P';

const PARAMS: Record<ContentEnc, { keyLength: number; ivLength: number; tagLength: number }> = {
  'A256CBC-HS512': { keyLength: 64, ivLength: 16, tagLength: 32 },
  A256GCM: { keyLength: 32, ivLength: 12, tagLength: 16 },
  XC20P: { keyLength: 32, ivLength: 24, tagLength: 16 },
};

export function isContentEnc(value: unknown): value is ContentEnc {
  return typeof value === 'string' && value in PARAMS;
}

export function contentParams(enc: ContentEnc) {
  return PARAMS[enc];
}

export interface Sealed {
  ciphertext: Uint8Array;
  tag: Uint8Array;
}

function cbcHmacTag(macKey: Uint8Array, aad: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  const al = new Uint8Array(8);
  new DataView(al.buffer).setBigUint64(0, BigInt(aad.length) * 8n, false);
  return hmac(sha512, macKey, concatBytes(aad, iv, ciphertext, al)).slice(0, 32);
}

function checkLengths(enc: ContentEnc, cek: Uint8Array, iv: Uint8Array, tag?: Uint8Array): void {
  const params = PARAMS[enc];
  if (cek.length !== params.keyLength) throw new Error(`${enc} requires a ${params.keyLength}-byte key`);
  if (iv.length !== params.ivLength) throw new Error(`${enc} requires a ${params.ivLength}-byte IV`);
  if (tag && tag.length !== params.tagLength) throw new Error(`${enc} requires a ${params.tagLength}-byte tag`);
}

export function encryptContent(
  enc: ContentEnc,
  cek: Uint8Array,
  iv: Uint8Array,
  aad: Uint8Array,
  plaintext: Uint8Array,
): Sealed {
  checkLengths(enc, cek, iv);
  if (enc === 'A256CBC-HS512') {
    const ciphertext = cbc(cek.subarray(32), iv).encrypt(plaintext);
    return { ciphertext, tag: cbcHmacTag(cek.subarray(0, 32), aad, iv, ciphertext) };
  }
  const sealed = enc === 'A256GCM' ? gcm(cek, iv, aad).encrypt(plaintext) : xchacha20poly1305(cek, iv, aad).encrypt(plaintext);
  const split = sealed.length - PARAMS[enc].tagLength;
  return { ciphertext: sealed.slice(0, split), tag: sealed.slice(split) };
}

export function decryptContent(
  enc: ContentEnc,
  cek: Uint8Array,
  iv: Uint8Array,
  aad: Uint8Array,
  sealed: Sealed,
): Uint8Array {
  checkLengths(enc, cek, iv, sealed.tag);
  if (enc === 'A256CBC-HS512') {
    const expected = cbcHmacTag(cek.subarray(0, 32), aad, iv, sealed.ciphertext);
    if (!bytesEqual(expected, sealed.tag)) throw new Error('A256CBC-HS512 authentication failed');
    return cbc(cek.subarray(32), iv).decrypt(sealed.ciphertext);
  }
  const joined = concatBytes(sealed.ciphertext, sealed.tag);
  return enc === 'A256GCM' ? gcm(cek, iv, aad).decrypt(joined) : xchacha20poly1305(cek, iv, aad).decrypt(joined);
}
