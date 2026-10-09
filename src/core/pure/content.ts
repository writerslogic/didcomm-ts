/**
 * JWE content encryption: A256CBC-HS512 (RFC 7518 §5.2.5), A256GCM, and XC20P
 * (XChaCha20-Poly1305, draft-irtf-cfrg-xchacha-03), plus A256KW (RFC 3394).
 * The AAD is the ASCII of the base64url protected header.
 */

import { createCipheriv, createDecipheriv, createHmac } from 'node:crypto';
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

const KW_IV = Buffer.from('A6A6A6A6A6A6A6A6', 'hex');

export function aesKeyWrap(kek: Uint8Array, key: Uint8Array): Uint8Array {
  const cipher = createCipheriv('id-aes256-wrap', kek, KW_IV);
  return new Uint8Array(Buffer.concat([cipher.update(key), cipher.final()]));
}

/** Throws if the wrapped key fails its RFC 3394 integrity check. */
export function aesKeyUnwrap(kek: Uint8Array, wrapped: Uint8Array): Uint8Array {
  const decipher = createDecipheriv('id-aes256-wrap', kek, KW_IV);
  return new Uint8Array(Buffer.concat([decipher.update(wrapped), decipher.final()]));
}

function rotl(value: number, shift: number): number {
  return ((value << shift) | (value >>> (32 - shift))) >>> 0;
}

function quarterRound(s: Uint32Array, a: number, b: number, c: number, d: number): void {
  s[a] = (s[a] + s[b]) >>> 0;
  s[d] = rotl(s[d] ^ s[a], 16);
  s[c] = (s[c] + s[d]) >>> 0;
  s[b] = rotl(s[b] ^ s[c], 12);
  s[a] = (s[a] + s[b]) >>> 0;
  s[d] = rotl(s[d] ^ s[a], 8);
  s[c] = (s[c] + s[d]) >>> 0;
  s[b] = rotl(s[b] ^ s[c], 7);
}

/** HChaCha20 (draft-irtf-cfrg-xchacha-03 §2.2): derives an XChaCha20 subkey from a key and a 16-byte nonce. */
export function hchacha20(key: Uint8Array, nonce16: Uint8Array): Uint8Array {
  const keyView = new DataView(key.buffer, key.byteOffset, 32);
  const nonceView = new DataView(nonce16.buffer, nonce16.byteOffset, 16);
  const s = new Uint32Array(16);
  s.set([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);
  for (let i = 0; i < 8; i++) s[4 + i] = keyView.getUint32(i * 4, true);
  for (let i = 0; i < 4; i++) s[12 + i] = nonceView.getUint32(i * 4, true);
  for (let round = 0; round < 10; round++) {
    quarterRound(s, 0, 4, 8, 12);
    quarterRound(s, 1, 5, 9, 13);
    quarterRound(s, 2, 6, 10, 14);
    quarterRound(s, 3, 7, 11, 15);
    quarterRound(s, 0, 5, 10, 15);
    quarterRound(s, 1, 6, 11, 12);
    quarterRound(s, 2, 7, 8, 13);
    quarterRound(s, 3, 4, 9, 14);
  }
  const out = new Uint8Array(32);
  const outView = new DataView(out.buffer);
  [0, 1, 2, 3, 12, 13, 14, 15].forEach((word, i) => outView.setUint32(i * 4, s[word], true));
  return out;
}

/** XChaCha20-Poly1305 = ChaCha20-Poly1305 under HChaCha20(key, nonce[0..16]) with nonce 0^4 || nonce[16..24]. */
function xchachaParams(key: Uint8Array, nonce: Uint8Array): { subkey: Uint8Array; iv: Uint8Array } {
  return {
    subkey: hchacha20(key, nonce.subarray(0, 16)),
    iv: concatBytes(new Uint8Array(4), nonce.subarray(16, 24)),
  };
}

function cbcHmacTag(macKey: Uint8Array, aad: Uint8Array, iv: Uint8Array, ciphertext: Uint8Array): Uint8Array {
  const al = new Uint8Array(8);
  new DataView(al.buffer).setBigUint64(0, BigInt(aad.length) * 8n, false);
  const mac = createHmac('sha512', macKey).update(aad).update(iv).update(ciphertext).update(al).digest();
  return new Uint8Array(mac.subarray(0, 32));
}

function checkLengths(enc: ContentEnc, cek: Uint8Array, iv: Uint8Array, tag?: Uint8Array): void {
  const params = PARAMS[enc];
  if (cek.length !== params.keyLength) throw new Error(`${enc} requires a ${params.keyLength}-byte key`);
  if (iv.length !== params.ivLength) throw new Error(`${enc} requires a ${params.ivLength}-byte IV`);
  // Must precede setAuthTag: Node otherwise accepts truncated GCM tags.
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
    const cipher = createCipheriv('aes-256-cbc', cek.subarray(32), iv);
    const ciphertext = new Uint8Array(Buffer.concat([cipher.update(plaintext), cipher.final()]));
    return { ciphertext, tag: cbcHmacTag(cek.subarray(0, 32), aad, iv, ciphertext) };
  }
  const cipher =
    enc === 'A256GCM'
      ? createCipheriv('aes-256-gcm', cek, iv, { authTagLength: 16 })
      : (() => {
          const { subkey, iv: chachaIv } = xchachaParams(cek, iv);
          return createCipheriv('chacha20-poly1305', subkey, chachaIv, { authTagLength: 16 });
        })();
  cipher.setAAD(aad, { plaintextLength: plaintext.length });
  const ciphertext = new Uint8Array(Buffer.concat([cipher.update(plaintext), cipher.final()]));
  return { ciphertext, tag: new Uint8Array(cipher.getAuthTag()) };
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
    const decipher = createDecipheriv('aes-256-cbc', cek.subarray(32), iv);
    return new Uint8Array(Buffer.concat([decipher.update(sealed.ciphertext), decipher.final()]));
  }
  const decipher =
    enc === 'A256GCM'
      ? createDecipheriv('aes-256-gcm', cek, iv, { authTagLength: 16 })
      : (() => {
          const { subkey, iv: chachaIv } = xchachaParams(cek, iv);
          return createDecipheriv('chacha20-poly1305', subkey, chachaIv, { authTagLength: 16 });
        })();
  decipher.setAAD(aad, { plaintextLength: sealed.ciphertext.length });
  decipher.setAuthTag(sealed.tag);
  try {
    return new Uint8Array(Buffer.concat([decipher.update(sealed.ciphertext), decipher.final()]));
  } catch {
    throw new Error(`${enc} authentication failed`);
  }
}
