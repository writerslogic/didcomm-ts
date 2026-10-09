/**
 * DIDComm v2 JWE (General JSON serialization), mirroring didcomm-rust's
 * `jwe/encrypt.rs` and `jwe/parse.rs`:
 * - protected header {typ, alg, enc, skid?, apu?, apv, epk};
 * - apv = SHA-256(sorted recipient kids joined by "."), apu = skid (authcrypt);
 * - content is encrypted first; each recipient's KEK is then derived (for
 *   ECDH-1PU, over the content tag) and wraps the CEK with A256KW.
 */

import { aeskw } from '@noble/ciphers/aes.js';
import { randomBytes } from '@noble/ciphers/utils.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { b64urlDecode, b64urlEncode, bytesEqual, fromUtf8, utf8 } from './bytes.js';
import { contentParams, decryptContent, encryptContent, isContentEnc, type ContentEnc } from './content.js';
import { deriveRecipientKek, deriveSenderKek, type KeyWrapAlg } from './kdf.js';
import {
  generateEphemeral,
  publicKeyFromJwk,
  publicKeyToJwk,
  type Jwk,
  type PrivateKey,
  type PublicKey,
} from './keys.js';

export const ENCRYPTED_TYP = 'application/didcomm-encrypted+json';

export interface JweJson {
  protected: string;
  recipients: { header: { kid: string }; encrypted_key: string }[];
  iv: string;
  ciphertext: string;
  tag: string;
}

interface ProtectedHeader {
  typ?: string;
  alg: KeyWrapAlg;
  enc: ContentEnc;
  skid?: string;
  apu?: string;
  apv: string;
  epk: Jwk;
}

export interface JweRecipient {
  kid: string;
  key: PublicKey;
}

export interface JweSender {
  kid: string;
  key: PrivateKey;
}

function didcommApv(kids: string[]): Uint8Array {
  return sha256(utf8([...kids].sort().join('.')));
}

export function encryptJwe(
  plaintext: Uint8Array,
  enc: ContentEnc,
  recipients: JweRecipient[],
  sender?: JweSender,
): JweJson {
  if (recipients.length === 0) throw new Error('JWE requires at least one recipient');
  const curve = recipients[0].key.curve;
  if (recipients.some((r) => r.key.curve !== curve)) {
    throw new Error('All JWE recipient keys must share one curve');
  }
  if (sender && sender.key.curve !== curve) {
    throw new Error(`Sender key curve ${sender.key.curve} does not match recipient curve ${curve}`);
  }
  const alg: KeyWrapAlg = sender ? 'ECDH-1PU+A256KW' : 'ECDH-ES+A256KW';
  if (alg === 'ECDH-1PU+A256KW' && enc !== 'A256CBC-HS512') {
    throw new Error('Authcrypt (ECDH-1PU) requires A256CBC-HS512');
  }

  const apv = didcommApv(recipients.map((r) => r.kid));
  const apu = sender ? utf8(sender.kid) : new Uint8Array(0);
  const epk = generateEphemeral(curve);

  const header: ProtectedHeader = {
    typ: ENCRYPTED_TYP,
    alg,
    enc,
    ...(sender ? { skid: sender.kid, apu: b64urlEncode(apu) } : {}),
    apv: b64urlEncode(apv),
    epk: publicKeyToJwk(epk.publicKey),
  };
  const protectedB64 = b64urlEncode(utf8(JSON.stringify(header)));

  const params = contentParams(enc);
  const cek = randomBytes(params.keyLength);
  const iv = randomBytes(params.ivLength);
  const { ciphertext, tag } = encryptContent(enc, cek, iv, utf8(protectedB64), plaintext);

  const wrapped = recipients.map((recipient) => {
    const kek = deriveSenderKek({ alg, apu, apv, ccTag: tag }, epk, recipient.key, sender?.key);
    const encryptedKey = aeskw(kek).encrypt(cek);
    kek.fill(0);
    return { header: { kid: recipient.kid }, encrypted_key: b64urlEncode(encryptedKey) };
  });
  cek.fill(0);
  epk.d.fill(0);

  return {
    protected: protectedB64,
    recipients: wrapped,
    iv: b64urlEncode(iv),
    ciphertext: b64urlEncode(ciphertext),
    tag: b64urlEncode(tag),
  };
}

export function isJwe(value: unknown): value is JweJson {
  const v = value as Partial<JweJson> | null;
  return (
    typeof v === 'object' &&
    v !== null &&
    typeof v.protected === 'string' &&
    Array.isArray(v.recipients) &&
    typeof v.iv === 'string' &&
    typeof v.ciphertext === 'string' &&
    typeof v.tag === 'string'
  );
}

export interface ParsedJwe {
  jwe: JweJson;
  alg: KeyWrapAlg;
  enc: ContentEnc;
  /** Sender kid (authcrypt only), validated against apu. */
  skid: string | null;
  recipientKids: string[];
  epk: PublicKey;
  apu: Uint8Array;
  apv: Uint8Array;
}

/** Parses and validates the JWE structure and DIDComm apu/apv rules without decrypting. */
export function parseJwe(jwe: JweJson): ParsedJwe {
  const header = JSON.parse(fromUtf8(b64urlDecode(jwe.protected))) as Partial<ProtectedHeader>;
  if (header.typ !== undefined && header.typ !== ENCRYPTED_TYP) {
    throw new Error(`Unexpected JWE typ: ${String(header.typ)}`);
  }
  const alg = header.alg;
  if (alg !== 'ECDH-ES+A256KW' && alg !== 'ECDH-1PU+A256KW') {
    throw new Error(`Unsupported JWE alg: ${String(alg)}`);
  }
  if (!isContentEnc(header.enc)) throw new Error(`Unsupported JWE enc: ${String(header.enc)}`);
  if (alg === 'ECDH-1PU+A256KW' && header.enc !== 'A256CBC-HS512') {
    throw new Error('ECDH-1PU requires A256CBC-HS512');
  }
  if (typeof header.apv !== 'string') throw new Error('JWE is missing apv');
  if (typeof header.epk !== 'object' || header.epk === null) throw new Error('JWE is missing epk');

  const recipientKids = jwe.recipients.map((r) => {
    const kid = r?.header?.kid;
    if (typeof kid !== 'string' || typeof r.encrypted_key !== 'string') {
      throw new Error('Malformed JWE recipient');
    }
    return kid;
  });
  if (recipientKids.length === 0) throw new Error('JWE has no recipients');

  const apv = b64urlDecode(header.apv);
  if (!bytesEqual(apv, didcommApv(recipientKids))) {
    throw new Error('JWE apv does not match its recipient kids');
  }

  const apu = typeof header.apu === 'string' ? b64urlDecode(header.apu) : new Uint8Array(0);
  let skid: string | null = null;
  if (alg === 'ECDH-1PU+A256KW') {
    if (apu.length === 0) throw new Error('Authcrypt JWE is missing apu');
    const apuKid = fromUtf8(apu);
    if (header.skid !== undefined && header.skid !== apuKid) {
      throw new Error('JWE skid does not match apu');
    }
    skid = apuKid;
  } else if (header.skid !== undefined) {
    throw new Error('Anoncrypt JWE must not carry skid');
  }

  return { jwe, alg, enc: header.enc, skid, recipientKids, epk: publicKeyFromJwk(header.epk), apu, apv };
}

/** Decrypts for `recipient` (whose kid must appear in the JWE). `sender` is required for authcrypt. */
export function decryptJwe(parsed: ParsedJwe, recipient: JweSender, sender?: PublicKey): Uint8Array {
  const entry = parsed.jwe.recipients.find((r) => r.header.kid === recipient.kid);
  if (!entry) throw new Error(`JWE is not encrypted to ${recipient.kid}`);
  if (parsed.epk.curve !== recipient.key.curve) {
    throw new Error(`JWE epk curve ${parsed.epk.curve} does not match recipient key curve`);
  }
  if (parsed.alg === 'ECDH-1PU+A256KW' && !sender) throw new Error('Authcrypt JWE requires the sender key');

  const tag = b64urlDecode(parsed.jwe.tag);
  const kek = deriveRecipientKek(
    { alg: parsed.alg, apu: parsed.apu, apv: parsed.apv, ccTag: tag },
    recipient.key,
    parsed.epk,
    sender,
  );
  let cek: Uint8Array;
  try {
    cek = aeskw(kek).decrypt(b64urlDecode(entry.encrypted_key));
  } catch {
    throw new Error('JWE key unwrap failed');
  } finally {
    kek.fill(0);
  }
  try {
    return decryptContent(parsed.enc, cek, b64urlDecode(parsed.jwe.iv), utf8(parsed.jwe.protected), {
      ciphertext: b64urlDecode(parsed.jwe.ciphertext),
      tag,
    });
  } finally {
    cek.fill(0);
  }
}
