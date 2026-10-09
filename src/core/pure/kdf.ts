/**
 * ConcatKDF (NIST SP 800-56A, as profiled by RFC 7518 §4.6.2) and the
 * ECDH-ES / ECDH-1PU (draft-madden-jose-ecdh-1pu-04) key derivations.
 *
 * Inputs are raw bytes: `apu` is the sender kid's UTF-8 bytes and `apv` the
 * 32-byte SHA-256 digest, not their base64url header forms. For ECDH-1PU
 * Z = Ze || Zs (ephemeral first) and the content-encryption tag is appended
 * to SuppPubInfo, so content must be encrypted before the CEK is wrapped.
 */

import { concatBytes, sha256, u32be, utf8 } from './bytes.js';
import { ecdh, type PrivateKey, type PublicKey } from './keys.js';

export type KeyWrapAlg = 'ECDH-ES+A256KW' | 'ECDH-1PU+A256KW';

const KEK_LENGTH = 32;

export function concatKdf(
  z: Uint8Array,
  keyLength: number,
  alg: Uint8Array,
  apu: Uint8Array,
  apv: Uint8Array,
  ccTag: Uint8Array = new Uint8Array(0),
): Uint8Array {
  const suppPubInfo =
    ccTag.length > 0
      ? concatBytes(u32be(keyLength * 8), u32be(ccTag.length), ccTag)
      : u32be(keyLength * 8);
  const otherInfo = concatBytes(
    u32be(alg.length),
    alg,
    u32be(apu.length),
    apu,
    u32be(apv.length),
    apv,
    suppPubInfo,
  );
  const out = new Uint8Array(keyLength);
  for (let counter = 1, offset = 0; offset < keyLength; counter++, offset += 32) {
    const block = sha256(concatBytes(u32be(counter), z, otherInfo));
    out.set(block.subarray(0, Math.min(32, keyLength - offset)), offset);
  }
  return out;
}

export interface KekInputs {
  alg: KeyWrapAlg;
  apu: Uint8Array;
  apv: Uint8Array;
  /** ECDH-1PU only: the JWE authentication tag. */
  ccTag?: Uint8Array;
}

/** Sender side: ephemeral (and, for 1PU, static sender) private keys against the recipient's public key. */
export function deriveSenderKek(
  inputs: KekInputs,
  ephemeral: PrivateKey,
  recipient: PublicKey,
  sender?: PrivateKey,
): Uint8Array {
  const ze = ecdh(ephemeral, recipient);
  const z = inputs.alg === 'ECDH-1PU+A256KW' ? concatBytes(ze, ecdh(requireSender(sender), recipient)) : ze;
  return finish(inputs, z);
}

/** Recipient side: the recipient's private key against the ephemeral (and, for 1PU, sender) public keys. */
export function deriveRecipientKek(
  inputs: KekInputs,
  recipient: PrivateKey,
  ephemeral: PublicKey,
  sender?: PublicKey,
): Uint8Array {
  const ze = ecdh(recipient, ephemeral);
  const z =
    inputs.alg === 'ECDH-1PU+A256KW'
      ? concatBytes(ze, ecdh(recipient, requireSender(sender)))
      : ze;
  return finish(inputs, z);
}

function requireSender<T>(sender: T | undefined): T {
  if (!sender) throw new Error('ECDH-1PU requires a sender key');
  return sender;
}

function finish(inputs: KekInputs, z: Uint8Array): Uint8Array {
  const ccTag = inputs.alg === 'ECDH-1PU+A256KW' ? inputs.ccTag : undefined;
  if (inputs.alg === 'ECDH-1PU+A256KW' && (!ccTag || ccTag.length === 0)) {
    throw new Error('ECDH-1PU key wrapping requires the content tag');
  }
  const kek = concatKdf(z, KEK_LENGTH, utf8(inputs.alg), inputs.apu, inputs.apv, ccTag);
  z.fill(0);
  return kek;
}
