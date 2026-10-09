/**
 * Adapts EAT device attestation (./eat.ts) into the `RecipientKeyAttestation`
 * gate that both pack backends run on every resolved recipient key before
 * multi-recipient packing (`resolveRecipientKeyIds` in src/core/types.ts).
 *
 * A valid EAT signature alone proves nothing about a DIDComm key, so the
 * token is bound to the key through its `nonce` claim:
 *   nonce = SHA-256(challenge || RFC 7638 JWK thumbprint of the key)
 * The verifier issues a fresh `challenge` per trust decision; the device
 * computes the nonce with `eatKeyBindingNonce` when it builds the token.
 * A token for key A therefore fails for key B, and a token built against an
 * old challenge fails against a new one.
 */

import type { RecipientKeyAttestation, VerificationMethod } from '../core/types.js';
import { bytesEqual, concatBytes, sha256, utf8 } from '../core/pure/bytes.js';
import { publicKeyFromVerificationMethod, publicKeyToJwk } from '../core/pure/keys.js';
import { verifyEatToken, type EatClaims, type EatVerifier } from './eat.js';

/** RFC 7638 thumbprint input: required members only, lexicographic order, no whitespace. */
function jwkThumbprint(vm: VerificationMethod): Uint8Array {
  const jwk = publicKeyToJwk(publicKeyFromVerificationMethod(vm));
  const members =
    jwk.kty === 'EC'
      ? { crv: jwk.crv, kty: jwk.kty, x: jwk.x, y: jwk.y }
      : { crv: jwk.crv, kty: jwk.kty, x: jwk.x };
  return sha256(utf8(JSON.stringify(members)));
}

/** The nonce a device must place in its EAT to attest `vm` against `challenge`. */
export function eatKeyBindingNonce(challenge: Uint8Array, vm: VerificationMethod): Uint8Array {
  if (challenge.length < 16) throw new Error('Attestation challenge must be at least 16 bytes');
  return sha256(concatBytes(challenge, jwkThumbprint(vm)));
}

export interface EatRecipientAttestationOptions {
  /** Fresh, unpredictable bytes issued by the verifier for this trust decision (>= 16 bytes). */
  challenge: Uint8Array;
  /** Returns the EAT the device presented for `keyId`, or null if none was presented. */
  tokenFor(keyId: string, verificationMethod: VerificationMethod): Promise<Uint8Array | null>;
  /** Verifies the token's COSE_Sign1 signature against a trusted attestation key. */
  verifier: EatVerifier;
  /** Additional claim policy (e.g. reject `dbgstat` Enabled, pin `oemid`). Default: accept. */
  acceptClaims?(claims: EatClaims, keyId: string): boolean | Promise<boolean>;
}

export function eatRecipientAttestation(options: EatRecipientAttestationOptions): RecipientKeyAttestation {
  return {
    async verify(keyId: string, verificationMethod: VerificationMethod): Promise<boolean> {
      const token = await options.tokenFor(keyId, verificationMethod);
      if (!token) return false;
      const claims = await verifyEatToken(token, options.verifier);
      if (!claims) return false;
      let expected: Uint8Array;
      try {
        expected = eatKeyBindingNonce(options.challenge, verificationMethod);
      } catch {
        return false;
      }
      if (claims.nonce.length !== expected.length || !bytesEqual(claims.nonce, expected)) return false;
      return options.acceptClaims ? await options.acceptClaims(claims, keyId) : true;
    },
  };
}
