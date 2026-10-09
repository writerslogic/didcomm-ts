/**
 * Thin, well-typed wrapper around the `didcomm` npm package (WASM bindings
 * over didcomm-rust, see https://github.com/sicpa-dlab/didcomm-rust/tree/main/wasm).
 *
 * Verified against the installed package version (didcomm@0.4.1, read from
 * node_modules/didcomm/index.d.ts in this repo): `Message#pack_encrypted(to, from,
 * sign_by, did_resolver, secrets_resolver, options)` and `Message.unpack(msg,
 * did_resolver, secrets_resolver, options)`. The `to` parameter of
 * `pack_encrypted` is a single DID or key ID; when it is a DID, didcomm-rust
 * multiplexes encryption over every key in that DID's `keyAgreement` array into
 * ONE JWE with one recipient entry per key, sharing a single CEK.
 *
 * MULTI-RECIPIENT SCOPE (confirmed by running the installed package, not
 * assumed): `pack_encrypted` rejects a resolved key set whose
 * `verificationMethod.controller` values span more than one DID, throwing
 * `DIDCommMalformed: Recipient keys are outside of one did or can't be
 * resolved to key agreement`. So "multiple recipients sharing one envelope"
 * here means multiple `keyAgreement` keys under ONE recipient DID Doc (e.g. a
 * group/conversation DID listing one key per member, or a multi-device DID) —
 * each key independently decryptable by whoever holds its matching secret.
 * Genuinely distinct recipient DIDs cannot share one CEK through this API;
 * `resolveRecipientKeyIds` validates this and throws a clear error rather
 * than silently looping into N separate envelopes or hand-rolling ECDH-1PU/ES
 * wrapping ourselves.
 */

import { Message } from 'didcomm';
import { randomUUID } from 'node:crypto';
import {
  resolveRecipientKeyIds,
  type DIDDoc,
  type DidResolver,
  type PackOptions,
  type PlaintextMessage,
  type UnpackResolvers,
  type UnpackResult,
  type VerificationMethod,
} from '../../src/core/types.js';
import { detectEnvelopeEncoding, encodeEnvelope, toPackedJson } from '../../src/core/encoding.js';

export * from '../../src/core/types.js';
export { detectEnvelopeEncoding } from '../../src/core/encoding.js';

/**
 * Wraps a real DidResolver so that resolving `syntheticId` returns a synthetic
 * DID Doc whose `keyAgreement` is the requested subset of recipient keys
 * (which all belong to one real DID, per `resolveRecipientKeyIds`'s
 * single-controller check above this function's call site), while every
 * other DID still resolves through the caller's real resolver (needed for
 * the sender DID in authcrypt).
 *
 * Used only for explicit-key-ID recipients (selecting a subset of a DID's
 * `keyAgreement`, e.g. specific devices): the override's key is synthetic
 * rather than the real recipient DID precisely so it does not shadow
 * resolving that same real DID for any *other* purpose — notably, a sender
 * device authcrypting to its own sibling devices, where the sender's DID
 * equals the recipient DID but the sender's own key must still resolve via
 * the full, real doc. Bare-DID recipients (requesting a DID's whole
 * `keyAgreement` set, e.g. `packAuthcrypt(msg, [peerDid], ...)`) skip this
 * override entirely and pack straight to the real DID (see `packEncrypted`),
 * which also satisfies didcomm-rust's requirement that a plaintext `to`
 * header list the DID `pack_encrypted` was asked to pack to.
 */
function buildMultiRecipientResolver(
  realResolver: DidResolver,
  syntheticId: string,
  keyIds: string[],
  verificationMethods: VerificationMethod[],
): DidResolver {
  const syntheticDoc: DIDDoc = {
    id: syntheticId,
    keyAgreement: keyIds,
    authentication: [],
    verificationMethod: verificationMethods,
    service: [],
  };
  return {
    async resolve(did: string): Promise<DIDDoc | null> {
      if (did === syntheticId) return syntheticDoc;
      return realResolver.resolve(did);
    },
  };
}

async function packEncrypted(
  plaintextMessage: PlaintextMessage,
  toDidsOrKeys: string[],
  fromDidOrKey: string | null,
  options: PackOptions,
): Promise<string | Uint8Array> {
  if (toDidsOrKeys.length === 0) {
    throw new Error('At least one recipient (DID or key ID) is required');
  }

  const { keyIds, verificationMethods } = await resolveRecipientKeyIds(
    toDidsOrKeys,
    options.did,
    options.attestation,
  );
  if (keyIds.length === 0) {
    throw new Error('No key agreement keys resolved for the given recipients');
  }

  // Every resolved key's `verificationMethod.controller` is the same real DID
  // (guaranteed by the single-controller check above); callers naming that
  // DID itself as a recipient (no `#` fragment, requesting its full
  // `keyAgreement` set) are the common case — the chat CLI's `send` does
  // this. For that case, pack straight to the real recipient DID through the
  // caller's own resolver, with no override at all: `pack_encrypted`'s `to`
  // argument is then a DID the plaintext `to` header can legitimately list,
  // and the sender's own DID (if it happens to equal the recipient DID, as
  // with one device of a multi-device DID messaging its own siblings via
  // explicit key IDs) still resolves normally.
  //
  // Callers naming an explicit key ID (selecting a subset of a DID's
  // `keyAgreement`, e.g. specific devices) keep the resolver-override path:
  // packing through a synthetic DID Doc exposing only the requested subset,
  // as before. Narrowing the override to the real DID in that case would
  // break resolving the *sender's* key when the sender is another key of
  // that same DID, since the override would intercept that resolution too.
  const recipientDid = verificationMethods[0].controller;
  const hasExplicitKeyId = toDidsOrKeys.some((entry) => entry.includes('#'));

  const packDidTarget = hasExplicitKeyId ? `did:didcomm-ts:multi:${randomUUID()}` : recipientDid;
  const packDidResolver = hasExplicitKeyId
    ? buildMultiRecipientResolver(options.did, packDidTarget, keyIds, verificationMethods)
    : options.did;

  const message = new Message(plaintextMessage);
  let packed: string;
  try {
    [packed] = await message.pack_encrypted(
      packDidTarget,
      fromDidOrKey,
      options.signBy ?? null,
      packDidResolver,
      options.secrets,
      { forward: options.forward ?? false },
    );
  } finally {
    message.free();
  }

  return encodeEnvelope(packed, options.encoding ?? 'json');
}

/**
 * Packs `plaintextMessage` as a DIDComm v2 authcrypt envelope addressed to
 * MULTIPLE recipients (`toDidsOrKeys`): one DID or key ID per recipient. All
 * resolved recipient keys share a single encrypted envelope and CEK — this is
 * not a loop producing N separate envelopes.
 */
export function packAuthcrypt(
  plaintextMessage: PlaintextMessage,
  toDidsOrKeys: string[],
  fromDidOrKey: string,
  options: PackOptions,
): Promise<string | Uint8Array> {
  if (!fromDidOrKey) {
    throw new Error('packAuthcrypt requires fromDidOrKey');
  }
  return packEncrypted(plaintextMessage, toDidsOrKeys, fromDidOrKey, options);
}

/**
 * Packs `plaintextMessage` as a DIDComm v2 anoncrypt envelope addressed to
 * MULTIPLE recipients (`toDidsOrKeys`), sharing one envelope/CEK as above, with
 * no sender authentication.
 */
export function packAnoncrypt(
  plaintextMessage: PlaintextMessage,
  toDidsOrKeys: string[],
  options: PackOptions,
): Promise<string | Uint8Array> {
  return packEncrypted(plaintextMessage, toDidsOrKeys, null, options);
}


/**
 * Decrypts (and, if present, verifies the signature of) a DIDComm v2 envelope.
 * Accepts either JSON- or CBOR-encoded input, auto-detecting which from the
 * envelope's leading byte (see `detectEnvelopeEncoding`).
 */
export async function unpack(
  envelope: string | Uint8Array,
  resolvers: UnpackResolvers,
): Promise<UnpackResult> {
  const encoding = detectEnvelopeEncoding(envelope);
  const packedJson = toPackedJson(envelope, encoding);

  const [message, metadata] = await Message.unpack(packedJson, resolvers.did, resolvers.secrets, {
    expect_decrypt_by_all_keys: false,
    unwrap_re_wrapping_forward: false,
  });

  let plaintext: PlaintextMessage;
  try {
    plaintext = message.as_value() as PlaintextMessage;
  } finally {
    message.free();
  }

  const candidateRecipientKeys = metadata.encrypted_to_kids ?? [];
  const ownedRecipientKeys = await resolvers.secrets.find_secrets(candidateRecipientKeys);
  const recipientKey = ownedRecipientKeys[0];
  if (!recipientKey) {
    throw new Error('Unable to determine recipient key: no owned secret among encrypted_to_kids');
  }

  return {
    message: plaintext,
    senderKey: metadata.encrypted_from_kid ?? null,
    recipientKey,
  };
}
