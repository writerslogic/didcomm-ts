/**
 * DIDComm v2 pack/unpack: authcrypt, anoncrypt and signed messages, with
 * JOSE implemented in `./jwe.ts` and `./jws.ts` over `node:crypto`.
 * Recipient resolution, the single-DID multi-recipient rule, and the
 * attestation gate live in `../types.ts`.
 */

import type { AnoncryptProvider, EncryptedMessage, PlaintextMessage as ForwardPlaintext } from '../../routing/forward.js';
import { detectEnvelopeEncoding, encodeEnvelope, toPackedJson } from '../encoding.js';
import {
  resolveRecipientKeyIds,
  type DidResolver,
  type PackOptions,
  type PlaintextMessage,
  type UnpackResolvers,
  type UnpackResult,
} from '../types.js';
import { fromUtf8, utf8 } from './bytes.js';
import { didOf, findKey, loadSecret, resolveDoc } from './resolve.js';
import { unpackFromPrior, type FromPrior } from './fromPrior.js';

const PLAIN_TYP = 'application/didcomm-plain+json';
import type { ContentEnc } from './content.js';
import { decryptJwe, encryptJwe, isJwe, parseJwe, type JweRecipient, type JweSender } from './jwe.js';
import { isJws, jwsSignerKid, signJws, verifyJws } from './jws.js';
import {
  publicKeyFromVerificationMethod,
  toKeyAgreementPrivate,
  toKeyAgreementPublic,
  type PublicKey,
} from './keys.js';

export interface PurePackOptions extends PackOptions {
  /** Anoncrypt content encryption. Default A256CBC-HS512 (the one every implementation must support). */
  anoncryptEnc?: ContentEnc;
}

/** DID rotation details, present when the message carried a valid `from_prior` header. */
export interface FromPriorResult {
  fromPrior: FromPrior | null;
  /** The prior DID's key that signed `from_prior`. */
  fromPriorIssuerKid: string | null;
}

export interface PureUnpackResult extends UnpackResult, FromPriorResult {
  /** Signer kid when the plaintext was wrapped in a JWS, otherwise null. */
  signedBy: string | null;
}

const MAX_ENVELOPE_LAYERS = 3;

function assertAddressing(message: PlaintextMessage, recipientDid: string, senderDid: string | null): void {
  if (message.to !== undefined && !message.to.map(didOf).includes(recipientDid)) {
    throw new Error(`Plaintext "to" does not contain the recipient DID ${recipientDid}`);
  }
  if (senderDid !== null && message.from !== undefined && didOf(message.from) !== senderDid) {
    throw new Error(`Plaintext "from" ${message.from} does not match the sender DID ${senderDid}`);
  }
}

async function signPayload(message: PlaintextMessage, signBy: string, options: PackOptions): Promise<Uint8Array> {
  const signerDid = didOf(signBy);
  if (message.from !== undefined && didOf(message.from) !== signerDid) {
    throw new Error(`signBy ${signBy} does not match plaintext "from" ${message.from}`);
  }
  const doc = await resolveDoc(options.did, signerDid);
  const candidates = signBy.includes('#') ? [signBy] : doc.authentication.map((ref) => (ref.startsWith('#') ? `${signerDid}${ref}` : ref));
  const owned = await options.secrets.find_secrets(candidates);
  if (owned.length === 0) throw new Error(`No signing secret available for ${signBy}`);
  findKey(doc, owned[0], 'authentication');
  const jws = signJws(utf8(JSON.stringify(message)), owned[0], await loadSecret(options.secrets, owned[0]));
  return utf8(JSON.stringify(jws));
}

/** Picks the first owned sender key-agreement key that shares a curve with at least one recipient. */
async function selectSender(
  fromDidOrKey: string,
  recipients: JweRecipient[],
  options: PackOptions,
): Promise<{ sender: JweSender; recipients: JweRecipient[] }> {
  const senderDid = didOf(fromDidOrKey);
  const doc = await resolveDoc(options.did, senderDid);
  const candidates = fromDidOrKey.includes('#')
    ? [fromDidOrKey]
    : doc.keyAgreement.map((ref) => (ref.startsWith('#') ? `${senderDid}${ref}` : ref));
  for (const kid of await options.secrets.find_secrets(candidates)) {
    findKey(doc, kid, 'keyAgreement');
    const key = toKeyAgreementPrivate(await loadSecret(options.secrets, kid));
    const matching = recipients.filter((r) => r.key.curve === key.curve);
    if (matching.length > 0) return { sender: { kid, key }, recipients: matching };
  }
  throw new Error(`No sender key agreement secret for ${fromDidOrKey} shares a curve with the recipients`);
}

async function packEncrypted(
  plaintextMessage: PlaintextMessage,
  toDidsOrKeys: string[],
  fromDidOrKey: string | null,
  options: PurePackOptions,
): Promise<string | Uint8Array> {
  if (toDidsOrKeys.length === 0) throw new Error('At least one recipient (DID or key ID) is required');
  if (options.forward) {
    throw new Error('The pure backend does not auto-wrap forwards; use routing.wrapInForward with pure.anoncryptProvider');
  }
  const { keyIds, verificationMethods } = await resolveRecipientKeyIds(toDidsOrKeys, options.did, options.attestation);
  const recipientDid = verificationMethods[0].controller;
  const senderDid = fromDidOrKey === null ? null : didOf(fromDidOrKey);
  assertAddressing(plaintextMessage, recipientDid, senderDid);

  let recipients: JweRecipient[] = keyIds.map((kid, i) => ({
    kid,
    key: toKeyAgreementPublic(publicKeyFromVerificationMethod(verificationMethods[i])),
  }));

  let sender: JweSender | undefined;
  if (fromDidOrKey !== null) {
    ({ sender, recipients } = await selectSender(fromDidOrKey, recipients, options));
  } else {
    recipients = recipients.filter((r) => r.key.curve === recipients[0].key.curve);
  }

  const payload = options.signBy
    ? await signPayload(plaintextMessage, options.signBy, options)
    : utf8(JSON.stringify(plaintextMessage));
  const enc: ContentEnc = sender ? 'A256CBC-HS512' : (options.anoncryptEnc ?? 'A256CBC-HS512');
  const jwe = encryptJwe(payload, enc, recipients, sender);
  return encodeEnvelope(JSON.stringify(jwe), options.encoding ?? 'json');
}

/** Authcrypt (ECDH-1PU+A256KW, A256CBC-HS512) to one or more keys of a single recipient DID. */
export function packAuthcrypt(
  plaintextMessage: PlaintextMessage,
  toDidsOrKeys: string[],
  fromDidOrKey: string,
  options: PurePackOptions,
): Promise<string | Uint8Array> {
  if (!fromDidOrKey) throw new Error('packAuthcrypt requires fromDidOrKey');
  return packEncrypted(plaintextMessage, toDidsOrKeys, fromDidOrKey, options);
}

/** Anoncrypt (ECDH-ES+A256KW) to one or more keys of a single recipient DID. */
export function packAnoncrypt(
  plaintextMessage: PlaintextMessage,
  toDidsOrKeys: string[],
  options: PurePackOptions,
): Promise<string | Uint8Array> {
  return packEncrypted(plaintextMessage, toDidsOrKeys, null, options);
}

/** A signed-only (JWS) message, without encryption. */
export async function packSigned(
  plaintextMessage: PlaintextMessage,
  signBy: string,
  options: Pick<PackOptions, 'did' | 'secrets'>,
): Promise<string> {
  return fromUtf8(await signPayload(plaintextMessage, signBy, options as PackOptions));
}

async function senderPublicKey(resolver: DidResolver, skid: string): Promise<PublicKey> {
  const doc = await resolveDoc(resolver, didOf(skid));
  return toKeyAgreementPublic(publicKeyFromVerificationMethod(findKey(doc, skid, 'keyAgreement')));
}

interface Unwrapped extends FromPriorResult {
  message: PlaintextMessage;
  recipientKey: string | null;
  senderKey: string | null;
  signedBy: string | null;
}

/** Validates plaintext structure, and verifies `from_prior` against the message's `from` when present. */
async function checkPlaintext(message: unknown, did: DidResolver): Promise<FromPriorResult & { message: PlaintextMessage }> {
  const m = message as PlaintextMessage;
  if (typeof m !== 'object' || m === null || Array.isArray(m) || typeof m.id !== 'string' || typeof m.type !== 'string') {
    throw new Error('Not a DIDComm plaintext message (requires string `id` and `type`)');
  }
  if (m.typ !== undefined && m.typ !== PLAIN_TYP) throw new Error(`Unexpected plaintext typ: ${String(m.typ)}`);
  if (m.from_prior === undefined) return { message: m, fromPrior: null, fromPriorIssuerKid: null };
  if (typeof m.from_prior !== 'string') throw new Error('from_prior must be a compact JWT string');
  const { fromPrior, issuerKid } = await unpackFromPrior(m.from_prior, did);
  if (m.from === undefined || didOf(m.from) !== fromPrior.sub) {
    throw new Error('from_prior `sub` does not match the message `from`');
  }
  return { message: m, fromPrior, fromPriorIssuerKid: issuerKid };
}

/** Peels JWE/JWS layers (anoncrypt around authcrypt, a JWS inside a JWE) down to the plaintext. */
async function unwrap(envelope: string | Uint8Array, resolvers: UnpackResolvers): Promise<Unwrapped> {
  let current: unknown = JSON.parse(toPackedJson(envelope, detectEnvelopeEncoding(envelope)));
  let recipientKey: string | null = null;
  let senderKey: string | null = null;
  let signedBy: string | null = null;

  for (let layer = 0; layer < MAX_ENVELOPE_LAYERS; layer++) {
    if (isJwe(current)) {
      if (signedBy !== null) throw new Error('Encrypted layer inside a signed message is not allowed');
      const parsed = parseJwe(current);
      const owned = await resolvers.secrets.find_secrets(parsed.recipientKids);
      if (owned.length === 0) throw new Error('No owned secret among the JWE recipients');
      const recipient = { kid: owned[0], key: toKeyAgreementPrivate(await loadSecret(resolvers.secrets, owned[0])) };
      const sender = parsed.skid ? await senderPublicKey(resolvers.did, parsed.skid) : undefined;
      const plaintext = decryptJwe(parsed, recipient, sender);
      if (parsed.skid) {
        if (senderKey !== null) throw new Error('Nested authcrypt layers are not allowed');
        senderKey = parsed.skid;
      }
      recipientKey ??= recipient.kid;
      current = JSON.parse(fromUtf8(plaintext));
    } else if (isJws(current)) {
      if (signedBy !== null) throw new Error('Nested signatures are not allowed');
      const kid = jwsSignerKid(current);
      const doc = await resolveDoc(resolvers.did, didOf(kid));
      const key = publicKeyFromVerificationMethod(findKey(doc, kid, 'authentication'));
      current = JSON.parse(fromUtf8(verifyJws(current, key)));
      signedBy = kid;
    } else {
      break;
    }
  }

  const { message, fromPrior, fromPriorIssuerKid } = await checkPlaintext(current, resolvers.did);
  if (recipientKey !== null) {
    assertAddressing(message, didOf(recipientKey), senderKey === null ? null : didOf(senderKey));
  }
  if (signedBy !== null && message.from !== undefined && didOf(message.from) !== didOf(signedBy)) {
    throw new Error(`Plaintext "from" ${message.from} does not match the signer ${signedBy}`);
  }
  return { message, recipientKey, senderKey, signedBy, fromPrior, fromPriorIssuerKid };
}

/**
 * Decrypts a DIDComm v2 envelope (JSON or CBOR), unwrapping nested layers:
 * anoncrypt around authcrypt (protected sender) and/or a JWS inside the JWE.
 */
export async function unpack(envelope: string | Uint8Array, resolvers: UnpackResolvers): Promise<PureUnpackResult> {
  const { recipientKey, ...rest } = await unwrap(envelope, resolvers);
  if (recipientKey === null) throw new Error('Envelope is not encrypted; use unpackSigned or unpackPlaintext');
  return { ...rest, recipientKey };
}

/** Verifies a signed-only (JWS) message and returns its plaintext and signer kid. */
export async function unpackSigned(
  envelope: string | Uint8Array,
  resolvers: UnpackResolvers,
): Promise<{ message: PlaintextMessage; signedBy: string } & FromPriorResult> {
  const { message, recipientKey, signedBy, fromPrior, fromPriorIssuerKid } = await unwrap(envelope, resolvers);
  if (recipientKey !== null || signedBy === null) throw new Error('Envelope is not a signed-only message');
  return { message, signedBy, fromPrior, fromPriorIssuerKid };
}

/**
 * Serializes a plaintext message (no protection: no confidentiality,
 * integrity or sender authentication). Validates its structure first.
 */
export function packPlaintext(plaintextMessage: PlaintextMessage): string {
  const m = plaintextMessage as unknown as Record<string, unknown>;
  if (typeof m.id !== 'string' || typeof m.type !== 'string') throw new Error('Plaintext requires string `id` and `type`');
  if (m.typ !== undefined && m.typ !== PLAIN_TYP) throw new Error(`Unexpected plaintext typ: ${String(m.typ)}`);
  return JSON.stringify({ ...plaintextMessage, typ: PLAIN_TYP });
}

/**
 * Parses an unenveloped plaintext message, verifying `from_prior` if present.
 * Rejects encrypted or signed envelopes so callers can't mistake them for
 * plaintext; use `unpack` / `unpackSigned` for those.
 */
export async function unpackPlaintext(
  envelope: string | Uint8Array,
  resolvers: Pick<UnpackResolvers, 'did'>,
): Promise<{ message: PlaintextMessage } & FromPriorResult> {
  const parsed: unknown = JSON.parse(toPackedJson(envelope, detectEnvelopeEncoding(envelope)));
  if (isJwe(parsed) || isJws(parsed)) throw new Error('Envelope is encrypted or signed; use unpack or unpackSigned');
  return checkPlaintext(parsed, resolvers.did);
}

/** An `AnoncryptProvider` for `routing.wrapInForward` backed by the pure packer. */
export function anoncryptProvider(resolvers: UnpackResolvers, enc?: ContentEnc): AnoncryptProvider {
  return {
    async encrypt(message: ForwardPlaintext, recipientKeyId: string): Promise<EncryptedMessage> {
      const packed = await packAnoncrypt(
        { typ: 'application/didcomm-plain+json', ...message } as PlaintextMessage,
        [recipientKeyId],
        { ...resolvers, anoncryptEnc: enc },
      );
      return JSON.parse(packed as string) as EncryptedMessage;
    },
    async decrypt(message: EncryptedMessage): Promise<ForwardPlaintext> {
      const { message: plaintext } = await unpack(JSON.stringify(message), resolvers);
      return plaintext as unknown as ForwardPlaintext;
    },
  };
}
