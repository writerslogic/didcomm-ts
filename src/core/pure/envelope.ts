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
  type DIDDoc,
  type DidResolver,
  type PackOptions,
  type PlaintextMessage,
  type SecretsResolver,
  type UnpackResolvers,
  type UnpackResult,
  type VerificationMethod,
} from '../types.js';
import { fromUtf8, utf8 } from './bytes.js';
import type { ContentEnc } from './content.js';
import { decryptJwe, encryptJwe, isJwe, parseJwe, type JweRecipient, type JweSender } from './jwe.js';
import { isJws, jwsSignerKid, signJws, verifyJws } from './jws.js';
import {
  privateKeyFromSecret,
  publicKeyFromVerificationMethod,
  toKeyAgreementPrivate,
  toKeyAgreementPublic,
  type PrivateKey,
  type PublicKey,
} from './keys.js';

export interface PurePackOptions extends PackOptions {
  /** Anoncrypt content encryption. Default A256CBC-HS512 (the one every implementation must support). */
  anoncryptEnc?: ContentEnc;
}

export interface PureUnpackResult extends UnpackResult {
  /** Signer kid when the plaintext was wrapped in a JWS, otherwise null. */
  signedBy: string | null;
}

const MAX_ENVELOPE_LAYERS = 3;

function didOf(didOrKid: string): string {
  return didOrKid.split('#')[0];
}

async function resolveDoc(resolver: DidResolver, did: string): Promise<DIDDoc> {
  const doc = await resolver.resolve(did);
  if (!doc) throw new Error(`DID could not be resolved: ${did}`);
  return doc;
}

function matchesKid(reference: string, kid: string, did: string): boolean {
  return reference === kid || (reference.startsWith('#') && `${did}${reference}` === kid);
}

/** Finds `kid` among the doc's verification methods, requiring it to be listed under `relationship`. */
function findKey(doc: DIDDoc, kid: string, relationship: 'keyAgreement' | 'authentication'): VerificationMethod {
  const did = didOf(kid);
  if (!doc[relationship].some((ref) => matchesKid(ref, kid, did))) {
    throw new Error(`${kid} is not listed under ${relationship} in ${doc.id}`);
  }
  const vm = doc.verificationMethod.find((candidate) => matchesKid(candidate.id, kid, did));
  if (!vm) throw new Error(`Verification method not found: ${kid}`);
  return vm;
}

async function loadSecret(secrets: SecretsResolver, kid: string): Promise<PrivateKey> {
  const secret = await secrets.get_secret(kid);
  if (!secret) throw new Error(`Secret not found: ${kid}`);
  return privateKeyFromSecret(secret);
}

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

interface Unwrapped {
  message: PlaintextMessage;
  recipientKey: string | null;
  senderKey: string | null;
  signedBy: string | null;
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

  const message = current as PlaintextMessage;
  if (typeof message !== 'object' || message === null || typeof message.id !== 'string' || typeof message.type !== 'string') {
    throw new Error('Unpacked payload is not a DIDComm plaintext message');
  }
  if (recipientKey !== null) {
    assertAddressing(message, didOf(recipientKey), senderKey === null ? null : didOf(senderKey));
  }
  if (signedBy !== null && message.from !== undefined && didOf(message.from) !== didOf(signedBy)) {
    throw new Error(`Plaintext "from" ${message.from} does not match the signer ${signedBy}`);
  }
  return { message, recipientKey, senderKey, signedBy };
}

/**
 * Decrypts a DIDComm v2 envelope (JSON or CBOR), unwrapping nested layers:
 * anoncrypt around authcrypt (protected sender) and/or a JWS inside the JWE.
 */
export async function unpack(envelope: string | Uint8Array, resolvers: UnpackResolvers): Promise<PureUnpackResult> {
  const { message, recipientKey, senderKey, signedBy } = await unwrap(envelope, resolvers);
  if (recipientKey === null) throw new Error('Envelope is not encrypted; use unpackSigned');
  return { message, senderKey, recipientKey, signedBy };
}

/** Verifies a signed-only (JWS) message and returns its plaintext and signer kid. */
export async function unpackSigned(
  envelope: string | Uint8Array,
  resolvers: UnpackResolvers,
): Promise<{ message: PlaintextMessage; signedBy: string }> {
  const { message, recipientKey, signedBy } = await unwrap(envelope, resolvers);
  if (recipientKey !== null || signedBy === null) throw new Error('Envelope is not a signed-only message');
  return { message, signedBy };
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
