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
import { decode as cborDecode, encode as cborEncode } from 'cbor-x';
import { randomUUID } from 'node:crypto';

// ---------------------------------------------------------------------------
// Resolver contracts, matching didcomm-rust's DIDResolver / SecretsResolver
// (these are declared but not exported from didcomm's .d.ts, so we define our
// own structurally-identical versions that callers implement and that we pass
// straight through to the `didcomm` package).
// ---------------------------------------------------------------------------

/** https://www.w3.org/TR/did-core/ */
export interface DIDDoc {
  id: string;
  keyAgreement: string[];
  authentication: string[];
  verificationMethod: VerificationMethod[];
  service: Service[];
}

export interface VerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyJwk?: unknown;
  publicKeyMultibase?: string;
  publicKeyBase58?: string;
}

export interface Service {
  id: string;
  type: string;
  serviceEndpoint: unknown;
}

export interface Secret {
  id: string;
  type: string;
  privateKeyJwk?: unknown;
  privateKeyMultibase?: string;
  privateKeyBase58?: string;
}

export interface DidResolver {
  /** Resolves a DID document by the given DID, or null if it cannot be found. */
  resolve(did: string): Promise<DIDDoc | null>;
}

export interface SecretsResolver {
  /** Finds the secret (private key) identified by the given key ID, or null. */
  get_secret(secretId: string): Promise<Secret | null>;
  /** Returns the subset of secretIds this resolver holds a secret for. */
  find_secrets(secretIds: string[]): Promise<string[]>;
}

// ---------------------------------------------------------------------------
// Message / envelope types
// ---------------------------------------------------------------------------

export type PlaintextMessage = {
  id: string;
  typ: string;
  type: string;
  body: unknown;
  from?: string;
  to?: string[];
  [header: string]: unknown;
};

export type EnvelopeEncoding = 'json' | 'cbor';

export interface PackOptions {
  /** Resolves recipient/sender DID Docs. Required: packing needs it to find keys. */
  did: DidResolver;
  /** Resolves the sender's (authcrypt) or forwarding secrets. Required. */
  secrets: SecretsResolver;
  /** Output encoding for the returned envelope. Default 'json'. */
  encoding?: EnvelopeEncoding;
  /**
   * Whether to wrap the encrypted message in a mediator `Forward` message.
   * Default false — this thin wrapper does not implement the Forward protocol.
   */
  forward?: boolean;
}

export interface UnpackResolvers {
  did: DidResolver;
  secrets: SecretsResolver;
}

export interface UnpackResult {
  message: PlaintextMessage;
  senderKey: string | null;
  recipientKey: string;
}

// ---------------------------------------------------------------------------
// Multi-recipient packing
// ---------------------------------------------------------------------------

/**
 * Resolves every entry in `toDidsOrKeys` (a DID, which contributes all of its
 * `keyAgreement` keys, or an explicit key ID) to a deduplicated list of key IDs
 * plus their verification methods.
 */
async function resolveRecipientKeyIds(
  toDidsOrKeys: string[],
  resolver: DidResolver,
): Promise<{ keyIds: string[]; verificationMethods: VerificationMethod[] }> {
  const keyIds: string[] = [];
  const verificationMethods: VerificationMethod[] = [];
  const docCache = new Map<string, DIDDoc>();

  for (const entry of toDidsOrKeys) {
    const did = entry.split('#')[0];
    let doc = docCache.get(did);
    if (!doc) {
      const resolved = await resolver.resolve(did);
      if (!resolved) {
        throw new Error(`DID could not be resolved: ${did}`);
      }
      doc = resolved;
      docCache.set(did, doc);
    }

    const requestedKeyIds = entry.includes('#') ? [entry] : doc.keyAgreement;
    for (const kid of requestedKeyIds) {
      if (keyIds.includes(kid)) continue;
      const vm = doc.verificationMethod.find((candidate) => candidate.id === kid);
      if (!vm) {
        throw new Error(`Key agreement verification method not found: ${kid}`);
      }
      keyIds.push(kid);
      verificationMethods.push(vm);
    }
  }

  const controllers = new Set(verificationMethods.map((vm) => vm.controller));
  if (controllers.size > 1) {
    throw new Error(
      'Recipients span more than one DID (distinct verificationMethod.controller values): ' +
        `${[...controllers].join(', ')}. didcomm-rust's pack_encrypted only shares one CEK ` +
        'across keyAgreement keys that belong to a single DID Doc (e.g. a group/multi-device ' +
        "DID listing one key per member); pack separately per recipient DID for genuinely " +
        'distinct parties.',
    );
  }

  return { keyIds, verificationMethods };
}

/**
 * Wraps a real DidResolver so that resolving `syntheticId` returns a synthetic
 * DID Doc whose `keyAgreement` is the full set of requested recipient keys
 * (which may belong to different real DIDs), while every other DID still
 * resolves through the caller's real resolver (needed for the sender DID in
 * authcrypt).
 *
 * Confirmed by running the installed package: a synthetic doc `id` that
 * differs from its `verificationMethod.controller` entries is accepted as
 * long as every controller among the requested keys is the same real DID
 * (see `resolveRecipientKeyIds`'s single-controller check above this
 * function's call site). It is only *cross-DID* controller sets that
 * `pack_encrypted` rejects.
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

function encodeEnvelope(packedJson: string, encoding: EnvelopeEncoding): string | Uint8Array {
  if (encoding === 'json') return packedJson;
  const asObject = JSON.parse(packedJson);
  return Uint8Array.from(cborEncode(asObject));
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

  const { keyIds, verificationMethods } = await resolveRecipientKeyIds(toDidsOrKeys, options.did);
  if (keyIds.length === 0) {
    throw new Error('No key agreement keys resolved for the given recipients');
  }

  // Always route packing through a synthetic aggregate DID Doc, even for a
  // single recipient DID, so there is exactly one code path that produces one
  // JWE with one recipient entry per resolved key, sharing one CEK.
  const syntheticId = `did:didcomm-ts:multi:${randomUUID()}`;
  const packDidResolver = buildMultiRecipientResolver(options.did, syntheticId, keyIds, verificationMethods);

  const message = new Message(plaintextMessage);
  let packed: string;
  try {
    [packed] = await message.pack_encrypted(
      syntheticId,
      fromDidOrKey,
      null,
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

// ---------------------------------------------------------------------------
// Encoding auto-detection + unpack
// ---------------------------------------------------------------------------

/**
 * Detects whether an envelope is JSON (a JWE serialized as text/UTF-8 bytes)
 * or CBOR, from its first significant byte:
 * - a string is always treated as JSON;
 * - bytes starting (after optional ASCII whitespace) with `{` (0x7B) are JSON;
 * - bytes whose first byte falls in 0xA0-0xBF (a CBOR map, major type 5 —
 *   DIDComm encrypted/signed messages serialize as a top-level map) are CBOR.
 */
export function detectEnvelopeEncoding(envelope: string | Uint8Array): EnvelopeEncoding {
  if (typeof envelope === 'string') return 'json';

  let i = 0;
  while (i < envelope.length && isAsciiWhitespace(envelope[i])) i++;
  const first = envelope[i];

  if (first === 0x7b) return 'json';
  if (first !== undefined && first >= 0xa0 && first <= 0xbf) return 'cbor';
  throw new Error('Unable to detect envelope encoding: unrecognized leading byte');
}

function isAsciiWhitespace(byte: number): boolean {
  return byte === 0x20 || byte === 0x09 || byte === 0x0a || byte === 0x0d;
}

function toPackedJson(envelope: string | Uint8Array, encoding: EnvelopeEncoding): string {
  if (encoding === 'json') {
    return typeof envelope === 'string' ? envelope : Buffer.from(envelope).toString('utf8');
  }
  const bytes = envelope instanceof Uint8Array ? envelope : Buffer.from(envelope as string, 'utf8');
  const decoded = cborDecode(bytes);
  return JSON.stringify(decoded);
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
