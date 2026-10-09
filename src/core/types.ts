/**
 * DIDComm resolver contracts, message/option types, and recipient-key
 * resolution shared by both crypto backends (`envelope.ts` over didcomm-rust
 * WASM, and `pure/` over noble). Must not import `didcomm`: the pure backend
 * depends on this module.
 */

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

/**
 * Multi-device trust gate (see src/attestation/eat.ts's header comment): before a
 * resolved recipient key is trusted for multi-recipient authcrypt/anoncrypt, the
 * caller may require proof — e.g. verification of an EAT token via
 * `verifyEatToken` from src/attestation — that the key belongs to an attested
 * device. `verify` returns false (not a thrown error) for a key that fails
 * attestation; `resolveRecipientKeyIds` turns that into a clear, key-naming error.
 */
export interface RecipientKeyAttestation {
  verify(keyId: string, verificationMethod: VerificationMethod): Promise<boolean>;
}

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
  /**
   * Optional multi-device trust gate. When present, every resolved recipient
   * key is checked with `attestation.verify` before it is included in the
   * envelope; a key that fails verification throws rather than being packed.
   * Omitted (the default): no gating, identical behavior to before this option
   * existed.
   */
  attestation?: RecipientKeyAttestation;
  /**
   * DID or key ID to sign the plaintext with (JWS) before encrypting it, for
   * non-repudiation. Omitted (the default): no inner signature.
   */
  signBy?: string;
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
export async function resolveRecipientKeyIds(
  toDidsOrKeys: string[],
  resolver: DidResolver,
  attestation?: RecipientKeyAttestation,
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

  if (attestation) {
    for (let i = 0; i < keyIds.length; i++) {
      const ok = await attestation.verify(keyIds[i], verificationMethods[i]);
      if (!ok) {
        throw new Error(`Recipient key failed attestation: ${keyIds[i]}`);
      }
    }
  }

  return { keyIds, verificationMethods };
}
