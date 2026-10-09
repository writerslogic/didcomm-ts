/** DID Document and secret lookups shared by envelope, signature and from_prior handling. */

import type { DIDDoc, DidResolver, SecretsResolver, VerificationMethod } from '../types.js';
import { privateKeyFromSecret, type PrivateKey } from './keys.js';

export function didOf(didOrKid: string): string {
  return didOrKid.split('#')[0];
}

export async function resolveDoc(resolver: DidResolver, did: string): Promise<DIDDoc> {
  const doc = await resolver.resolve(did);
  if (!doc) throw new Error(`DID could not be resolved: ${did}`);
  return doc;
}

function matchesKid(reference: string, kid: string, did: string): boolean {
  return reference === kid || (reference.startsWith('#') && `${did}${reference}` === kid);
}

/** Finds `kid` among the doc's verification methods, requiring it to be listed under `relationship`. */
export function findKey(doc: DIDDoc, kid: string, relationship: 'keyAgreement' | 'authentication'): VerificationMethod {
  const did = didOf(kid);
  if (!doc[relationship].some((ref) => matchesKid(ref, kid, did))) {
    throw new Error(`${kid} is not listed under ${relationship} in ${doc.id}`);
  }
  const vm = doc.verificationMethod.find((candidate) => matchesKid(candidate.id, kid, did));
  if (!vm) throw new Error(`Verification method not found: ${kid}`);
  return vm;
}

export async function loadSecret(secrets: SecretsResolver, kid: string): Promise<PrivateKey> {
  const secret = await secrets.get_secret(kid);
  if (!secret) throw new Error(`Secret not found: ${kid}`);
  return privateKeyFromSecret(secret);
}

