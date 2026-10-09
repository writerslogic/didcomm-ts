import { generateKeyPairSync, randomBytes, randomUUID, sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';
import {
  DebugStatus,
  buildEatToken,
  eatKeyBindingNonce,
  eatRecipientAttestation,
  type EatSigner,
  type EatVerifier,
} from '../src/attestation/index.js';
import * as wasm from './support/wasmBackend.js';
import * as pure from '../src/core/pure/index.js';
import type { DIDDoc, PlaintextMessage, Secret, VerificationMethod } from '../src/core/types.js';

const attestationKey = generateKeyPairSync('ed25519');
const signer: EatSigner = {
  alg: 'EdDSA',
  kid: 'device-attestation-1',
  sign: async (bytes) => new Uint8Array(cryptoSign(null, Buffer.from(bytes), attestationKey.privateKey)),
};
const verifier: EatVerifier = {
  verify: async (bytes, signature, kid) =>
    kid === signer.kid && cryptoVerify(null, Buffer.from(bytes), attestationKey.publicKey, Buffer.from(signature)),
};

function x25519Party(name: string, keys: number) {
  const did = `did:example:${name}-${randomUUID()}`;
  const doc: DIDDoc = { id: did, keyAgreement: [], authentication: [], verificationMethod: [], service: [] };
  const secrets: Secret[] = [];
  for (let i = 1; i <= keys; i++) {
    const kid = `${did}#key-${i}`;
    const { publicKey, privateKey } = generateKeyPairSync('x25519');
    doc.keyAgreement.push(kid);
    doc.verificationMethod.push({ id: kid, type: 'JsonWebKey2020', controller: did, publicKeyJwk: publicKey.export({ format: 'jwk' }) });
    secrets.push({ id: kid, type: 'JsonWebKey2020', privateKeyJwk: privateKey.export({ format: 'jwk' }) });
  }
  return { did, doc, secrets };
}

function resolversFor(docs: DIDDoc[], secrets: Secret[]) {
  return {
    did: { resolve: async (did: string) => docs.find((d) => d.id === did) ?? null },
    secrets: {
      get_secret: async (id: string) => secrets.find((s) => s.id === id) ?? null,
      find_secrets: async (ids: string[]) => ids.filter((id) => secrets.some((s) => s.id === id)),
    },
  };
}

function deviceToken(challenge: Uint8Array, vm: VerificationMethod, dbgstat = DebugStatus.DisabledPermanently) {
  return buildEatToken({ ueid: randomBytes(16), nonce: eatKeyBindingNonce(challenge, vm), dbgstat }, signer);
}

const alice = x25519Party('alice', 1);
const group = x25519Party('group', 2);
const docs = [alice.doc, group.doc];
const vmFor = (kid: string) => group.doc.verificationMethod.find((vm) => vm.id === kid) as VerificationMethod;
const message = (): PlaintextMessage => ({
  id: randomUUID(),
  typ: 'application/didcomm-plain+json',
  type: 'https://didcomm.org/basicmessage/2.0/message',
  from: alice.did,
  to: [group.did],
  body: {},
});

describe.each([
  ['pure', pure],
  ['wasm', wasm],
] as const)('EAT-gated multi-recipient packing (%s)', (_name, backend) => {
  async function packWith(tokens: Map<string, Uint8Array>, challenge: Uint8Array, acceptClaims?: () => boolean) {
    const attestation = eatRecipientAttestation({
      challenge,
      verifier,
      tokenFor: async (kid) => tokens.get(kid) ?? null,
      acceptClaims,
    });
    return backend.packAuthcrypt(message(), [group.did], alice.did, { ...resolversFor(docs, alice.secrets), attestation });
  }

  test('packs when every recipient key presents a token bound to it and the current challenge', async () => {
    const challenge = randomBytes(32);
    const tokens = new Map<string, Uint8Array>();
    for (const kid of group.doc.keyAgreement) tokens.set(kid, await deviceToken(challenge, vmFor(kid)));
    const packed = await packWith(tokens, challenge);
    for (const secret of group.secrets) {
      const result = await backend.unpack(packed, resolversFor(docs, [secret]));
      expect(result.recipientKey).toBe(secret.id);
    }
  });

  test("refuses a valid token for key 1 presented for key 2", async () => {
    const challenge = randomBytes(32);
    const [key1, key2] = group.doc.keyAgreement;
    const token1 = await deviceToken(challenge, vmFor(key1));
    await expect(packWith(new Map([[key1, token1], [key2, token1]]), challenge)).rejects.toThrow(
      `Recipient key failed attestation: ${key2}`,
    );
  });

  test('refuses a token built against a previous challenge', async () => {
    const stale = randomBytes(32);
    const tokens = new Map<string, Uint8Array>();
    for (const kid of group.doc.keyAgreement) tokens.set(kid, await deviceToken(stale, vmFor(kid)));
    await expect(packWith(tokens, randomBytes(32))).rejects.toThrow('Recipient key failed attestation');
  });

  test('refuses a token signed by an untrusted attestation key', async () => {
    const challenge = randomBytes(32);
    const rogue = generateKeyPairSync('ed25519');
    const rogueSigner: EatSigner = {
      ...signer,
      sign: async (bytes) => new Uint8Array(cryptoSign(null, Buffer.from(bytes), rogue.privateKey)),
    };
    const tokens = new Map<string, Uint8Array>();
    for (const kid of group.doc.keyAgreement) {
      tokens.set(kid, await buildEatToken({ ueid: randomBytes(16), nonce: eatKeyBindingNonce(challenge, vmFor(kid)) }, rogueSigner));
    }
    await expect(packWith(tokens, challenge)).rejects.toThrow('Recipient key failed attestation');
  });

  test('applies the claim policy', async () => {
    const challenge = randomBytes(32);
    const tokens = new Map<string, Uint8Array>();
    for (const kid of group.doc.keyAgreement) tokens.set(kid, await deviceToken(challenge, vmFor(kid), DebugStatus.Enabled));
    await expect(packWith(tokens, challenge, () => false)).rejects.toThrow('Recipient key failed attestation');
  });
});
