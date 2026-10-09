/**
 * Differential check of the node:crypto primitives against the noble-based
 * implementation they replaced (frozen in test/support/noble): same inputs,
 * same outputs, for every curve and content encryption.
 */
import { randomBytes } from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519.js';
import * as node from '../src/core/pure/keys.js';
import * as nodeContent from '../src/core/pure/content.js';
import * as noble from './support/noble/keys.js';
import * as nobleContent from './support/noble/content.js';

const CURVES = ['X25519', 'P-256', 'P-384', 'P-521', 'secp256k1'] as const;
const ROUNDS = 8;

describe.each(CURVES)('%s', (curve) => {
  test('ECDH, key import and public derivation agree', () => {
    for (let i = 0; i < ROUNDS; i++) {
      const a = noble.generateEphemeral(curve);
      const b = node.generateEphemeral(curve);
      const aJwk = { ...noble.publicKeyToJwk(a.publicKey), d: Buffer.from(a.d).toString('base64url') };
      const bJwk = { ...node.publicKeyToJwk(b.publicKey), d: Buffer.from(b.d).toString('base64url') };
      const aNode = node.privateKeyFromJwk(aJwk);
      const bNoble = noble.privateKeyFromJwk(bJwk);
      expect(aNode.publicKey.bytes).toEqual(a.publicKey.bytes);
      expect(bNoble.publicKey.bytes).toEqual(b.publicKey.bytes);
      expect(node.ecdh(aNode, b.publicKey)).toEqual(noble.ecdh(a, bNoble.publicKey));
    }
  });
});

test('Ed25519 -> X25519 conversion agrees (public and private)', () => {
  for (let i = 0; i < ROUNDS; i++) {
    const seed = randomBytes(32);
    const jwk = {
      kty: 'OKP',
      crv: 'Ed25519',
      x: Buffer.from(ed25519.getPublicKey(seed)).toString('base64url'),
      d: seed.toString('base64url'),
    };
    const ours = node.toKeyAgreementPrivate(node.privateKeyFromJwk(jwk));
    const theirs = noble.toKeyAgreementPrivate(noble.privateKeyFromJwk(jwk));
    expect(ours.publicKey.bytes).toEqual(theirs.publicKey.bytes);
    expect(node.toKeyAgreementPublic(node.publicKeyFromJwk(jwk)).bytes).toEqual(theirs.publicKey.bytes);
  }
});

test.each(['Ed25519', 'P-256', 'secp256k1'] as const)('%s signatures verify across implementations', (curve) => {
  for (let i = 0; i < ROUNDS; i++) {
    const message = randomBytes(64);
    let jwk: Record<string, string>;
    if (curve === 'Ed25519') {
      const seed = randomBytes(32);
      jwk = { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(ed25519.getPublicKey(seed)).toString('base64url'), d: seed.toString('base64url') };
    } else {
      const k = node.generateEphemeral(curve);
      jwk = { ...(node.publicKeyToJwk(k.publicKey) as Record<string, string>), d: Buffer.from(k.d).toString('base64url') };
    }
    const ours = node.privateKeyFromJwk(jwk);
    const theirs = noble.privateKeyFromJwk(jwk);
    expect(noble.verify(theirs.publicKey, message, node.sign(ours, message))).toBe(true);
    expect(node.verify(ours.publicKey, message, noble.sign(theirs, message))).toBe(true);
    expect(node.verify(ours.publicKey, randomBytes(64), noble.sign(theirs, message))).toBe(false);
  }
});

test.each(['A256CBC-HS512', 'A256GCM', 'XC20P'] as const)('%s content encryption agrees', (enc) => {
  const { keyLength, ivLength } = nodeContent.contentParams(enc);
  for (let i = 0; i < ROUNDS; i++) {
    const cek = randomBytes(keyLength);
    const iv = randomBytes(ivLength);
    const aad = randomBytes(40);
    const plaintext = randomBytes(1 + i * 97);
    const ours = nodeContent.encryptContent(enc, cek, iv, aad, plaintext);
    expect(ours).toEqual(nobleContent.encryptContent(enc, cek, iv, aad, plaintext));
    expect(nodeContent.decryptContent(enc, cek, iv, aad, ours)).toEqual(new Uint8Array(plaintext));
  }
});

test('parsed-key caches keep public and private parses apart and notice mutated JWKs', () => {
  const k = node.generateEphemeral('P-256');
  const jwk: Record<string, string> = { ...(node.publicKeyToJwk(k.publicKey) as Record<string, string>), d: Buffer.from(k.d).toString('base64url') };
  const pub = node.publicKeyFromJwk(jwk);
  const priv = node.privateKeyFromJwk(jwk);
  expect('d' in pub).toBe(false);
  expect(priv.d).toEqual(k.d);
  expect(node.privateKeyFromJwk(jwk)).toBe(priv);

  const other = node.generateEphemeral('P-256');
  Object.assign(jwk, node.publicKeyToJwk(other.publicKey), { d: Buffer.from(other.d).toString('base64url') });
  expect(node.privateKeyFromJwk(jwk).publicKey.bytes).toEqual(other.publicKey.bytes);
  const message = randomBytes(32);
  expect(node.verify(other.publicKey, message, node.sign(node.privateKeyFromJwk(jwk), message))).toBe(true);
});
