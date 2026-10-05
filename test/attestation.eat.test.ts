import { generateKeyPairSync, sign as cryptoSign, verify as cryptoVerify, KeyObject } from 'crypto';
import {
  buildEatToken,
  verifyEatToken,
  DebugStatus,
  type EatClaims,
  type EatSigner,
  type EatVerifier,
} from '../src/attestation/index.js';

function makeKeyPair(): { publicKey: KeyObject; privateKey: KeyObject } {
  return generateKeyPairSync('ed25519');
}

function makeSigner(privateKey: KeyObject, kid: string): EatSigner {
  return {
    alg: 'EdDSA',
    kid,
    async sign(bytes: Uint8Array): Promise<Uint8Array> {
      const sig = cryptoSign(null, Buffer.from(bytes), privateKey);
      return new Uint8Array(sig);
    },
  };
}

function makeVerifier(publicKey: KeyObject, expectedKid: string): EatVerifier {
  return {
    async verify(signedBytes: Uint8Array, signature: Uint8Array, kid: string): Promise<boolean> {
      if (kid !== expectedKid) return false;
      return cryptoVerify(null, Buffer.from(signedBytes), publicKey, Buffer.from(signature));
    },
  };
}

describe('EAT attestation token', () => {
  const claims: EatClaims = {
    ueid: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]),
    nonce: new Uint8Array([9, 9, 9, 9]),
    oemid: 0x1234,
    hwmodel: new Uint8Array([0xaa, 0xbb]),
    swname: 'didcomm-ts-device-agent',
    swversion: '1.0.0',
    dbgstat: DebugStatus.DisabledPermanently,
  };

  test('round trips a signed token through verify', async () => {
    const { publicKey, privateKey } = makeKeyPair();
    const kid = 'device-key-1';
    const token = await buildEatToken(claims, makeSigner(privateKey, kid));

    expect(token).toBeInstanceOf(Uint8Array);

    const verified = await verifyEatToken(token, makeVerifier(publicKey, kid));
    expect(verified).not.toBeNull();
    expect(verified).toEqual(claims);
  });

  test('rejects a token whose payload was tampered with after signing', async () => {
    const { publicKey, privateKey } = makeKeyPair();
    const kid = 'device-key-1';
    const token = await buildEatToken(claims, makeSigner(privateKey, kid));

    const tampered = Uint8Array.from(token);
    // Flip a byte well into the payload region to corrupt a claim without
    // producing a structurally invalid CBOR document.
    const flipIndex = Math.floor(tampered.length * 0.6);
    tampered[flipIndex] = tampered[flipIndex] ^ 0xff;

    const verified = await verifyEatToken(tampered, makeVerifier(publicKey, kid));
    expect(verified).toBeNull();
  });

  test('rejects a token signature produced by a different key', async () => {
    const { privateKey } = makeKeyPair();
    const { publicKey: otherPublicKey } = makeKeyPair();
    const kid = 'device-key-1';
    const token = await buildEatToken(claims, makeSigner(privateKey, kid));

    const verified = await verifyEatToken(token, makeVerifier(otherPublicKey, kid));
    expect(verified).toBeNull();
  });
});
