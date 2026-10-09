/**
 * Known-answer tests for the pure backend: primitive vectors (RFC 3394,
 * RFC 7518 App. B.3, draft-madden-jose-ecdh-1pu-04 App. B via askar) and
 * didcomm-rust's own encrypted/signed test vectors, decrypted without WASM.
 */
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { aeskw } from '@noble/ciphers/aes.js';
import { encryptContent, decryptContent } from '../src/core/pure/content.js';
import { concatKdf } from '../src/core/pure/kdf.js';
import { ecdh, privateKeyFromJwk, publicKeyFromJwk } from '../src/core/pure/keys.js';
import { b64urlEncode, utf8 } from '../src/core/pure/bytes.js';
import { unpack, unpackSigned } from '../src/core/pure/index.js';
import type { DIDDoc, Secret } from '../src/core/types.js';

const hex = (s: string) => Uint8Array.from(Buffer.from(s.replace(/\s+/g, ''), 'hex'));
const toHex = (b: Uint8Array) => Buffer.from(b).toString('hex');

interface Vectors {
  didDocs: Record<string, DIDDoc>;
  secrets: Secret[];
  encrypted: Record<string, unknown>;
  invalidEncrypted: Record<string, unknown>;
  signed: Record<string, unknown>;
  plaintextSimple: Record<string, unknown>;
}

const vectors = JSON.parse(
  readFileSync(join(process.cwd(), 'test/fixtures/didcomm-rust-vectors.json'), 'utf8'),
) as Vectors;

const resolvers = {
  did: { resolve: async (did: string) => vectors.didDocs[did] ?? null },
  secrets: {
    get_secret: async (id: string) => vectors.secrets.find((s) => s.id === id) ?? null,
    find_secrets: async (ids: string[]) => ids.filter((id) => vectors.secrets.some((s) => s.id === id)),
  },
};

describe('pure primitives (known-answer)', () => {
  test('AES-KW 256 (RFC 3394 §4.3)', () => {
    const kek = hex('000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F');
    const wrapped = aeskw(kek).encrypt(hex('00112233445566778899aabbccddeeff'));
    expect(toHex(wrapped)).toBe('64e8c3f9ce0f5ba263e9777905818a2a93c8191e7d6e8ae7');
  });

  test('A256CBC-HS512 (RFC 7518 App. B.3)', () => {
    const key = hex(
      '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f',
    );
    const iv = hex('1af38c2dc2b96ffdd86694092341bc04');
    const aad = utf8('The second principle of Auguste Kerckhoffs');
    const plaintext = utf8(
      'A cipher system must not be required to be secret, and it must be able to fall into the hands of the enemy without inconvenience',
    );
    const sealed = encryptContent('A256CBC-HS512', key, iv, aad, plaintext);
    expect(toHex(sealed.ciphertext) + toHex(sealed.tag)).toBe(
      '4affaaadb78c31c5da4b1b590d10ffbd3dd8d5d302423526912da037ecbcc7bd' +
        '822c301dd67c373bccb584ad3e9279c2e6d12a1374b77f077553df829410446b' +
        '36ebd97066296ae6427ea75c2e0846a11a09ccf5370dc80bfecbad28c73f09b3' +
        'a3b75e662a2594410ae496b2e2e6609e31e6e02cc837f053d21f37ff4f51950b' +
        'be2638d09dd7a4930930806d0703b1f64dd3b4c088a7f45c216839645b2012bf' +
        '2e6269a8c56a816dbc1b267761955bc5',
    );
    expect(decryptContent('A256CBC-HS512', key, iv, aad, sealed)).toEqual(plaintext);
    const forged = { ...sealed, tag: sealed.tag.map((b, i) => (i === 0 ? b ^ 1 : b)) };
    expect(() => decryptContent('A256CBC-HS512', key, iv, aad, forged)).toThrow('authentication failed');
  });

  test('ConcatKDF (askar expected_1pu_output)', () => {
    const z = hex(
      '9e56d91d817135d372834283bf84269cfb316ea3da806a48f6daa7798cfe90c4e3ca3474384c9f62b30bfd4c688b3e7d4110a1b4badc3cc54ef7b81241efd50d',
    );
    expect(toHex(concatKdf(z, 32, utf8('A256GCM'), utf8('Alice'), utf8('Bob')))).toBe(
      '6caf13723d14850ad4b42cd6dde935bffd2fff00a9ba70de05c203a5e1722ca7',
    );
  });

  // draft-madden-jose-ecdh-1pu-04 Appendix B: content first, then the KEK over the tag.
  test('ECDH-1PU X25519 with tag (draft-madden-jose-ecdh-1pu-04 App. B)', () => {
    const alice = privateKeyFromJwk({
      kty: 'OKP',
      crv: 'X25519',
      x: 'Knbm_BcdQr7WIoz-uqit9M0wbcfEr6y-9UfIZ8QnBD4',
      d: 'i9KuFhSzEBsiv3PKVL5115OCdsqQai5nj_Flzfkw5jU',
    });
    const bob = publicKeyFromJwk({ kty: 'OKP', crv: 'X25519', x: 'BT7aR0ItXfeDAldeeOlXL_wXqp-j5FltT0vRSG16kRw' });
    const ephemeral = privateKeyFromJwk({
      kty: 'OKP',
      crv: 'X25519',
      x: 'k9of_cpAajy0poW5gaixXGs9nHkwg1AFqUAFa39dyBc',
      d: 'x8EVZH4Fwk673_mUujnliJoSrLz0zYzzCWp5GUX2fc8',
    });

    const protectedHeader =
      '{"alg":"ECDH-1PU+A128KW","enc":"A256CBC-HS512","apu":"QWxpY2U","apv":"Qm9iIGFuZCBDaGFybGll",' +
      '"epk":{"kty":"OKP","crv":"X25519","x":"k9of_cpAajy0poW5gaixXGs9nHkwg1AFqUAFa39dyBc"}}';
    const cek = hex(
      'fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0',
    );
    const sealed = encryptContent(
      'A256CBC-HS512',
      cek,
      hex('000102030405060708090a0b0c0d0e0f'),
      utf8(b64urlEncode(utf8(protectedHeader))),
      utf8('Three is a magic number.'),
    );
    expect(b64urlEncode(sealed.ciphertext)).toBe('Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw');
    expect(b64urlEncode(sealed.tag)).toBe('HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ');

    // Z = Ze || Zs, ephemeral first.
    const z = new Uint8Array([...ecdh(ephemeral, bob), ...ecdh(alice, bob)]);
    const kek = concatKdf(z, 16, utf8('ECDH-1PU+A128KW'), utf8('Alice'), utf8('Bob and Charlie'), sealed.tag);
    expect(toHex(kek)).toBe('df4c37a0668306a11e3d6b0074b5d8df');
  });

  test('P-256 ECDH matches askar expected_1pu_direct_output', () => {
    const alice = privateKeyFromJwk({
      kty: 'EC',
      crv: 'P-256',
      x: 'WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis',
      y: 'y77t-RvAHRKTsSGdIYUfweuOvwrvDD-Q3Hv5J0fSKbE',
      d: 'Hndv7ZZjs_ke8o9zXYo3iq-Yr8SewI5vrqd0pAvEPqg',
    });
    const bob = publicKeyFromJwk({
      kty: 'EC',
      crv: 'P-256',
      x: 'weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ',
      y: 'e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck',
    });
    const ephemeral = privateKeyFromJwk({
      kty: 'EC',
      crv: 'P-256',
      x: 'gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0',
      y: 'SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps',
      d: '0_NxaRPUMQoAJt50Gz8YiTr8gRTwyEaCumd-MToTmIo',
    });
    const z = new Uint8Array([...ecdh(ephemeral, bob), ...ecdh(alice, bob)]);
    expect(toHex(concatKdf(z, 32, utf8('A256GCM'), utf8('Alice'), utf8('Bob')))).toBe(
      '6caf13723d14850ad4b42cd6dde935bffd2fff00a9ba70de05c203a5e1722ca7',
    );
  });

  test('rejects an EC public key that is not on the curve', () => {
    expect(() =>
      publicKeyFromJwk({
        kty: 'EC',
        crv: 'P-256',
        x: 'WKn-ZIGevcwGIyyrzFoZNBdaq9_TsqzGl96oc0CWuis',
        y: 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA',
      }),
    ).toThrow();
  });
});

describe('pure backend decrypts didcomm-rust test vectors', () => {
  const encryptedNames = Object.keys(vectors.encrypted).filter(
    (name) => 'ciphertext' in (vectors.encrypted[name] as object),
  );

  test.each(encryptedNames)('%s', async (name) => {
    const result = await unpack(JSON.stringify(vectors.encrypted[name]), resolvers);
    expect(result.message).toEqual(vectors.plaintextSimple);
    expect(result.recipientKey.startsWith('did:example:bob#')).toBe(true);
    if (name.includes('AUTH')) expect(result.senderKey?.startsWith('did:example:alice#')).toBe(true);
    else expect(result.senderKey).toBeNull();
  });

  const signed = {
    ...vectors.signed,
    ENCRYPTED_MSG_AUTH_P256_SIGNED: vectors.encrypted.ENCRYPTED_MSG_AUTH_P256_SIGNED,
  };
  test.each(Object.keys(signed))('signed %s (EdDSA / ES256 / ES256K)', async (name) => {
    const result = await unpackSigned(JSON.stringify(signed[name as keyof typeof signed]), resolvers);
    expect(result.message).toEqual(vectors.plaintextSimple);
    expect(result.signedBy.startsWith('did:example:alice#')).toBe(true);
  });

  test.each(Object.keys(vectors.invalidEncrypted))('rejects %s', async (name) => {
    await expect(unpack(JSON.stringify(vectors.invalidEncrypted[name]), resolvers)).rejects.toThrow();
  });

  test('rejects a tampered ciphertext', async () => {
    const jwe = { ...(vectors.encrypted.ENCRYPTED_MSG_AUTH_X25519 as Record<string, string>) };
    jwe.ciphertext = (jwe.ciphertext[0] === 'A' ? 'B' : 'A') + jwe.ciphertext.slice(1);
    await expect(unpack(JSON.stringify(jwe), resolvers)).rejects.toThrow();
  });
});
