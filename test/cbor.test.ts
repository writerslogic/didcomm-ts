import { decode as cborxDecode } from 'cbor-x';
import { CborTag, decodeCbor, encodeCbor } from '../src/core/cbor.js';
import { encodeEnvelope, toPackedJson } from '../src/core/encoding.js';

const hex = (s: string) => Uint8Array.from(Buffer.from(s, 'hex'));
const toHex = (b: Uint8Array) => Buffer.from(b).toString('hex');

// RFC 8949 Appendix A (subset covering every major type and length width).
const VECTORS: Array<[unknown, string]> = [
  [0, '00'],
  [23, '17'],
  [24, '1818'],
  [100, '1864'],
  [1000, '1903e8'],
  [1000000, '1a000f4240'],
  [1000000000000, '1b000000e8d4a51000'],
  [18446744073709551615n, '1bffffffffffffffff'],
  [-1, '20'],
  [-100, '3863'],
  [-1000, '3903e7'],
  [1.1, 'fb3ff199999999999a'],
  [false, 'f4'],
  [true, 'f5'],
  [null, 'f6'],
  [new Uint8Array([1, 2, 3, 4]), '4401020304'],
  ['', '60'],
  ['IETF', '6449455446'],
  ['ü', '62c3bc'],
  [[], '80'],
  [[1, [2, 3], [4, 5]], '8301820203820405'],
  [{}, 'a0'],
  [new Map([[1, 2], [3, 4]]), 'a201020304'],
  [{ a: 1, b: [2, 3] }, 'a26161016162820203'],
  [new CborTag(18, [1]), 'd28101'],
];

test.each(VECTORS)('RFC 8949 vector %p', (value, encoded) => {
  expect(toHex(encodeCbor(value))).toBe(encoded);
  expect(decodeCbor(hex(encoded))).toEqual(value);
});

test.each([
  ['f93c00', 1],
  ['f97c00', Infinity],
  ['fa47c35000', 100000],
])('decodes non-preferred float %s', (encoded, value) => {
  expect(decodeCbor(hex(encoded))).toBe(value);
});

test.each([
  ['truncated byte string', '45010203'],
  ['length beyond input (no huge allocation)', '5bffffffffffffffff'],
  ['array count beyond input', '9bffffffffffffffff'],
  ['indefinite length', '5f4101ff'],
  ['reserved additional info', '1c'],
  ['trailing bytes', '0000'],
  ['duplicate text key', 'a2616101616102'],
  ['duplicate int key', 'a201010102'],
  ['empty input', ''],
])('rejects %s', (_name, encoded) => {
  expect(() => decodeCbor(hex(encoded))).toThrow();
});

test('rejects nesting deeper than the limit', () => {
  expect(() => decodeCbor(new Uint8Array(200).fill(0x81))).toThrow('nested too deeply');
});

test('"__proto__" keys stay data', () => {
  const decoded = decodeCbor(encodeCbor(JSON.parse('{"__proto__":{"polluted":1}}'))) as Record<string, unknown>;
  expect(Object.getPrototypeOf(decoded)).toBe(Object.prototype);
  expect(({} as Record<string, unknown>).polluted).toBeUndefined();
  expect(Object.keys(decoded)).toEqual(['__proto__']);
});

test('CBOR envelopes are plain RFC 8949 that another decoder (cbor-x) reads identically', () => {
  const jwe = { protected: 'eyJ0eXAiOiJ4In0', recipients: [{ header: { kid: 'did:example:bob#k1' }, encrypted_key: 'abc' }], iv: 'aa', ciphertext: 'bb', tag: 'cc' };
  const bytes = encodeEnvelope(JSON.stringify(jwe), 'cbor') as Uint8Array;
  expect(cborxDecode(bytes)).toEqual(jwe);
  expect(JSON.parse(toPackedJson(bytes, 'cbor'))).toEqual(jwe);
});

test('CBOR envelopes with non-JSON values are rejected', () => {
  expect(() => toPackedJson(encodeCbor({ iv: new Uint8Array([1]) }), 'cbor')).toThrow('no JSON equivalent');
});
