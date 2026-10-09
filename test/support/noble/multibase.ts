/** Multibase (base58btc `z...`) + multicodec public-key decoding, per the DID Core Multikey format. */

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
/** Multikey values are short; bound the BigInt work on untrusted input. */
const MAX_MULTIBASE_LENGTH = 256;

// Multicodec varints, per https://github.com/multiformats/multicodec/blob/master/table.csv
const CODECS = [
  { codec: 'x25519', prefix: [0xec, 0x01] },
  { codec: 'ed25519', prefix: [0xed, 0x01] },
] as const;

export type MultikeyCodec = (typeof CODECS)[number]['codec'];

function base58btcDecode(input: string): Uint8Array {
  let num = 0n;
  for (const char of input) {
    const index = BASE58_ALPHABET.indexOf(char);
    if (index === -1) throw new Error(`invalid base58 character: ${char}`);
    num = num * 58n + BigInt(index);
  }
  const bytes: number[] = [];
  while (num > 0n) {
    bytes.unshift(Number(num % 256n));
    num /= 256n;
  }
  let leadingOnes = 0;
  while (input[leadingOnes] === '1') leadingOnes++;
  return new Uint8Array([...new Array<number>(leadingOnes).fill(0), ...bytes]);
}

export function decodeMultibaseKey(value: string): { codec: MultikeyCodec; publicKeyBytes: Uint8Array } {
  if (!value.startsWith('z')) throw new Error(`unsupported multibase prefix in multikey value: ${value}`);
  if (value.length > MAX_MULTIBASE_LENGTH) throw new Error('multikey value too long');
  const decoded = base58btcDecode(value.slice(1));
  for (const { codec, prefix } of CODECS) {
    if (prefix.every((byte, i) => decoded[i] === byte)) {
      return { codec, publicKeyBytes: decoded.slice(prefix.length) };
    }
  }
  throw new Error(`unsupported multicodec prefix in multikey value: ${value}`);
}
