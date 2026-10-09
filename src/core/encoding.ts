/** JSON/CBOR envelope encoding shared by both crypto backends. */

import { decode as cborDecode, encode as cborEncode } from 'cbor-x';
import type { EnvelopeEncoding } from './types.js';

export function encodeEnvelope(packedJson: string, encoding: EnvelopeEncoding): string | Uint8Array {
  if (encoding === 'json') return packedJson;
  const asObject = JSON.parse(packedJson);
  return Uint8Array.from(cborEncode(asObject));
}

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

export function toPackedJson(envelope: string | Uint8Array, encoding: EnvelopeEncoding): string {
  if (encoding === 'json') {
    return typeof envelope === 'string' ? envelope : Buffer.from(envelope).toString('utf8');
  }
  const bytes = envelope instanceof Uint8Array ? envelope : Buffer.from(envelope as string, 'utf8');
  const decoded = cborDecode(bytes);
  return JSON.stringify(decoded);
}
