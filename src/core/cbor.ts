/**
 * Minimal CBOR (RFC 8949) codec for DIDComm envelopes and COSE/EAT tokens.
 *
 * Encoding uses plain major types with shortest-form lengths and no
 * library-specific tags: Uint8Array -> byte string, Map -> map (insertion
 * order), plain object -> text-keyed map, non-integer numbers -> float64.
 *
 * Decoding treats input as untrusted: definite lengths only, bounded depth
 * and item counts, no allocation beyond the remaining input, no duplicate
 * map keys, no trailing bytes. Text-keyed maps decode to plain objects and
 * any other map to `Map`; tags decode to `CborTag`.
 */

export class CborTag {
  constructor(
    readonly tag: number,
    readonly value: unknown,
  ) {}
}

const MAX_DEPTH = 64;
const encoder = new TextEncoder();
const decoder = new TextDecoder('utf-8', { fatal: true });

class Writer {
  private chunks: Uint8Array[] = [];
  private length = 0;

  push(bytes: Uint8Array): void {
    this.chunks.push(bytes);
    this.length += bytes.length;
  }

  head(major: number, value: number | bigint): void {
    const n = BigInt(value);
    const m = major << 5;
    if (n < 24n) this.push(Uint8Array.of(m | Number(n)));
    else if (n < 0x100n) this.push(Uint8Array.of(m | 24, Number(n)));
    else if (n < 0x10000n) this.push(Uint8Array.of(m | 25, Number(n >> 8n), Number(n & 0xffn)));
    else if (n < 0x100000000n) {
      const out = new Uint8Array(5);
      out[0] = m | 26;
      new DataView(out.buffer).setUint32(1, Number(n));
      this.push(out);
    } else if (n < 0x10000000000000000n) {
      const out = new Uint8Array(9);
      out[0] = m | 27;
      new DataView(out.buffer).setBigUint64(1, n);
      this.push(out);
    } else {
      throw new Error('CBOR integer out of range');
    }
  }

  bytes(): Uint8Array {
    const out = new Uint8Array(this.length);
    let offset = 0;
    for (const chunk of this.chunks) {
      out.set(chunk, offset);
      offset += chunk.length;
    }
    return out;
  }
}

function encodeInto(w: Writer, value: unknown, depth: number): void {
  if (depth > MAX_DEPTH) throw new Error('CBOR value nested too deeply');
  if (value === null) return w.push(Uint8Array.of(0xf6));
  if (value === undefined) return w.push(Uint8Array.of(0xf7));
  if (value === false) return w.push(Uint8Array.of(0xf4));
  if (value === true) return w.push(Uint8Array.of(0xf5));
  if (typeof value === 'bigint') return value >= 0n ? w.head(0, value) : w.head(1, -1n - value);
  if (typeof value === 'number') {
    if (Number.isSafeInteger(value)) return value >= 0 ? w.head(0, value) : w.head(1, -1 - value);
    const out = new Uint8Array(9);
    out[0] = 0xfb;
    new DataView(out.buffer).setFloat64(1, value);
    return w.push(out);
  }
  if (typeof value === 'string') {
    const bytes = encoder.encode(value);
    w.head(3, bytes.length);
    return w.push(bytes);
  }
  if (value instanceof Uint8Array) {
    w.head(2, value.length);
    return w.push(value);
  }
  if (value instanceof CborTag) {
    w.head(6, value.tag);
    return encodeInto(w, value.value, depth + 1);
  }
  if (Array.isArray(value)) {
    w.head(4, value.length);
    for (const item of value) encodeInto(w, item, depth + 1);
    return;
  }
  if (value instanceof Map) {
    w.head(5, value.size);
    for (const [k, v] of value) {
      encodeInto(w, k, depth + 1);
      encodeInto(w, v, depth + 1);
    }
    return;
  }
  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).filter(([, v]) => v !== undefined);
    w.head(5, entries.length);
    for (const [k, v] of entries) {
      encodeInto(w, k, depth + 1);
      encodeInto(w, v, depth + 1);
    }
    return;
  }
  throw new Error(`Cannot CBOR-encode a ${typeof value}`);
}

export function encodeCbor(value: unknown): Uint8Array {
  const w = new Writer();
  encodeInto(w, value, 0);
  return w.bytes();
}

class Reader {
  offset = 0;
  constructor(readonly data: Uint8Array) {}

  get remaining(): number {
    return this.data.length - this.offset;
  }

  take(n: number): Uint8Array {
    if (n > this.remaining) throw new Error('Unexpected end of CBOR data');
    const out = this.data.subarray(this.offset, this.offset + n);
    this.offset += n;
    return out;
  }

  view(n: number): DataView {
    const bytes = this.take(n);
    return new DataView(bytes.buffer, bytes.byteOffset, n);
  }

  /** Reads the argument for additional info `info`; returns a bigint so 64-bit values are exact. */
  argument(info: number): bigint {
    if (info < 24) return BigInt(info);
    if (info === 24) return BigInt(this.take(1)[0]);
    if (info === 25) return BigInt(this.view(2).getUint16(0));
    if (info === 26) return BigInt(this.view(4).getUint32(0));
    if (info === 27) return this.view(8).getBigUint64(0);
    if (info === 31) throw new Error('Indefinite-length CBOR items are not supported');
    throw new Error(`Reserved CBOR additional info ${info}`);
  }

  /** A length or count that must be satisfiable from the remaining input (each item is >= 1 byte). */
  count(info: number): number {
    const n = this.argument(info);
    if (n > BigInt(this.remaining)) throw new Error('CBOR length exceeds remaining input');
    return Number(n);
  }
}

function toNumber(n: bigint): number | bigint {
  return n <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(n) : n;
}

function halfToFloat(bits: number): number {
  const exponent = (bits >> 10) & 0x1f;
  const mantissa = bits & 0x3ff;
  const sign = bits & 0x8000 ? -1 : 1;
  if (exponent === 0) return sign * mantissa * 2 ** -24;
  if (exponent === 31) return mantissa ? NaN : sign * Infinity;
  return sign * (1 + mantissa / 1024) * 2 ** (exponent - 15);
}

function decodeItem(r: Reader, depth: number): unknown {
  if (depth > MAX_DEPTH) throw new Error('CBOR value nested too deeply');
  const initial = r.take(1)[0];
  const major = initial >> 5;
  const info = initial & 0x1f;
  switch (major) {
    case 0:
      return toNumber(r.argument(info));
    case 1:
      return toNumber(-1n - r.argument(info));
    case 2:
      return r.take(r.count(info)).slice();
    case 3:
      return decoder.decode(r.take(r.count(info)));
    case 4: {
      const n = r.count(info);
      const items: unknown[] = [];
      for (let i = 0; i < n; i++) items.push(decodeItem(r, depth + 1));
      return items;
    }
    case 5: {
      const n = r.count(info);
      const entries: [unknown, unknown][] = [];
      for (let i = 0; i < n; i++) entries.push([decodeItem(r, depth + 1), decodeItem(r, depth + 1)]);
      if (entries.every(([k]) => typeof k === 'string')) {
        const obj: Record<string, unknown> = {};
        for (const [k, v] of entries) {
          if (Object.prototype.hasOwnProperty.call(obj, k as string)) throw new Error(`Duplicate CBOR map key: ${k}`);
          // defineProperty so a "__proto__" key is data, never a prototype change.
          Object.defineProperty(obj, k as string, { value: v, enumerable: true, writable: true, configurable: true });
        }
        return obj;
      }
      const map = new Map<unknown, unknown>();
      for (const [k, v] of entries) {
        if (map.has(k)) throw new Error('Duplicate CBOR map key');
        map.set(k, v);
      }
      return map;
    }
    case 6: {
      const tag = r.argument(info);
      if (tag > BigInt(Number.MAX_SAFE_INTEGER)) throw new Error('CBOR tag out of range');
      return new CborTag(Number(tag), decodeItem(r, depth + 1));
    }
    default: {
      if (info === 20) return false;
      if (info === 21) return true;
      if (info === 22) return null;
      if (info === 23) return undefined;
      if (info === 25) return halfToFloat(r.view(2).getUint16(0));
      if (info === 26) return r.view(4).getFloat32(0);
      if (info === 27) return r.view(8).getFloat64(0);
      throw new Error(`Unsupported CBOR simple value ${info}`);
    }
  }
}

export function decodeCbor(data: Uint8Array): unknown {
  const r = new Reader(data);
  const value = decodeItem(r, 0);
  if (r.remaining !== 0) throw new Error('Trailing bytes after CBOR item');
  return value;
}
