/**
 * SHA-256 (FIPS 180-4) in plain TypeScript. permitkit runs in runtimes without `node:crypto`,
 * and Web Crypto `digest()` is asynchronous, so a decision could no longer be a synchronous
 * call. The input sizes are bounded (see bounds.ts), so a table-free implementation is fast
 * enough.
 *
 * Every built-in that a call uses is captured when the module loads: caller code that replaces
 * a prototype method later (String.prototype.charAt, TypedArray.prototype.set, Reflect.apply)
 * would otherwise change every digest, and approvals bind to the request digest.
 */

const apply = Reflect.apply;
const floor = Math.floor;
const ByteArray = Uint8Array;
const WordArray = Int32Array;
// The length getter of all typed arrays, read through %TypedArray%.prototype.
const typedArrayLength: unknown = Reflect.getOwnPropertyDescriptor(
  Reflect.getPrototypeOf(Uint8Array.prototype) ?? {},
  "length",
)?.get;

const roundConstants = Int32Array.from([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]);

const initialState = [
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

// Captured once, so a later change to TextEncoder.prototype cannot change the encoding.
const encoder = new TextEncoder();
// Called with Reflect.apply on `encoder`, never unbound.
// oxlint-disable-next-line typescript/unbound-method
const encode = TextEncoder.prototype.encode;

const hexDigits = "0123456789abcdef";
/** Two hex digits per byte value, built once with string indexing only. */
const hexOfByte: string[] = [];
for (let value = 0; value < 256; value += 1) {
  hexOfByte.push(`${hexDigits[value >>> 4] ?? ""}${hexDigits[value & 15] ?? ""}`);
}

function lengthOf(bytes: Uint8Array): number {
  if (typeof typedArrayLength !== "function") throw new TypeError("No typed array length getter.");
  const length: unknown = apply(typedArrayLength, bytes, []);
  if (typeof length !== "number") throw new TypeError("Not a typed array.");
  return length;
}

/** Lowercase hex SHA-256 over the UTF-8 encoding of a string. Lone surrogates become U+FFFD. */
export function sha256Hex(text: string): string {
  return sha256HexOfBytes(apply(encode, encoder, [text]));
}

/** Lowercase hex SHA-256 over bytes. */
export function sha256HexOfBytes(bytes: Uint8Array): string {
  const length = lengthOf(bytes);
  // The message, one 0x80 byte, zero padding and the 64-bit length fill whole 64-byte blocks.
  const end = (((length + 8) >>> 6) + 1) << 6;
  const padded = new ByteArray(end);
  for (let index = 0; index < length; index += 1) padded[index] = bytes[index] ?? 0;
  padded[length] = 0x80;
  const bitLengthHigh = floor(length / 0x20000000);
  const bitLengthLow = (length << 3) >>> 0;
  writeWord(padded, end - 8, bitLengthHigh);
  writeWord(padded, end - 4, bitLengthLow);

  const state = new WordArray(8);
  for (let index = 0; index < 8; index += 1) state[index] = initialState[index] ?? 0;
  const schedule = new WordArray(64);
  for (let offset = 0; offset < end; offset += 64) compress(state, schedule, padded, offset);

  let hex = "";
  for (let index = 0; index < 8; index += 1) {
    const word = state[index] ?? 0;
    for (let shift = 24; shift >= 0; shift -= 8) hex += hexOfByte[(word >>> shift) & 255] ?? "";
  }
  return hex;
}

function writeWord(target: Uint8Array, offset: number, word: number): void {
  target[offset] = word >>> 24;
  target[offset + 1] = word >>> 16;
  target[offset + 2] = word >>> 8;
  target[offset + 3] = word;
}

function rotateRight(word: number, count: number): number {
  return (word >>> count) | (word << (32 - count));
}

function compress(
  state: Int32Array,
  schedule: Int32Array,
  block: Uint8Array,
  offset: number,
): void {
  for (let index = 0; index < 16; index += 1) {
    const at = offset + index * 4;
    schedule[index] =
      ((block[at] ?? 0) << 24) |
      ((block[at + 1] ?? 0) << 16) |
      ((block[at + 2] ?? 0) << 8) |
      (block[at + 3] ?? 0);
  }
  for (let index = 16; index < 64; index += 1) {
    const back15 = schedule[index - 15] ?? 0;
    const back2 = schedule[index - 2] ?? 0;
    const sigma0 = rotateRight(back15, 7) ^ rotateRight(back15, 18) ^ (back15 >>> 3);
    const sigma1 = rotateRight(back2, 17) ^ rotateRight(back2, 19) ^ (back2 >>> 10);
    schedule[index] =
      ((schedule[index - 16] ?? 0) + sigma0 + (schedule[index - 7] ?? 0) + sigma1) | 0;
  }

  let a = state[0] ?? 0;
  let b = state[1] ?? 0;
  let c = state[2] ?? 0;
  let d = state[3] ?? 0;
  let e = state[4] ?? 0;
  let f = state[5] ?? 0;
  let g = state[6] ?? 0;
  let h = state[7] ?? 0;
  for (let index = 0; index < 64; index += 1) {
    const sum1 = rotateRight(e, 6) ^ rotateRight(e, 11) ^ rotateRight(e, 25);
    const choice = (e & f) ^ (~e & g);
    const temp1 = (h + sum1 + choice + (roundConstants[index] ?? 0) + (schedule[index] ?? 0)) | 0;
    const sum0 = rotateRight(a, 2) ^ rotateRight(a, 13) ^ rotateRight(a, 22);
    const majority = (a & b) ^ (a & c) ^ (b & c);
    const temp2 = (sum0 + majority) | 0;
    h = g;
    g = f;
    f = e;
    e = (d + temp1) | 0;
    d = c;
    c = b;
    b = a;
    a = (temp1 + temp2) | 0;
  }
  state[0] = ((state[0] ?? 0) + a) | 0;
  state[1] = ((state[1] ?? 0) + b) | 0;
  state[2] = ((state[2] ?? 0) + c) | 0;
  state[3] = ((state[3] ?? 0) + d) | 0;
  state[4] = ((state[4] ?? 0) + e) | 0;
  state[5] = ((state[5] ?? 0) + f) | 0;
  state[6] = ((state[6] ?? 0) + g) | 0;
  state[7] = ((state[7] ?? 0) + h) | 0;
}
