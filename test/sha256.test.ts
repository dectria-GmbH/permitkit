import { createHash } from "node:crypto";

import * as fc from "fast-check";
import { describe, expect, it } from "vitest";

import { canonicalJson, digest } from "../src/index.js";
import { sha256Hex, sha256HexOfBytes } from "../src/sha256.js";
import { digestCorpus } from "./digest-corpus.js";

const nodeSha256 = (input: string | Uint8Array): string =>
  createHash("sha256").update(input).digest("hex");

const propertyTimeout = { timeout: 60_000 };

describe("sha256Hex", propertyTimeout, () => {
  it("matches the FIPS 180-4 example vectors", () => {
    expect(sha256Hex("")).toBe("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    expect(sha256Hex("abc")).toBe(
      "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
    expect(sha256Hex("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")).toBe(
      "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    );
    expect(sha256Hex("a".repeat(1_000_000))).toBe(
      "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0",
    );
  });

  it("matches node:crypto around the 55, 56 and 64 byte padding edges", () => {
    for (const length of [0, 1, 54, 55, 56, 57, 62, 63, 64, 65, 119, 120, 127, 128, 129]) {
      const text = "x".repeat(length);
      expect({ length, hex: sha256Hex(text) }).toEqual({ length, hex: nodeSha256(text) });
      const bytes = Uint8Array.from({ length }, (_, index) => (index * 37 + 11) & 0xff);
      expect({ length, hex: sha256HexOfBytes(bytes) }).toEqual({ length, hex: nodeSha256(bytes) });
    }
  });

  it("encodes a lone surrogate as U+FFFD, like node:crypto", () => {
    expect(sha256Hex("\ud800")).toBe(sha256Hex("�"));
    expect(sha256Hex("a\udc00b")).toBe(nodeSha256("a\udc00b"));
  });

  it("equals node:crypto for arbitrary strings and bytes", () => {
    const codeUnit = fc.integer({ min: 0, max: 0xffff }).map((unit) => String.fromCharCode(unit));
    const text = fc.oneof(
      fc.string({ unit: "binary", maxLength: 300 }),
      fc.string({ unit: codeUnit, maxLength: 300 }),
      fc.string({ unit: "grapheme", maxLength: 100 }),
    );
    fc.assert(
      fc.property(text, (value) => {
        expect(sha256Hex(value)).toBe(nodeSha256(value));
      }),
      { numRuns: 2_000 },
    );
    fc.assert(
      fc.property(fc.uint8Array({ maxLength: 300 }), (bytes) => {
        expect(sha256HexOfBytes(bytes)).toBe(nodeSha256(bytes));
      }),
      { numRuns: 500 },
    );
  });
});

describe("digest", propertyTimeout, () => {
  it("equals node:crypto over the canonical JSON form", () => {
    fc.assert(
      fc.property(fc.jsonValue(), (value) => {
        expect(digest(value)).toBe(nodeSha256(canonicalJson(value)));
      }),
      { numRuns: 500 },
    );
  });

  it("gives the digests of the node:crypto implementation for a fixed corpus", () => {
    // Produced on origin/main e258cf0 (createHash from node:crypto) from test/digest-corpus.ts.
    const expected: Record<string, string> = {
      "catalogue digest": "946f66e520e46f04e9c5ee9411b4220e13d8d395b3298327c910f09978820c37",
      "policy digest": "66a0dae3913f874895f0540a44d2bee42ebb090aa91e9e8b8bf92c8dd3ad0799",
      "request, direct": "a05b4769700bbe2a589b13e1099cdafb0f943a0d528c33407efa7cc49dafb904",
      "request, agent chain": "48fbaaf57ca438c3edba3ebf1f4888587a51d232e0ccd45bd30e7f75faf5fe2b",
      "request, non-ASCII": "424dd3807a6953132363a9c7fa8e5043be1c541e3a54039f0b7ff46b193d58f3",
      "request, astral characters":
        "87bb2db6de2fb505eaf7311c6d81e0cd42c319ac85993069505358fac72d56c2",
      "request, 4,096-char string":
        "4d8f4b5060237c719fb9794483a2697b8f035dce4e3ea75e8812d3cbe5ab60be",
      "request, lone surrogate": "a4311d197d8260ce0efafa9176d2c465f29ae0ae6069f37dbbe91b67cf26f170",
      "value, empty string": "12ae32cb1ec02d01eda3581b127c1fee3b0dc53572ed6baf239721a03d82e126",
      "value, lone surrogates": "ede93dd833f0d0bb3960de2787f3b08ae1cd205844e30d41573291286c349f1d",
      "value, nested keys": "590c68a5d2bceeaae497dba2a52778752e36f2b3be51fdaccb84608b7a262c66",
    };
    expect(Object.fromEntries(digestCorpus.map(([label, run]) => [label, run()]))).toEqual(
      expected,
    );
  });
});
