import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import { canonicalJson, digest, PermitkitError } from "../src/index.js";

/**
 * canonicalJson and digest must not change when caller code replaces a built-in after load:
 * approvals bind to the request digest. Each replacement below is applied alone, the results are
 * collected without arrays or iterators (some replacements break them), then it is restored.
 */

const getDescriptor = Reflect.getOwnPropertyDescriptor;
const define = Reflect.defineProperty;
const remove = Reflect.deleteProperty;
const sha256 = (text: string): string => createHash("sha256").update(text).digest("hex");

const value = { b: [1, "x", { d: null, c: true }], a: "é" };
const valueJson = '{"a":"é","b":[1,"x",{"c":true,"d":null}]}';
// Reproduced in review: a patched toSorted that drops keys gave these two the same digest.
const first = { id: "r1", amount: 10 };
const second = { id: "r2", amount: 999_999 };
const firstJson = '{"amount":10,"id":"r1"}';
const secondJson = '{"amount":999999,"id":"r2"}';

function holed(): unknown[] {
  const items: unknown[] = [1];
  items[2] = 3;
  return items;
}

const cyclic: Record<string, unknown> = { a: 1 };
cyclic["self"] = cyclic;
/** Inputs that the code before this change also refuses with not_canonical. */
const refused: Record<string, unknown> = {
  swappedMap: Object.setPrototypeOf(new Map([["a", 1]]), Object.prototype),
  infinity: { a: Infinity },
  cyclic,
  symbolKey: { a: 1, [Symbol("s")]: 2 },
  getter: Object.defineProperty({}, "a", { enumerable: true, get: () => 1 }),
  hole: holed(),
};

function codeOf(call: () => unknown): string {
  try {
    call();
    return "ok";
  } catch (error) {
    return error instanceof PermitkitError ? error.code : "raw error";
  }
}

function notAConstructor(): void {}

interface Observed {
  value: string;
  valueDigest: string;
  first: string;
  second: string;
  firstDigest: string;
  secondDigest: string;
  swappedMap: string;
  infinity: string;
  cyclic: string;
  symbolKey: string;
  getter: string;
  hole: string;
}

function run(make: () => string): string {
  try {
    return make();
  } catch (error) {
    return error instanceof PermitkitError ? error.code : "raw error";
  }
}

function observe(): Observed {
  return {
    value: run(() => canonicalJson(value)),
    valueDigest: run(() => digest(value)),
    first: run(() => canonicalJson(first)),
    second: run(() => canonicalJson(second)),
    firstDigest: run(() => digest(first)),
    secondDigest: run(() => digest(second)),
    swappedMap: codeOf(() => canonicalJson(refused["swappedMap"])),
    infinity: codeOf(() => canonicalJson(refused["infinity"])),
    cyclic: codeOf(() => canonicalJson(refused["cyclic"])),
    symbolKey: codeOf(() => canonicalJson(refused["symbolKey"])),
    getter: codeOf(() => canonicalJson(refused["getter"])),
    hole: codeOf(() => canonicalJson(refused["hole"])),
  };
}

const expected: Observed = {
  value: valueJson,
  valueDigest: sha256(valueJson),
  first: firstJson,
  second: secondJson,
  firstDigest: sha256(firstJson),
  secondDigest: sha256(secondJson),
  swappedMap: "not_canonical",
  infinity: "not_canonical",
  cyclic: "not_canonical",
  symbolKey: "not_canonical",
  getter: "not_canonical",
  hole: "not_canonical",
};

/** Replaces one property while `observe` runs, then restores it, also if it was inherited. */
function observeWith(target: object, key: PropertyKey, replacement: PropertyDescriptor): Observed {
  const original = getDescriptor(target, key);
  if (!define(target, key, { ...replacement, configurable: true })) {
    throw new Error(`could not replace ${String(key)}`);
  }
  try {
    return observe();
  } finally {
    if (original === undefined) remove(target, key);
    else define(target, key, original);
  }
}

// oxlint-disable-next-line typescript/unbound-method
const realToSorted = Array.prototype.toSorted;
const replacements: [string, object, PropertyKey, PropertyDescriptor][] = [
  ["JSON.stringify", JSON, "stringify", { value: () => '"x"' }],
  ["Object.keys", Object, "keys", { value: () => [] }],
  ["Reflect.ownKeys", Reflect, "ownKeys", { value: () => [] }],
  [
    "Reflect.getOwnPropertyDescriptor",
    Reflect,
    "getOwnPropertyDescriptor",
    { value: () => ({ value: 1 }) },
  ],
  ["Reflect.apply", Reflect, "apply", { value: () => undefined }],
  ["Object.getPrototypeOf", Object, "getPrototypeOf", { value: () => Object.prototype }],
  ["Object.hasOwn", Object, "hasOwn", { value: () => true }],
  ["Array.isArray", Array, "isArray", { value: () => false }],
  ["Number.isFinite", Number, "isFinite", { value: () => true }],
  [
    "Array.prototype.toSorted (drops keys)",
    Array.prototype,
    "toSorted",
    {
      value(this: string[], compare: (left: string, right: string) => number) {
        const sorted: string[] = Reflect.apply(realToSorted, this, [compare]);
        return sorted.filter((key) => key !== "id" && key !== "amount");
      },
    },
  ],
  ["Array.prototype.join", Array.prototype, "join", { value: () => "" }],
  ["Array.prototype.push", Array.prototype, "push", { value: () => 0 }],
  [
    "Array.prototype[Symbol.iterator]",
    Array.prototype,
    Symbol.iterator,
    {
      *value() {
        // An empty iterator: for-of over any array sees no items.
      },
    },
  ],
  ["Array.prototype[0] accessor", Array.prototype, "0", { get: () => "x", set: () => undefined }],
  ["Set.prototype.has", Set.prototype, "has", { value: () => true }],
  ["Set.prototype.add", Set.prototype, "add", { value: () => undefined }],
  ["Set.prototype.delete", Set.prototype, "delete", { value: () => false }],
  ["globalThis.Set", globalThis, "Set", { value: notAConstructor }],
  ["globalThis.String", globalThis, "String", { value: () => "0" }],
  ["Function.prototype.call", Function.prototype, "call", { value: () => undefined }],
  ["Function.prototype.apply", Function.prototype, "apply", { value: () => undefined }],
];

describe("canonicalJson with built-ins replaced after load", () => {
  it("gives the reference result before any replacement", () => {
    expect(observe()).toEqual(expected);
  });

  it("gives the reference result and the same refusals with each one replaced", () => {
    const results: Record<string, Observed> = {};
    for (let index = 0; index < replacements.length; index += 1) {
      const [label, target, key, replacement] = replacements[index] ?? [];
      if (label === undefined || target === undefined || key === undefined) continue;
      results[label] = observeWith(target, key, replacement ?? {});
    }
    const expectedAll = Object.fromEntries(replacements.map(([label]) => [label, expected]));
    expect(results).toEqual(expectedAll);
  });
});
