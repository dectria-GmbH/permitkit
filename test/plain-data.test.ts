import { createRequire } from "node:module";
import { types } from "node:util";

import { describe, expect, it } from "vitest";

import { requestBounds, snapshotOf } from "../src/bounds.js";
import { canonicalJson } from "../src/index.js";
import {
  hasInternalSlots,
  isProxy,
  nodeChecks,
  plainDataRuntime,
  portableChecks,
} from "../src/plain.js";
import { expectedRuntime } from "./runtime.js";

/**
 * The checks of src/plain.ts on origin/main e258cf0, before the portable path. The Node path
 * must give the same result for every item of the corpus.
 */
function referenceHasInternalSlots(value: object): boolean {
  return (
    types.isMap(value) ||
    types.isSet(value) ||
    types.isWeakMap(value) ||
    types.isWeakSet(value) ||
    types.isDate(value) ||
    types.isRegExp(value) ||
    types.isPromise(value) ||
    types.isAnyArrayBuffer(value) ||
    types.isArrayBufferView(value) ||
    types.isBoxedPrimitive(value) ||
    types.isNativeError(value) ||
    types.isGeneratorObject(value) ||
    types.isMapIterator(value) ||
    types.isSetIterator(value) ||
    types.isModuleNamespaceObject(value) ||
    types.isArgumentsObject(value) ||
    types.isExternal(value)
  );
}

function strictArguments(..._items: unknown[]): object {
  // oxlint-disable-next-line prefer-rest-params
  return arguments;
}

/** An arguments object of a sloppy-mode function with every key but the indices deleted. */
function sloppyArgumentsWithIndicesOnly(): object {
  // Only the Function constructor makes a sloppy-mode function inside an ES module.
  // oxlint-disable-next-line no-new-func, typescript/no-implied-eval
  const make = new Function("return arguments") as (...items: unknown[]) => object;
  const value = make(1, 2);
  for (const key of ["length", "callee", Symbol.iterator]) Reflect.deleteProperty(value, key);
  return value;
}

function* generate(): Generator<never> {}

function errorWithoutKeys(): object {
  const error = new Error();
  Reflect.deleteProperty(error, "stack");
  return error;
}

/** One maker per kind that plain.ts caught on origin/main. util.types.isExternal is left out. */
const slotKinds: readonly (readonly [string, () => object])[] = [
  ["Map", () => new Map([["a", 1]])],
  ["Set", () => new Set([1])],
  ["WeakMap", () => new WeakMap()],
  ["WeakSet", () => new WeakSet()],
  ["Date", () => new Date(0)],
  ["RegExp", () => /a/g],
  ["Promise", () => Promise.resolve(1)],
  ["ArrayBuffer", () => new ArrayBuffer(8)],
  ["SharedArrayBuffer", () => new SharedArrayBuffer(8)],
  ["Uint8Array", () => new Uint8Array(4)],
  ["Float64Array", () => new Float64Array(2)],
  ["DataView", () => new DataView(new ArrayBuffer(4))],
  ["Number object", () => Object(1) as object],
  ["String object", () => Object("ab") as object],
  ["Boolean object", () => Object(true) as object],
  ["Symbol object", () => Object(Symbol("s")) as object],
  ["BigInt object", () => Object(1n) as object],
  ["Error", () => new Error("x")],
  ["TypeError", () => new TypeError("x")],
  ["Error without own keys", errorWithoutKeys],
  ["generator object", () => generate()],
  ["Map iterator", () => new Map().keys()],
  ["Set iterator", () => new Set().values()],
  ["arguments, strict", () => strictArguments(1, 2)],
  ["arguments, sloppy, indices only", sloppyArgumentsWithIndicesOnly],
];

function revokedProxy(): object {
  const { proxy, revoke } = Proxy.revocable({ a: 1 }, {});
  revoke();
  return proxy;
}

const corpus: readonly (readonly [string, () => object])[] = [
  ...slotKinds.flatMap(([kind, make]): (readonly [string, () => object])[] => [
    [`${kind}, Object.prototype`, () => Object.setPrototypeOf(make(), Object.prototype)],
    [`${kind}, null prototype`, () => Object.setPrototypeOf(make(), null)],
  ]),
  // A module namespace has a null prototype that cannot be changed.
  ["module namespace", () => moduleNamespace as object],
  ["proxy of a plain object", () => new Proxy({ a: 1 }, {})],
  ["proxy of an array", () => new Proxy([1, 2], {})],
  [
    "proxy of a Map, Object.prototype",
    () => Object.setPrototypeOf(new Proxy(new Map(), {}), Object.prototype),
  ],
  ["revoked proxy", revokedProxy],
];

// A native module namespace. The vitest module runner wraps imports in proxies, so the module is
// loaded with require(), which returns the engine's namespace object for an ES module.
const moduleNamespace: unknown = createRequire(import.meta.url)("./namespace-fixture.mjs");

function resultsOf(proxyCheck: (value: object) => unknown, slotCheck: (value: object) => unknown) {
  return corpus.map(([label, make]) => {
    const value = make();
    return { label, proxy: proxyCheck(value), slots: slotCheck(value) };
  });
}

function referenceResults() {
  return resultsOf(types.isProxy, referenceHasInternalSlots);
}

describe("plain-data checks", () => {
  it("runs on the path that this vitest project forces", () => {
    expect(plainDataRuntime).toBe(expectedRuntime);
  });

  it("gives today's node:util results on the Node path, for every item", () => {
    // Read at test time: the portable project hides getBuiltinModule only while modules load.
    const nodePath = nodeChecks(process);
    expect(nodePath?.runtime).toBe("node");
    const node = resultsOf(
      (value) => nodePath?.isProxy(value),
      (value) => nodePath?.hasInternalSlots(value),
    );
    expect(node).toEqual(referenceResults());
    // Every slot kind is caught today, with either prototype. This guards the corpus itself.
    expect(referenceResults().filter((item) => !item.proxy && !item.slots)).toEqual([]);
  });

  it.runIf(expectedRuntime === "node")("uses the Node path in the module-level checks", () => {
    expect(resultsOf(isProxy, hasInternalSlots)).toEqual(referenceResults());
  });

  it.runIf(expectedRuntime === "node")("refuses every item on the Node path", () => {
    for (const [label, make] of corpus) {
      expect({ label, snapshot: snapshotOf({ nested: make() }, requestBounds) }).toEqual({
        label,
        snapshot: { ok: false, reason: "not_plain" },
      });
      expect({ label, code: codeOf(() => canonicalJson({ nested: make() })) }).toEqual({
        label,
        code: "not_canonical",
      });
    }
  });

  /**
   * Which mechanism handles each item on the portable path:
   * - "brand check": portableChecks.hasInternalSlots identifies the built-in.
   * - "own keys": the item has non-enumerable or symbol own keys, which the size guard and
   *   canonicalJson refuse.
   * - "throws when read": reading the item throws, which both refuse.
   * - "copies as {}": no own keys, the copy is `{}`; the schema decides.
   * - "copies its data": the copy holds the item's own data; the schema decides.
   */
  const portableMechanisms: Record<string, string> = {
    "Map, Object.prototype": "brand check",
    "Map, null prototype": "brand check",
    "Set, Object.prototype": "brand check",
    "Set, null prototype": "brand check",
    "WeakMap, Object.prototype": "brand check",
    "WeakMap, null prototype": "brand check",
    "WeakSet, Object.prototype": "brand check",
    "WeakSet, null prototype": "brand check",
    "Date, Object.prototype": "brand check",
    "Date, null prototype": "brand check",
    "RegExp, Object.prototype": "brand check",
    "RegExp, null prototype": "brand check",
    "Promise, Object.prototype": "copies as {}",
    "Promise, null prototype": "copies as {}",
    "ArrayBuffer, Object.prototype": "brand check",
    "ArrayBuffer, null prototype": "brand check",
    "SharedArrayBuffer, Object.prototype": "brand check",
    "SharedArrayBuffer, null prototype": "brand check",
    "Uint8Array, Object.prototype": "brand check",
    "Uint8Array, null prototype": "brand check",
    "Float64Array, Object.prototype": "brand check",
    "Float64Array, null prototype": "brand check",
    "DataView, Object.prototype": "brand check",
    "DataView, null prototype": "brand check",
    "Number object, Object.prototype": "brand check",
    "Number object, null prototype": "brand check",
    "String object, Object.prototype": "brand check",
    "String object, null prototype": "brand check",
    "Boolean object, Object.prototype": "brand check",
    "Boolean object, null prototype": "brand check",
    "Symbol object, Object.prototype": "brand check",
    "Symbol object, null prototype": "brand check",
    "BigInt object, Object.prototype": "brand check",
    "BigInt object, null prototype": "brand check",
    "Error, Object.prototype": "brand check",
    "Error, null prototype": "brand check",
    "TypeError, Object.prototype": "brand check",
    "TypeError, null prototype": "brand check",
    "Error without own keys, Object.prototype": "brand check",
    "Error without own keys, null prototype": "brand check",
    "generator object, Object.prototype": "copies as {}",
    "generator object, null prototype": "copies as {}",
    "Map iterator, Object.prototype": "copies as {}",
    "Map iterator, null prototype": "copies as {}",
    "Set iterator, Object.prototype": "copies as {}",
    "Set iterator, null prototype": "copies as {}",
    "arguments, strict, Object.prototype": "own keys",
    "arguments, strict, null prototype": "own keys",
    "arguments, sloppy, indices only, Object.prototype": "copies its data",
    "arguments, sloppy, indices only, null prototype": "copies its data",
    "module namespace": "own keys",
    "proxy of a plain object": "copies its data",
    "proxy of an array": "copies its data",
    "proxy of a Map, Object.prototype": "copies as {}",
    "revoked proxy": "throws when read",
  };

  it("brand-checks exactly the listed kinds on the portable path", () => {
    const brand = corpus
      .filter(([, make]) => portableChecks.hasInternalSlots(make()))
      .map(([label]) => label);
    const listed = Object.entries(portableMechanisms)
      .filter(([, mechanism]) => mechanism === "brand check")
      .map(([label]) => label);
    expect(brand).toEqual(listed);
    expect(corpus.filter(([, make]) => portableChecks.isProxy(make()))).toEqual([]);
  });

  it.runIf(expectedRuntime === "portable")("handles each item with the listed mechanism", () => {
    const observed = Object.fromEntries(corpus.map(([label, make]) => [label, mechanismOf(make)]));
    expect(observed).toEqual(portableMechanisms);
  });
});

function mechanismOf(make: () => object): string {
  const snapshot = snapshotOf(make(), requestBounds);
  const code = codeOf(() => canonicalJson(make()));
  if (portableChecks.hasInternalSlots(make())) {
    return !snapshot.ok && code === "not_canonical" ? "brand check" : "brand check not enforced";
  }
  if (!snapshot.ok && code === "not_canonical") {
    if (codeOf(() => Reflect.ownKeys(make())) !== "ok") return "throws when read";
    const value = make();
    return Reflect.ownKeys(value).length === Object.keys(value).length ? "unexplained" : "own keys";
  }
  if (snapshot.ok && code === "ok") {
    return JSON.stringify(snapshot.value) === "{}" ? "copies as {}" : "copies its data";
  }
  return `inconsistent: ${JSON.stringify({ snapshot, code })}`;
}

function codeOf(run: () => unknown): unknown {
  try {
    run();
    return "ok";
  } catch (error) {
    return error instanceof Error && "code" in error ? error.code : "raw error";
  }
}

describe("nodeChecks with an untrusted host", () => {
  const hosts: [string, () => unknown][] = [
    ["absent", () => undefined],
    ["null", () => null],
    ["no getBuiltinModule", () => ({})],
    ["getBuiltinModule not a function", () => ({ getBuiltinModule: 1 })],
    [
      "getBuiltinModule throws",
      () => ({
        getBuiltinModule() {
          throw new Error("boom");
        },
      }),
    ],
    [
      "throwing getter",
      () => ({
        get getBuiltinModule(): never {
          throw new Error("boom");
        },
      }),
    ],
    ["returns null", () => ({ getBuiltinModule: () => null })],
    ["returns no types", () => ({ getBuiltinModule: () => ({}) })],
    [
      "returns a types object with a check missing",
      () => {
        const partial: Record<string, unknown> = { ...types };
        delete partial["isExternal"];
        return { getBuiltinModule: () => ({ types: partial }) };
      },
    ],
    [
      "returns stubs that answer false",
      () => {
        const stubs = Object.fromEntries(Object.keys(types).map((name) => [name, () => false]));
        return { getBuiltinModule: () => ({ types: stubs }) };
      },
    ],
    [
      "a proxy whose every read throws",
      () =>
        new Proxy(
          {},
          {
            get() {
              throw new Error("boom");
            },
          },
        ),
    ],
  ];

  it("falls back to the portable path instead of throwing", () => {
    for (const [label, make] of hosts) {
      expect({ label, checks: nodeChecks(make()) }).toEqual({ label, checks: undefined });
    }
  });

  it("keeps the checks it captured when util.types is changed later", () => {
    const util: { types: Record<string, unknown> } = { types: { ...types } };
    const checks = nodeChecks({ getBuiltinModule: () => util });
    util.types.isMap = () => false;
    util.types.isProxy = () => false;
    const swapped = Object.setPrototypeOf(new Map(), Object.prototype) as object;
    expect(checks?.hasInternalSlots(swapped)).toBe(true);
    expect(checks?.isProxy(new Proxy({}, {}))).toBe(true);
  });
});

describe("portable brand checks", () => {
  it("are not changed by a later replacement of the prototype functions", () => {
    const original = Object.getOwnPropertyDescriptor(Map.prototype, "size");
    if (original === undefined) throw new Error("Map.prototype.size is missing");
    try {
      // oxlint-disable-next-line no-extend-native
      Object.defineProperty(Map.prototype, "size", { get: () => 0, configurable: true });
      const fake = Object.setPrototypeOf({}, Object.prototype) as object;
      expect(portableChecks.hasInternalSlots(fake)).toBe(false);
      const map = Object.setPrototypeOf(new Map(), Object.prototype) as object;
      expect(portableChecks.hasInternalSlots(map)).toBe(true);
    } finally {
      // oxlint-disable-next-line no-extend-native
      Object.defineProperty(Map.prototype, "size", original);
    }
  });

  it("run no caller code", () => {
    let reads = 0;
    const trap = new Proxy(
      {},
      {
        get(target, key, receiver) {
          reads += 1;
          return Reflect.get(target, key, receiver) as unknown;
        },
        getPrototypeOf() {
          reads += 1;
          return Object.prototype;
        },
        ownKeys() {
          reads += 1;
          return [];
        },
        getOwnPropertyDescriptor() {
          reads += 1;
          return undefined;
        },
      },
    );
    expect(portableChecks.hasInternalSlots(trap)).toBe(false);
    expect(reads).toBe(0);
  });

  it("treat RegExp.prototype, which has no slot, like Node does", () => {
    expect(portableChecks.hasInternalSlots(RegExp.prototype)).toBe(
      referenceHasInternalSlots(RegExp.prototype),
    );
  });
});
