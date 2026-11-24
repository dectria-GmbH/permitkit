import { createRequire } from "node:module";
import { types } from "node:util";

import { describe, expect, it } from "vitest";

import { boundedSnapshot, requestBounds, snapshotOf } from "../src/bounds.js";
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
  ["Uint8Array, empty", () => new Uint8Array(0)],
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

/**
 * Built-ins with own keys added by hand. On the portable path the brand checks run only on
 * objects without own keys, so these copy as their own keys there. Node refuses them.
 */
const keyedKinds: readonly (readonly [string, () => object])[] = [
  ["Map with an own key", () => Object.assign(new Map([["a", 1]]), { kind: "all" })],
  ["Date with an own key", () => Object.assign(new Date(0), { kind: "all" })],
  ["Uint8Array with an own key", () => Object.assign(new Uint8Array(2), { kind: "all" })],
];

/** The kinds with their prototype set to Object.prototype and to null. */
function withSwappedPrototypes(
  kinds: readonly (readonly [string, () => object])[],
): (readonly [string, () => object])[] {
  return kinds.flatMap(([kind, make]): (readonly [string, () => object])[] => [
    [`${kind}, Object.prototype`, () => Object.setPrototypeOf(make(), Object.prototype)],
    [`${kind}, null prototype`, () => Object.setPrototypeOf(make(), null)],
  ]);
}

/** The flag that the call sites in bounds.ts and canonical.ts pass to hasInternalSlots. */
function hasOwnKeys(value: object): boolean {
  try {
    return Reflect.ownKeys(value).length > 0;
  } catch {
    // A revoked proxy. The call sites throw before they get here.
    return false;
  }
}

function revokedProxy(): object {
  const { proxy, revoke } = Proxy.revocable({ a: 1 }, {});
  revoke();
  return proxy;
}

const corpus: readonly (readonly [string, () => object])[] = [
  ...withSwappedPrototypes(slotKinds),
  ...withSwappedPrototypes(keyedKinds),
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
      (value) => nodePath?.hasInternalSlots(value, hasOwnKeys(value)),
    );
    expect(node).toEqual(referenceResults());
    // The Node path does not use the own-keys flag.
    for (const flag of [true, false]) {
      const fixed = resultsOf(
        (value) => nodePath?.isProxy(value),
        (value) => nodePath?.hasInternalSlots(value, flag),
      );
      expect({ flag, fixed }).toEqual({ flag, fixed: referenceResults() });
    }
    // Every slot kind is caught today, with either prototype. This guards the corpus itself.
    expect(referenceResults().filter((item) => !item.proxy && !item.slots)).toEqual([]);
  });

  it.runIf(expectedRuntime === "node")("uses the Node path in the module-level checks", () => {
    const active = resultsOf(isProxy, (value) => hasInternalSlots(value, hasOwnKeys(value)));
    expect(active).toEqual(referenceResults());
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
   * - "brand check": portableChecks.hasInternalSlots identifies the built-in. It runs only on
   *   items without own keys.
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
    "RegExp, Object.prototype": "own keys",
    "RegExp, null prototype": "own keys",
    "Promise, Object.prototype": "copies as {}",
    "Promise, null prototype": "copies as {}",
    "ArrayBuffer, Object.prototype": "brand check",
    "ArrayBuffer, null prototype": "brand check",
    "SharedArrayBuffer, Object.prototype": "brand check",
    "SharedArrayBuffer, null prototype": "brand check",
    "Uint8Array, Object.prototype": "copies its data",
    "Uint8Array, null prototype": "copies its data",
    "Float64Array, Object.prototype": "copies its data",
    "Float64Array, null prototype": "copies its data",
    "Uint8Array, empty, Object.prototype": "brand check",
    "Uint8Array, empty, null prototype": "brand check",
    "DataView, Object.prototype": "brand check",
    "DataView, null prototype": "brand check",
    "Number object, Object.prototype": "brand check",
    "Number object, null prototype": "brand check",
    "String object, Object.prototype": "own keys",
    "String object, null prototype": "own keys",
    "Boolean object, Object.prototype": "brand check",
    "Boolean object, null prototype": "brand check",
    "Symbol object, Object.prototype": "brand check",
    "Symbol object, null prototype": "brand check",
    "BigInt object, Object.prototype": "brand check",
    "BigInt object, null prototype": "brand check",
    "Error, Object.prototype": "own keys",
    "Error, null prototype": "own keys",
    "TypeError, Object.prototype": "own keys",
    "TypeError, null prototype": "own keys",
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
    "Map with an own key, Object.prototype": "copies its data",
    "Map with an own key, null prototype": "copies its data",
    "Date with an own key, Object.prototype": "copies its data",
    "Date with an own key, null prototype": "copies its data",
    "Uint8Array with an own key, Object.prototype": "copies its data",
    "Uint8Array with an own key, null prototype": "copies its data",
    "module namespace": "own keys",
    "proxy of a plain object": "copies its data",
    "proxy of an array": "copies its data",
    "proxy of a Map, Object.prototype": "copies as {}",
    "revoked proxy": "throws when read",
  };

  it("brand-checks exactly the listed kinds on the portable path", () => {
    const brand = corpus
      .filter(([, make]) => {
        const value = make();
        return portableChecks.hasInternalSlots(value, hasOwnKeys(value));
      })
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
  const value = make();
  if (portableChecks.hasInternalSlots(value, hasOwnKeys(value))) {
    return !snapshot.ok && code === "not_canonical" ? "brand check" : "brand check not enforced";
  }
  if (!snapshot.ok && code === "not_canonical") {
    if (codeOf(() => Reflect.ownKeys(value)) !== "ok") return "throws when read";
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

describe("built-ins with a swapped prototype and own keys", () => {
  const items: [string, () => object, unknown][] = [
    [
      "Map",
      () =>
        Object.assign(Object.setPrototypeOf(new Map([["a", 1]]), Object.prototype), {
          kind: "all",
        }),
      { kind: "all" },
    ],
    [
      "Date",
      () => Object.assign(Object.setPrototypeOf(new Date(0), null), { kind: "all" }),
      { kind: "all" },
    ],
    [
      "Uint8Array",
      () =>
        Object.assign(Object.setPrototypeOf(new Uint8Array(2), Object.prototype), { kind: "all" }),
      { 0: 0, 1: 0, kind: "all" },
    ],
  ];

  it("are identified by the Node checks and skipped by the portable checks", () => {
    const nodePath = nodeChecks(process);
    for (const [label, make] of items) {
      const value = make();
      expect({ label, node: nodePath?.hasInternalSlots(value, true) }).toEqual({
        label,
        node: true,
      });
      expect({ label, portable: portableChecks.hasInternalSlots(value, true) }).toEqual({
        label,
        portable: false,
      });
    }
  });

  it.runIf(expectedRuntime === "node")("are refused on the Node path", () => {
    for (const [label, make] of items) {
      expect({ label, copy: boundedSnapshot(make(), requestBounds) }).toEqual({
        label,
        copy: undefined,
      });
      expect({ label, code: codeOf(() => canonicalJson(make())) }).toEqual({
        label,
        code: "not_canonical",
      });
    }
  });

  it.runIf(expectedRuntime === "portable")("copy as their own keys on the portable path", () => {
    for (const [label, make, ownData] of items) {
      expect({ label, copy: { ...(boundedSnapshot(make(), requestBounds) as object) } }).toEqual({
        label,
        copy: ownData,
      });
      expect({ label, json: canonicalJson(make()) }).toEqual({
        label,
        json: canonicalJson(ownData),
      });
    }
  });
});

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
        delete partial["isPromise"];
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

  it("takes the Node path when only isExternal is missing, as in Deno", () => {
    const partial: Record<string, unknown> = { ...types };
    delete partial["isExternal"];
    const checks = nodeChecks({ getBuiltinModule: () => ({ types: partial }) });
    expect(checks?.runtime).toBe("node");
    const reference = resultsOf(types.isProxy, referenceHasInternalSlots);
    const results = resultsOf(
      (value) => checks?.isProxy(value),
      (value) => checks?.hasInternalSlots(value, hasOwnKeys(value)),
    );
    expect(results).toEqual(reference);
  });

  it("keeps the checks it captured when util.types is changed later", () => {
    const util: { types: Record<string, unknown> } = { types: { ...types } };
    const checks = nodeChecks({ getBuiltinModule: () => util });
    util.types.isMap = () => false;
    util.types.isProxy = () => false;
    const swapped = Object.setPrototypeOf(new Map(), Object.prototype) as object;
    expect(checks?.hasInternalSlots(swapped, false)).toBe(true);
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
      expect(portableChecks.hasInternalSlots(fake, false)).toBe(false);
      const map = Object.setPrototypeOf(new Map(), Object.prototype) as object;
      expect(portableChecks.hasInternalSlots(map, false)).toBe(true);
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
    expect(portableChecks.hasInternalSlots(trap, false)).toBe(false);
    expect(reads).toBe(0);
  });

  it("treat RegExp.prototype, which has no slot, like Node does", () => {
    // RegExp.prototype has own keys; the flag is false here to reach the brand checks.
    expect(portableChecks.hasInternalSlots(RegExp.prototype, false)).toBe(
      referenceHasInternalSlots(RegExp.prototype),
    );
  });
});
