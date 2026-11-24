import { createRequire } from "node:module";
import { types } from "node:util";

import { describe, expect, it } from "vitest";

import { boundedSnapshot, requestBounds, snapshotOf } from "../src/bounds.js";
import { canonicalJson, decide, type AccessRequest, type Scope } from "../src/index.js";
import {
  hasInternalSlots,
  isProxy,
  nodeChecks,
  plainDataRuntime,
  portableChecks,
} from "../src/plain.js";
import { accessRequest, everywhere, human, role } from "../src/testing/index.js";
import { policy } from "./fixtures.js";
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
 * Built-ins with own keys added by hand. The portable path has no check for a Map or Date, so
 * they copy as their own keys there. Typed arrays, DataViews and errors are still refused: their
 * checks never throw and run on every object. Node refuses all of them.
 */
const keyedKinds: readonly (readonly [string, () => object])[] = [
  ["Map with an own key", () => Object.assign(new Map([["a", 1]]), { kind: "all" })],
  ["Date with an own key", () => Object.assign(new Date(0), { kind: "all" })],
  ["Uint8Array with an own key", () => Object.assign(new Uint8Array(2), { kind: "all" })],
  ["DataView with an own key", () => Object.assign(new DataView(new ArrayBuffer(2)), { a: 1 })],
  ["Error with an own key", () => Object.assign(errorWithoutKeys(), { kind: "all" })],
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
      (value) => nodePath?.hasInternalSlots(value),
    );
    expect(node).toEqual(referenceResults());
    // Every slot kind is caught today, with either prototype. This guards the corpus itself.
    expect(referenceResults().filter((item) => !item.proxy && !item.slots)).toEqual([]);
  });

  it.runIf(expectedRuntime === "node")("uses the Node path in the module-level checks", () => {
    const active = resultsOf(isProxy, hasInternalSlots);
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
   * - "slot check": portableChecks.hasInternalSlots identifies the built-in, by ArrayBuffer.isView,
   *   Error.isError or a non-enumerable own `length`.
   * - "own keys": the item has non-enumerable or symbol own keys, which the size guard and
   *   canonicalJson refuse.
   * - "throws when read": reading the item throws, which both refuse.
   * - "copies as {}": no own keys, the copy is `{}`; the schema decides.
   * - "copies its data": the copy holds the item's own data; the schema decides.
   */
  const portableMechanisms: Record<string, string> = {
    "Map, Object.prototype": "copies as {}",
    "Map, null prototype": "copies as {}",
    "Set, Object.prototype": "copies as {}",
    "Set, null prototype": "copies as {}",
    "WeakMap, Object.prototype": "copies as {}",
    "WeakMap, null prototype": "copies as {}",
    "WeakSet, Object.prototype": "copies as {}",
    "WeakSet, null prototype": "copies as {}",
    "Date, Object.prototype": "copies as {}",
    "Date, null prototype": "copies as {}",
    "RegExp, Object.prototype": "own keys",
    "RegExp, null prototype": "own keys",
    "Promise, Object.prototype": "copies as {}",
    "Promise, null prototype": "copies as {}",
    "ArrayBuffer, Object.prototype": "copies as {}",
    "ArrayBuffer, null prototype": "copies as {}",
    "SharedArrayBuffer, Object.prototype": "copies as {}",
    "SharedArrayBuffer, null prototype": "copies as {}",
    "Uint8Array, Object.prototype": "slot check",
    "Uint8Array, null prototype": "slot check",
    "Float64Array, Object.prototype": "slot check",
    "Float64Array, null prototype": "slot check",
    "Uint8Array, empty, Object.prototype": "slot check",
    "Uint8Array, empty, null prototype": "slot check",
    "DataView, Object.prototype": "slot check",
    "DataView, null prototype": "slot check",
    "Number object, Object.prototype": "copies as {}",
    "Number object, null prototype": "copies as {}",
    "String object, Object.prototype": "slot check",
    "String object, null prototype": "slot check",
    "Boolean object, Object.prototype": "copies as {}",
    "Boolean object, null prototype": "copies as {}",
    "Symbol object, Object.prototype": "copies as {}",
    "Symbol object, null prototype": "copies as {}",
    "BigInt object, Object.prototype": "copies as {}",
    "BigInt object, null prototype": "copies as {}",
    "Error, Object.prototype": "slot check",
    "Error, null prototype": "slot check",
    "TypeError, Object.prototype": "slot check",
    "TypeError, null prototype": "slot check",
    "Error without own keys, Object.prototype": "slot check",
    "Error without own keys, null prototype": "slot check",
    "generator object, Object.prototype": "copies as {}",
    "generator object, null prototype": "copies as {}",
    "Map iterator, Object.prototype": "copies as {}",
    "Map iterator, null prototype": "copies as {}",
    "Set iterator, Object.prototype": "copies as {}",
    "Set iterator, null prototype": "copies as {}",
    "arguments, strict, Object.prototype": "slot check",
    "arguments, strict, null prototype": "slot check",
    "arguments, sloppy, indices only, Object.prototype": "copies its data",
    "arguments, sloppy, indices only, null prototype": "copies its data",
    "Map with an own key, Object.prototype": "copies its data",
    "Map with an own key, null prototype": "copies its data",
    "Date with an own key, Object.prototype": "copies its data",
    "Date with an own key, null prototype": "copies its data",
    "Uint8Array with an own key, Object.prototype": "slot check",
    "Uint8Array with an own key, null prototype": "slot check",
    "DataView with an own key, Object.prototype": "slot check",
    "DataView with an own key, null prototype": "slot check",
    "Error with an own key, Object.prototype": "slot check",
    "Error with an own key, null prototype": "slot check",
    "module namespace": "own keys",
    "proxy of a plain object": "copies its data",
    "proxy of an array": "copies its data",
    "proxy of a Map, Object.prototype": "copies as {}",
    "revoked proxy": "throws when read",
  };

  it("identifies exactly the listed kinds on the portable path", () => {
    const identified = corpus
      .filter(([, make]) => portableChecks.hasInternalSlots(make()))
      .map(([label]) => label);
    const listed = Object.entries(portableMechanisms)
      .filter(([, mechanism]) => mechanism === "slot check")
      .map(([label]) => label);
    expect(identified).toEqual(listed);
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
  if (portableChecks.hasInternalSlots(value)) {
    return !snapshot.ok && code === "not_canonical" ? "slot check" : "slot check not enforced";
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
  ];
  /** Kinds whose portable checks never throw, so they run on every object: refused on both. */
  const refusedEverywhere: [string, () => object][] = [
    ["non-empty Uint8Array", () => Object.setPrototypeOf(new Uint8Array(2), Object.prototype)],
    [
      "Uint8Array with an own key",
      () => Object.assign(Object.setPrototypeOf(new Uint8Array(2), null), { kind: "all" }),
    ],
    [
      "DataView with an own key",
      () =>
        Object.assign(Object.setPrototypeOf(new DataView(new ArrayBuffer(2)), Object.prototype), {
          kind: "all",
        }),
    ],
    [
      "Error with an own key",
      () => Object.assign(Object.setPrototypeOf(new Error("x"), Object.prototype), { a: 1 }),
    ],
  ];

  it("refuses typed arrays, DataViews and errors with own keys on both paths", () => {
    const nodePath = nodeChecks(process);
    for (const [label, make] of refusedEverywhere) {
      const value = make();
      expect({ label, node: nodePath?.hasInternalSlots(value) }).toEqual({
        label,
        node: true,
      });
      expect({ label, portable: portableChecks.hasInternalSlots(value) }).toEqual({
        label,
        portable: true,
      });
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

  it("are identified by the Node checks and skipped by the portable checks", () => {
    const nodePath = nodeChecks(process);
    for (const [label, make] of items) {
      const value = make();
      expect({ label, node: nodePath?.hasInternalSlots(value) }).toEqual({
        label,
        node: true,
      });
      expect({ label, portable: portableChecks.hasInternalSlots(value) }).toEqual({
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

/**
 * Decided 2026-11-24: the portable path has no brand checks that throw for a wrong receiver. A
 * built-in whose kind only such a check identifies copies as `{}` there when its prototype is
 * swapped and it has no own keys. Node refuses each one.
 */
const keylessKinds: readonly (readonly [string, () => object])[] = [
  ["Map", () => new Map([["queue", "vip"]])],
  ["Set", () => new Set(["vip"])],
  ["WeakMap", () => new WeakMap()],
  ["WeakSet", () => new WeakSet()],
  ["Date", () => new Date(0)],
  ["Promise", () => Promise.resolve(1)],
  ["ArrayBuffer", () => new ArrayBuffer(8)],
  ["SharedArrayBuffer", () => new SharedArrayBuffer(8)],
  ["Number object", () => Object(1) as object],
  ["Boolean object", () => Object(true) as object],
  ["Symbol object", () => Object(Symbol("s")) as object],
  ["BigInt object", () => Object(1n) as object],
  ["generator object", () => generate()],
  ["Map iterator", () => new Map([["queue", "vip"]]).keys()],
  ["Set iterator", () => new Set(["vip"]).values()],
];

function withProperties(request: AccessRequest, properties: object): AccessRequest {
  return { ...request, resource: { ...request.resource, properties: properties as never } };
}

const lead = human("u-lead", role("lead", everywhere));
const auditor = human("u-aud", role("auditor", everywhere));
const support = human("u-sup", role("support", everywhere));

/** Where a request can hold an object. Each builds the request around `value`. */
const positions: readonly (readonly [string, (value: object) => AccessRequest])[] = [
  [
    "resource.properties, role scope everywhere",
    (value) => withProperties(accessRequest(lead, "ticket:read"), value),
  ],
  [
    "resource.properties, grant scope that matches a project",
    (value) => withProperties(accessRequest(auditor, "ticket:read"), value),
  ],
  [
    "resource.properties, deny rule that matches a queue",
    (value) => withProperties(accessRequest(support, "ticket:close"), value),
  ],
  [
    "resource.properties, range limit",
    (value) => withProperties(accessRequest(support, "ticket:refund"), value),
  ],
  [
    "a property value",
    (value) => withProperties(accessRequest(lead, "ticket:read"), { queue: value }),
  ],
  [
    "a role scope",
    (value) => accessRequest(human("u-x", role("lead", value as Scope)), "ticket:read"),
  ],
];

/**
 * The decision for plain `{}` in each position. Both vitest projects assert this table, so the
 * portable path decides for a keyless built-in exactly what Node decides for `{}`.
 */
const plainObjectDecisions: Record<string, string> = {
  "resource.properties, role scope everywhere": "allow granted",
  "resource.properties, grant scope that matches a project": "deny scope_mismatch",
  "resource.properties, deny rule that matches a queue": "deny denied_by_rule",
  "resource.properties, range limit": "deny limit_exceeded",
  "a property value": "deny invalid_request",
  "a role scope": "deny invalid_request",
};

describe("keyless built-ins with a swapped prototype", () => {
  const items = withSwappedPrototypes(keylessKinds);

  it("pins the decision for plain {} in each position", () => {
    const observed = Object.fromEntries(
      positions.map(([label, at]) => {
        const decision = decide(policy, at({}));
        return [label, `${decision.outcome} ${decision.reason}`];
      }),
    );
    expect(observed).toEqual(plainObjectDecisions);
  });

  it("are identified by the Node checks and not by the portable checks", () => {
    const nodePath = nodeChecks(process);
    for (const [label, make] of items) {
      expect({ label, node: nodePath?.hasInternalSlots(make()) }).toEqual({ label, node: true });
      expect({ label, portable: portableChecks.hasInternalSlots(make()) }).toEqual({
        label,
        portable: false,
      });
    }
  });

  it.runIf(expectedRuntime === "node")("are refused on the Node path, in every position", () => {
    for (const [label, make] of items) {
      expect({ label, snapshot: snapshotOf(make(), requestBounds) }).toEqual({
        label,
        snapshot: { ok: false, reason: "not_plain" },
      });
      expect({ label, code: codeOf(() => canonicalJson(make())) }).toEqual({
        label,
        code: "not_canonical",
      });
      for (const [position, at] of positions) {
        const decision = decide(policy, at(make()));
        expect({ label, position, result: `${decision.outcome} ${decision.reason}` }).toEqual({
          label,
          position,
          result: "deny invalid_request",
        });
      }
    }
  });

  it.runIf(expectedRuntime === "portable")(
    "copy as {} on the portable path and decide exactly as {} does",
    () => {
      for (const [label, make] of items) {
        const snapshot = snapshotOf(make(), requestBounds);
        expect({
          label,
          ok: snapshot.ok,
          keys: snapshot.ok ? Reflect.ownKeys(snapshot.value as object) : undefined,
        }).toEqual({ label, ok: true, keys: [] });
        expect({ label, json: canonicalJson(make()) }).toEqual({ label, json: "{}" });
        for (const [position, at] of positions) {
          expect({ label, position, decision: decide(policy, at(make())) }).toEqual({
            label,
            position,
            decision: decide(policy, at({})),
          });
        }
      }
    },
  );
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
      (value) => checks?.hasInternalSlots(value),
    );
    expect(results).toEqual(reference);
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

/** A proxy that revokes itself in its getOwnPropertyDescriptor trap and reports a length. */
function selfRevokingProxy(): object {
  const { proxy, revoke } = Proxy.revocable(
    {},
    {
      getOwnPropertyDescriptor() {
        revoke();
        return { value: 0, enumerable: false, configurable: true, writable: true };
      },
    },
  );
  return proxy;
}

describe("portable checks", () => {
  it("are not changed by a later replacement of the built-ins they use", () => {
    const isView = Object.getOwnPropertyDescriptor(ArrayBuffer, "isView");
    const isArray = Object.getOwnPropertyDescriptor(Array, "isArray");
    if (isView === undefined || isArray === undefined) throw new Error("a built-in is missing");
    try {
      Object.defineProperty(ArrayBuffer, "isView", { value: () => false, configurable: true });
      Object.defineProperty(Array, "isArray", { value: () => true, configurable: true });
      const typed = Object.setPrototypeOf(new Uint8Array(2), Object.prototype) as object;
      expect(portableChecks.hasInternalSlots(typed)).toBe(true);
      const boxed = Object.setPrototypeOf(Object("ab"), Object.prototype) as object;
      expect(portableChecks.hasInternalSlots(boxed)).toBe(true);
    } finally {
      Object.defineProperty(ArrayBuffer, "isView", isView);
      Object.defineProperty(Array, "isArray", isArray);
    }
  });

  /**
   * The length rule: an object other than an array with a non-enumerable own `length` is refused
   * before its keys are listed. JSON cannot produce such a key; the size guard and canonicalJson
   * refuse a non-enumerable key anyway, so the rule changes only when the refusal comes.
   */
  const lengthItems: [string, () => object, boolean][] = [
    [
      "non-enumerable data length",
      () => Object.defineProperty({}, "length", { value: 0, enumerable: false }),
      true,
    ],
    [
      "non-enumerable accessor length",
      () => Object.defineProperty({}, "length", { get: () => 0, enumerable: false }),
      true,
    ],
    ["enumerable length", () => ({ length: 0 }), false],
    ["array", () => [1, 2], false],
  ];

  it("refuse an object with a non-enumerable own length, but not an array", () => {
    for (const [label, make, refused] of lengthItems) {
      expect({ label, refused: portableChecks.hasInternalSlots(make()) }).toEqual({
        label,
        refused,
      });
    }
  });

  it("refuse a non-enumerable own length in the size guard and canonicalJson", () => {
    for (const [label, make, refused] of lengthItems) {
      if (!refused) continue;
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

  it("run no caller code, apart from one O(1) read of an own length", () => {
    const reads: string[] = [];
    const trap = new Proxy(
      {},
      {
        get(target, key, receiver) {
          reads.push(`get ${String(key)}`);
          return Reflect.get(target, key, receiver) as unknown;
        },
        getPrototypeOf() {
          reads.push("getPrototypeOf");
          return Object.prototype;
        },
        ownKeys() {
          reads.push("ownKeys");
          return [];
        },
        getOwnPropertyDescriptor(_target, key) {
          reads.push(`getOwnPropertyDescriptor ${String(key)}`);
          return undefined;
        },
      },
    );
    expect(portableChecks.hasInternalSlots(trap)).toBe(false);
    // The size guard and canonicalJson read every own descriptor of an object anyway.
    expect(reads).toEqual(["getOwnPropertyDescriptor length"]);
  });

  it("read a proxy once also when it reports a non-enumerable length", () => {
    const reads: string[] = [];
    const trap = new Proxy(
      {},
      {
        getOwnPropertyDescriptor(_target, key) {
          reads.push(`getOwnPropertyDescriptor ${String(key)}`);
          return { value: 0, enumerable: false, configurable: true, writable: true };
        },
        getPrototypeOf() {
          reads.push("getPrototypeOf");
          return Object.prototype;
        },
      },
    );
    expect(portableChecks.hasInternalSlots(trap)).toBe(true);
    expect(reads).toEqual(["getOwnPropertyDescriptor length"]);
  });

  it("refuse a proxy that revokes itself while its length is read, without throwing", () => {
    expect(codeOf(() => portableChecks.hasInternalSlots(selfRevokingProxy()))).toBe("ok");
    expect(portableChecks.hasInternalSlots(selfRevokingProxy())).toBe(true);
    expect(snapshotOf({ nested: selfRevokingProxy() }, requestBounds)).toEqual({
      ok: false,
      reason: "not_plain",
    });
    expect(codeOf(() => canonicalJson({ nested: selfRevokingProxy() }))).toBe("not_canonical");
  });

  it("treat RegExp.prototype, which has no slot, like Node does", () => {
    expect(portableChecks.hasInternalSlots(RegExp.prototype)).toBe(
      referenceHasInternalSlots(RegExp.prototype),
    );
  });
});
