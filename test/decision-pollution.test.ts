// Decisions never throw. Under data-valued pollution of built-ins, decide, explain and evaluate
// return the request's real decision and throw only policy_unknown. Every built-in on the decision
// path is captured at load, so pollution of its methods changes nothing; replacement-fuzz.test.ts
// covers every built-in, and catch-paths.test.ts the internal-failure deny. The pollution can break
// the test framework, so each case captures first and asserts after clean-up.
import { describe, expect, it } from "vitest";

import {
  compilePolicy,
  decide,
  defineCatalog,
  evaluate,
  explain,
  PermitkitError,
  requestDigest,
  type AuthZenRequest,
} from "../src/index.js";
import { accessRequest, everywhere, human, role } from "../src/testing/index.js";

const catalog = defineCatalog({ ticket: { actions: ["read"], scopes: ["queue"] } });
const document = {
  schema: 2,
  version: "v",
  roles: {
    reader: {
      grants: [
        {
          id: "g",
          permissions: ["ticket:read"],
          scope: { kind: "all" },
          limits: { kind: "unlimited" },
        },
      ],
    },
  },
  denies: [],
  approvalRules: [],
  separationOfDuties: {
    requesterNeverApprovesSameType: false,
    exclusiveRequestAndApproveRoles: false,
  },
};
const policy = compilePolicy(catalog, document);
const request = () =>
  accessRequest(human("u", role("reader", everywhere)), "ticket:read", {
    properties: { queue: "a" },
  });
const authzen = (): AuthZenRequest => ({
  subject: {
    type: "human",
    id: "u",
    properties: { roles: [{ role: "reader", scope: { kind: "all" } }], act: null },
  },
  action: { name: "read" },
  resource: { type: "ticket", properties: { queue: "a" } },
  context: { now: "2026-01-15T10:00:00Z" },
});

function capture(run: () => string): string {
  try {
    return run();
  } catch (error) {
    if (PermitkitError.is(error)) return `threw ${error.code}`;
    return `threw raw ${String(error)}`;
  }
}

/** decide, explain and evaluate on a request that the clean policy allows. */
function decisions(): string[] {
  return [
    capture(() => decide(policy, request()).reason),
    capture(() => explain(policy, request()).decision.reason),
    capture(() => evaluate(policy, authzen()).context.reason_codes[0] ?? "none"),
  ];
}

function withProperty<T>(target: object, key: string, value: unknown, run: () => T): T {
  const saved = Object.getOwnPropertyDescriptor(target, key);
  // The test simulates a prototype-pollution bug elsewhere in the process.
  // oxlint-disable-next-line no-extend-native
  Object.defineProperty(target, key, { value, writable: false, configurable: true });
  try {
    return run();
  } finally {
    if (saved === undefined) Reflect.deleteProperty(target, key);
    else Object.defineProperty(target, key, saved);
  }
}

const granted = ["granted", "granted", "granted"];

/**
 * Each pollution and the decisions it gives. Before the first fix, the first four cases threw.
 * Until arrays grew through defineProperty, the read-only index broke explain, and the Set cases
 * gave the internal-failure deny.
 */
const cases: [label: string, target: object, key: string, value: unknown, expected: string[]][] = [
  // explain appends its trace steps with defineProperty, so an inherited read-only index does
  // not stop it.
  ['Object.prototype["1"] read-only', Object.prototype, "1", "x", granted],
  // Captured at load or not called, so the decision holds.
  ["Array.prototype.join = 1", Array.prototype, "join", 1, granted],
  ["Array.prototype.toSorted = 1", Array.prototype, "toSorted", 1, granted],
  ["JSON.stringify = 1", JSON, "stringify", 1, granted],
  ["Set.prototype.has = 1", Set.prototype, "has", 1, granted],
  ["Set.prototype.add = 1", Set.prototype, "add", 1, granted],
  // Used by the cycle check of the canonical digest, through a method captured at load.
  ["Set.prototype.delete = 1", Set.prototype, "delete", 1, granted],
  // Captured at load: the registry of compiled policies still works.
  ["WeakMap.prototype.get = 1", WeakMap.prototype, "get", 1, granted],
  ["WeakMap.prototype.set = 1", WeakMap.prototype, "set", 1, granted],
];

describe("decisions under polluted built-ins", () => {
  it.each(cases)("%s: no throw", (_label, target, key, value, expected) => {
    const result = withProperty(target, key, value, decisions);
    expect(result).toEqual(expected);
  });

  it("still throw policy_unknown for a policy from elsewhere", () => {
    const forged = { version: "v", digest: "d" } as never;
    const result = withProperty(Array.prototype, "join", 1, () => [
      capture(() => decide(forged, request()).reason),
      capture(() => explain(forged, request()).decision.reason),
      capture(() => String(evaluate(forged, authzen()).decision)),
    ]);
    expect(result).toEqual([
      "threw policy_unknown",
      "threw policy_unknown",
      "threw policy_unknown",
    ]);
  });

  it("requestDigest gives the clean digest with WeakMap.prototype.get polluted", () => {
    const clean = requestDigest(policy, request());
    const result = withProperty(WeakMap.prototype, "get", 1, () =>
      capture(() => requestDigest(policy, request())),
    );
    expect(result).toBe(clean);
  });

  it("compilePolicy tells catalogues apart with WeakSet methods polluted", () => {
    const result = withProperty(WeakSet.prototype, "has", 1, () => [
      capture(() => compilePolicy({} as never, document).version),
      capture(() => compilePolicy(catalog, document).version),
    ]);
    const added = withProperty(WeakSet.prototype, "add", 1, () =>
      capture(
        () => compilePolicy(defineCatalog({ ticket: { actions: ["read"] } }), document).version,
      ),
    );
    expect([...result, added]).toEqual(["threw catalog_invalid", "v", "v"]);
  });
});

/** A PermitkitError whose code getter throws a raw error. */
class ThrowingCode extends PermitkitError {
  constructor() {
    super("policy_unknown", "made by the caller");
    Object.defineProperty(this, "code", {
      get(): never {
        throw new Error("raw error from the code getter");
      },
    });
  }
}

/** Like capture(), but reads the code only from an own data property, so no getter runs. */
function captureSafe(run: () => string): string {
  try {
    return run();
  } catch (error) {
    if (!PermitkitError.is(error)) return "threw raw";
    const code = Object.getOwnPropertyDescriptor(error, "code");
    return code !== undefined && "value" in code ? `threw ${String(code.value)}` : "threw spoof";
  }
}

/** Runs with target[key] as a getter that throws the made value. Returns results and calls. */
function withThrowingGetter<T>(
  target: object,
  key: string,
  make: () => unknown,
  run: () => T,
): { result: T; calls: number } {
  const saved = Object.getOwnPropertyDescriptor(target, key);
  let calls = 0;
  // The test simulates accessor pollution of a built-in prototype elsewhere in the process.
  // oxlint-disable-next-line no-extend-native
  Object.defineProperty(target, key, {
    get() {
      calls += 1;
      throw make();
    },
    configurable: true,
  });
  try {
    return { result: run(), calls };
  } finally {
    if (saved === undefined) Reflect.deleteProperty(target, key);
    else Object.defineProperty(target, key, saved);
  }
}

const spoofs: [label: string, make: () => unknown][] = [
  ["a caller-made policy_unknown", () => new PermitkitError("policy_unknown", "spoof")],
  ["a PermitkitError with a throwing code getter", () => new ThrowingCode()],
];

describe("decisions under accessor pollution", () => {
  // Set.prototype.has and Array.prototype.includes ran inside decide and evaluate until every
  // built-in was captured at load. The getter now never runs, and the decision holds. How the
  // catch blocks treat what such a getter threw is in catch-paths.test.ts.
  it.each(spoofs)("decide and explain never read Set.prototype.has (%s)", (_label, make) => {
    const { result, calls } = withThrowingGetter(Set.prototype, "has", make, () => [
      captureSafe(() => decide(policy, request()).reason),
      captureSafe(() => explain(policy, request()).decision.reason),
    ]);
    expect([result, calls]).toEqual([["granted", "granted"], 0]);
  });

  it.each(spoofs)("evaluate never reads Array.prototype.includes (%s)", (_label, make) => {
    const { result, calls } = withThrowingGetter(Array.prototype, "includes", make, () =>
      captureSafe(() => evaluate(policy, authzen()).context.reason_codes[0] ?? "none"),
    );
    expect([result, calls]).toEqual(["granted", 0]);
  });

  it("still throw policy_unknown for a policy from elsewhere", () => {
    const forged = { version: "v", digest: "d" } as never;
    const { result } = withThrowingGetter(
      Set.prototype,
      "has",
      () => new ThrowingCode(),
      () => [
        captureSafe(() => decide(forged, request()).reason),
        captureSafe(() => explain(forged, request()).decision.reason),
        captureSafe(() => String(evaluate(forged, authzen()).decision)),
      ],
    );
    expect(result).toEqual([
      "threw policy_unknown",
      "threw policy_unknown",
      "threw policy_unknown",
    ]);
  });
});
