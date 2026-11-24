// Decisions never throw. Under data-valued pollution of built-ins, decide, explain and evaluate
// return the request's real decision or the internal-failure deny (invalid_request), and throw
// only policy_unknown. The registries of compiled policies and catalogues use methods captured
// at load, so pollution of WeakMap and WeakSet methods changes nothing. The pollution can break
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

const denied = ["invalid_request", "invalid_request", "invalid_request"];
const granted = ["granted", "granted", "granted"];

/** Each pollution and the decisions it gives. Before the fix, the first four cases threw. */
const cases: [label: string, target: object, key: string, value: unknown, expected: string[]][] = [
  ['Object.prototype["1"] read-only', Object.prototype, "1", "x", denied],
  ["Array.prototype.join = 1", Array.prototype, "join", 1, denied],
  ["Array.prototype.toSorted = 1", Array.prototype, "toSorted", 1, denied],
  ["JSON.stringify = 1", JSON, "stringify", 1, denied],
  ["Set.prototype.has = 1", Set.prototype, "has", 1, denied],
  ["Set.prototype.add = 1", Set.prototype, "add", 1, denied],
  // Used by the cycle check of the canonical digest.
  ["Set.prototype.delete = 1", Set.prototype, "delete", 1, denied],
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
