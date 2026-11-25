// Named regressions for built-ins that caller code replaces after permitkit loads. Each one
// widened a decision or changed a digest before every built-in on the decision path was
// captured at load. replacement-fuzz.test.ts runs every built-in in every mode; these cases name
// the ones that failed. The replacement can break the test framework, so each case records while
// it is active and asserts after the restore.
import { describe, expect, it } from "vitest";

import {
  compilePolicy,
  decide,
  defineCatalog,
  evaluate,
  explain,
  parseRequest,
  requestDigest,
  type AccessRequest,
  type AuthZenRequest,
  type Decision,
} from "../src/index.js";
import {
  accessRequest,
  everywhere,
  human,
  role,
  unlimited,
  viaAgent,
} from "../src/testing/index.js";

const catalog = defineCatalog({
  ticket: { actions: ["read", "refund", "delete"], scopes: ["queue"], limits: ["amount"] },
});
const policy = compilePolicy(catalog, {
  schema: 2,
  version: "v",
  roles: {
    worker: {
      grants: [
        {
          id: "work",
          permissions: ["ticket:read", "ticket:refund", "ticket:delete"],
          scope: { kind: "all" },
          limits: { kind: "unlimited" },
        },
      ],
    },
    reader: {
      grants: [{ id: "read", permissions: ["ticket:read"], scope: everywhere, limits: unlimited }],
    },
    approver: { grants: [] },
  },
  denies: [
    {
      id: "no-worker-refund",
      permissions: ["ticket:refund"],
      roles: ["worker"],
      scope: everywhere,
    },
    {
      id: "no-agent-delete",
      permissions: ["ticket:delete"],
      subjectTypes: ["agent"],
      scope: everywhere,
    },
  ],
  approvalRules: [
    {
      id: "big-read",
      permissions: ["ticket:read"],
      when: { kind: "threshold", properties: { amount: { gte: 100 } } },
      approvers: 1,
      expiresInSeconds: 600,
      eligibleApprovers: { kind: "roles", roles: ["approver"] },
      requireProof: false,
    },
  ],
  separationOfDuties: {
    requesterNeverApprovesSameType: false,
    exclusiveRequestAndApproveRoles: true,
  },
});

const worker = human("u", role("worker", everywhere));
/** Denied by the rule for the worker role. */
const refund = accessRequest(worker, "ticket:refund");
/** Denied by the rule for agents. */
const agentDelete = accessRequest(
  viaAgent(worker, "bot", {
    entries: [{ permissions: ["ticket:delete"], scope: everywhere, limits: unlimited }],
  }),
  "ticket:delete",
);
/** No grant of the reader role includes ticket:refund. */
const readerRefund = accessRequest(human("r", role("reader", everywhere)), "ticket:refund");
/** Denied by separation of duties: the subject holds the approver role. */
const conflicted = accessRequest(
  human("c", role("reader", everywhere), role("approver", everywhere)),
  "ticket:read",
);
/** Needs approval: amount at the threshold. */
const bigRead = accessRequest(human("r", role("reader", everywhere)), "ticket:read", {
  properties: { amount: 150 },
});
const cases: [name: string, request: AccessRequest][] = [
  ["refund by a worker", refund],
  ["delete through an agent", agentDelete],
  ["refund by a reader", readerRefund],
  ["read with the approver role", conflicted],
  ["read of 150", bigRead],
];

function authzenOf(request: AccessRequest): AuthZenRequest {
  return {
    subject: {
      type: request.subject.type,
      id: request.subject.id,
      properties: { roles: request.subject.roles, act: request.subject.act },
    },
    action: request.action,
    resource: { type: request.resource.type },
    context: { now: request.context.now },
  };
}

const define = Object.defineProperty;
const describeOwn = Object.getOwnPropertyDescriptor;

/** Runs with owner[key] replaced by the value, then restores it. */
function replaced<T>(owner: object, key: PropertyKey, value: unknown, run: () => T): T {
  const saved = describeOwn(owner, key);
  if (saved === undefined) throw new Error(`no ${String(key)} to replace`);
  // The test simulates caller code that replaces a built-in after permitkit loaded.
  // oxlint-disable-next-line no-extend-native
  define(owner, key, { value, writable: true, configurable: true });
  try {
    return run();
  } finally {
    define(owner, key, saved);
  }
}

interface Results {
  decide: Decision[];
  explain: Decision[];
  evaluate: boolean[];
  digests: string[];
}

function results(): Results {
  const out: Results = { decide: [], explain: [], evaluate: [], digests: [] };
  for (let index = 0; index < cases.length; index += 1) {
    const request = (cases[index] as [string, AccessRequest])[1];
    out.decide[index] = decide(policy, request);
    out.explain[index] = explain(policy, request).decision;
    out.evaluate[index] = evaluate(policy, authzenOf(request)).decision;
    out.digests[index] = requestDigest(policy, request);
  }
  return out;
}

const clean = results();

const arrayIterator = Object.getPrototypeOf([][Symbol.iterator]()) as object;
const done = () => ({ done: true, value: undefined });
const emptyIterator = () => ({ next: done });
const originalIncludes = Array.prototype.includes;
const denyLists = policy.document.denies.map((rule) => rule.permissions);
/** False for the permission lists of the deny rules, the real answer elsewhere. */
function includesExceptDenies(this: unknown[], item: unknown): boolean {
  // The original method, not `includes`: that is this function while it is installed.
  if (Reflect.apply(originalIncludes, denyLists, [this])) return false;
  return Reflect.apply(originalIncludes, this, [item]);
}

const replacements: [label: string, owner: object, key: PropertyKey, value: unknown][] = [
  ["Array.prototype.some returns false", Array.prototype, "some", () => false],
  [
    "Array.prototype.includes skips the deny rules",
    Array.prototype,
    "includes",
    includesExceptDenies,
  ],
  ["Array.prototype.includes returns true", Array.prototype, "includes", () => true],
  ["%ArrayIteratorPrototype%.next is done at once", arrayIterator, "next", done],
  ["Array.prototype[Symbol.iterator] is empty", Array.prototype, Symbol.iterator, emptyIterator],
  ["Array.prototype.map returns []", Array.prototype, "map", () => []],
  ["Array.prototype.filter returns []", Array.prototype, "filter", () => []],
  ["Array.prototype.forEach does nothing", Array.prototype, "forEach", () => undefined],
  ["Array.prototype.push does nothing", Array.prototype, "push", () => 0],
  ["Set.prototype.has returns false", Set.prototype, "has", () => false],
  [
    "Set.prototype.add does nothing",
    Set.prototype,
    "add",
    function (this: unknown) {
      return this;
    },
  ],
  ["Map.prototype.get returns undefined", Map.prototype, "get", () => undefined],
  [
    "Date.prototype.toISOString returns a fixed time",
    Date.prototype,
    "toISOString",
    () => "2000-01-01T00:00:00.000Z",
  ],
  ["Object.keys returns []", Object, "keys", () => []],
  ["Object.hasOwn returns true", Object, "hasOwn", () => true],
  ["RegExp.prototype.exec returns null", RegExp.prototype, "exec", () => null],
  ["Date.parse returns 0", Date, "parse", () => 0],
  ["globalThis.Set is a stub", globalThis, "Set", function Stub() {}],
];

describe("built-ins replaced after load", () => {
  it("the clean corpus has the expected decisions", () => {
    expect(clean.decide.map((decision) => decision.reason)).toEqual([
      "denied_by_rule",
      "denied_by_rule",
      "no_grant",
      "sod_role_conflict",
      "approval_required",
    ]);
  });

  it.each(replacements)(
    "%s: every decision and digest is the clean one",
    (_label, owner, key, value) => {
      const polluted = replaced(owner, key, value, results);
      expect(polluted).toEqual(clean);
    },
  );

  it("validation still reports issues with Array.prototype.push replaced", () => {
    const issues = replaced(
      Array.prototype,
      "push",
      () => 0,
      () => {
        const parsed = parseRequest({ ...refund, resource: { type: "x".repeat(200) } });
        return parsed.ok ? [] : parsed.issues.map((issue) => issue.path);
      },
    );
    expect(issues).toEqual(["resource.type"]);
  });
});
