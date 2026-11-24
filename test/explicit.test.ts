import { afterEach, describe, expect, it } from "vitest";

import { limitsHold, scopeCovers, scopeTouches, whenApplies } from "../src/engine/conditions.js";
import {
  canonicalJson,
  compilePolicy,
  decide,
  digest,
  evaluate,
  evaluateApprovals,
  explain,
  PermitkitError,
  requestDigest,
} from "../src/index.js";
import {
  accessRequest,
  everywhere,
  human,
  role,
  unlimited,
  viaAgent,
  within,
} from "../src/testing/index.js";
import { catalog, editablePolicyInput, policy } from "./fixtures.js";
import { expectedRuntime } from "./runtime.js";

const polluted: string[] = [];

function pollute(key: string, value: unknown): void {
  polluted.push(key);
  // The test simulates a prototype-pollution bug elsewhere in the process.
  // oxlint-disable-next-line no-extend-native
  Object.defineProperty(Object.prototype, key, { value, configurable: true, writable: true });
}

afterEach(() => {
  for (const key of polluted.splice(0)) delete (Object.prototype as Record<string, unknown>)[key];
});

function codeOf(run: () => unknown): unknown {
  try {
    run();
    return "no error";
  } catch (error) {
    return error instanceof PermitkitError ? error.code : error;
  }
}

function issuesOf(run: () => unknown): { path: string; message: string }[] {
  try {
    run();
    return [];
  } catch (error) {
    return error instanceof PermitkitError ? [...error.issues] : [];
  }
}

/** Every way a scope can be lost, emptied or misspelt. None of them may mean everywhere. */
const brokenScopes: [string, unknown][] = [
  ["missing", undefined],
  ["empty object", {}],
  ["null", null],
  ["old shape", { queue: ["billing"] }],
  ["unknown kind", { kind: "ALL" }],
  ["kind true", { kind: true }],
  ["star string", "*"],
  ["array", []],
  ["match without properties", { kind: "match" }],
  ["match with empty properties", { kind: "match", properties: {} }],
  ["all with properties", { kind: "all", properties: { queue: ["billing"] } }],
  ["star value in match", { kind: "match", properties: { queue: ["*"] } }],
];

function withAssignmentScope(scope: unknown) {
  const assignment: Record<string, unknown> = { role: "lead" };
  if (scope !== undefined) assignment["scope"] = scope;
  return {
    ...accessRequest(human("u-lead"), "ticket:read", { properties: { queue: "billing" } }),
    subject: { type: "human", id: "u-lead", roles: [assignment], act: null },
  };
}

describe("explicit everywhere: role assignment scopes", () => {
  it("allows with the explicit all marker", () => {
    expect(decide(policy, withAssignmentScope({ kind: "all" })).outcome).toBe("allow");
  });

  it("refuses a missing, empty, null or malformed assignment scope", () => {
    for (const [label, scope] of brokenScopes) {
      expect({ label, reason: decide(policy, withAssignmentScope(scope)).reason }).toEqual({
        label,
        reason: "invalid_request",
      });
    }
  });

  it("names the accepted shapes in the explain issue", () => {
    const issues = explain(policy, withAssignmentScope({})).steps[0];
    expect(issues).toMatchObject({ step: "validate", ok: false });
    const text = JSON.stringify(issues);
    expect(text).toContain("subject.roles.0.scope");
    expect(text).toContain("State the scope explicitly");
  });

  it("refuses an empty assignment scope under a polluted kind", () => {
    pollute("kind", "all");
    expect(decide(policy, withAssignmentScope({})).reason).toBe("invalid_request");
  });

  it('does not read "*" in a match scope as everywhere', () => {
    const request = withAssignmentScope({ kind: "match", properties: { queue: ["*"] } });
    expect(decide(policy, request).reason).toBe("invalid_request");
    const literal = within({ queue: ["billing"] });
    const other = accessRequest(human("u", role("lead", literal)), "ticket:read", {
      properties: { queue: "*" },
    });
    expect(decide(policy, other).reason).toBe("scope_mismatch");
  });
});

describe("explicit everywhere: agent grant entries", () => {
  const lead = human("u-lead", role("lead", everywhere));
  const entry = (fields: Record<string, unknown>) =>
    viaAgent(lead, "bot", {
      entries: [{ permissions: ["ticket:read"], ...fields } as never],
    });

  it("allows with explicit all and unlimited", () => {
    const subject = entry({ scope: everywhere, limits: unlimited });
    expect(decide(policy, accessRequest(subject, "ticket:read")).outcome).toBe("allow");
  });

  it("refuses a missing, empty, null or malformed entry scope", () => {
    for (const [label, scope] of brokenScopes) {
      const fields: Record<string, unknown> = { limits: unlimited };
      if (scope !== undefined) fields["scope"] = scope;
      const reason = decide(policy, accessRequest(entry(fields), "ticket:read")).reason;
      expect({ label, reason }).toEqual({ label, reason: "invalid_request" });
    }
  });

  it("refuses missing, empty or null entry limits", () => {
    for (const limits of [
      undefined,
      {},
      null,
      { amount: { min: null, max: 5 } },
      { kind: "range" },
    ]) {
      const fields: Record<string, unknown> = { scope: everywhere };
      if (limits !== undefined) fields["limits"] = limits;
      const reason = decide(policy, accessRequest(entry(fields), "ticket:read")).reason;
      expect({ limits, reason }).toEqual({ limits, reason: "invalid_request" });
    }
  });

  it("refuses a grant without notBefore or revokedAt, and an actor without grant or act", () => {
    const valid = entry({ scope: everywhere, limits: unlimited });
    const actor = valid.act!;
    const grant = actor.grant!;
    const variants = [
      { ...actor, grant: { ...grant, revokedAt: undefined } },
      { ...actor, grant: { ...grant, notBefore: undefined } },
      { ...actor, grant: undefined },
      { ...actor, act: undefined },
    ];
    for (const variant of variants) {
      const request = accessRequest({ ...lead, act: variant as never }, "ticket:read");
      expect(decide(policy, request).reason).toBe("invalid_request");
    }
    expect(decide(policy, accessRequest(valid, "ticket:read")).outcome).toBe("allow");
  });

  it("refuses a subject without act instead of reading it as acting directly", () => {
    const request = accessRequest(lead, "ticket:delete");
    expect(decide(policy, request).outcome).toBe("allow");
    const { act: _act, ...withoutAct } = lead;
    expect(decide(policy, { ...request, subject: withoutAct }).reason).toBe("invalid_request");
  });

  it("puts the entry scope into the request digest", () => {
    const wide = accessRequest(entry({ scope: everywhere, limits: unlimited }), "ticket:read", {
      properties: { queue: "a" },
    });
    const narrow = accessRequest(
      entry({ scope: within({ queue: ["a"] }), limits: unlimited }),
      "ticket:read",
      { properties: { queue: "a" } },
    );
    expect(requestDigest(policy, wide)).not.toBe(requestDigest(policy, narrow));
  });
});

type Input = ReturnType<typeof editablePolicyInput>;

/** Sets a field, or deletes it for undefined. */
function set(target: object, key: string, value: unknown): void {
  if (value === undefined) delete (target as Record<string, unknown>)[key];
  else (target as Record<string, unknown>)[key] = value;
}

describe("explicit everywhere: policy documents", () => {
  it("refuses a missing, empty, null or malformed grant scope", () => {
    for (const [label, scope] of brokenScopes) {
      const input = editablePolicyInput();
      set(input.roles["support"]!.grants[0]!, "scope", scope);
      const issues = issuesOf(() => compilePolicy(catalog, input));
      expect({ label, refused: issues.length > 0 }).toEqual({ label, refused: true });
      expect(issues[0]?.path.startsWith("roles.support.grants.0.scope")).toBe(true);
    }
  });

  it("refuses a missing, empty, null or malformed deny scope", () => {
    for (const [label, scope] of brokenScopes) {
      const input = editablePolicyInput();
      set(input.denies[1]!, "scope", scope);
      expect({ label, code: codeOf(() => compilePolicy(catalog, input)) }).toEqual({
        label,
        code: "policy_invalid",
      });
    }
  });

  it("refuses missing, empty or malformed grant limits, when and approver eligibility", () => {
    const changes: [string, (input: Input) => void][] = [
      ["limits missing", (input) => set(input.roles["support"]!.grants[1]!, "limits", undefined)],
      ["limits empty", (input) => set(input.roles["support"]!.grants[1]!, "limits", {})],
      ["limits null", (input) => set(input.roles["support"]!.grants[1]!, "limits", null)],
      ["when missing", (input) => set(input.approvalRules[0]!, "when", undefined)],
      ["when empty", (input) => set(input.approvalRules[0]!, "when", {})],
      ["when old shape", (input) => set(input.approvalRules[0]!, "when", { amount: { gte: 1 } })],
      ["eligibility missing", (input) => set(input.approvalRules[0]!, "eligibleApprovers", null)],
      [
        "eligibility empty roles",
        (input) => set(input.approvalRules[0]!, "eligibleApprovers", { kind: "roles", roles: [] }),
      ],
      ["old approverRoles", (input) => set(input.approvalRules[0]!, "approverRoles", ["lead"])],
      ["requireProof missing", (input) => set(input.approvalRules[0]!, "requireProof", undefined)],
      [
        "requireProof without proofTypes",
        (input) => set(input.approvalRules[0]!, "requireProof", true),
      ],
      ["denies missing", (input) => set(input, "denies", undefined)],
      ["approvalRules missing", (input) => set(input, "approvalRules", undefined)],
      ["separationOfDuties missing", (input) => set(input, "separationOfDuties", undefined)],
      [
        "separation flag missing",
        (input) => set(input.separationOfDuties, "exclusiveRequestAndApproveRoles", undefined),
      ],
    ];
    for (const [label, change] of changes) {
      const input = editablePolicyInput();
      change(input);
      expect({ label, code: codeOf(() => compilePolicy(catalog, input)) }).toEqual({
        label,
        code: "policy_invalid",
      });
    }
  });

  it("refuses an empty grant scope under a polluted kind", () => {
    const input = editablePolicyInput();
    set(input.roles["support"]!.grants[0]!, "scope", {});
    pollute("kind", "all");
    expect(codeOf(() => compilePolicy(catalog, input))).toBe("policy_invalid");
  });

  it("refuses a policy in the old schema with its own error code", () => {
    const old = {
      schema: 1,
      version: "old",
      roles: { r: { grants: [{ id: "g", permissions: ["ticket:read"] }] } },
    };
    expect(codeOf(() => compilePolicy(catalog, old))).toBe("policy_schema_unsupported");
    const issues = issuesOf(() => compilePolicy(catalog, old));
    expect(issues[0]?.path).toBe("schema");
    expect(issues[0]?.message).toMatch(/no automatic migration/);
    expect(codeOf(() => compilePolicy(catalog, { ...editablePolicyInput(), schema: 3 }))).toBe(
      "policy_schema_unsupported",
    );
  });
});

/** A lead with a role assignment whose scope is not type-checked. */
function leadWithScope(scope: unknown) {
  return human("u-lead", { role: "lead", scope } as never);
}

describe("a key set to undefined inside an AND-combined record", () => {
  it("refuses it in a policy grant scope, range and threshold instead of dropping a condition", () => {
    const changes: [string, (input: Input) => void][] = [
      [
        "grant match scope",
        (input) =>
          set(input.roles["auditor"]!.grants[0]!, "scope", {
            kind: "match",
            properties: { project: ["alpha"], queue: undefined },
          }),
      ],
      [
        "range bound",
        (input) =>
          set(input.roles["support"]!.grants[1]!, "limits", {
            kind: "range",
            properties: { amount: { min: 0, max: undefined } },
          }),
      ],
      [
        "range property",
        (input) =>
          set(input.roles["support"]!.grants[1]!, "limits", {
            kind: "range",
            properties: { amount: { min: null, max: 500 }, other: undefined },
          }),
      ],
      [
        "threshold property",
        (input) =>
          set(input.approvalRules[0]!, "when", {
            kind: "threshold",
            properties: { amount: { gte: 100 }, other: undefined },
          }),
      ],
      [
        "deny match scope",
        (input) =>
          set(input.denies[1]!, "scope", {
            kind: "match",
            properties: { queue: ["vip"], project: undefined },
          }),
      ],
    ];
    for (const [label, change] of changes) {
      const input = editablePolicyInput();
      change(input);
      expect({ label, code: codeOf(() => compilePolicy(catalog, input)) }).toEqual({
        label,
        code: "policy_invalid",
      });
    }
  });

  it("refuses it in an assignment scope, an agent grant entry and an approver scope", async () => {
    const narrow = { kind: "match", properties: { queue: ["billing"], project: undefined } };
    const resource = { properties: { queue: "billing", project: "other" } };
    expect(
      decide(policy, accessRequest(leadWithScope(narrow), "ticket:read", resource)).reason,
    ).toBe("invalid_request");
    const agent = viaAgent(human("u-lead", role("lead", everywhere)), "bot", {
      entries: [
        { permissions: ["ticket:read"], scope: narrow as never, limits: unlimited },
        {
          permissions: ["ticket:refund"],
          scope: everywhere,
          limits: { kind: "range", properties: { amount: { min: 0, max: undefined } } } as never,
        },
      ],
    });
    expect(decide(policy, accessRequest(agent, "ticket:read", resource)).reason).toBe(
      "invalid_request",
    );

    const input = editablePolicyInput();
    input.approvalRules[0]!.eligibleApprovers = { kind: "roles", roles: ["approver"] };
    const withRoles = compilePolicy(catalog, input);
    const request = accessRequest(human("u-req", role("lead", everywhere)), "ticket:refund", {
      properties: { amount: 500, queue: "billing", project: "other" },
    });
    const digestValue = requestDigest(withRoles, request);
    const approvals = ["u-a", "u-b"].map((id) => ({
      approver: human(id, { role: "approver", scope: narrow } as never),
      approvedAt: "2026-01-15T10:10:00.000Z",
      requestDigest: digestValue,
    }));
    const result = await evaluateApprovals(withRoles, {
      request,
      now: "2026-01-15T10:30:00.000Z",
      approvals,
    });
    expect(result.counted).toEqual([]);
    expect(result.rejected.map((item) => item.reason)).toEqual([
      "approval_invalid",
      "approval_invalid",
    ]);
  });

  it("still reads undefined as absent in an optional field", () => {
    const request = accessRequest(human("u-lead", role("lead", everywhere)), "ticket:read");
    const withUndefined = {
      ...request,
      resource: { ...request.resource, id: undefined },
      context: { ...request.context, policyVersion: undefined },
    };
    expect(decide(policy, withUndefined).outcome).toBe("allow");
  });
});

describe("range bounds", () => {
  it("refuses a range with a missing bound or two null bounds", () => {
    for (const amount of [{ min: 0 }, { max: 500 }, { min: null, max: null }, {}]) {
      const input = editablePolicyInput();
      input.roles["support"]!.grants[1]!.limits = {
        kind: "range",
        properties: { amount },
      } as never;
      expect({ amount, code: codeOf(() => compilePolicy(catalog, input)) }).toEqual({
        amount,
        code: "policy_invalid",
      });
      const subject = viaAgent(human("u-lead", role("lead", everywhere)), "bot", {
        entries: [
          {
            permissions: ["ticket:refund"],
            scope: everywhere,
            limits: { kind: "range", properties: { amount } } as never,
          },
        ],
      });
      const request = accessRequest(subject, "ticket:refund", { properties: { amount: 50 } });
      expect({ amount, reason: decide(policy, request).reason }).toEqual({
        amount,
        reason: "invalid_request",
      });
    }
  });

  it("reads null as an open side", () => {
    const input = editablePolicyInput();
    input.roles["support"]!.grants[1]!.limits = {
      kind: "range",
      properties: { amount: { min: 0, max: null } },
    };
    const open = compilePolicy(catalog, input);
    const support = human("u-s", role("support", everywhere));
    const big = accessRequest(support, "ticket:refund", { properties: { amount: 99 } });
    expect(decide(open, big).outcome).toBe("allow");
    const negative = accessRequest(support, "ticket:refund", { properties: { amount: -1 } });
    expect(decide(open, negative).reason).toBe("limit_exceeded");
  });

  it("holds for nothing in the engine with a missing bound or two null bounds", () => {
    const missing = { kind: "range", properties: { amount: { min: 0 } } } as never;
    expect(limitsHold(missing, { amount: 1e12 }).ok).toBe(false);
    const open = { kind: "range", properties: { amount: { min: null, max: null } } } as never;
    expect(limitsHold(open, { amount: 1e12 }).ok).toBe(false);
  });
});

function swappedScope(): unknown {
  return Object.setPrototypeOf(
    new Map([["properties", { queue: ["billing"] }]]),
    Object.prototype,
  ) as unknown;
}

function swappedProperties(): unknown {
  return Object.setPrototypeOf(new Map([["queue", "vip"]]), Object.prototype) as unknown;
}

describe("built-in objects with a swapped prototype", () => {
  const request = accessRequest(human("u-lead", role("lead", everywhere)), "ticket:read");
  const withProperties = (properties: unknown) => ({
    ...request,
    resource: { ...request.resource, properties },
  });

  it.runIf(expectedRuntime === "node")("refuses a swapped Map as a scope or properties", () => {
    expect(decide(policy, withAssignmentScope(swappedScope())).reason).toBe("invalid_request");
    expect(decide(policy, withProperties(swappedProperties())).reason).toBe("invalid_request");
  });

  // Decided 2026-11-24: the portable path copies a swapped Map as `{}` (see src/plain.ts).
  it.runIf(expectedRuntime === "portable")("decides for a swapped Map as for {}", () => {
    expect(decide(policy, withAssignmentScope(swappedScope())).reason).toBe("invalid_request");
    expect(decide(policy, withProperties(swappedProperties()))).toEqual(
      decide(policy, withProperties({})),
    );
  });
});

describe("prior request history", () => {
  it("refuses a history entry whose permission is not in the catalogue", async () => {
    const input = editablePolicyInput();
    input.separationOfDuties.requesterNeverApprovesSameType = true;
    const strict = compilePolicy(catalog, input);
    const request = accessRequest(human("u-req", role("lead", everywhere)), "ticket:refund", {
      properties: { amount: 500 },
    });
    const digestValue = requestDigest(strict, request);
    const approvals = ["u-a", "u-b"].map((id) => ({
      approver: human(id, role("lead", everywhere)),
      approvedAt: "2026-01-15T10:10:00.000Z",
      requestDigest: digestValue,
    }));
    const base = { request, now: "2026-01-15T10:30:00.000Z", approvals };
    const exact = await evaluateApprovals(strict, {
      ...base,
      priorRequests: [{ principalId: "u-a", permission: "ticket:refund" }],
    });
    expect(exact.rejected[0]?.reason).toBe("sod_prior_request");
    for (const permission of ["ticket:refunds", "Ticket:refund", "refund"]) {
      const result = await evaluateApprovals(strict, {
        ...base,
        priorRequests: [{ principalId: "u-a", permission }],
      });
      expect({ permission, reason: result.reason }).toEqual({
        permission,
        reason: "invalid_input",
      });
    }
  });
});

describe("explicit everywhere: deny scopes stay deny-biased", () => {
  it("counts a missing or non-string property as inside a deny match scope", () => {
    const support = human("u-s", role("support", everywhere));
    for (const properties of [{}, { queue: 7 }, { queue: null }, { queue: "vip" }]) {
      const request = accessRequest(support, "ticket:close", { properties });
      expect(decide(policy, request).reason).toBe("denied_by_rule");
    }
    const outside = accessRequest(support, "ticket:close", { properties: { queue: "billing" } });
    expect(decide(policy, outside).outcome).toBe("allow");
  });
});

function authzen(properties: Record<string, unknown>) {
  return {
    subject: { type: "human", id: "u-lead", properties },
    action: { name: "read" },
    resource: { type: "ticket" },
    context: { now: "2026-01-15T10:00:00.000Z" },
  };
}

describe("explicit everywhere: AuthZEN", () => {
  it("needs act: null for a principal that acts directly", () => {
    const roles = [{ role: "lead", scope: { kind: "all" } }];
    expect(evaluate(policy, authzen({ roles, act: null })).decision).toBe(true);
    expect(evaluate(policy, authzen({ roles })).context.reason_codes).toEqual(["invalid_request"]);
  });
});

describe("explicit everywhere: approvers", () => {
  it("does not count an approver without act", async () => {
    const request = accessRequest(human("u-req", role("lead", everywhere)), "ticket:refund", {
      properties: { amount: 500 },
    });
    const digestValue = requestDigest(policy, request);
    const approval = (approver: unknown) => ({
      approver,
      approvedAt: "2026-01-15T10:10:00.000Z",
      requestDigest: digestValue,
    });
    const { act: _act, ...withoutAct } = human("u-a", role("lead", everywhere));
    const result = await evaluateApprovals(policy, {
      request,
      now: "2026-01-15T10:30:00.000Z",
      approvals: [approval(withoutAct), approval(human("u-b", role("lead", everywhere)))],
    });
    expect(result.counted).toEqual(["u-b"]);
    expect(result.rejected[0]?.reason).toBe("approval_invalid");
  });
});

describe("condition engine fails toward less access on an unknown kind", () => {
  const properties = { queue: "billing", amount: 5 };
  const bogus = { kind: "bogus" } as never;

  it("covers nothing with an unknown or empty scope", () => {
    expect(scopeCovers(bogus, properties).ok).toBe(false);
    expect(scopeCovers({ kind: "match", properties: {} }, properties).ok).toBe(false);
    expect(scopeCovers({} as never, properties).ok).toBe(false);
  });

  it("touches every resource with an unknown deny scope", () => {
    expect(scopeTouches(bogus, properties)).toBe(true);
    expect(scopeTouches({} as never, properties)).toBe(true);
  });

  it("holds for nothing with unknown or empty limits", () => {
    expect(limitsHold(bogus, properties).ok).toBe(false);
    expect(limitsHold({ kind: "range", properties: {} }, properties).ok).toBe(false);
  });

  it("applies an unknown when condition", () => {
    expect(whenApplies(bogus, properties)).toBe(true);
  });

  it("does not read an inherited kind", () => {
    pollute("kind", "all");
    // A plain object inherits from Object.prototype, where the polluted kind lives.
    expect(scopeCovers({} as never, properties).ok).toBe(false);
  });
});

describe("canonicalJson refuses non-plain data with a coded error", () => {
  const variants: [string, () => unknown][] = [
    [
      "revoked proxy",
      () => {
        const { proxy, revoke } = Proxy.revocable({ a: 1 }, {});
        revoke();
        return proxy;
      },
    ],
    ["symbol key", () => ({ a: 1, [Symbol("hidden")]: 2 })],
    [
      "non-enumerable key",
      () => Object.defineProperty({ a: 1 }, "hidden", { value: 2, enumerable: false }),
    ],
    [
      "throwing getter",
      () =>
        Object.defineProperty({}, "a", {
          enumerable: true,
          get() {
            throw new Error("raw");
          },
        }),
    ],
    [
      "class instance",
      () =>
        new (class Point {
          x = 1;
        })(),
    ],
    ["Map", () => new Map([["a", 1]])],
    ["Date", () => new Date(0)],
    ["array with a named key", () => Object.assign([1], { extra: true })],
    [
      "array with a hole",
      () => {
        // A hole: length 3 with only two own indices.
        const holed: number[] = [];
        holed[0] = 1;
        holed[2] = 3;
        return holed;
      },
    ],
    ["array subclass", () => new (class List extends Array {})()],
    [
      "boxed string with Object.prototype",
      () => Object.setPrototypeOf(Object("ab"), Object.prototype),
    ],
    [
      "very deep nesting",
      () => {
        let nested: unknown = 1;
        for (let index = 0; index < 100_000; index += 1) nested = [nested];
        return nested;
      },
    ],
  ];

  // Only Node can detect a proxy. Without node:util, a proxy serializes as the data it reports.
  it.runIf(expectedRuntime === "node")("throws not_canonical for a proxy on Node", () => {
    expect(codeOf(() => canonicalJson(new Proxy({ a: 1 }, {})))).toBe("not_canonical");
    expect(codeOf(() => digest({ nested: new Proxy({ a: 1 }, {}) }))).toBe("not_canonical");
  });

  it.runIf(expectedRuntime === "portable")("serializes a proxy as its data elsewhere", () => {
    expect(canonicalJson(new Proxy({ a: 1 }, {}))).toBe('{"a":1}');
    expect(digest({ nested: new Proxy({ a: 1 }, {}) })).toBe(digest({ nested: { a: 1 } }));
  });

  // Decided 2026-11-24: the portable path has no check for these kinds (see src/plain.ts).
  const swappedWithoutKeys: [string, () => unknown][] = [
    [
      "Map with Object.prototype",
      () => Object.setPrototypeOf(new Map([["a", 1]]), Object.prototype),
    ],
    ["Date with Object.prototype", () => Object.setPrototypeOf(new Date(0), Object.prototype)],
  ];

  it.runIf(expectedRuntime === "node")("throws not_canonical for a swapped Map on Node", () => {
    for (const [label, make] of swappedWithoutKeys) {
      expect({ label, code: codeOf(() => canonicalJson(make())) }).toEqual({
        label,
        code: "not_canonical",
      });
    }
  });

  it.runIf(expectedRuntime === "portable")("serializes a swapped Map as {} elsewhere", () => {
    for (const [label, make] of swappedWithoutKeys) {
      expect({ label, json: canonicalJson(make()) }).toEqual({ label, json: "{}" });
    }
  });

  it("throws not_canonical for every non-plain value, in canonicalJson and digest", () => {
    for (const [label, make] of variants) {
      expect({ label, code: codeOf(() => canonicalJson(make())) }).toEqual({
        label,
        code: "not_canonical",
      });
      expect({ label, code: codeOf(() => digest({ nested: make() })) }).toEqual({
        label,
        code: "not_canonical",
      });
    }
  });

  it("does not run a getter", () => {
    let reads = 0;
    const value = Object.defineProperty({}, "a", {
      enumerable: true,
      get() {
        reads += 1;
        return 1;
      },
    });
    expect(codeOf(() => canonicalJson(value))).toBe("not_canonical");
    expect(reads).toBe(0);
  });

  it("still serializes plain and null-prototype objects", () => {
    const bare = Object.assign(Object.create(null) as object, { b: 1, a: [true, null, "x"] });
    expect(canonicalJson(bare)).toBe('{"a":[true,null,"x"],"b":1}');
    expect(canonicalJson({ a: undefined, b: 2 })).toBe('{"b":2}');
  });
});

describe("timestamp range", () => {
  const lead = human("u-lead", role("lead", everywhere));
  const at = (now: string) =>
    decide(policy, accessRequest(lead, "ticket:refund", { properties: { amount: 500 } }, { now }));

  it("accepts the earliest instant and refuses one millisecond before it", () => {
    expect(at("0000-01-01T00:00:00.000Z").outcome).toBe("approval_required");
    expect(at("0000-01-01T00:30:00+01:00").reason).toBe("invalid_request");
  });

  it("formats the approval window end at the latest request time as a valid timestamp", () => {
    const input = editablePolicyInput();
    input.approvalRules[0]!.expiresInSeconds = 31 * 24 * 3600;
    const longest = compilePolicy(catalog, input);
    const request = accessRequest(
      lead,
      "ticket:refund",
      { properties: { amount: 500 } },
      { now: "9999-11-30T23:59:59.999Z" },
    );
    const decision = decide(longest, request);
    expect(decision.approval?.expiresAt).toBe("9999-12-31T23:59:59.999Z");
    // The produced value passes the timestamp schema, for example as an agent grant expiry.
    const subject = viaAgent(lead, "bot", {
      entries: [{ permissions: ["ticket:refund"], scope: everywhere, limits: unlimited }],
      expiresAt: decision.approval!.expiresAt,
    });
    expect(decide(longest, { ...request, subject }).outcome).toBe("approval_required");
  });

  it("refuses a request time after the latest request time and a timestamp after 9999", () => {
    expect(at("9999-12-01T00:00:00.000Z").reason).toBe("invalid_request");
    const subject = viaAgent(lead, "bot", {
      entries: [{ permissions: ["ticket:read"], scope: everywhere, limits: unlimited }],
      expiresAt: "9999-12-31T23:59:59-00:01",
    });
    expect(decide(policy, accessRequest(subject, "ticket:read")).reason).toBe("invalid_request");
  });
});

describe("evaluateApprovals cost bounds", () => {
  const request = accessRequest(human("u-req", role("lead", everywhere)), "ticket:refund", {
    properties: { amount: 500 },
  });
  const digestValue = requestDigest(policy, request);
  const approval = (id: string) => ({
    approver: human(id, role("lead", everywhere)),
    approvedAt: "2026-01-15T10:10:00.000Z",
    requestDigest: digestValue,
  });
  const now = "2026-01-15T10:30:00.000Z";

  it("evaluates 20 approvals", async () => {
    const approvals = Array.from({ length: 20 }, (_, index) => approval(`u-${index}`));
    const result = await evaluateApprovals(policy, { request, now, approvals });
    expect(result).toMatchObject({ reason: "approved" });
    expect(result.counted).toHaveLength(20);
  });

  it("refuses more than 20 approvals before reading any of them", async () => {
    let reads = 0;
    const counting = Object.defineProperty({}, "approver", {
      enumerable: true,
      get() {
        reads += 1;
        return human("u-x", role("lead", everywhere));
      },
    });
    const approvals = [
      ...Array.from({ length: 20 }, (_, index) => approval(`u-${index}`)),
      counting,
    ];
    const result = await evaluateApprovals(policy, { request, now, approvals });
    expect(result.reason).toBe("too_many_approvals");
    expect(reads).toBe(0);
    // Checked first: a huge request does not change the reason.
    const huge = { ...request, resource: { ...request.resource, id: "x".repeat(10_000) } };
    expect((await evaluateApprovals(policy, { request: huge, now, approvals })).reason).toBe(
      "too_many_approvals",
    );
  });

  it("refuses a request over the request bounds", async () => {
    // About 24,000 values: over the request bounds (20,000), inside the approval input bounds.
    const values = Array.from({ length: 90 }, (_, index) => `q${index}`);
    const roles = Array.from({ length: 250 }, () => role("lead", within({ queue: values })));
    const big = { ...request, subject: { ...request.subject, roles } };
    const result = await evaluateApprovals(policy, { request: big, now, approvals: [] });
    expect(result.reason).toBe("input_too_large");
  });

  it("refuses a whole input over the approval input bounds", async () => {
    const junk = Array.from({ length: 1_000 }, () => ({ a: 1, b: 2, c: 3, d: 4 }));
    const approvals = Array.from({ length: 20 }, () => junk);
    const result = await evaluateApprovals(policy, { request, now, approvals });
    expect(result.reason).toBe("input_too_large");
  });
});
