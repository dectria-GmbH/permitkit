// Regression tests for findings of the second cold security review.
import { afterEach, describe, expect, it } from "vitest";

import {
  compilePolicy,
  decide,
  decideAndRecord,
  evaluateApprovals,
  reevaluate,
  requestDigest,
  toDecisionRecord,
  type ApprovalProofVerifier,
  type PolicyInput,
} from "../src/index.js";
import { accessRequest, human, role } from "../src/testing/index.js";
import { catalog, editablePolicyInput, policy } from "./fixtures.js";

const pollutionKeys = [
  "roles",
  "subjectTypes",
  "scope",
  "limits",
  "when",
  "approverRoles",
  "properties",
  "act",
  "grant",
  "policyVersion",
  "policyDigest",
] as const;
const pollution: Record<(typeof pollutionKeys)[number], unknown> = {
  roles: ["nobody"],
  subjectTypes: ["service"],
  scope: { queue: ["billing"] },
  limits: { amount: { max: 1e300 } },
  when: { amount: { gte: 1e300 } },
  approverRoles: ["ghost"],
  properties: { queue: "billing", amount: 0 },
  act: undefined,
  grant: undefined,
  policyVersion: undefined,
  policyDigest: undefined,
};

function pollute(): void {
  for (const key of pollutionKeys) {
    if (pollution[key] !== undefined) {
      // The test simulates a prototype-pollution bug elsewhere in the process.
      // oxlint-disable-next-line no-extend-native
      Object.defineProperty(Object.prototype, key, {
        value: pollution[key],
        configurable: true,
        writable: true,
      });
    }
  }
}

function cleanUp(): void {
  for (const key of pollutionKeys) {
    delete (Object.prototype as Record<string, unknown>)[key];
  }
}

const pollutedInput: PolicyInput = {
  schema: 1,
  version: "p",
  roles: {
    worker: {
      grants: [
        { id: "w-scoped", permissions: ["ticket:read"], scope: { queue: ["billing"] } },
        { id: "w-refund", permissions: ["ticket:refund"] },
      ],
    },
    lead: { grants: [{ id: "l-all", permissions: ["ticket:delete", "ticket:refund"] }] },
  },
  denies: [{ id: "no-delete", permissions: ["ticket:delete"] }],
  approvalRules: [
    { id: "refund", permissions: ["ticket:refund"], approvers: 2, expiresInSeconds: 3600 },
  ],
};

describe("a polluted Object.prototype does not change decisions", () => {
  afterEach(cleanUp);

  it("keeps deny rules, approval rules, scopes and peer eligibility", async () => {
    const compiled = compilePolicy(catalog, pollutedInput);
    const lead = human("u-lead", role("lead"));
    const worker = human("u-w", role("worker"));
    const refund = accessRequest(lead, "ticket:refund", { properties: { amount: 5 } });
    const digestValue = requestDigest(compiled, refund);
    const approvals = ["u-1", "u-2"].map((id) => ({
      approver: human(id, role("ghost")),
      approvedAt: "2026-01-15T10:10:00.000Z",
      requestDigest: digestValue,
    }));
    // Build every request before the pollution, so only permitkit reads the polluted prototype.
    const deleteRequest = accessRequest(lead, "ticket:delete");
    const scopedRequest = accessRequest(worker, "ticket:read");
    const run = async () => ({
      delete: decide(compiled, deleteRequest).outcome,
      refund: decide(compiled, refund).outcome,
      scoped: decide(compiled, scopedRequest).outcome,
      approvals: (
        await evaluateApprovals(compiled, {
          request: refund,
          now: "2026-01-15T10:30:00Z",
          approvals,
        })
      ).outcome,
    });
    const baseline = await run();
    expect(baseline).toEqual({
      delete: "deny",
      refund: "approval_required",
      scoped: "deny",
      approvals: "pending",
    });
    pollute();
    expect(await run()).toEqual(baseline);
  });

  it("compiles the same digest while the prototype is polluted", () => {
    const clean = compilePolicy(catalog, pollutedInput).digest;
    pollute();
    expect(compilePolicy(catalog, pollutedInput).digest).toBe(clean);
  });
});

describe("audit records", () => {
  it("records exactly the request that was decided", () => {
    let reads = 0;
    const request = accessRequest(human("u-lead", role("lead")), "ticket:read");
    const shifting = {
      ...request,
      get action() {
        reads += 1;
        return { name: reads === 1 ? "read" : "delete" };
      },
    };
    const { decision, record } = decideAndRecord(policy, shifting);
    expect(decision.outcome).toBe("allow");
    expect(record.request?.action.name).toBe("read");
    expect(reevaluate(policy, record).status).toBe("reproduced");
  });

  it("reports a record with non-JSON values as not replayable", () => {
    const request = accessRequest(human("u-lead", role("lead")), "ticket:read");
    const record = toDecisionRecord(request, decide(policy, request));
    for (const rule of [() => 1, Number.NaN, 1n, Symbol("x")]) {
      expect(reevaluate(policy, { ...record, rule } as never).status).toBe("not_replayable");
    }
  });
});

describe("proof verifier results", () => {
  const input = editablePolicyInput();
  input.approvalRules = [{ ...input.approvalRules![0]!, requireProof: true }];
  const proofPolicy = compilePolicy(catalog, input);
  const request = accessRequest(human("u-req", role("lead")), "ticket:refund", {
    properties: { amount: 500 },
  });
  const digestValue = requestDigest(proofPolicy, request);
  const approvals = ["u-a", "u-b"].map((id) => ({
    approver: human(id, role("lead")),
    approvedAt: "2026-01-15T10:10:00.000Z",
    requestDigest: digestValue,
    proof: { type: "t", approverId: id, requestDigest: digestValue, payload: {} },
  }));

  it("rejects anything but the exact success shape and never throws", async () => {
    const results: unknown[] = [null, undefined, "yes", { valid: "false" }, { valid: 1 }, {}];
    for (const value of results) {
      const verifier = { type: "t", verify: () => value } as unknown as ApprovalProofVerifier;
      const result = await evaluateApprovals(
        proofPolicy,
        { request, now: "2026-01-15T10:30:00.000Z", approvals },
        { verifiers: [verifier] },
      );
      expect(result.outcome).toBe("pending");
      expect(result.rejected.map((item) => item.reason)).toEqual([
        "proof_invalid",
        "proof_invalid",
      ]);
    }
  });
});

describe("policy pins", () => {
  it("denies when the pinned digest differs, also with the same version label", () => {
    const input = editablePolicyInput();
    input.roles["lead"]!.grants[0]!.permissions = ["ticket:read"];
    const sameLabel = compilePolicy(catalog, input);
    const lead = human("u-lead", role("lead"));
    const pinned = accessRequest(lead, "ticket:read", {}, { policyVersion: policy.version });
    const withDigest = { ...pinned, context: { ...pinned.context, policyDigest: policy.digest } };
    expect(decide(sameLabel, pinned).outcome).toBe("allow");
    expect(decide(sameLabel, withDigest).reason).toBe("policy_version_mismatch");
    expect(decide(policy, withDigest).outcome).toBe("allow");
  });
});

describe("empty restrictions", () => {
  it("rejects empty scope, limits and when, which would restrict nothing", () => {
    const empties: ((input: ReturnType<typeof editablePolicyInput>) => void)[] = [
      (input) => {
        input.roles["support"]!.grants[0]!.scope = {};
      },
      (input) => {
        input.roles["support"]!.grants[1]!.limits = {};
      },
      (input) => {
        input.denies![1]!.scope = {};
      },
      (input) => {
        input.approvalRules![0]!.when = {};
      },
    ];
    for (const change of empties) {
      const input = editablePolicyInput();
      change(input);
      expect(() => compilePolicy(catalog, input)).toThrow(/not valid/);
    }
  });

  it("still accepts an explicit empty assignment scope", () => {
    expect(decide(policy, accessRequest(human("u", role("lead", {})), "ticket:read")).outcome).toBe(
      "allow",
    );
  });
});
