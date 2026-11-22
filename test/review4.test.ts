// Regression tests for findings of the fourth cold security review.
import { afterEach, describe, expect, it } from "vitest";

import * as api from "../src/index.js";
import {
  compilePolicy,
  decide,
  evaluateApprovals,
  PermitkitError,
  reasonHints,
  reevaluate,
  requestDigest,
  toDecisionRecord,
  type ApprovalProofVerifier,
} from "../src/index.js";
import { accessRequest, everywhere, human, role, viaAgent } from "../src/testing/index.js";
import { catalog, editablePolicyInput, policy } from "./fixtures.js";

const polluted: string[] = [];

function pollute(key: string, value: unknown, enumerable = false): void {
  polluted.push(key);
  // The test simulates a prototype-pollution bug elsewhere in the process.
  // oxlint-disable-next-line no-extend-native
  Object.defineProperty(Object.prototype, key, {
    value,
    configurable: true,
    writable: true,
    enumerable,
  });
}

afterEach(() => {
  for (const key of polluted.splice(0)) delete (Object.prototype as Record<string, unknown>)[key];
});

const later = "2026-01-15T10:30:00.000Z";

describe("array holes", () => {
  it("does not fill a hole in roles from a polluted prototype", () => {
    const request = accessRequest(human("u9"), "ticket:delete");
    // Setting length leaves a hole: index 0 is not an own property.
    const roles: unknown[] = [];
    roles.length = 1;
    const holey = { ...request, subject: { ...request.subject, roles } };
    pollute("0", { role: "lead", scope: { kind: "all" } });
    expect(decide(policy, holey).outcome).toBe("deny");
  });

  it("does not fill a hole in the approvals from a polluted prototype", async () => {
    const request = accessRequest(human("u-req", role("lead", everywhere)), "ticket:refund", {
      properties: { amount: 500 },
    });
    const digestValue = requestDigest(policy, request);
    const approval = (id: string) => ({
      approver: human(id, role("lead", everywhere)),
      approvedAt: "2026-01-15T10:10:00.000Z",
      requestDigest: digestValue,
    });
    const approvals: unknown[] = [approval("u5")];
    approvals.length = 2;
    pollute("1", approval("u7"));
    const result = await evaluateApprovals(policy, { request, now: later, approvals });
    expect(result.outcome).not.toBe("allow");
  });
});

describe("verifier results", () => {
  it("does not read valid or the echo from a polluted prototype", async () => {
    const input = editablePolicyInput();
    input.approvalRules = [
      { ...input.approvalRules[0]!, approvers: 1, requireProof: true, proofTypes: ["t"] },
    ];
    const onePolicy = compilePolicy(catalog, input);
    const request = accessRequest(human("u-req", role("lead", everywhere)), "ticket:refund", {
      properties: { amount: 500 },
    });
    const digestValue = requestDigest(onePolicy, request);
    const approvals = [
      {
        approver: human("u5", role("lead", everywhere)),
        approvedAt: "2026-01-15T10:10:00.000Z",
        requestDigest: digestValue,
        proof: { type: "t", approverId: "u5", requestDigest: digestValue, payload: {} },
      },
    ];
    const verifier = { type: "t", verify: () => ({}) } as unknown as ApprovalProofVerifier;
    pollute("valid", true);
    pollute("approverId", "u5");
    pollute("requestDigest", digestValue);
    const result = await evaluateApprovals(
      onePolicy,
      { request, now: later, approvals },
      { verifiers: [verifier] },
    );
    expect(result.outcome).toBe("pending");
  });
});

describe("compiled policy under a polluted prototype", () => {
  it("keeps the separation-of-duties defaults and the digest", () => {
    const minimal = {
      schema: 2,
      version: "v",
      roles: {},
      denies: [],
      approvalRules: [],
      separationOfDuties: {
        requesterNeverApprovesSameType: false,
        exclusiveRequestAndApproveRoles: false,
      },
    };
    const clean = compilePolicy(catalog, minimal);
    pollute("requesterNeverApprovesSameType", true);
    const dirty = compilePolicy(catalog, minimal);
    expect(dirty.document.separationOfDuties.requesterNeverApprovesSameType).toBe(false);
    expect(dirty.digest).toBe(clean.digest);
  });

  it("does not read scope or limits names from a polluted prototype", () => {
    pollute("scope", { injected: ["a"] });
    pollute("limits", { injected: { min: null, max: 1 } });
    expect(compilePolicy(catalog, editablePolicyInput()).digest).toBe(policy.digest);
  });
});

describe("Zod error path and thenables under a polluted prototype", () => {
  it("denies instead of throwing when Zod's error options are polluted", () => {
    const request = accessRequest(human("u-lead", role("lead", everywhere)), "ticket:refund", {
      properties: { amount: "x", queue: 5 },
    });
    const broken = { ...request, resource: { ...request.resource, properties: { amount: [1] } } };
    for (const [key, value] of [
      ["errorMap", "x"],
      ["path", 5],
    ] as const) {
      pollute(key, value);
      expect(() => decide(policy, broken)).not.toThrow();
      expect(decide(policy, broken).outcome).toBe("deny");
    }
  });

  it("settles the approval promise when Object.prototype.then is polluted", async () => {
    const request = accessRequest(human("u-req", role("lead", everywhere)), "ticket:refund", {
      properties: { amount: 500 },
    });
    // oxlint-disable-next-line unicorn/no-thenable
    pollute("then", () => undefined);
    const settled = await Promise.race([
      evaluateApprovals(policy, { request, now: later, approvals: [] }).then(() => "settled"),
      new Promise((resolve) => {
        setTimeout(() => resolve("timeout"), 1000);
      }),
    ]);
    expect(settled).toBe("settled");
  });
});

describe("agent grants and request-time checks", () => {
  it("denies a grant issued by a principal of another type with the same id", () => {
    const humanGrant = viaAgent(human("u1", role("lead", everywhere)), "bot", {
      entries: [
        { permissions: ["ticket:read"], scope: { kind: "all" }, limits: { kind: "unlimited" } },
      ],
    });
    const asService = { ...humanGrant, type: "service" as const };
    expect(decide(policy, accessRequest(asService, "ticket:read")).reason).toBe(
      "agent_grant_principal_mismatch",
    );
  });

  it("denies approvals for a request that was not approvable when it was made", async () => {
    const subject = viaAgent(human("u-req", role("lead", everywhere)), "bot", {
      entries: [
        { permissions: ["ticket:refund"], scope: { kind: "all" }, limits: { kind: "unlimited" } },
      ],
      notBefore: "2026-01-15T10:05:00.000Z",
    });
    const request = accessRequest(subject, "ticket:refund", { properties: { amount: 500 } });
    expect(decide(policy, request).reason).toBe("agent_grant_not_yet_valid");
    const digestValue = requestDigest(policy, request);
    const approvals = ["u-a", "u-b"].map((id) => ({
      approver: human(id, role("lead", everywhere)),
      approvedAt: "2026-01-15T10:10:00.000Z",
      requestDigest: digestValue,
    }));
    const result = await evaluateApprovals(policy, { request, now: later, approvals });
    expect(result).toMatchObject({ outcome: "deny", reason: "not_approvable_at_request_time" });
  });
});

describe("public surface", () => {
  it("rejects a policy that compilePolicy did not return in reevaluate", () => {
    const request = accessRequest(human("u-lead", role("lead", everywhere)), "ticket:read");
    const record = toDecisionRecord(request, decide(policy, request));
    for (const fake of [null, { version: "zz", digest: "x" }]) {
      expect(() => reevaluate(fake as never, record)).toThrow(PermitkitError);
    }
  });

  it("freezes the reason objects and exports no live schemas", () => {
    expect(Object.isFrozen(reasonHints)).toBe(true);
    expect(Object.isFrozen(api.reasonCodes)).toBe(true);
    expect(Object.isFrozen(api.approvalReasonCodes)).toBe(true);
    expect(Object.isFrozen(api.approvalRejectionCodes)).toBe(true);
    expect(Object.keys(api)).not.toContain("accessRequestSchema");
    expect(Object.keys(api)).not.toContain("policySchema");
  });
});
