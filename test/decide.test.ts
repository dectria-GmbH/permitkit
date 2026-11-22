import { describe, expect, it } from "vitest";

import { compilePolicy, decide, PermitkitError, type CompiledPolicy } from "../src/index.js";
import { accessRequest, fixedNow, human, role, service } from "../src/testing/index.js";
import { catalog, editablePolicyInput, policy } from "./fixtures.js";

const support = human("u-support", role("support"));
const lead = human("u-lead", role("lead"));

describe("deny by default", () => {
  it("denies a subject without roles", () => {
    const decision = decide(policy, accessRequest(human("u-none"), "ticket:read"));
    expect(decision).toMatchObject({
      outcome: "deny",
      allowed: false,
      reason: "no_grant",
      rule: null,
    });
  });

  it("denies a subject whose role is not in the policy", () => {
    const decision = decide(policy, accessRequest(human("u-x", role("ghost")), "ticket:read"));
    expect(decision.reason).toBe("no_grant");
  });

  it("denies a role name that only exists on Object.prototype", () => {
    for (const name of ["constructor", "toString", "__proto__", "hasOwnProperty"]) {
      const decision = decide(policy, accessRequest(human("u-x", role(name)), "ticket:read"));
      expect({ name, outcome: decision.outcome }).toEqual({ name, outcome: "deny" });
    }
  });

  it("denies a permission that the subject's roles do not include", () => {
    const decision = decide(policy, accessRequest(support, "ticket:delete"));
    expect(decision.reason).toBe("no_grant");
  });

  it("denies a permission that is not in the catalogue", () => {
    const decision = decide(policy, accessRequest(lead, "ticket:archive"));
    expect(decision.reason).toBe("unknown_permission");
  });

  it("allows a covered request and names the grant", () => {
    const decision = decide(policy, accessRequest(support, "ticket:read"));
    expect(decision).toMatchObject({
      outcome: "allow",
      allowed: true,
      reason: "granted",
      rule: { kind: "grant", role: "support", id: "support-work" },
      policy: { version: "2026-01-01.1", digest: policy.digest },
    });
    expect(decision.requestDigest).toMatch(/^[0-9a-f]{64}$/);
  });

  it("allows a service principal with a role", () => {
    const decision = decide(
      policy,
      accessRequest(service("svc-sync", role("support")), "ticket:read"),
    );
    expect(decision.outcome).toBe("allow");
  });
});

describe("invalid input", () => {
  it("denies a request with an unknown key", () => {
    const request = { ...accessRequest(support, "ticket:read"), extra: true };
    expect(decide(policy, request).reason).toBe("invalid_request");
  });

  it("denies a role assignment without an explicit scope", () => {
    const request = accessRequest(support, "ticket:read");
    const broken = { ...request, subject: { ...request.subject, roles: [{ role: "support" }] } };
    expect(decide(policy, broken).reason).toBe("invalid_request");
  });

  it("denies a request without a time or with a time without offset", () => {
    const request = accessRequest(support, "ticket:read");
    expect(decide(policy, { ...request, context: {} }).reason).toBe("invalid_request");
    expect(decide(policy, { ...request, context: { now: "2026-01-15T10:00:00" } }).reason).toBe(
      "invalid_request",
    );
  });

  it("denies non-objects", () => {
    for (const value of [null, undefined, 42, "x", []]) {
      expect(decide(policy, value).reason).toBe("invalid_request");
    }
  });

  it("throws for a policy that compilePolicy did not return", () => {
    const forged = { ...policy } as CompiledPolicy;
    expect(() => decide(forged, accessRequest(support, "ticket:read"))).toThrow(PermitkitError);
  });
});

describe("policy version", () => {
  it("denies when the request pins another policy version", () => {
    const request = accessRequest(lead, "ticket:read", {}, { policyVersion: "2025-12-01.1" });
    expect(decide(policy, request)).toMatchObject({
      outcome: "deny",
      reason: "policy_version_mismatch",
    });
  });

  it("allows when the request pins the loaded policy version", () => {
    const request = accessRequest(lead, "ticket:read", {}, { policyVersion: "2026-01-01.1" });
    expect(decide(policy, request).outcome).toBe("allow");
  });
});

describe("scopes", () => {
  const scopedSupport = human("u-s", role("support", { queue: ["billing", "general"] }));

  it("allows inside the assignment scope", () => {
    const request = accessRequest(scopedSupport, "ticket:read", {
      properties: { queue: "billing" },
    });
    expect(decide(policy, request).outcome).toBe("allow");
  });

  it("denies when the resource is outside the assignment scope", () => {
    const request = accessRequest(scopedSupport, "ticket:read", { properties: { queue: "legal" } });
    expect(decide(policy, request)).toMatchObject({ outcome: "deny", reason: "scope_mismatch" });
  });

  it("denies when a scoped property is missing on the resource", () => {
    expect(decide(policy, accessRequest(scopedSupport, "ticket:read")).reason).toBe(
      "scope_mismatch",
    );
  });

  it("denies when a scoped property is not a string", () => {
    for (const value of [1, true, null]) {
      const request = accessRequest(scopedSupport, "ticket:read", { properties: { queue: value } });
      expect(decide(policy, request).reason).toBe("scope_mismatch");
    }
  });

  it("denies when the resource is outside the grant scope", () => {
    const auditor = human("u-a", role("auditor"));
    const inside = accessRequest(auditor, "report:read", { properties: { project: "alpha" } });
    const outside = accessRequest(auditor, "report:read", { properties: { project: "beta" } });
    expect(decide(policy, inside).outcome).toBe("allow");
    expect(decide(policy, outside).reason).toBe("scope_mismatch");
  });

  it("does not read inherited properties for scope checks", () => {
    const tricky = human(
      "u-t",
      role("support", { queue: ["function Object() { [native code] }"] }),
    );
    const request = accessRequest(tricky, "ticket:read", { properties: {} });
    expect(decide(policy, request).reason).toBe("scope_mismatch");
  });

  it("uses any assignment that covers the resource", () => {
    const twoScopes = human(
      "u-2",
      role("support", { queue: ["billing"] }),
      role("support", { queue: ["legal"] }),
    );
    const request = accessRequest(twoScopes, "ticket:read", { properties: { queue: "legal" } });
    expect(decide(policy, request).outcome).toBe("allow");
  });
});

describe("limits", () => {
  it("allows at the limit and denies above it", () => {
    const atLimit = accessRequest(support, "ticket:refund", { properties: { amount: 50 } });
    expect(decide(policy, atLimit).outcome).toBe("allow");
    const above = accessRequest(support, "ticket:refund", { properties: { amount: 500.01 } });
    expect(decide(policy, above).reason).toBe("limit_exceeded");
  });

  it("denies when the limited property is missing or not a number", () => {
    expect(decide(policy, accessRequest(support, "ticket:refund")).reason).toBe("limit_exceeded");
    const text = accessRequest(support, "ticket:refund", { properties: { amount: "10" } });
    expect(decide(policy, text).reason).toBe("limit_exceeded");
  });
});

describe("deny rules", () => {
  it("denies by rule even when a grant covers the request", () => {
    const request = accessRequest(support, "ticket:close", { properties: { queue: "vip" } });
    expect(decide(policy, request)).toMatchObject({
      outcome: "deny",
      reason: "denied_by_rule",
      rule: { kind: "deny", id: "vip-queue-frozen" },
    });
  });

  it("applies a scoped deny rule when the scoped property is missing", () => {
    expect(decide(policy, accessRequest(support, "ticket:close")).reason).toBe("denied_by_rule");
  });

  it("does not apply a scoped deny rule outside its scope", () => {
    const request = accessRequest(support, "ticket:close", { properties: { queue: "general" } });
    expect(decide(policy, request).outcome).toBe("allow");
  });

  it("does not apply a role-bound deny rule to other roles", () => {
    const request = accessRequest(lead, "ticket:close", { properties: { queue: "vip" } });
    expect(decide(policy, request).outcome).toBe("allow");
  });
});

describe("approval rules", () => {
  it("returns approval_required at or above the threshold", () => {
    const request = accessRequest(lead, "ticket:refund", { properties: { amount: 100 } });
    const decision = decide(policy, request);
    expect(decision).toMatchObject({
      outcome: "approval_required",
      allowed: false,
      reason: "approval_required",
      rule: { kind: "grant", id: "lead-all" },
      approval: {
        ruleId: "refund-dual",
        approvers: 2,
        approverRoles: null,
        requireProof: false,
        expiresAt: "2026-01-15T11:00:00.000Z",
      },
    });
  });

  it("allows below the threshold", () => {
    const request = accessRequest(lead, "ticket:refund", { properties: { amount: 99.99 } });
    expect(decide(policy, request).outcome).toBe("allow");
  });

  it("requires approval when the threshold property is missing", () => {
    expect(decide(policy, accessRequest(lead, "ticket:refund")).outcome).toBe("approval_required");
  });
});

describe("separation of duties at request time", () => {
  const input = editablePolicyInput();
  input.separationOfDuties = { exclusiveRequestAndApproveRoles: true };
  input.approvalRules = [{ ...input.approvalRules![0]!, approverRoles: ["approver"] }];
  const strict = compilePolicy(catalog, input);

  it("denies a requester who also holds an approving role", () => {
    const both = human("u-both", role("lead"), role("approver"));
    const request = accessRequest(both, "ticket:refund", { properties: { amount: 10 } });
    expect(decide(strict, request).reason).toBe("sod_role_conflict");
  });

  it("allows the same request when the setting is off", () => {
    const both = human("u-both", role("lead"), role("approver"));
    const request = accessRequest(both, "ticket:refund", { properties: { amount: 10 } });
    expect(decide(policy, request).outcome).toBe("allow");
  });
});

describe("determinism", () => {
  it("returns equal decisions for equal inputs and does not depend on the clock", () => {
    const request = accessRequest(lead, "ticket:refund", { properties: { amount: 300 } });
    const first = decide(policy, request);
    const second = decide(policy, structuredClone(request));
    expect(second).toEqual(first);
    expect(first.approval?.expiresAt).toBe(new Date(Date.parse(fixedNow) + 3600_000).toISOString());
  });

  it("rejects getters without running them", () => {
    let reads = 0;
    const properties = {
      get queue() {
        reads += 1;
        return reads === 1 ? "general" : "vip";
      },
    };
    const request = accessRequest(support, "ticket:close");
    const decision = decide(policy, { ...request, resource: { type: "ticket", properties } });
    expect(decision.reason).toBe("invalid_request");
    expect(reads).toBe(0);
  });
});
