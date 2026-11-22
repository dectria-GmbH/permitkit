// Regression tests for findings of the eighth cold security review.
import { afterEach, describe, expect, it } from "vitest";

import { compilePolicy, decide, evaluateApprovals, requestDigest } from "../src/index.js";
import { accessRequest, human, role } from "../src/testing/index.js";
import { catalog, editablePolicyInput, policy } from "./fixtures.js";

afterEach(() => {
  delete (Object.prototype as Record<string, unknown>)["scope"];
});

function deletingAssignment(): object {
  return {
    get role() {
      delete (this as Record<string, unknown>)["scope"];
      return "support";
    },
    scope: { queue: ["billing"] },
  };
}

function reparentingAssignment(): object {
  return {
    get role() {
      Object.setPrototypeOf(this, { scope: {} });
      delete (this as Record<string, unknown>)["scope"];
      return "support";
    },
    scope: { queue: ["billing"] },
  };
}

describe("accessor properties in the input", () => {
  it("does not let a getter swap a scope for an inherited value", () => {
    // The test simulates a prototype-pollution bug elsewhere in the process.
    // oxlint-disable-next-line no-extend-native
    Object.defineProperty(Object.prototype, "scope", {
      value: {},
      configurable: true,
      writable: true,
    });
    const base = accessRequest(human("u"), "ticket:close", { properties: { queue: "other" } });
    for (const assignment of [deletingAssignment(), reparentingAssignment()]) {
      const request = { ...base, subject: { ...base.subject, roles: [assignment] } };
      expect(decide(policy, request).outcome).toBe("deny");
    }
  });

  it("does not count an approver whose assignment uses such a getter", async () => {
    const input = editablePolicyInput();
    input.approvalRules = [
      { ...input.approvalRules![0]!, approvers: 1, approverRoles: ["approver"] },
    ];
    const withRoles = compilePolicy(catalog, input);
    const request = accessRequest(human("u-req", role("lead")), "ticket:refund", {
      properties: { amount: 500, queue: "other" },
    });
    const digestValue = requestDigest(withRoles, request);
    const sneaky = {
      get role() {
        Object.setPrototypeOf(this, { scope: {} });
        delete (this as Record<string, unknown>)["scope"];
        return "approver";
      },
      scope: { queue: ["billing"] },
    };
    const result = await evaluateApprovals(withRoles, {
      request,
      now: "2026-01-15T10:30:00.000Z",
      approvals: [
        {
          approver: { type: "human", id: "u-a", roles: [sneaky] },
          approvedAt: "2026-01-15T10:10:00.000Z",
          requestDigest: digestValue,
        },
      ],
    });
    expect(result.outcome).not.toBe("allow");
  });
});
