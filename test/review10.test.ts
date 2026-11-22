// Regression tests for findings of the tenth cold security review.
import { afterEach, describe, expect, it } from "vitest";

import { compilePolicy, decide, evaluate, evaluateApprovals, requestDigest } from "../src/index.js";
import { accessRequest, human, role, viaAgent } from "../src/testing/index.js";
import { catalog, editablePolicyInput, policy } from "./fixtures.js";

afterEach(() => {
  delete (Object.prototype as Record<string, unknown>)["value"];
});

function polluteValue(value: unknown): void {
  // The test simulates a prototype-pollution bug elsewhere in the process.
  // oxlint-disable-next-line no-extend-native
  Object.defineProperty(Object.prototype, "value", { value, configurable: true, writable: true });
}

describe("accessors with a polluted Object.prototype.value", () => {
  it("denies a getter on subject.roles", () => {
    const base = accessRequest(human("u2"), "ticket:delete");
    const subject = {
      type: "human",
      id: "u2",
      get roles() {
        return [];
      },
    };
    polluteValue([{ role: "lead", scope: {} }]);
    expect(decide(policy, { ...base, subject }).outcome).toBe("deny");
  });

  it("denies a getter on an agent grant's revokedAt", () => {
    const subject = viaAgent(human("u-lead", role("lead")), "bot", {
      entries: [{ permissions: ["ticket:read"] }],
    });
    const grant = {
      ...subject.act!.grant!,
      get revokedAt() {
        return "2020-01-01T00:00:00Z";
      },
    };
    const request = accessRequest({ ...subject, act: { ...subject.act!, grant } }, "ticket:read");
    polluteValue(undefined);
    expect(decide(policy, request).outcome).toBe("deny");
  });

  it("does not count an approval whose approver id is a getter", async () => {
    const request = accessRequest(human("u-alice", role("lead")), "ticket:refund", {
      properties: { amount: 500 },
    });
    const digestValue = requestDigest(policy, request);
    const approval = (id: string) => ({
      approver: {
        type: "human",
        get id() {
          return id;
        },
        roles: [{ role: "lead", scope: {} }],
      },
      approvedAt: "2026-01-15T10:10:00.000Z",
      requestDigest: digestValue,
    });
    polluteValue("mallory");
    const result = await evaluateApprovals(policy, {
      request,
      now: "2026-01-15T10:30:00.000Z",
      approvals: [approval("u-alice"), approval("u-alice")],
    });
    expect(result.outcome).not.toBe("allow");
  });

  it("rejects a policy grant whose scope is a getter", () => {
    const input = editablePolicyInput();
    const grant = {
      id: "getter-scope",
      permissions: ["ticket:close"],
      get scope() {
        return { queue: ["general"] };
      },
    };
    input.roles = { ...input.roles, getter: { grants: [grant] } };
    // Capture the outcome first: with Object.prototype.value polluted, the test framework's own
    // property definitions fail, so the assertion runs after the clean-up.
    polluteValue(undefined);
    let outcome: unknown;
    try {
      compilePolicy(catalog, input);
      outcome = "compiled";
    } catch (error) {
      outcome = (error as { code?: unknown }).code;
    } finally {
      delete (Object.prototype as Record<string, unknown>)["value"];
    }
    expect(outcome).toBe("policy_invalid");
  });
});

describe("proofTypes without requireProof", () => {
  it("is rejected at compile time", () => {
    const input = editablePolicyInput();
    input.approvalRules = [{ ...input.approvalRules![0]!, proofTypes: ["webauthn"] }];
    expect(() => compilePolicy(catalog, input)).toThrow(/not valid/);
  });
});

describe("AuthZEN evaluate with a replaced array method", () => {
  it("denies instead of throwing", () => {
    const original = Array.prototype.includes;
    let response: ReturnType<typeof evaluate> | undefined;
    try {
      // oxlint-disable-next-line no-extend-native
      Object.defineProperty(Array.prototype, "includes", {
        value: 1,
        configurable: true,
        writable: true,
      });
      response = evaluate(policy, {
        subject: { type: "human", id: "u", properties: { roles: [{ role: "lead", scope: {} }] } },
        action: { name: "read" },
        resource: { type: "ticket", id: "t" },
        context: { now: "2026-01-15T10:00:00.000Z" },
      });
    } finally {
      // oxlint-disable-next-line no-extend-native
      Object.defineProperty(Array.prototype, "includes", {
        value: original,
        configurable: true,
        writable: true,
      });
    }
    expect(response?.decision).toBe(false);
  });
});
