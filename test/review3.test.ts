// Regression tests for findings of the third cold security review.
import { afterEach, describe, expect, it } from "vitest";

import {
  compilePolicy,
  decide,
  decideAndRecord,
  evaluate,
  evaluateApprovals,
  requestDigest,
  type ApprovalProofVerifier,
} from "../src/index.js";
import { accessRequest, everywhere, human, role } from "../src/testing/index.js";
import { catalog, editablePolicyInput, policy } from "./fixtures.js";

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

const now = "2026-01-15T10:00:00.000Z";

describe("AuthZEN evaluate", () => {
  it("does not take roles or the time from a polluted prototype", () => {
    const noRoles = {
      subject: { type: "human", id: "mallory" },
      action: { name: "delete" },
      resource: { type: "ticket", id: "t-1" },
      context: { now },
    };
    const noContext = {
      subject: {
        type: "human",
        id: "u",
        properties: { roles: [{ role: "lead", scope: { kind: "all" } }], act: null },
      },
      action: { name: "read" },
      resource: { type: "ticket", id: "t-1" },
    };
    // Empty own objects are where an inherited value could be read.
    const emptyProperties = { ...noRoles, subject: { ...noRoles.subject, properties: {} } };
    const emptyContext = { ...noContext, context: {} };
    pollute("roles", [{ role: "lead", scope: { kind: "all" } }]);
    pollute("act", null);
    pollute("now", now);
    for (const request of [noRoles, emptyProperties]) {
      expect(evaluate(policy, request).decision).toBe(false);
    }
    for (const request of [noContext, emptyContext]) {
      expect(evaluate(policy, request).context.reason_codes).toEqual(["invalid_request"]);
    }
  });

  it("rejects keys that it does not map instead of ignoring them", () => {
    const base = {
      subject: {
        type: "human",
        id: "u-lead",
        properties: { roles: [{ role: "lead", scope: { kind: "all" } }], act: null } as Record<
          string,
          unknown
        >,
      },
      action: { name: "read" },
      resource: { type: "ticket", id: "t-1" },
      context: { now } as Record<string, unknown>,
    };
    expect(evaluate(policy, base).decision).toBe(true);
    const variants = [
      {
        ...base,
        subject: { ...base.subject, properties: { ...base.subject.properties, actor: {} } },
      },
      { ...base, context: { ...base.context, act: {} } },
      { ...base, context: { ...base.context, policyVersion: "other" } },
      { ...base, context: { ...base.context, policyDigest: "0".repeat(64) } },
      { ...base, extra: true },
    ];
    for (const variant of variants) {
      expect(evaluate(policy, variant as never).context.reason_codes).toEqual(["invalid_request"]);
    }
  });

  it("applies the snake_case pins", () => {
    const request = {
      subject: {
        type: "human",
        id: "u-lead",
        properties: { roles: [{ role: "lead", scope: { kind: "all" } }], act: null },
      },
      action: { name: "read" },
      resource: { type: "ticket", id: "t-1" },
      context: { now, policy_digest: "0".repeat(64) },
    };
    expect(evaluate(policy, request).context.reason_codes).toEqual(["policy_version_mismatch"]);
  });
});

describe("schema checks under a polluted prototype", () => {
  it("does not count a polluted act toward the actor chain", () => {
    pollute("act", { type: "agent", id: "x", grant: null, act: null });
    expect(
      decide(policy, accessRequest(human("u-lead", role("lead", everywhere)), "ticket:read"))
        .outcome,
    ).toBe("allow");
  });
});

describe("decideAndRecord", () => {
  it("does not read the request a second time after a failed parse", () => {
    let reads = 0;
    const request = accessRequest(human("u-lead", role("lead", everywhere)), "ticket:read");
    const flipping = {
      ...request,
      get action() {
        reads += 1;
        return { name: reads === 1 ? 42 : "delete" };
      },
    };
    const { decision, record } = decideAndRecord(policy, flipping);
    expect(decision.reason).toBe("invalid_request");
    expect(record.request).toBeNull();
    // Getters are rejected without being run, so there is no first read either.
    expect(reads).toBe(0);
  });
});

describe("proof verifiers and options", () => {
  const input = editablePolicyInput();
  input.approvalRules = [{ ...input.approvalRules[0]!, requireProof: true, proofTypes: ["t"] }];
  const proofPolicy = compilePolicy(catalog, input);
  const request = accessRequest(human("u-req", role("lead", everywhere)), "ticket:refund", {
    properties: { amount: 500 },
  });
  const digestValue = requestDigest(proofPolicy, request);
  const approvals = ["u-a", "u-b"].map((id) => ({
    approver: human(id, role("lead", everywhere)),
    approvedAt: "2026-01-15T10:10:00.000Z",
    requestDigest: digestValue,
    proof: { type: "t", approverId: id, requestDigest: digestValue, payload: {} },
  }));
  const evaluateWith = (verify: () => unknown) =>
    evaluateApprovals(
      proofPolicy,
      { request, now: "2026-01-15T10:30:00.000Z", approvals },
      { verifiers: [{ type: "t", verify } as unknown as ApprovalProofVerifier] },
    );

  it("rejects instead of throwing when the verifier result or error is hostile", async () => {
    const revoked = Proxy.revocable({}, {});
    revoked.revoke();
    const hostile: (() => unknown)[] = [
      () => ({
        get valid(): boolean {
          throw new Error("boom");
        },
      }),
      () => {
        const error = new Error("x");
        Object.defineProperty(error, "message", {
          get() {
            throw new Error("boom");
          },
        });
        throw error;
      },
      () => {
        throw revoked.proxy;
      },
    ];
    for (const verify of hostile) {
      const result = await evaluateWith(verify);
      expect(result.outcome).toBe("pending");
      expect(result.rejected.map((item) => item.reason)).toEqual([
        "proof_invalid",
        "proof_invalid",
      ]);
    }
  });

  it("throws a coded error for bad options and duplicate verifier types", async () => {
    const base = { request, now: "2026-01-15T10:30:00.000Z", approvals };
    const ok = { type: "t", verify: () => ({ valid: false, reason: "no" }) };
    for (const options of [
      null,
      { verifiers: "x" },
      { verifiers: [{}] },
      { verifiers: [ok, ok] },
    ]) {
      await expect(evaluateApprovals(proofPolicy, base, options as never)).rejects.toMatchObject({
        code: "options_invalid",
      });
    }
  });
});

describe("limits with a minimum", () => {
  it("denies values below the minimum and rejects min above max", () => {
    const input = editablePolicyInput();
    input.roles["support"]!.grants[1]!.limits = {
      kind: "range",
      properties: { amount: { min: 0, max: 500 } },
    };
    const bounded = compilePolicy(catalog, input);
    const support = human("u-s", role("support", everywhere));
    const negative = accessRequest(support, "ticket:refund", { properties: { amount: -1e9 } });
    expect(decide(policy, negative).outcome).toBe("allow");
    expect(decide(bounded, negative).reason).toBe("limit_exceeded");
    expect(
      decide(bounded, accessRequest(support, "ticket:refund", { properties: { amount: 0 } }))
        .outcome,
    ).toBe("allow");
    input.roles["support"]!.grants[1]!.limits = {
      kind: "range",
      properties: { amount: { min: 10, max: 5 } },
    };
    expect(() => compilePolicy(catalog, input)).toThrow(/not valid/);
  });
});

describe("calendar days in early years", () => {
  it("accepts 29 February of the year 0, which is a leap year", () => {
    const request = accessRequest(
      human("u-lead", role("lead", everywhere)),
      "ticket:read",
      {},
      {
        now: "0000-02-29T00:00:00Z",
      },
    );
    expect(decide(policy, request).outcome).toBe("allow");
  });
});
