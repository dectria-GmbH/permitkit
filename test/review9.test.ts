// Regression tests for findings of the ninth cold security review.
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
} from "../src/index.js";
import { accessRequest, everywhere, human, role, viaAgent, within } from "../src/testing/index.js";
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

describe("bounds set to undefined", () => {
  it("rejects a limit of { max: undefined } in a policy and in an agent grant", () => {
    const input = editablePolicyInput();
    input.roles["support"]!.grants[1]!.limits = {
      kind: "range",
      properties: { amount: { max: undefined } },
    };
    expect(() => compilePolicy(catalog, input)).toThrow(/not valid/);
    const subject = viaAgent(human("u-lead", role("lead", everywhere)), "bot", {
      entries: [
        {
          permissions: ["ticket:refund"],
          limits: { kind: "range", properties: { amount: { max: undefined } } },
          scope: { kind: "all" },
        },
      ],
    });
    const request = accessRequest(subject, "ticket:refund", { properties: { amount: 50 } });
    expect(decide(policy, request).reason).toBe("invalid_request");
  });
});

describe("reevaluate under a polluted prototype", () => {
  it("does not read missing record fields from the prototype", () => {
    const request = accessRequest(human("u-lead", role("lead", everywhere)), "ticket:read");
    const record = toDecisionRecord(request, decide(policy, request));
    const { rule, approval, ...withoutRule } = record;
    const { request: stored, ...withoutRequest } = record;
    pollute("rule", rule);
    pollute("approval", approval);
    pollute("request", stored);
    expect(reevaluate(policy, withoutRule as never).status).not.toBe("reproduced");
    expect(reevaluate(policy, withoutRequest as never).status).not.toBe("reproduced");
  });
});

/** A lead assignment whose match scope lists billing plus `others` more values. */
function assignment(others: number) {
  return role(
    "lead",
    within({ queue: ["billing", ...Array.from({ length: others }, (_, index) => `q${index}`)] }),
  );
}

describe("requests at the size limit", () => {
  // 252 assignments of 79 values each, one of 78, plus the request frame of 14: the read request
  // has exactly 20,000 values, the limit. Its record and an approval input around it are larger.
  const roles = [...Array.from({ length: 252 }, () => assignment(72)), assignment(71)];
  const subject = human("u-big", ...roles);

  it("replays the record of a request at the limit", () => {
    const request = accessRequest(subject, "ticket:read", { properties: { queue: "billing" } });
    const { decision, record } = decideAndRecord(policy, request);
    expect(decision.outcome).toBe("allow");
    expect(reevaluate(policy, record).status).toBe("reproduced");
  });

  it("evaluates approvals for a request at the limit", async () => {
    // One value fewer, because the refund request carries one more property.
    const trimmed = human("u-big", ...roles.slice(0, -1), assignment(70));
    const request = accessRequest(trimmed, "ticket:refund", {
      properties: { amount: 500, queue: "billing" },
    });
    expect(decide(policy, request).outcome).toBe("approval_required");
    const result = await evaluateApprovals(policy, {
      request,
      now: "2026-01-15T10:30:00.000Z",
      approvals: [],
    });
    expect(result.reason).toBe("approvals_pending");
  });
});

describe("nested actor grants", () => {
  it("denies a chain whose prior actor acted for another principal", () => {
    const current = viaAgent(human("u-alice", role("lead", everywhere)), "bot1", {
      entries: [
        { permissions: ["ticket:refund"], scope: { kind: "all" }, limits: { kind: "unlimited" } },
      ],
    });
    const prior = viaAgent(human("u-carol"), "bot0", {
      entries: [
        { permissions: ["ticket:refund"], scope: { kind: "all" }, limits: { kind: "unlimited" } },
      ],
    });
    const subject = { ...current, act: { ...current.act!, act: prior.act } };
    const request = accessRequest(subject, "ticket:refund", { properties: { amount: 500 } });
    expect(decide(policy, request).reason).toBe("agent_grant_principal_mismatch");
  });
});

describe("proof types", () => {
  it("rejects a proof type that the rule does not accept", async () => {
    const input = editablePolicyInput();
    input.approvalRules = [
      { ...input.approvalRules[0]!, approvers: 1, requireProof: true, proofTypes: ["strong"] },
    ];
    const typed = compilePolicy(catalog, input);
    const request = accessRequest(human("u-req", role("lead", everywhere)), "ticket:refund", {
      properties: { amount: 500 },
    });
    const digestValue = requestDigest(typed, request);
    const weak: ApprovalProofVerifier = {
      type: "weak",
      verify: (_proof, expected) => ({ valid: true, ...expected }),
    };
    const result = await evaluateApprovals(
      typed,
      {
        request,
        now: "2026-01-15T10:30:00.000Z",
        approvals: [
          {
            approver: human("u-a", role("lead", everywhere)),
            approvedAt: "2026-01-15T10:10:00.000Z",
            requestDigest: digestValue,
            proof: { type: "weak", approverId: "u-a", requestDigest: digestValue, payload: {} },
          },
        ],
      },
      { verifiers: [weak] },
    );
    expect(result.rejected.map((item) => item.reason)).toEqual(["proof_type_not_allowed"]);
  });
});
