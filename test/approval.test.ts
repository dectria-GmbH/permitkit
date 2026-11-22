import { describe, expect, it } from "vitest";

import {
  compilePolicy,
  decide,
  evaluateApprovals,
  requestDigest,
  type ApprovalProof,
  type ApprovalProofVerifier,
  type Subject,
} from "../src/index.js";
import { accessRequest, everywhere, human, role, viaAgent, within } from "../src/testing/index.js";
import { catalog, editablePolicyInput, policy } from "./fixtures.js";

const requester = human("u-req", role("lead", everywhere));
const peerA = human("u-a", role("lead", everywhere));
const peerB = human("u-b", role("lead", everywhere));
const request = accessRequest(requester, "ticket:refund", {
  id: "t-1",
  properties: { amount: 250 },
});
const digest = requestDigest(policy, request);
const later = "2026-01-15T10:30:00.000Z";

function approval(approver: Subject, extra: Record<string, unknown> = {}) {
  return { approver, approvedAt: "2026-01-15T10:10:00.000Z", requestDigest: digest, ...extra };
}

describe("dual approval", () => {
  it("binds the decision to the request digest", () => {
    expect(decide(policy, request).requestDigest).toBe(digest);
  });

  it("allows with enough distinct eligible approvers", async () => {
    const result = await evaluateApprovals(policy, {
      request,
      now: later,
      approvals: [approval(peerA), approval(peerB)],
    });
    expect(result).toMatchObject({
      outcome: "allow",
      allowed: true,
      reason: "approved",
      ruleId: "refund-dual",
      required: 2,
      counted: ["u-a", "u-b"],
      rejected: [],
      requestDigest: digest,
    });
  });

  it("stays pending with too few approvers", async () => {
    const result = await evaluateApprovals(policy, {
      request,
      now: later,
      approvals: [approval(peerA)],
    });
    expect(result).toMatchObject({
      outcome: "pending",
      allowed: false,
      reason: "approvals_pending",
    });
  });

  it("does not count the requester as an approver", async () => {
    const result = await evaluateApprovals(policy, {
      request,
      now: later,
      approvals: [approval(requester), approval(peerA)],
    });
    expect(result.outcome).toBe("pending");
    expect(result.rejected).toEqual([
      { index: 0, approverId: "u-req", reason: "requester_cannot_approve" },
    ]);
  });

  it("does not count the principal behind a requesting agent", async () => {
    const agentRequest = accessRequest(
      viaAgent(requester, "agent-1", {
        entries: [
          { permissions: ["ticket:refund"], scope: { kind: "all" }, limits: { kind: "unlimited" } },
        ],
      }),
      "ticket:refund",
      { id: "t-1", properties: { amount: 250 } },
    );
    expect(decide(policy, agentRequest).outcome).toBe("approval_required");
    const agentDigest = requestDigest(policy, agentRequest);
    const result = await evaluateApprovals(policy, {
      request: agentRequest,
      now: later,
      approvals: [
        { ...approval(requester), requestDigest: agentDigest },
        { ...approval(peerA), requestDigest: agentDigest },
      ],
    });
    expect(result.outcome).toBe("pending");
    expect(result.rejected[0]?.reason).toBe("requester_cannot_approve");
  });

  it("counts one approver only once", async () => {
    const result = await evaluateApprovals(policy, {
      request,
      now: later,
      approvals: [approval(peerA), approval(peerA), approval({ ...peerA, roles: [] })],
    });
    expect(result).toMatchObject({ outcome: "pending", counted: ["u-a"] });
    expect(result.rejected.map((item) => item.reason)).toEqual([
      "duplicate_approver",
      "duplicate_approver",
    ]);
  });

  it("does not let one subject satisfy a one-approver rule alone", async () => {
    const input = editablePolicyInput();
    input.approvalRules = [{ ...input.approvalRules[0]!, approvers: 1 }];
    const single = compilePolicy(catalog, input);
    const singleDigest = requestDigest(single, request);
    const result = await evaluateApprovals(single, {
      request,
      now: later,
      approvals: [{ ...approval(requester), requestDigest: singleDigest }],
    });
    expect(result.outcome).toBe("pending");
  });

  it("rejects agents and services as approvers", async () => {
    const agentApprover = viaAgent(peerA, "agent-9", {
      entries: [
        { permissions: ["ticket:refund"], scope: { kind: "all" }, limits: { kind: "unlimited" } },
      ],
    });
    const result = await evaluateApprovals(policy, {
      request,
      now: later,
      approvals: [
        approval(agentApprover),
        approval({ type: "service", id: "svc-1", roles: [role("lead", everywhere)], act: null }),
      ],
    });
    expect(result.rejected.map((item) => item.reason)).toEqual([
      "approver_is_delegated",
      "approver_not_human",
    ]);
  });

  it("rejects an approval for another request digest", async () => {
    const other = accessRequest(requester, "ticket:refund", {
      id: "t-1",
      properties: { amount: 251 },
    });
    const result = await evaluateApprovals(policy, {
      request,
      now: later,
      approvals: [
        { ...approval(peerA), requestDigest: requestDigest(policy, other) },
        approval(peerB),
      ],
    });
    expect(result.rejected[0]?.reason).toBe("digest_mismatch");
    expect(result.outcome).toBe("pending");
  });

  it("gives a new request instance a new digest", () => {
    const again = accessRequest(
      requester,
      "ticket:refund",
      { id: "t-1", properties: { amount: 250 } },
      {
        now: "2026-01-15T10:00:01.000Z",
      },
    );
    expect(requestDigest(policy, again)).not.toBe(digest);
  });

  it("denies after the approval window closes", async () => {
    const result = await evaluateApprovals(policy, {
      request,
      now: "2026-01-15T11:00:00.001Z",
      approvals: [approval(peerA), approval(peerB)],
    });
    expect(result).toMatchObject({ outcome: "deny", reason: "approval_window_expired" });
  });

  it("allows at the end of the approval window", async () => {
    const result = await evaluateApprovals(policy, {
      request,
      now: "2026-01-15T11:00:00.000Z",
      approvals: [approval(peerA), approval(peerB)],
    });
    expect(result.outcome).toBe("allow");
  });

  it("rejects approvals outside the window or after the evaluation time", async () => {
    const result = await evaluateApprovals(policy, {
      request,
      now: later,
      approvals: [
        approval(peerA, { approvedAt: "2026-01-15T09:59:59.000Z" }),
        approval(peerB, { approvedAt: "2026-01-15T10:30:00.001Z" }),
      ],
    });
    expect(result.rejected.map((item) => item.reason)).toEqual([
      "approved_before_request",
      "approved_in_future",
    ]);
  });

  it("denies when the requester lost the permission", async () => {
    const result = await evaluateApprovals(policy, {
      request: { ...request, subject: human("u-req") },
      now: later,
      approvals: [approval(peerA), approval(peerB)],
    });
    expect(result).toMatchObject({ outcome: "deny", reason: "requester_denied" });
    expect(result.requesterDecision?.reason).toBe("no_grant");
  });

  it("reports approval_not_required below the threshold", async () => {
    const small = accessRequest(requester, "ticket:refund", { properties: { amount: 5 } });
    const result = await evaluateApprovals(policy, { request: small, now: later, approvals: [] });
    expect(result).toMatchObject({ outcome: "allow", reason: "approval_not_required" });
  });

  it("rejects malformed input and malformed approvals", async () => {
    expect((await evaluateApprovals(policy, { request, now: later })).reason).toBe("invalid_input");
    expect(
      (await evaluateApprovals(policy, { request, now: "2026-01-15T09:00:00.000Z", approvals: [] }))
        .reason,
    ).toBe("invalid_input");
    const result = await evaluateApprovals(policy, {
      request,
      now: later,
      approvals: [{ approver: peerA }],
    });
    expect(result.rejected[0]?.reason).toBe("approval_invalid");
  });

  it("invalidates approvals when the policy changes", async () => {
    const input = editablePolicyInput();
    input.version = "2026-01-02.1";
    const next = compilePolicy(catalog, input);
    const result = await evaluateApprovals(next, {
      request,
      now: later,
      approvals: [approval(peerA), approval(peerB)],
    });
    expect(result.rejected.map((item) => item.reason)).toEqual([
      "digest_mismatch",
      "digest_mismatch",
    ]);
  });
});

describe("approver eligibility", () => {
  it("requires peers to hold the permission when no approver roles are set", async () => {
    const result = await evaluateApprovals(policy, {
      request,
      now: later,
      approvals: [approval(human("u-x")), approval(peerA), approval(peerB)],
    });
    expect(result.outcome).toBe("allow");
    expect(result.rejected[0]).toMatchObject({
      reason: "approver_not_permitted",
      detail: "no_grant",
    });
  });

  const input = editablePolicyInput();
  input.approvalRules = [
    { ...input.approvalRules[0]!, eligibleApprovers: { kind: "roles", roles: ["approver"] } },
  ];
  const withRoles = compilePolicy(catalog, input);
  const rolesDigest = requestDigest(withRoles, request);
  const roleApproval = (approver: Subject) => ({
    ...approval(approver),
    requestDigest: rolesDigest,
  });

  it("requires an approver role in a scope that covers the resource", async () => {
    const scoped = accessRequest(requester, "ticket:refund", {
      id: "t-1",
      properties: { amount: 250, queue: "billing" },
    });
    const scopedDigest = requestDigest(withRoles, scoped);
    const make = (approver: Subject) => ({ ...approval(approver), requestDigest: scopedDigest });
    const result = await evaluateApprovals(withRoles, {
      request: scoped,
      now: later,
      approvals: [
        make(peerA),
        make(human("u-c", role("approver", within({ queue: ["legal"] })))),
        make(human("u-d", role("approver", within({ queue: ["billing"] })))),
        make(human("u-e", role("approver", everywhere))),
      ],
    });
    expect(result.outcome).toBe("allow");
    expect(result.counted).toEqual(["u-d", "u-e"]);
    expect(result.rejected.map((item) => item.reason)).toEqual([
      "approver_role_missing",
      "approver_role_missing",
    ]);
  });

  it("checks exclusive roles at approval time", async () => {
    const strictInput = editablePolicyInput();
    strictInput.approvalRules = [
      {
        ...strictInput.approvalRules[0]!,
        eligibleApprovers: { kind: "roles", roles: ["approver"] },
      },
    ];
    strictInput.separationOfDuties = {
      exclusiveRequestAndApproveRoles: true,
      requesterNeverApprovesSameType: false,
    };
    const strict = compilePolicy(catalog, strictInput);
    const strictDigest = requestDigest(strict, request);
    const make = (approver: Subject) => ({ ...approval(approver), requestDigest: strictDigest });
    const result = await evaluateApprovals(strict, {
      request,
      now: later,
      approvals: [
        make(human("u-c", role("approver", everywhere), role("support", everywhere))),
        make(human("u-d", role("approver", everywhere))),
        make(human("u-e", role("approver", everywhere))),
      ],
    });
    expect(result.outcome).toBe("allow");
    expect(result.rejected).toEqual([
      { index: 0, approverId: "u-c", reason: "sod_role_conflict", detail: "support" },
    ]);
  });

  it("uses role approval when configured", async () => {
    const result = await evaluateApprovals(withRoles, {
      request,
      now: later,
      approvals: [
        roleApproval(human("u-d", role("approver", everywhere))),
        roleApproval(human("u-e", role("approver", everywhere))),
      ],
    });
    expect(result.outcome).toBe("allow");
  });
});

describe("separation of duties by history", () => {
  const input = editablePolicyInput();
  input.separationOfDuties = {
    requesterNeverApprovesSameType: true,
    exclusiveRequestAndApproveRoles: false,
  };
  const history = compilePolicy(catalog, input);
  const historyDigest = requestDigest(history, request);
  const make = (approver: Subject) => ({ ...approval(approver), requestDigest: historyDigest });

  it("rejects an approver who requested the same action type before", async () => {
    const result = await evaluateApprovals(history, {
      request,
      now: later,
      approvals: [make(peerA), make(peerB)],
      priorRequests: [
        { principalId: "u-a", permission: "ticket:refund" },
        { principalId: "u-b", permission: "ticket:close" },
      ],
    });
    expect(result.outcome).toBe("pending");
    expect(result.rejected).toEqual([{ index: 0, approverId: "u-a", reason: "sod_prior_request" }]);
  });

  it("fails closed without request history", async () => {
    const result = await evaluateApprovals(history, {
      request,
      now: later,
      approvals: [make(peerA), make(peerB)],
    });
    expect(result).toMatchObject({ outcome: "deny", reason: "sod_history_missing" });
  });

  it("ignores history when the setting is off", async () => {
    const result = await evaluateApprovals(policy, {
      request,
      now: later,
      approvals: [approval(peerA), approval(peerB)],
      priorRequests: [{ principalId: "u-a", permission: "ticket:refund" }],
    });
    expect(result.outcome).toBe("allow");
  });
});

describe("approval proofs", () => {
  const input = editablePolicyInput();
  input.approvalRules = [
    { ...input.approvalRules[0]!, requireProof: true, proofTypes: ["test-signature", "other"] },
  ];
  const proofPolicy = compilePolicy(catalog, input);
  const proofDigest = requestDigest(proofPolicy, request);

  const verifier: ApprovalProofVerifier = {
    type: "test-signature",
    verify(proof: ApprovalProof, expected) {
      const payload = proof.payload as { signedBy?: string; over?: string };
      if (payload.signedBy !== expected.approverId || payload.over !== expected.requestDigest) {
        return { valid: false, reason: "bad signature" };
      }
      return {
        valid: true,
        approverId: expected.approverId,
        requestDigest: expected.requestDigest,
      };
    },
  };
  const signed = (
    approver: Subject,
    payload?: unknown,
    proofExtra: Record<string, unknown> = {},
  ) => ({
    approver,
    approvedAt: "2026-01-15T10:10:00.000Z",
    requestDigest: proofDigest,
    proof: {
      type: "test-signature",
      approverId: approver.id,
      requestDigest: proofDigest,
      payload: payload ?? { signedBy: approver.id, over: proofDigest },
      ...proofExtra,
    },
  });

  it("allows with valid proofs", async () => {
    const result = await evaluateApprovals(
      proofPolicy,
      { request, now: later, approvals: [signed(peerA), signed(peerB)] },
      { verifiers: [verifier] },
    );
    expect(result.outcome).toBe("allow");
  });

  it("rejects missing, mismatched, unverifiable and invalid proofs", async () => {
    const result = await evaluateApprovals(
      proofPolicy,
      {
        request,
        now: later,
        approvals: [
          { approver: peerA, approvedAt: "2026-01-15T10:10:00.000Z", requestDigest: proofDigest },
          signed(peerB, undefined, { approverId: "u-a" }),
          signed(human("u-c", role("lead", everywhere)), undefined, { type: "other" }),
          signed(human("u-d", role("lead", everywhere)), { signedBy: "u-a", over: proofDigest }),
        ],
      },
      { verifiers: [verifier] },
    );
    expect(result.outcome).toBe("pending");
    expect(result.rejected.map((item) => item.reason)).toEqual([
      "proof_missing",
      "proof_mismatch",
      "proof_verifier_missing",
      "proof_invalid",
    ]);
  });

  it("rejects a verifier echo for another request and a verifier that throws", async () => {
    const lazy: ApprovalProofVerifier = {
      type: "test-signature",
      verify: () => ({ valid: true, approverId: "u-a", requestDigest: "0".repeat(64) }),
    };
    const throwing: ApprovalProofVerifier = {
      type: "test-signature",
      verify: async () => {
        throw new Error("key not found");
      },
    };
    for (const candidate of [lazy, throwing]) {
      const result = await evaluateApprovals(
        proofPolicy,
        { request, now: later, approvals: [signed(peerA), signed(peerB)] },
        { verifiers: [candidate] },
      );
      expect(result.outcome).toBe("pending");
      expect(result.rejected.every((item) => item.reason === "proof_invalid")).toBe(true);
    }
  });
});
