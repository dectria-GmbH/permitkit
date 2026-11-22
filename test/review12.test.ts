// Regression tests for findings of the twelfth cold security review.
import { describe, expect, it } from "vitest";

import {
  canonicalJson,
  compilePolicy,
  evaluateApprovals,
  parseRequest,
  PermitkitError,
  requestDigest,
  toDecisionRecord,
  decide,
} from "../src/index.js";
import { accessRequest, human, role } from "../src/testing/index.js";
import { catalog, editablePolicyInput, policy } from "./fixtures.js";

const request = accessRequest(human("u-lead", role("lead")), "ticket:read");

describe("exported helpers under a polluted Array.prototype", () => {
  it("parseRequest, toDecisionRecord and requestDigest do not throw raw errors", () => {
    const decision = decide(policy, request);
    // oxlint-disable-next-line no-extend-native
    Object.defineProperty(Array.prototype, "constructor", {
      value: 1,
      configurable: true,
      writable: true,
    });
    const outcomes: unknown[] = [];
    try {
      for (const run of [
        () => parseRequest(request).ok,
        () => toDecisionRecord(request, decision).schema,
        () => requestDigest(policy, request),
      ]) {
        try {
          outcomes.push(run());
        } catch (error) {
          outcomes.push(error instanceof PermitkitError ? error.code : `raw ${String(error)}`);
        }
      }
    } finally {
      // oxlint-disable-next-line no-extend-native
      Object.defineProperty(Array.prototype, "constructor", {
        value: Array,
        configurable: true,
        writable: true,
      });
    }
    expect(outcomes).toEqual([false, "permitkit.decision/1", "request_invalid"]);
  });
});

describe("canonical JSON arrays", () => {
  it("rejects holes and named array properties", () => {
    const holey: unknown[] = [];
    holey.length = 2;
    holey[1] = 1;
    for (const value of [holey, Object.assign([1], { x: 2 })]) {
      expect(() => canonicalJson(value)).toThrow(PermitkitError);
    }
    expect(canonicalJson([1, [2]])).toBe("[1,[2]]");
  });
});

describe("functions in the input", () => {
  it("never reach a proof verifier", async () => {
    const input = editablePolicyInput();
    input.approvalRules = [{ ...input.approvalRules![0]!, approvers: 1, requireProof: true }];
    const proofPolicy = compilePolicy(catalog, input);
    const refund = accessRequest(human("u-req", role("lead")), "ticket:refund", {
      properties: { amount: 500 },
    });
    const digestValue = requestDigest(proofPolicy, refund);
    let seen = false;
    const result = await evaluateApprovals(
      proofPolicy,
      {
        request: refund,
        now: "2026-01-15T10:30:00.000Z",
        approvals: [
          {
            approver: human("u-a", role("lead")),
            approvedAt: "2026-01-15T10:10:00.000Z",
            requestDigest: digestValue,
            proof: { type: "t", approverId: "u-a", requestDigest: digestValue, payload: () => 1 },
          },
        ],
      },
      {
        verifiers: [
          {
            type: "t",
            verify: () => {
              seen = true;
              return { valid: false, reason: "no" };
            },
          },
        ],
      },
    );
    expect(seen).toBe(false);
    expect(result.reason).toBe("invalid_input");
  });
});
