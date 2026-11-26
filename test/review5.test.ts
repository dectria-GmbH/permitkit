// Regression tests for findings of the fifth cold security review.
import { afterEach, describe, expect, it } from "vitest";

import { compilePolicy, evaluateApprovals, PermitkitError, requestDigest } from "../src/index.js";
import { accessRequest, everywhere, human, role } from "../src/testing/index.js";
import { bare, catalog, editablePolicyInput, policy } from "./fixtures.js";

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

const later = "2026-01-15T10:30:00.000Z";
const input = editablePolicyInput();
input.approvalRules = [
  { ...input.approvalRules[0]!, approvers: 1, requireProof: true, proofTypes: ["t"] },
];
const proofPolicy = compilePolicy(catalog, input);
const request = accessRequest(human("u-req", role("lead", everywhere)), "ticket:refund", {
  properties: { amount: 500 },
});
const digestValue = requestDigest(proofPolicy, request);
const unproven = {
  approver: human("u5", role("lead", everywhere)),
  approvedAt: "2026-01-15T10:10:00.000Z",
  requestDigest: digestValue,
};
const strict = { type: "t", verify: () => bare({ valid: false, reason: "strict" }) };

describe("proof path under a polluted then", () => {
  it("does not count an approval without a proof", async () => {
    // A thenable that resolves with null would turn a plain rejection object into "counted".
    // oxlint-disable-next-line unicorn/no-thenable
    pollute("then", function (this: unknown, resolve: (value: unknown) => void) {
      resolve(null);
    });
    const outcome = await Promise.race([
      evaluateApprovals(proofPolicy, { request, now: later, approvals: [unproven] }).then(
        (result) => (result as { outcome: string }).outcome,
      ),
      new Promise((resolve) => {
        setTimeout(() => resolve("timeout"), 1000);
      }),
    ]);
    expect(outcome).not.toBe("allow");
  });
});

describe("verifier options", () => {
  const base = { request, now: later, approvals: [unproven] };

  it("reads a verifier type once, so a changing getter cannot replace a strict verifier", async () => {
    let reads = 0;
    const sneaky = {
      get type() {
        reads += 1;
        return reads === 2 ? "x" : "t";
      },
      verify: () => bare({ valid: true, approverId: "u5", requestDigest: digestValue }),
    };
    await expect(
      evaluateApprovals(proofPolicy, base, { verifiers: [strict, sneaky] as never }),
    ).rejects.toMatchObject({ code: "options_invalid" });
  });

  it("does not take a verifier type from a polluted prototype", async () => {
    pollute("type", "t");
    const typeless = { verify: () => bare({ valid: true }) };
    await expect(
      evaluateApprovals(proofPolicy, base, { verifiers: [typeless] as never }),
    ).rejects.toMatchObject({ code: "options_invalid" });
  });

  it("validates options on every path and rejects unknown keys", async () => {
    const small = accessRequest(human("u-req", role("lead", everywhere)), "ticket:refund", {
      properties: { amount: 5 },
    });
    for (const options of [null, { verifiers: "nope" }, { verifier: [strict] }]) {
      await expect(
        evaluateApprovals(policy, { request: small, now: later, approvals: [] }, options as never),
      ).rejects.toMatchObject({ code: "options_invalid" });
    }
  });
});

describe("requestDigest", () => {
  it("rejects a policy that compilePolicy did not return", () => {
    expect(() => requestDigest({ version: "v", digest: "d" } as never, request)).toThrow(
      PermitkitError,
    );
  });
});
