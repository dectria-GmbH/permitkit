import { describe, expect, it } from "vitest";

import {
  accessRequest,
  assertDecision,
  DecisionAssertionError,
  everywhere,
  human,
  permissionMatrix,
  role,
  service,
} from "../src/testing/index.js";
import { policy } from "./fixtures.js";

describe("test kit", () => {
  it("asserts outcomes and reasons", () => {
    const lead = human("u-lead", role("lead", everywhere));
    expect(
      assertDecision(policy, accessRequest(lead, "ticket:read"), { outcome: "allow" }).reason,
    ).toBe("granted");
    expect(() =>
      assertDecision(policy, accessRequest(lead, "ticket:read"), { outcome: "deny" }),
    ).toThrow(DecisionAssertionError);
    expect(() =>
      assertDecision(policy, accessRequest(human("u-x"), "ticket:read"), {
        outcome: "deny",
        reason: "scope_mismatch",
      }),
    ).toThrow(/"step": "permission"/);
  });

  it("rejects permission names without a resource", () => {
    expect(() => accessRequest(human("u"), "read")).toThrow(/form/);
  });

  it("builds a sorted permission matrix", () => {
    const rows = permissionMatrix(
      policy,
      {
        support: human("u-s", role("support", everywhere)),
        sync: service("svc", role("auditor", everywhere)),
      },
      [
        { permission: "ticket:read" },
        { permission: "ticket:refund", properties: { amount: 200 }, label: "refund 200" },
        { permission: "report:read", properties: { project: "alpha" } },
      ],
    );
    expect(rows).toMatchInlineSnapshot(`
      [
        {
          "case": "ticket:read",
          "outcome": "allow",
          "reason": "granted",
          "subject": "support",
        },
        {
          "case": "refund 200",
          "outcome": "approval_required",
          "reason": "approval_required",
          "subject": "support",
        },
        {
          "case": "report:read",
          "outcome": "deny",
          "reason": "no_grant",
          "subject": "support",
        },
        {
          "case": "ticket:read",
          "outcome": "deny",
          "reason": "scope_mismatch",
          "subject": "sync",
        },
        {
          "case": "refund 200",
          "outcome": "deny",
          "reason": "no_grant",
          "subject": "sync",
        },
        {
          "case": "report:read",
          "outcome": "allow",
          "reason": "granted",
          "subject": "sync",
        },
      ]
    `);
  });
});
