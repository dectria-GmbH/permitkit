// Regression tests for findings of the sixth cold security review.
import { afterEach, describe, expect, it } from "vitest";

import {
  compilePolicy,
  decide,
  defineCatalog,
  evaluate,
  evaluateApprovals,
  PermitkitError,
  requestDigest,
} from "../src/index.js";
import { accessRequest, human, role } from "../src/testing/index.js";
import { catalog, editablePolicyInput, policy } from "./fixtures.js";

afterEach(() => {
  delete (Object.prototype as Record<string, unknown>)["actions"];
});

class GetterScope {
  get queue(): string[] {
    return ["billing"];
  }
}

function nonPlainScopes(): unknown[] {
  const hidden = {};
  Object.defineProperty(hidden, "queue", { value: ["billing"], enumerable: false });
  return [
    new Map([["queue", ["billing"]]]),
    hidden,
    Object.create({ queue: ["billing"] }) as object,
    new GetterScope(),
    new Date(0),
    { [Symbol("queue")]: ["billing"] },
  ];
}

describe("non-plain scopes never read as everywhere", () => {
  it("denies a role assignment whose scope is not a plain object", () => {
    const plain = accessRequest(human("u", role("lead", { queue: ["billing"] })), "ticket:read", {
      properties: { queue: "vip" },
    });
    expect(decide(policy, plain).reason).toBe("scope_mismatch");
    for (const scope of nonPlainScopes()) {
      const request = {
        ...plain,
        subject: { ...plain.subject, roles: [{ role: "lead", scope }] },
      };
      expect(decide(policy, request).outcome).toBe("deny");
      const authzen = evaluate(policy, {
        subject: { type: "human", id: "u", properties: { roles: [{ role: "lead", scope }] } },
        action: { name: "read" },
        resource: { type: "ticket", id: "t", properties: { queue: "vip" } },
        context: { now: "2026-01-15T10:00:00.000Z" },
      });
      expect(authzen.decision).toBe(false);
    }
  });

  it("rejects an array with extra named properties", () => {
    const plain = accessRequest(human("u", role("lead")), "ticket:read");
    const roles = Object.assign([{ role: "lead", scope: {} }], { extra: true });
    expect(decide(policy, { ...plain, subject: { ...plain.subject, roles } }).reason).toBe(
      "invalid_request",
    );
  });

  it("does not count an approver whose assignment scope is not a plain object", async () => {
    const input = editablePolicyInput();
    input.approvalRules = [
      { ...input.approvalRules![0]!, approvers: 1, approverRoles: ["approver"] },
    ];
    const withRoles = compilePolicy(catalog, input);
    const request = accessRequest(human("u-req", role("lead")), "ticket:refund", {
      properties: { amount: 500, queue: "vip" },
    });
    const digestValue = requestDigest(withRoles, request);
    const approval = {
      approver: {
        type: "human",
        id: "u-a",
        roles: [{ role: "approver", scope: new Map([["queue", ["billing"]]]) }],
      },
      approvedAt: "2026-01-15T10:10:00.000Z",
      requestDigest: digestValue,
    };
    const result = await evaluateApprovals(withRoles, {
      request,
      now: "2026-01-15T10:30:00.000Z",
      approvals: [approval],
    });
    expect(result.outcome).not.toBe("allow");
  });

  it("rejects non-plain policy parts instead of dropping their fields", () => {
    class LimitedGrant {
      id = "g";
      permissions = ["ticket:refund"];
      get limits() {
        return { amount: { max: 10 } };
      }
    }
    const variants: ((input: ReturnType<typeof editablePolicyInput>) => void)[] = [
      (input) => {
        (input as Record<string, unknown>)["separationOfDuties"] = new Map([
          ["exclusiveRequestAndApproveRoles", true],
        ]);
      },
      (input) => {
        input.roles = { ...input.roles, limited: { grants: [new LimitedGrant()] } };
      },
    ];
    for (const change of variants) {
      const input = editablePolicyInput();
      change(input);
      expect(() => compilePolicy(catalog, input)).toThrow(PermitkitError);
    }
  });
});

describe("catalogue", () => {
  it("does not read actions from a polluted prototype", () => {
    // The test simulates a prototype-pollution bug elsewhere in the process.
    // oxlint-disable-next-line no-extend-native
    Object.defineProperty(Object.prototype, "actions", {
      value: ["read"],
      configurable: true,
      writable: true,
    });
    expect(() => defineCatalog({ ghost: {} as never })).toThrow(PermitkitError);
  });
});
