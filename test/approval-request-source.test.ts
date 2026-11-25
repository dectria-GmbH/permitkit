// evaluateApprovals and reevaluate decide on the request that the hand-written validator read
// from the plain-data copy of the input, never on the request that Zod returned. Zod 3 calls
// Array.prototype.push and other built-ins at call time. An input-dependent push, installed after
// permitkit loads, can add a role to the request that Zod returns, or swap the whole request.
// Each case records while the replacement is active and asserts after the restore.
import { describe, expect, it } from "vitest";

import {
  compilePolicy,
  decide,
  defineCatalog,
  evaluateApprovals,
  reevaluate,
  requestDigest,
  toDecisionRecord,
  type AccessRequest,
  type DecisionRecord,
} from "../src/index.js";

const apply = Reflect.apply;
// Unbound on purpose: the replacement calls it with apply and its receiver.
// oxlint-disable-next-line typescript/unbound-method
const originalPush = Array.prototype.push;
const define = Object.defineProperty;

const all = { kind: "all" } as const;
const catalog = defineCatalog({ ticket: { actions: ["refund", "read"] } });
const policy = compilePolicy(catalog, {
  schema: 2,
  version: "p1",
  roles: {
    lead: {
      grants: [
        { id: "lead", permissions: ["ticket:refund"], scope: all, limits: { kind: "unlimited" } },
      ],
    },
    approver: {
      grants: [
        { id: "appr", permissions: ["ticket:read"], scope: all, limits: { kind: "unlimited" } },
      ],
    },
    viewer: {
      grants: [
        { id: "view", permissions: ["ticket:read"], scope: all, limits: { kind: "unlimited" } },
      ],
    },
  },
  denies: [],
  approvalRules: [
    {
      id: "refund-dual",
      permissions: ["ticket:refund"],
      when: { kind: "always" },
      approvers: 1,
      expiresInSeconds: 3600,
      eligibleApprovers: { kind: "roles", roles: ["approver"] },
      requireProof: false,
    },
  ],
  separationOfDuties: {
    requesterNeverApprovesSameType: false,
    exclusiveRequestAndApproveRoles: false,
  },
});

const requestAs = (role: string): AccessRequest => ({
  subject: { type: "human", id: "u-req", roles: [{ role, scope: all }], act: null },
  action: { name: "refund" },
  resource: { type: "ticket", id: "t1" },
  context: { now: "2026-01-15T10:00:00.000Z" },
});

/** Runs the body with Array.prototype.push replaced, and restores it in every case. */
async function withPush<T>(
  replacement: (this: unknown[], ...items: unknown[]) => number,
  body: () => Promise<T> | T,
): Promise<T> {
  define(Array.prototype, "push", { value: replacement, writable: true, configurable: true });
  try {
    return await body();
  } finally {
    define(Array.prototype, "push", { value: originalPush, writable: true, configurable: true });
  }
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null;

/** After each viewer assignment that it adds, also adds a lead assignment. */
function forgeLead(this: unknown[], ...items: unknown[]): number {
  apply(originalPush, this, items);
  for (let index = 0; index < items.length; index += 1) {
    const item = items[index];
    if (isRecord(item) && item["role"] === "viewer") {
      apply(originalPush, this, [{ role: "lead", scope: { kind: "all" } }]);
    }
  }
  return this.length;
}

describe("the approval request comes from the hand-written validator", () => {
  it("a push that adds a role to the Zod output does not let a viewer pass", async () => {
    // The requester holds only viewer, which grants no refund.
    const request = requestAs("viewer");
    const input = {
      request,
      now: "2026-01-15T10:10:00.000Z",
      approvals: [
        {
          approver: {
            type: "human",
            id: "eve",
            roles: [{ role: "approver", scope: all }],
            act: null,
          },
          approvedAt: "2026-01-15T10:05:00.000Z",
          requestDigest: requestDigest(policy, request),
        },
      ],
    };
    const clean = await evaluateApprovals(policy, input);
    const polluted = await withPush(forgeLead, () => evaluateApprovals(policy, input));
    expect([clean.outcome, clean.reason]).toEqual(["deny", "requester_denied"]);
    expect([polluted.outcome, polluted.reason]).toEqual(["deny", "requester_denied"]);
  });

  it("a push that swaps the request in the Zod output does not change the decision", async () => {
    const viewer = requestAs("viewer");
    const lead = requestAs("lead");
    const input = {
      request: viewer,
      now: "2026-01-15T10:10:00.000Z",
      approvals: [
        {
          approver: {
            type: "human",
            id: "eve",
            roles: [{ role: "approver", scope: all }],
            act: null,
          },
          approvedAt: "2026-01-15T10:05:00.000Z",
          requestDigest: requestDigest(policy, lead),
        },
      ],
    };
    const clean = await evaluateApprovals(policy, input);
    const polluted = await withPush(swapRequest(lead), () => evaluateApprovals(policy, input));
    expect(clean.outcome).toBe("deny");
    expect([polluted.outcome, polluted.reason]).toEqual([clean.outcome, clean.reason]);
  });
});

/**
 * Zod 3 collects the parsed fields of an object as { key, value } pairs with push. This
 * replacement swaps the parsed value of the key "request" for another request.
 */
function swapRequest(replacement: AccessRequest) {
  return function swap(this: unknown[], ...items: unknown[]): number {
    for (let index = 0; index < items.length; index += 1) {
      const item = items[index];
      if (!isRecord(item)) continue;
      const key = item["key"];
      const value = item["value"];
      if (isRecord(key) && key["value"] === "request" && isRecord(value) && "status" in value) {
        items[index] = { ...item, value: { status: "valid", value: replacement } };
      }
    }
    apply(originalPush, this, items);
    return this.length;
  };
}

describe("reevaluate replays the request that the hand-written validator read", () => {
  it("a push that swaps the stored request does not reproduce a forged record", async () => {
    const viewer = requestAs("viewer");
    const lead = requestAs("lead");
    // A forged record: the stored request is the viewer's, the stored result is the lead's.
    const leadRecord = toDecisionRecord(lead, decide(policy, lead));
    const forged: DecisionRecord = { ...leadRecord, request: viewer };
    const clean = reevaluate(policy, forged);
    const polluted = await withPush(swapRequest(lead), () => reevaluate(policy, forged));
    expect(clean.status).toBe("diverged");
    expect(polluted.status).toBe("diverged");
  });
});
