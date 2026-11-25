// A built-in replaced after load with a function that depends on its input. Up to f04df14, Zod 3
// validated approval inputs and decision records and called built-ins while it ran: such a
// replacement could add an item to its output, drop one, or change permitkit's plain-data copy
// in place before permitkit read it. The hand-written validators call no built-in at call time,
// so each case here gives the result without the replacement. The cases come from security
// reviews; each one widened a result on f04df14.
import { describe, expect, it } from "vitest";

import {
  compilePolicy,
  decide,
  decideAndRecord,
  defineCatalog,
  evaluateApprovals,
  reevaluate,
  requestDigest,
  toDecisionRecord,
  type ApprovalDecision,
  type DecisionRecord,
  type PolicyInput,
} from "../src/index.js";

const apply = Reflect.apply;
const define = Object.defineProperty;
const getPrototypeOf = Object.getPrototypeOf;
const create = Object.create;
const hasOwn = Object.hasOwn;
const originalPush = Array.prototype.push;
const originalIsArray = Array.isArray;
const pushDescriptor = Object.getOwnPropertyDescriptor(Array.prototype, "push");
const isArrayDescriptor = Object.getOwnPropertyDescriptor(Array, "isArray");

const all = { kind: "all" } as const;
const catalog = defineCatalog({ ticket: { actions: ["refund", "read"] } });

function policyOf(roles: PolicyInput["roles"], approvalRules: boolean, history = false) {
  return compilePolicy(catalog, {
    schema: 2,
    version: "p1",
    roles,
    denies: [],
    approvalRules: approvalRules
      ? [
          {
            id: "refund-dual",
            permissions: ["ticket:refund"],
            when: { kind: "always" },
            approvers: 1,
            expiresInSeconds: 3600,
            eligibleApprovers: { kind: "roles", roles: ["approver"] },
            requireProof: false,
          },
        ]
      : [],
    separationOfDuties: {
      requesterNeverApprovesSameType: history,
      exclusiveRequestAndApproveRoles: false,
    },
  });
}

const grant = (id: string, permissions: string[]) => ({
  id,
  permissions,
  scope: all,
  limits: { kind: "unlimited" as const },
});

const request = (role: string) => ({
  subject: { type: "human" as const, id: "u-req", roles: [{ role, scope: all }], act: null },
  action: { name: "refund" },
  resource: { type: "ticket", id: "t1" },
  context: { now: "2026-01-15T10:00:00.000Z" },
});

const approvalBy = (policy: ReturnType<typeof policyOf>, id: string, role: string) => ({
  approver: { type: "human", id, roles: [{ role, scope: all }], act: null },
  approvedAt: "2026-01-15T10:05:00.000Z",
  requestDigest: requestDigest(policy, request("lead")),
});

const short = (decision: ApprovalDecision): string =>
  `${decision.outcome}/${decision.reason} counted=${decision.counted.length}`;

function isRecord(item: unknown): item is Record<string, unknown> {
  return typeof item === "object" && item !== null;
}

/** Defines a replacement as an own data property, as an assignment would. */
function replace(owner: object, key: string, value: unknown): void {
  define(owner, key, { value, writable: true, enumerable: false, configurable: true });
}

/** Runs the body with Array.prototype.push replaced, and restores it when the body settles. */
async function withPush<T>(
  replacement: (this: unknown[], ...items: unknown[]) => number,
  body: () => T,
) {
  replace(Array.prototype, "push", replacement);
  try {
    return await body();
  } finally {
    if (pushDescriptor !== undefined) define(Array.prototype, "push", pushDescriptor);
  }
}

async function withIsArray<T>(replacement: (value: unknown) => boolean, body: () => T) {
  replace(Array, "isArray", replacement);
  try {
    return await body();
  } finally {
    if (isArrayDescriptor !== undefined) define(Array, "isArray", isArrayDescriptor);
  }
}

// The replacements. Each one calls the original, so the test framework keeps working.

/** Adds an approver role after each pushed role assignment of a viewer. */
function addApproverRole(this: unknown[], ...items: unknown[]): number {
  apply(originalPush, this, items);
  for (let index = 0; index < items.length; index += 1) {
    const item = items[index];
    if (isRecord(item) && item["role"] === "viewer") {
      apply(originalPush, this, [{ role: "approver", scope: all }]);
    }
  }
  return this.length;
}

let forgedApproval: unknown = null;

/** Pushes the forged approval in place of a pushed item `{ junk: 1 }`. */
function swapJunk(this: unknown[], ...items: unknown[]): number {
  for (let index = 0; index < items.length; index += 1) {
    const item = items[index];
    if (isRecord(item) && item["junk"] === 1) items[index] = forgedApproval;
  }
  apply(originalPush, this, items);
  return this.length;
}

/** Leaves out every pushed item whose principalId is bob. */
function dropBob(this: unknown[], ...items: unknown[]): number {
  const kept: unknown[] = [];
  for (let index = 0; index < items.length; index += 1) {
    const item = items[index];
    if (!(isRecord(item) && item["principalId"] === "bob")) kept[kept.length] = item;
  }
  apply(originalPush, this, kept);
  return this.length;
}

let rewrites = 0;

/** On a copy without a prototype that holds a request, turns the action refund into read. */
function refundToRead(value: unknown): boolean {
  if (isRecord(value) && getPrototypeOf(value) === null && hasOwn(value, "request")) {
    const copied = value["request"];
    const action = isRecord(copied) ? copied["action"] : undefined;
    if (isRecord(action) && action["name"] === "refund") {
      action["name"] = "read";
      rewrites += 1;
    }
  }
  return originalIsArray(value);
}

/** On a copied subject u-req, replaces the first role assignment with lead. */
function promoteRequester(value: unknown): boolean {
  if (
    isRecord(value) &&
    getPrototypeOf(value) === null &&
    value["type"] === "human" &&
    value["id"] === "u-req" &&
    originalIsArray(value["roles"])
  ) {
    const lead = create(null) as Record<string, unknown>;
    lead["role"] = "lead";
    lead["scope"] = all;
    define(value["roles"], 0, {
      value: lead,
      writable: true,
      enumerable: true,
      configurable: true,
    });
  }
  return originalIsArray(value);
}

/** On a pushed Zod pair for the key request, changes the first role of its value to lead. */
function promoteInPair(this: unknown[], ...items: unknown[]): number {
  for (let index = 0; index < items.length; index += 1) {
    const item = items[index];
    const key = isRecord(item) ? item["key"] : undefined;
    const pair = isRecord(item) ? item["value"] : undefined;
    const value = isRecord(pair) ? pair["value"] : undefined;
    const subject = isRecord(value) ? value["subject"] : undefined;
    const roles = isRecord(subject) ? subject["roles"] : undefined;
    if (isRecord(key) && key["value"] === "request" && originalIsArray(roles)) {
      const first: unknown = roles[0];
      if (isRecord(first)) first["role"] = "lead";
    }
  }
  apply(originalPush, this, items);
  return this.length;
}

describe("a built-in replaced after load, depending on its input", () => {
  it("a push that adds the approver role does not count a viewer", async () => {
    const policy = policyOf(
      {
        lead: { grants: [grant("lead", ["ticket:refund"])] },
        approver: { grants: [grant("appr", ["ticket:read"])] },
        viewer: { grants: [grant("view", ["ticket:read"])] },
      },
      true,
    );
    const input = {
      request: request("lead"),
      now: "2026-01-15T10:10:00.000Z",
      approvals: [approvalBy(policy, "bob", "viewer")],
    };
    const clean = short(await evaluateApprovals(policy, input));
    const replaced = short(await withPush(addApproverRole, () => evaluateApprovals(policy, input)));
    expect({ clean, replaced }).toEqual({
      clean: "pending/approvals_pending counted=0",
      replaced: "pending/approvals_pending counted=0",
    });
  });

  it("a push that swaps an invalid approval for a forged one adds no approval", async () => {
    const policy = policyOf(
      { lead: { grants: [grant("lead", ["ticket:refund"])] }, approver: { grants: [] } },
      true,
    );
    forgedApproval = approvalBy(policy, "mallory", "approver");
    const input = {
      request: request("lead"),
      now: "2026-01-15T10:10:00.000Z",
      approvals: [{ junk: 1 }],
    };
    const clean = short(await evaluateApprovals(policy, input));
    const replaced = short(await withPush(swapJunk, () => evaluateApprovals(policy, input)));
    expect({ clean, replaced }).toEqual({
      clean: "pending/approvals_pending counted=0",
      replaced: "pending/approvals_pending counted=0",
    });
  });

  it("a push that drops a prior request does not let a prior requester approve", async () => {
    const policy = policyOf(
      { lead: { grants: [grant("lead", ["ticket:refund"])] }, approver: { grants: [] } },
      true,
      true,
    );
    const input = {
      request: request("lead"),
      now: "2026-01-15T10:10:00.000Z",
      approvals: [approvalBy(policy, "bob", "approver")],
      priorRequests: [{ principalId: "bob", permission: "ticket:refund" }],
    };
    const clean = short(await evaluateApprovals(policy, input));
    const replaced = short(await withPush(dropBob, () => evaluateApprovals(policy, input)));
    expect({ clean, replaced }).toEqual({
      clean: "pending/approvals_pending counted=0",
      replaced: "pending/approvals_pending counted=0",
    });
  });

  it("an isArray that rewrites the copied request in place does not turn refund into read", async () => {
    const policy = policyOf(
      {
        lead: { grants: [grant("lead", ["ticket:refund", "ticket:read"])] },
        approver: { grants: [grant("appr", ["ticket:read"])] },
      },
      true,
    );
    const input = { request: request("lead"), now: "2026-01-15T10:10:00.000Z", approvals: [] };
    rewrites = 0;
    const clean = short(await evaluateApprovals(policy, input));
    const replaced = short(await withIsArray(refundToRead, () => evaluateApprovals(policy, input)));
    expect({ clean, replaced, rewrites }).toEqual({
      clean: "pending/approvals_pending counted=0",
      replaced: "pending/approvals_pending counted=0",
      rewrites: 0,
    });
  });

  it("an isArray that adds a role to the copied request keeps a requester denied", async () => {
    const policy = policyOf(
      {
        lead: { grants: [grant("lead", ["ticket:refund"])] },
        viewer: { grants: [grant("view", ["ticket:read"])] },
        approver: { grants: [grant("appr", ["ticket:read"])] },
      },
      true,
    );
    const input = { request: request("viewer"), now: "2026-01-15T10:10:00.000Z", approvals: [] };
    const clean = short(await evaluateApprovals(policy, input));
    const replaced = short(
      await withIsArray(promoteRequester, () => evaluateApprovals(policy, input)),
    );
    expect({ clean, replaced }).toEqual({
      clean: "deny/requester_denied counted=0",
      replaced: "deny/requester_denied counted=0",
    });
  });

  it("an isArray that rewrites the copied record does not change the reevaluation", async () => {
    const policy = policyOf(
      {
        lead: { grants: [grant("lead", ["ticket:refund", "ticket:read"])] },
        approver: { grants: [grant("appr", ["ticket:read"])] },
      },
      true,
    );
    const { record } = decideAndRecord(policy, request("lead"));
    const copy = structuredClone(record);
    rewrites = 0;
    const clean = reevaluate(policy, record);
    const replaced = await withIsArray(refundToRead, () => reevaluate(policy, copy));
    expect({ clean: clean.status, replaced: replaced.status, rewrites }).toEqual({
      clean: "reproduced",
      replaced: "reproduced",
      rewrites: 0,
    });
    expect(replaced.status === "reproduced" ? replaced.decision.outcome : null).toBe(
      "approval_required",
    );
  });

  it("a push that changes the copied record in place keeps a forged record diverged", async () => {
    const policy = policyOf(
      {
        lead: { grants: [grant("lead", ["ticket:refund"])] },
        viewer: { grants: [grant("view", ["ticket:read"])] },
      },
      false,
    );
    // The stored request is the viewer's (deny), the stored result is the lead's (allow).
    const lead = toDecisionRecord(request("lead"), decide(policy, request("lead")));
    const forged: DecisionRecord = { ...lead, request: { ...lead.request!, ...request("viewer") } };
    const clean = reevaluate(policy, forged).status;
    const replaced = await withPush(promoteInPair, () => reevaluate(policy, forged).status);
    expect({ clean, replaced }).toEqual({ clean: "diverged", replaced: "diverged" });
  });
});
