// Zod never touches the data that permitkit reads later. evaluateApprovals and reevaluate read
// the request and `now` from their plain-data copy of the input with the hand-written validators,
// before any Zod call, and hand Zod a separate copy. Zod 3 passes the input's own objects to
// built-ins (Array.isArray in getParsedType, push in ZodObject). A built-in replaced after load
// could change that copy in place, and a validator that ran after Zod would read changed data.
// Each case records while the replacement is active and asserts after the restore.
import { describe, expect, it } from "vitest";

import {
  compilePolicy,
  decide,
  decideAndRecord,
  defineCatalog,
  evaluateApprovals,
  reevaluate,
  toDecisionRecord,
  type AccessRequest,
  type DecisionRecord,
} from "../src/index.js";

const apply = Reflect.apply;
const define = Object.defineProperty;
const getPrototypeOf = Object.getPrototypeOf;
const create = Object.create;
const originalIsArray = Array.isArray;
// Unbound on purpose: the replacement calls it with apply and its receiver.
// oxlint-disable-next-line typescript/unbound-method
const originalPush = Array.prototype.push;

const all = { kind: "all" } as const;
const catalog = defineCatalog({ ticket: { actions: ["refund", "read"] } });
const unlimited = { kind: "unlimited" } as const;
const policy = compilePolicy(catalog, {
  schema: 2,
  version: "p1",
  roles: {
    lead: {
      grants: [
        {
          id: "lead",
          permissions: ["ticket:refund", "ticket:read"],
          scope: all,
          limits: unlimited,
        },
      ],
    },
    viewer: {
      grants: [{ id: "view", permissions: ["ticket:read"], scope: all, limits: unlimited }],
    },
    approver: {
      grants: [{ id: "appr", permissions: ["ticket:read"], scope: all, limits: unlimited }],
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

const requestAs = (role: string, action = "refund"): AccessRequest => ({
  subject: { type: "human", id: "u-req", roles: [{ role, scope: all }], act: null },
  action: { name: action },
  resource: { type: "ticket", id: "t1" },
  context: { now: "2026-01-15T10:00:00.000Z" },
});

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null;

/** Runs the body with a replaced built-in, and restores the original in every case. */
async function replaced<T>(
  owner: object,
  key: string,
  replacement: unknown,
  original: unknown,
  body: () => Promise<T> | T,
): Promise<T> {
  define(owner, key, { value: replacement, writable: true, configurable: true });
  try {
    return await body();
  } finally {
    define(owner, key, { value: original, writable: true, configurable: true });
  }
}

const withIsArray = <T>(replacement: (value: unknown) => boolean, body: () => Promise<T> | T) =>
  replaced(Array, "isArray", replacement, originalIsArray, body);

/**
 * Rewrites the action of every prototype-free object with a `request` key that Zod hands to
 * Array.isArray. permitkit's plain-data copies have no prototype, the caller's input has one.
 */
function readInsteadOfRefund(value: unknown): boolean {
  if (isRecord(value) && getPrototypeOf(value) === null && "request" in value) {
    const request = value["request"];
    const action = isRecord(request) ? request["action"] : undefined;
    if (isRecord(action) && action["name"] === "refund") action["name"] = "read";
  }
  return originalIsArray(value);
}

/** Gives the requester u-req the role lead in every prototype-free subject that it sees. */
function leadForRequester(value: unknown): boolean {
  if (isRecord(value) && getPrototypeOf(value) === null && value["id"] === "u-req") {
    const roles = value["roles"];
    if (originalIsArray(roles) && roles.length === 1) {
      const scope = create(null) as Record<string, unknown>;
      scope["kind"] = "all";
      const lead = create(null) as Record<string, unknown>;
      lead["role"] = "lead";
      lead["scope"] = scope;
      define(roles, 0, { value: lead, writable: true, enumerable: true, configurable: true });
    }
  }
  return originalIsArray(value);
}

/**
 * Zod 3 collects the parsed fields of an object as { key, value } pairs with push. For
 * `request: z.unknown()` in a decision record, the parsed value is the input's own request.
 * This replacement gives its first role the name lead, in place.
 */
function leadInPlace(this: unknown[], ...items: unknown[]): number {
  for (let index = 0; index < items.length; index += 1) {
    const item = items[index];
    if (!isRecord(item) || !isRecord(item["key"]) || item["key"]["value"] !== "request") continue;
    const parsed = item["value"];
    const request = isRecord(parsed) ? parsed["value"] : undefined;
    const subject = isRecord(request) ? request["subject"] : undefined;
    const roles = isRecord(subject) ? subject["roles"] : undefined;
    const first: unknown = originalIsArray(roles) ? roles[0] : undefined;
    if (isRecord(first)) first["role"] = "lead";
  }
  return apply(originalPush, this, items);
}

/** An approval input without approvals, ten minutes after the request. */
const input = (request: AccessRequest) => ({
  request,
  now: "2026-01-15T10:10:00.000Z",
  approvals: [],
});

describe("evaluateApprovals reads the request before Zod and hands Zod its own copy", () => {
  it("an Array.isArray that rewrites the action does not turn pending into allow", async () => {
    const clean = await evaluateApprovals(policy, input(requestAs("lead")));
    const polluted = await withIsArray(readInsteadOfRefund, () =>
      evaluateApprovals(policy, input(requestAs("lead"))),
    );
    expect([clean.outcome, clean.reason]).toEqual(["pending", "approvals_pending"]);
    expect([polluted.outcome, polluted.reason, polluted.requestDigest]).toEqual([
      clean.outcome,
      clean.reason,
      clean.requestDigest,
    ]);
  });

  it("an Array.isArray that adds a role to the requester does not let a viewer pass", async () => {
    const clean = await evaluateApprovals(policy, input(requestAs("viewer")));
    const polluted = await withIsArray(leadForRequester, () =>
      evaluateApprovals(policy, input(requestAs("viewer"))),
    );
    expect([clean.outcome, clean.reason]).toEqual(["deny", "requester_denied"]);
    expect([polluted.outcome, polluted.reason]).toEqual(["deny", "requester_denied"]);
  });
});

describe("reevaluate reads the stored request before Zod and hands Zod its own copy", () => {
  it("an Array.isArray that rewrites the stored action does not change the replay", async () => {
    const { record } = decideAndRecord(policy, requestAs("lead"));
    const clean = reevaluate(policy, record);
    const polluted = await withIsArray(readInsteadOfRefund, () => reevaluate(policy, record));
    expect(clean.status).toBe("reproduced");
    expect(polluted.status).toBe("reproduced");
    const digestOf = (result: typeof clean) =>
      "decision" in result ? result.decision.requestDigest : null;
    expect(digestOf(polluted)).toBe(digestOf(clean));
  });

  it("a push that changes the stored request in place does not reproduce a forged record", async () => {
    // A forged record: the stored request is the viewer's, the stored result is the lead's.
    const lead = requestAs("lead");
    const forged: DecisionRecord = {
      ...toDecisionRecord(lead, decide(policy, lead)),
      request: requestAs("viewer"),
    };
    const clean = reevaluate(policy, forged);
    const polluted = await replaced(Array.prototype, "push", leadInPlace, originalPush, () =>
      reevaluate(policy, forged),
    );
    expect(clean.status).toBe("diverged");
    expect(polluted.status).toBe("diverged");
  });
});
