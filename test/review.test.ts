// Regression tests for findings of the first cold security review.
import { describe, expect, it } from "vitest";

import {
  compilePolicy,
  decide,
  defineCatalog,
  evaluate,
  evaluateApprovals,
  PermitkitError,
  reevaluate,
  requestDigest,
  toDecisionRecord,
  type Catalog,
  type Subject,
} from "../src/index.js";
import {
  accessRequest,
  everywhere,
  human,
  role,
  unlimited,
  viaAgent,
} from "../src/testing/index.js";
import { catalog, editablePolicyInput, policy } from "./fixtures.js";

const lead = human("u-lead", role("lead", everywhere));
const later = "2026-01-15T10:30:00.000Z";

describe("compiled policy cannot be changed", () => {
  it("exposes no lookup tables and rejects new or changed properties", () => {
    expect(Object.keys(policy).toSorted()).toEqual(["catalog", "digest", "document", "version"]);
    expect(Object.isFrozen(policy)).toBe(true);
    const target = policy as unknown as Record<string, unknown>;
    expect(() => {
      target["roles"] = new Map();
    }).toThrow(TypeError);
    expect(() => {
      target["version"] = "other";
    }).toThrow(TypeError);
    const ghost = human("u-ghost", role("ghost", everywhere));
    expect(decide(policy, accessRequest(ghost, "ticket:read")).outcome).toBe("deny");
  });

  it("rejects a catalogue that defineCatalog did not create", () => {
    const forged = { ...catalog, isPermission: () => true } as Catalog;
    expect(() => compilePolicy(forged, editablePolicyInput())).toThrow(PermitkitError);
  });
});

describe("timestamps fail closed", () => {
  const grantEntries = [{ permissions: ["ticket:read"], scope: everywhere, limits: unlimited }];
  const unreadable = [
    "2026-01-01T00:00:00+24:00",
    "2020-01-01T00:00:00+99:99",
    "2026-01-01T00:00:00+0100",
    "2026-01-01T00:00:00.1234Z",
    "2026-02-30T00:00:00Z",
    "2026-01-01T00:00:00",
  ];

  it("rejects timestamps that engines cannot read the same way", () => {
    for (const value of unreadable) {
      const request = accessRequest(lead, "ticket:read", {}, { now: value });
      expect({ value, reason: decide(policy, request).reason }).toEqual({
        value,
        reason: "invalid_request",
      });
    }
  });

  it("does not allow with an unreadable revokedAt, expiresAt or notBefore", () => {
    for (const value of unreadable) {
      for (const field of ["revokedAt", "expiresAt", "notBefore"] as const) {
        const subject = viaAgent(lead, "agent-1", { entries: grantEntries, [field]: value });
        expect(decide(policy, accessRequest(subject, "ticket:read")).outcome).toBe("deny");
      }
    }
  });

  it("does not count an approval with an unreadable time", async () => {
    const request = accessRequest(lead, "ticket:refund", { properties: { amount: 500 } });
    const digestValue = requestDigest(policy, request);
    const approvals = ["u-a", "u-b"].map((id) => ({
      approver: human(id, role("lead", everywhere)),
      approvedAt: "2030-01-01T00:00:00+24:00",
      requestDigest: digestValue,
    }));
    const result = await evaluateApprovals(policy, { request, now: later, approvals });
    expect(result.outcome).toBe("pending");
    expect(result.rejected.map((item) => item.reason)).toEqual([
      "approval_invalid",
      "approval_invalid",
    ]);
  });
});

describe("hostile input does not throw", () => {
  it("denies a throwing getter, a revoked proxy and null", () => {
    const request = accessRequest(lead, "ticket:read");
    const throwing = {
      ...request,
      get resource() {
        throw new Error("boom");
      },
    };
    const { proxy, revoke } = Proxy.revocable(request, {});
    revoke();
    expect(decide(policy, throwing).reason).toBe("invalid_request");
    expect(decide(policy, proxy).reason).toBe("invalid_request");
    expect(evaluate(policy, null as never).decision).toBe(false);
  });

  it("reports a malformed record as not replayable", () => {
    expect(reevaluate(policy, {} as never).status).toBe("not_replayable");
  });

  it("throws a coded error from requestDigest for an invalid request", () => {
    expect(() => requestDigest(policy, { bad: true })).toThrow(
      expect.objectContaining({ code: "request_invalid" }),
    );
  });
});

describe("agent grants are bound to the agent", () => {
  it("denies a grant presented by another agent", () => {
    const subject = viaAgent(lead, "bot", {
      entries: [
        { permissions: ["ticket:read"], scope: { kind: "all" }, limits: { kind: "unlimited" } },
      ],
    });
    const other: Subject = { ...subject, act: { ...subject.act!, id: "other-agent" } };
    expect(decide(policy, accessRequest(other, "ticket:read")).reason).toBe(
      "agent_grant_actor_mismatch",
    );
  });

  it("gives requests with different grant content different digests", () => {
    const narrow = viaAgent(lead, "bot", {
      entries: [
        {
          permissions: ["ticket:refund"],
          limits: { kind: "range", properties: { amount: { max: 10 } } },
          scope: { kind: "all" },
        },
      ],
    });
    const wide = viaAgent(lead, "bot", {
      entries: [
        { permissions: ["ticket:refund"], scope: { kind: "all" }, limits: { kind: "unlimited" } },
      ],
    });
    const properties = { amount: 500 };
    expect(requestDigest(policy, accessRequest(narrow, "ticket:refund", { properties }))).not.toBe(
      requestDigest(policy, accessRequest(wide, "ticket:refund", { properties })),
    );
  });
});

describe("approver exclusions", () => {
  it("does not count an approver whose id is an agent in the requester's chain", async () => {
    const request = accessRequest(
      viaAgent(lead, "bot", {
        entries: [
          { permissions: ["ticket:refund"], scope: { kind: "all" }, limits: { kind: "unlimited" } },
        ],
      }),
      "ticket:refund",
      { properties: { amount: 500 } },
    );
    const digestValue = requestDigest(policy, request);
    const result = await evaluateApprovals(policy, {
      request,
      now: later,
      approvals: [
        {
          approver: human("bot", role("lead", everywhere)),
          approvedAt: later,
          requestDigest: digestValue,
        },
      ],
    });
    expect(result.rejected[0]?.reason).toBe("requester_cannot_approve");
  });

  it("does not count an approver that a deny rule for the permission matches", async () => {
    const input = editablePolicyInput();
    input.roles = { ...input.roles, suspended: { grants: [] } };
    input.denies = [
      ...(input.denies ?? []),
      {
        id: "suspended-no-refunds",
        permissions: ["ticket:refund"],
        roles: ["suspended"],
        scope: { kind: "all" },
      },
    ];
    input.approvalRules = [
      { ...input.approvalRules[0]!, eligibleApprovers: { kind: "roles", roles: ["approver"] } },
    ];
    const withDeny = compilePolicy(catalog, input);
    const request = accessRequest(lead, "ticket:refund", { properties: { amount: 500 } });
    const digestValue = requestDigest(withDeny, request);
    const result = await evaluateApprovals(withDeny, {
      request,
      now: later,
      approvals: [
        {
          approver: human("u-sue", role("approver", everywhere), role("suspended", everywhere)),
          approvedAt: later,
          requestDigest: digestValue,
        },
      ],
    });
    expect(result.rejected).toEqual([
      {
        index: 0,
        approverId: "u-sue",
        reason: "approver_denied_by_rule",
        detail: "suspended-no-refunds",
      },
    ]);
  });
});

describe("re-evaluation compares the actor chain", () => {
  it("reports a record with a changed actor chain as diverged", () => {
    const request = accessRequest(lead, "ticket:read");
    const record = toDecisionRecord(request, decide(policy, request));
    const forged = {
      ...record,
      actorChain: [{ type: "human" as const, id: "u-x", grantId: null }],
    };
    expect(reevaluate(policy, forged).status).toBe("diverged");
    expect(reevaluate(policy, record).status).toBe("reproduced");
  });
});

describe("catalogue registry", () => {
  it("accepts catalogues from defineCatalog", () => {
    const fresh = defineCatalog({ note: { actions: ["read"] } });
    expect(() =>
      compilePolicy(fresh, {
        schema: 2,
        version: "v",
        roles: {},
        denies: [],
        approvalRules: [],
        separationOfDuties: {
          requesterNeverApprovesSameType: false,
          exclusiveRequestAndApproveRoles: false,
        },
      }),
    ).not.toThrow();
  });
});

describe("calendar days", () => {
  it("accepts 29 February only in leap years", () => {
    const leap = accessRequest(lead, "ticket:read", {}, { now: "2028-02-29T00:00:00Z" });
    const common = accessRequest(lead, "ticket:read", {}, { now: "2027-02-29T00:00:00Z" });
    const april = accessRequest(lead, "ticket:read", {}, { now: "2026-04-31T00:00:00Z" });
    expect(decide(policy, leap).outcome).toBe("allow");
    expect(decide(policy, common).reason).toBe("invalid_request");
    expect(decide(policy, april).reason).toBe("invalid_request");
  });
});
