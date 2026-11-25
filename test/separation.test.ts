// The separation rule per request (Rule A and Rule B as data from the caller). Each case names
// the rule it checks; see docs/reference.md, "Separation rule per request".
import { describe, expect, it } from "vitest";

import {
  compilePolicy,
  defineCatalog,
  evaluateApprovals,
  PermitkitError,
  requestDigest,
  type ApprovalDecision,
  type PolicyInput,
  type SeparationRule,
  type Subject,
} from "../src/index.js";

const all = { kind: "all" } as const;
const unlimited = { kind: "unlimited" } as const;
const catalog = defineCatalog({ ticket: { actions: ["refund", "read"] } });

function policyOf(
  options: {
    sameType?: boolean;
    exclusive?: boolean;
    perRequestRule?: "required";
    eligibility?: "roles" | "permission";
  } = {},
) {
  const input: PolicyInput = {
    schema: 2,
    version: "sep-1",
    roles: {
      lead: {
        grants: [{ id: "lead", permissions: ["ticket:refund"], scope: all, limits: unlimited }],
      },
      approver: { grants: [] },
    },
    denies: [],
    approvalRules: [
      {
        id: "refund-dual",
        permissions: ["ticket:refund"],
        when: { kind: "always" },
        approvers: 2,
        expiresInSeconds: 3600,
        eligibleApprovers:
          options.eligibility === "permission"
            ? { kind: "permission" }
            : { kind: "roles", roles: ["approver"] },
        requireProof: false,
      },
    ],
    separationOfDuties: {
      requesterNeverApprovesSameType: options.sameType ?? false,
      exclusiveRequestAndApproveRoles: options.exclusive ?? false,
      ...(options.perRequestRule === undefined ? {} : { perRequestRule: options.perRequestRule }),
    },
  };
  return compilePolicy(catalog, input);
}

const policy = policyOf();
const person = (id: string, ...roles: string[]): Subject => ({
  type: "human",
  id,
  roles: roles.map((role) => ({ role, scope: all })),
  act: null,
});
// The requester can request and approve, so that self-approval has an eligible approver.
const requester = person("u-req", "lead", "approver");
const peerA = person("u-a", "approver");
const peerB = person("u-b", "approver");
const contributor = person("u-con", "approver");
const priorRequester = person("u-prior", "approver");

const requestOf = (subject: Subject) => ({
  subject,
  action: { name: "refund" },
  resource: { type: "ticket", id: "t1" },
  context: { now: "2026-01-15T10:00:00.000Z" },
});
const request = requestOf(requester);
const now = "2026-01-15T10:30:00.000Z";

const approvalBy = (approver: Subject, forRequest: unknown = request, on = policy) => ({
  approver,
  approvedAt: "2026-01-15T10:10:00.000Z",
  requestDigest: requestDigest(on, forRequest),
});

const history = [{ principalId: "u-prior", permission: "ticket:refund" }];

function rule(
  requesterMayApprove: boolean,
  roleSeparation: SeparationRule["roleSeparation"],
  contributors: string[] | "absent" = ["u-con"],
): Record<string, unknown> {
  return {
    version: "v7",
    requesterMayApprove,
    roleSeparation,
    ...(contributors === "absent" ? {} : { contributors }),
  };
}

function inputOf(approvers: Subject[], separation?: unknown, extra: Record<string, unknown> = {}) {
  return {
    request,
    now,
    approvals: approvers.map((approver) => approvalBy(approver)),
    priorRequests: history,
    ...(separation === undefined ? {} : { separation }),
    ...extra,
  };
}

const rejections = (decision: ApprovalDecision) =>
  decision.rejected.map((item) => `${item.approverId ?? "?"}:${item.reason}`);

describe("Rule A: self-approval", () => {
  it("refuses the requester under the default, without a rule and with requesterMayApprove false", async () => {
    const without = await evaluateApprovals(policy, inputOf([requester, peerA]));
    const off = await evaluateApprovals(policy, inputOf([requester, peerA], rule(false, "off")));
    for (const decision of [without, off]) {
      expect(decision.outcome).toBe("pending");
      expect(decision.counted).toEqual(["u-a"]);
      expect(rejections(decision)).toEqual(["u-req:requester_cannot_approve"]);
      expect(decision.waived).toEqual([]);
    }
    expect(without.separation).toBeNull();
    expect(off.separation).toEqual({
      version: "v7",
      requesterMayApprove: false,
      roleSeparation: "off",
    });
  });

  it("counts the requester once where allowed, and still requires two distinct approvers", async () => {
    const both = await evaluateApprovals(policy, inputOf([requester, peerA], rule(true, "off")));
    expect(both.outcome).toBe("allow");
    expect(both.counted).toEqual(["u-req", "u-a"]);
    expect(both.waived).toEqual([{ approverId: "u-req", checks: ["requester"] }]);
    const alone = await evaluateApprovals(policy, inputOf([requester], rule(true, "off")));
    expect(alone.outcome).toBe("pending");
    expect(alone.required).toBe(2);
    expect(alone.counted).toEqual(["u-req"]);
    const twice = await evaluateApprovals(
      policy,
      inputOf([requester, requester], rule(true, "simple")),
    );
    expect(twice.outcome).toBe("pending");
    expect(rejections(twice)).toEqual(["u-req:duplicate_approver"]);
  });
});

describe("conflicts", () => {
  it("refuses strict Rule B together with self-approval", async () => {
    const decision = await evaluateApprovals(policy, inputOf([peerA, peerB], rule(true, "strict")));
    expect([decision.outcome, decision.reason]).toEqual(["deny", "separation_conflict"]);
    expect(decision.counted).toEqual([]);
  });

  it("refuses a rule that waives what a policy flag requires", async () => {
    const sameType = policyOf({ sameType: true });
    const exclusive = policyOf({ exclusive: true });
    const byPermission = policyOf({ eligibility: "permission" });
    const cases: [ReturnType<typeof policyOf>, Record<string, unknown>][] = [
      [sameType, rule(true, "simple")],
      [sameType, rule(false, "off")],
      [exclusive, rule(true, "off")],
      [exclusive, rule(true, "simple")],
      [byPermission, rule(false, "strict")],
    ];
    // The requester holds no approver role, so that the policy flag does not deny it first.
    const leadRequest = requestOf(person("u-lead-req", "lead"));
    for (const [on, separation] of cases) {
      const input = {
        request: leadRequest,
        now,
        approvals: [approvalBy(peerA, leadRequest, on), approvalBy(peerB, leadRequest, on)],
        priorRequests: [],
        separation,
      };
      const decision = await evaluateApprovals(on, input);
      expect([decision.outcome, decision.reason]).toEqual(["deny", "separation_policy_conflict"]);
    }
  });

  it("accepts a rule that keeps what the policy flags require", async () => {
    const sameType = policyOf({ sameType: true });
    const input = {
      request,
      now,
      approvals: [approvalBy(peerA, request, sameType), approvalBy(peerB, request, sameType)],
      priorRequests: [],
      separation: rule(false, "simple"),
    };
    const decision = await evaluateApprovals(sameType, input);
    expect([decision.outcome, decision.reason]).toEqual(["allow", "approved"]);
  });
});

describe("Rule B: contributors and earlier requesters", () => {
  it("refuses a contributor under simple and strict Rule B, and counts one with a waiver otherwise", async () => {
    // The requester holds no approver role, so that strict Rule B does not refuse it first.
    const leadRequest = requestOf(person("u-lead-req", "lead"));
    for (const separation of [rule(false, "simple"), rule(false, "strict")]) {
      const decision = await evaluateApprovals(policy, {
        request: leadRequest,
        now,
        approvals: [approvalBy(contributor, leadRequest), approvalBy(peerA, leadRequest)],
        priorRequests: history,
        separation,
      });
      expect(rejections(decision)).toEqual(["u-con:sod_contributor"]);
      expect(decision.outcome).toBe("pending");
    }
    for (const separation of [rule(true, "simple"), rule(false, "off"), rule(true, "off")]) {
      const decision = await evaluateApprovals(policy, inputOf([contributor, peerA], separation));
      expect(decision.outcome).toBe("allow");
      expect(decision.waived).toEqual([{ approverId: "u-con", checks: ["contributor"] }]);
    }
  });

  it("refuses an earlier requester of the same type under simple Rule B, and counts one with a waiver otherwise", async () => {
    const refused = await evaluateApprovals(
      policy,
      inputOf([priorRequester, peerA], rule(false, "simple")),
    );
    expect(rejections(refused)).toEqual(["u-prior:sod_prior_request"]);
    const waived = await evaluateApprovals(
      policy,
      inputOf([priorRequester, peerA], rule(true, "simple")),
    );
    expect(waived.outcome).toBe("allow");
    expect(waived.waived).toEqual([{ approverId: "u-prior", checks: ["same_type"] }]);
  });

  it("lists every waived check of one approver in a fixed order", async () => {
    const everything = await evaluateApprovals(
      policy,
      inputOf([requester, peerA], rule(true, "simple", ["u-req"]), {
        priorRequests: [{ principalId: "u-req", permission: "ticket:refund" }],
      }),
    );
    expect(everything.waived).toEqual([
      { approverId: "u-req", checks: ["requester", "contributor", "same_type"] },
    ]);
  });

  it("strict Rule B refuses an approver with a requesting role and a requester with an approver role", async () => {
    const dual = person("u-dual", "approver", "lead");
    const onlyLead = person("u-lead-req", "lead");
    const strictInput = {
      request: requestOf(onlyLead),
      now,
      approvals: [approvalBy(dual, requestOf(onlyLead)), approvalBy(peerA, requestOf(onlyLead))],
      priorRequests: [],
      separation: rule(false, "strict", []),
    };
    const approverSide = await evaluateApprovals(policy, strictInput);
    expect(rejections(approverSide)).toEqual(["u-dual:sod_role_conflict"]);
    const simple = await evaluateApprovals(policy, {
      ...strictInput,
      separation: rule(false, "simple", []),
    });
    expect(simple.outcome).toBe("allow");
    const requesterSide = await evaluateApprovals(policy, {
      ...inputOf([peerA, peerB]),
      separation: rule(false, "strict", []),
    });
    expect([requesterSide.outcome, requesterSide.reason]).toEqual([
      "deny",
      "requester_role_conflict",
    ]);
  });
});

describe("missing Rule B inputs refuse, never read as empty", () => {
  it("refuses a rule without contributors", async () => {
    for (const separation of [
      rule(false, "simple", "absent"),
      rule(false, "strict", "absent"),
      rule(true, "off", "absent"),
    ]) {
      const decision = await evaluateApprovals(policy, inputOf([peerA, peerB], separation));
      expect([decision.outcome, decision.reason]).toEqual(["deny", "sod_contributors_missing"]);
    }
  });

  it("refuses a rule without priorRequests", async () => {
    const input: Record<string, unknown> = inputOf([peerA, peerB], rule(false, "simple"));
    delete input["priorRequests"];
    const decision = await evaluateApprovals(policy, input);
    expect([decision.outcome, decision.reason]).toEqual(["deny", "sod_history_missing"]);
  });
});

describe("agents", () => {
  // A subject cannot have the type "agent": an agent acts only in an actor chain. So an agent
  // approves either as a non-human principal or through a human's chain.
  const machine: Subject = {
    type: "service",
    id: "bot-x",
    roles: [{ role: "approver", scope: all }],
    act: null,
  };
  const delegated: Subject = {
    ...peerA,
    act: { type: "agent", id: "bot-y", grant: null, act: null },
  };
  const rules = [
    undefined,
    rule(false, "off"),
    rule(false, "simple"),
    rule(false, "strict", []),
    rule(true, "off"),
    rule(true, "simple"),
  ];

  it("never counts an agent approver, under every rule", async () => {
    const onlyLead = person("u-lead-req", "lead");
    for (const separation of rules) {
      const decision = await evaluateApprovals(policy, {
        request: requestOf(onlyLead),
        now,
        approvals: [
          approvalBy(machine, requestOf(onlyLead)),
          approvalBy(delegated, requestOf(onlyLead)),
        ],
        priorRequests: [],
        ...(separation === undefined ? {} : { separation }),
      });
      expect(decision.counted).toEqual([]);
      expect(rejections(decision)).toEqual([
        "bot-x:approver_not_human",
        "u-a:approver_is_delegated",
      ]);
    }
  });

  it("treats an agent's request as the principal's own: the principal only with self-approval, the agent never", async () => {
    const viaAgent: Subject = {
      ...requester,
      act: {
        type: "agent",
        id: "bot",
        grant: {
          id: "g",
          principalId: "u-req",
          principalType: "human",
          agentId: "bot",
          entries: [{ permissions: ["ticket:refund"], scope: all, limits: unlimited }],
          notBefore: null,
          expiresAt: "2027-01-01T00:00:00Z",
          revokedAt: null,
        },
        act: null,
      },
    };
    const agentRequest = requestOf(viaAgent);
    // A human account with the agent's id: the chain id still never approves.
    const botHuman = person("bot", "approver");
    const inputFor = (separation?: unknown) => ({
      request: agentRequest,
      now,
      approvals: [approvalBy(requester, agentRequest), approvalBy(botHuman, agentRequest)],
      priorRequests: [],
      ...(separation === undefined ? {} : { separation }),
    });
    for (const separation of [undefined, rule(false, "off"), rule(false, "simple")]) {
      const decision = await evaluateApprovals(policy, inputFor(separation));
      expect(rejections(decision)).toEqual([
        "u-req:requester_cannot_approve",
        "bot:requester_cannot_approve",
      ]);
    }
    const allowed = await evaluateApprovals(policy, inputFor(rule(true, "off")));
    expect(allowed.counted).toEqual(["u-req"]);
    expect(allowed.waived).toEqual([{ approverId: "u-req", checks: ["requester"] }]);
    expect(rejections(allowed)).toEqual(["bot:requester_cannot_approve"]);
  });
});

describe("a required rule and the rule's shape", () => {
  const required = policyOf({ perRequestRule: "required" });
  const requiredInput = (separation?: unknown) => ({
    request,
    now,
    approvals: [approvalBy(peerA, request, required), approvalBy(peerB, request, required)],
    priorRequests: [],
    ...(separation === undefined ? {} : { separation }),
  });

  it("refuses an input without a rule where the policy requires one", async () => {
    const decision = await evaluateApprovals(required, requiredInput());
    expect([decision.outcome, decision.reason]).toEqual(["deny", "separation_rule_missing"]);
    const withRule = await evaluateApprovals(required, requiredInput(rule(false, "simple")));
    expect([withRule.outcome, withRule.reason]).toEqual(["allow", "approved"]);
    // The same input without the option is evaluated as before.
    const before = await evaluateApprovals(policy, {
      ...requiredInput(),
      approvals: [approvalBy(peerA), approvalBy(peerB)],
    });
    expect([before.outcome, before.reason]).toEqual(["allow", "approved"]);
  });

  it("refuses every malformed rule with separation_invalid, also where self-approval would widen", async () => {
    const malformed: unknown[] = [
      null,
      "simple",
      [],
      {},
      { ...rule(true, "off"), requesterMayApprove: "true" },
      { ...rule(true, "off"), requesterMayApprove: 1 },
      { ...rule(true, "off"), roleSeparation: "Simple" },
      { ...rule(true, "off"), roleSeparation: "none" },
      { ...rule(true, "off"), extra: 1 },
      { ...rule(true, "off"), version: "" },
      { ...rule(true, "off"), version: "x".repeat(129) },
      { ...rule(true, "off"), contributors: [""] },
      { ...rule(true, "off"), contributors: "u-con" },
      { requesterMayApprove: true, roleSeparation: "off", contributors: [] },
      JSON.parse(
        '{"__proto__":{"requesterMayApprove":true},"version":"v","roleSeparation":"off","contributors":[]}',
      ),
    ];
    for (const on of [policy, required]) {
      for (const separation of malformed) {
        const input = {
          request,
          now,
          approvals: [approvalBy(requester, request, on), approvalBy(peerA, request, on)],
          priorRequests: [],
          separation,
        };
        const decision = await evaluateApprovals(on, input);
        expect([decision.outcome, decision.reason, decision.separation]).toEqual([
          "deny",
          "separation_invalid",
          null,
        ]);
      }
    }
  });

  it("does not change the input, and the rule does not change the request digest", async () => {
    const input = inputOf([requester, peerA], rule(true, "simple"));
    const frozen = structuredClone(input);
    const deepFreeze = (value: unknown): void => {
      if (typeof value !== "object" || value === null) return;
      Object.freeze(value);
      for (const item of Object.values(value)) deepFreeze(item);
    };
    deepFreeze(frozen);
    const decision = await evaluateApprovals(policy, frozen);
    expect(decision.outcome).toBe("allow");
    expect(frozen).toEqual(input);
    const without = await evaluateApprovals(policy, inputOf([peerA, peerB]));
    expect(decision.requestDigest).toBe(requestDigest(policy, request));
    expect(without.requestDigest).toBe(decision.requestDigest);
  });

  it("refuses a policy with another perRequestRule value", () => {
    expect(() => policyOf({ perRequestRule: "optional" as "required" })).toThrow(PermitkitError);
  });
});
