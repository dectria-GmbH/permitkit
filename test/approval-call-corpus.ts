// The approval and record calls that the call-time spy watches: evaluateApprovals on inputs that
// reach every branch (each decision reason and each rejection reason, options checks, proofs
// and verifier results), and reevaluate, toDecisionRecord and decideAndRecord on valid, forged
// and malformed records. Everything is built before the spies are installed. Verifiers are
// caller code: each one pauses the spy while it runs, so only permitkit's own code is recorded,
// also its handling of the verifier result.
import {
  compilePolicy,
  decide,
  decideAndRecord,
  defineCatalog,
  requestDigest,
  toDecisionRecord,
  type AccessRequest,
  type ApprovalProofVerifier,
  type CompiledPolicy,
  type DecisionRecord,
  type PolicyInput,
  type Subject,
} from "../src/index.js";

export const approvalCatalog = defineCatalog({
  ticket: { actions: ["refund", "read"], scopes: ["queue"], limits: ["amount"] },
});

const all = { kind: "all" } as const;
const unlimited = { kind: "unlimited" } as const;

function rule(
  eligibleApprovers: PolicyInput["approvalRules"][number]["eligibleApprovers"],
  proof: boolean,
): PolicyInput["approvalRules"][number] {
  return {
    id: "refund-dual",
    permissions: ["ticket:refund"],
    when: { kind: "threshold", properties: { amount: { gte: 100 } } },
    approvers: 2,
    expiresInSeconds: 3600,
    eligibleApprovers,
    requireProof: proof,
    ...(proof ? { proofTypes: ["sig", "otp"] } : {}),
  };
}

const roles: PolicyInput["roles"] = {
  lead: {
    grants: [
      { id: "lead", permissions: ["ticket:refund", "ticket:read"], scope: all, limits: unlimited },
    ],
  },
  approver: {
    grants: [{ id: "appr", permissions: ["ticket:read"], scope: all, limits: unlimited }],
  },
  peer: {
    grants: [
      {
        id: "peer",
        permissions: ["ticket:refund"],
        scope: { kind: "match", properties: { queue: ["a"] } },
        limits: unlimited,
      },
    ],
  },
  suspended: { grants: [] },
};

/** Role eligibility, both separation-of-duties settings and a deny rule for approvers. */
const byRole: PolicyInput = {
  schema: 2,
  version: "approval-roles",
  roles,
  denies: [
    { id: "no-suspended", permissions: ["ticket:refund"], roles: ["suspended"], scope: all },
  ],
  approvalRules: [rule({ kind: "roles", roles: ["approver", "peer"] }, false)],
  separationOfDuties: {
    requesterNeverApprovesSameType: true,
    exclusiveRequestAndApproveRoles: true,
  },
};

/** Permission eligibility with proofs of two types. */
const byPermission: PolicyInput = {
  schema: 2,
  version: "approval-permission",
  roles,
  denies: [],
  approvalRules: [rule({ kind: "permission" }, true)],
  separationOfDuties: {
    requesterNeverApprovesSameType: false,
    exclusiveRequestAndApproveRoles: false,
  },
};

/** One role with one grant of one permission: the one-item paths of compilePolicy. */
export const oneRolePolicyInput: PolicyInput = {
  schema: 2,
  version: "one-role",
  roles: {
    lead: { grants: [{ id: "lead", permissions: ["ticket:read"], scope: all, limits: unlimited }] },
  },
  denies: [],
  approvalRules: [],
  separationOfDuties: {
    requesterNeverApprovesSameType: false,
    exclusiveRequestAndApproveRoles: false,
  },
};

export const approvalPolicyInputs = { byRole, byPermission, oneRole: oneRolePolicyInput };

export const approvalPolicies = {
  byRole: compilePolicy(approvalCatalog, byRole),
  byPermission: compilePolicy(approvalCatalog, byPermission),
  oneRole: compilePolicy(approvalCatalog, oneRolePolicyInput),
};

const person = (id: string, ...held: string[]): Subject => ({
  type: "human",
  id,
  roles: held.map((role) => ({
    role,
    scope: role === "peer" ? { kind: "match", properties: { queue: ["a"] } } : all,
  })),
  act: null,
});

const requestAt = "2026-01-15T10:00:00.000Z";
const later = "2026-01-15T10:30:00.000Z";

function requestOf(subject: Subject, action: string, amount: number): AccessRequest {
  return {
    subject,
    action: { name: action },
    resource: { type: "ticket", id: "t1", properties: { queue: "a", amount } },
    context: { now: requestAt },
  };
}

const requester = person("u-req", "lead");
const refund = requestOf(requester, "refund", 500);

export interface ApprovalCase {
  readonly name: string;
  readonly policy: CompiledPolicy;
  readonly input: unknown;
  readonly options?: unknown;
}

/** Hooks that a verifier calls, so the spy does not record caller code. */
export interface SpyHooks {
  pause(): void;
  resume(): void;
}

export function approvalCases(hooks: SpyHooks): ApprovalCase[] {
  const roleDigest = requestDigest(approvalPolicies.byRole, refund);
  const permissionDigest = requestDigest(approvalPolicies.byPermission, refund);
  const approval = (
    approver: Subject,
    extra: Record<string, unknown> = {},
    digest = roleDigest,
  ) => ({
    approver,
    approvedAt: "2026-01-15T10:10:00.000Z",
    requestDigest: digest,
    ...extra,
  });
  const proofOf = (
    approver: Subject,
    type: string,
    payload: unknown,
    digest = permissionDigest,
  ) => ({
    type,
    approverId: approver.id,
    requestDigest: digest,
    payload,
  });
  const signed = (approver: Subject, type: string, payload: unknown) =>
    approval(approver, { proof: proofOf(approver, type, payload) }, permissionDigest);

  /** A verifier that pauses the spy while it runs and answers from the payload. */
  const verifierOf = (
    type: string,
    answer: (payload: unknown, approverId: string, digest: string) => unknown,
  ) => ({
    type,
    verify(proof: { payload?: unknown }, expected: { approverId: string; requestDigest: string }) {
      hooks.pause();
      try {
        return answer(proof.payload, expected.approverId, expected.requestDigest);
      } finally {
        hooks.resume();
      }
    },
  });
  const sig = verifierOf("sig", (payload, approverId, digest) => {
    switch (payload) {
      case "ok":
        return { valid: true, approverId, requestDigest: digest };
      case "async-ok":
        return Promise.resolve({ valid: true, approverId, requestDigest: digest });
      case "async-bad":
        return Promise.resolve({ valid: false, reason: "bad signature" });
      case "async-throws":
        return Promise.reject(new Error("verifier down"));
      case "echo":
        return { valid: true, approverId: "someone-else", requestDigest: digest };
      case "string":
        return "valid";
      case "thenable":
        // oxlint-disable-next-line unicorn/no-thenable
        return { then: (resolve: (value: unknown) => void) => resolve({ valid: true }) };
      case "throws":
        throw new Error("verifier failed");
      default:
        return { valid: false, reason: "bad signature" };
    }
  });
  const options = { verifiers: [sig] as ApprovalProofVerifier[] };

  const peerA = person("u-a", "approver");
  const peerB = person("u-b", "approver");
  const peerC = person("u-c", "peer");
  const lead = person("u-lead", "lead", "approver");
  const suspended = person("u-s", "approver", "suspended");
  const prior = person("u-prior", "approver");
  const roleless = person("u-x");
  const service: Subject = { ...person("u-svc", "approver"), type: "service" };
  const delegated: Subject = {
    ...person("u-del", "approver"),
    act: { type: "agent", id: "bot", grant: null, act: null },
  };
  const viaRequesterAgent: Subject = {
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
  // The agent grant starts after the request time, so the request was not approvable then.
  const lateAgent: Subject = {
    ...viaRequesterAgent,
    act: {
      type: "agent",
      id: "bot",
      grant: {
        id: "g",
        principalId: "u-req",
        principalType: "human",
        agentId: "bot",
        entries: [{ permissions: ["ticket:refund"], scope: all, limits: unlimited }],
        notBefore: "2026-01-15T10:15:00.000Z",
        expiresAt: "2027-01-01T00:00:00Z",
        revokedAt: null,
      },
      act: null,
    },
  };
  const history = [{ principalId: "u-prior", permission: "ticket:refund" }];
  const base = { request: refund, now: later, priorRequests: history };
  const byRolePolicy = approvalPolicies.byRole;
  const byPermissionPolicy = approvalPolicies.byPermission;

  const cases: ApprovalCase[] = [
    // Allowed and pending.
    {
      name: "approved",
      policy: byRolePolicy,
      input: { ...base, approvals: [approval(peerA), approval(peerB)] },
    },
    { name: "pending", policy: byRolePolicy, input: { ...base, approvals: [approval(peerA)] } },
    {
      name: "approval not required",
      policy: byRolePolicy,
      input: { ...base, request: requestOf(requester, "refund", 5), approvals: [] },
    },
    {
      name: "one role, no approval rule",
      policy: approvalPolicies.oneRole,
      input: { ...base, request: requestOf(person("u", "lead"), "read", 1), approvals: [] },
    },
    // Every rejection of an approval.
    {
      name: "each rejection",
      policy: byRolePolicy,
      input: {
        ...base,
        approvals: [
          { junk: 1 },
          approval(service),
          approval(delegated),
          approval(requester),
          approval(peerA),
          approval(peerA),
          approval(peerB, {}, "0".repeat(64)),
          approval(peerC, { approvedAt: "2026-01-15T09:00:00.000Z" }),
          approval(peerC, { approvedAt: "2026-01-15T11:30:00.000Z" }),
          approval(peerC, { approvedAt: "2026-01-15T10:45:00.000Z" }),
          approval(suspended),
          approval(roleless),
          approval(lead),
          approval(prior),
        ],
      },
    },
    {
      name: "agent of the requester cannot approve",
      policy: byRolePolicy,
      input: {
        ...base,
        request: requestOf(viaRequesterAgent, "refund", 500),
        approvals: [approval(person("bot", "approver"))],
      },
    },
    {
      name: "permission eligibility and proofs",
      policy: byPermissionPolicy,
      input: {
        request: refund,
        now: later,
        approvals: [
          signed(person("p-ok", "lead"), "sig", "ok"),
          signed(person("p-async", "lead"), "sig", "async-ok"),
          approval(person("p-none", "lead"), {}, permissionDigest),
          signed(person("p-type", "lead"), "pin", "ok"),
          approval(
            person("p-mismatch", "lead"),
            { proof: proofOf(peerA, "sig", "ok") },
            permissionDigest,
          ),
          signed(person("p-otp", "lead"), "otp", "ok"),
          signed(person("p-bad", "lead"), "sig", "bad"),
          signed(person("p-async-bad", "lead"), "sig", "async-bad"),
          signed(person("p-async-throws", "lead"), "sig", "async-throws"),
          signed(person("p-echo", "lead"), "sig", "echo"),
          signed(person("p-string", "lead"), "sig", "string"),
          signed(person("p-thenable", "lead"), "sig", "thenable"),
          signed(person("p-throws", "lead"), "sig", "throws"),
          signed(person("p-not-permitted", "approver"), "sig", "ok"),
        ],
      },
      options,
    },
    // Decision reasons before the approvals.
    {
      name: "requester denied",
      policy: byRolePolicy,
      input: {
        ...base,
        request: requestOf(person("u-v", "approver"), "refund", 500),
        approvals: [],
      },
    },
    {
      name: "not approvable at request time",
      policy: byRolePolicy,
      input: { ...base, request: requestOf(lateAgent, "refund", 500), approvals: [] },
    },
    {
      name: "window expired",
      policy: byRolePolicy,
      input: { ...base, now: "2026-01-15T11:30:00.000Z", approvals: [] },
    },
    {
      name: "history missing",
      policy: byRolePolicy,
      input: { request: refund, now: later, approvals: [] },
    },
    {
      name: "history with an unknown permission",
      policy: byRolePolicy,
      input: {
        ...base,
        priorRequests: [{ principalId: "u-a", permission: "ticket:fly" }],
        approvals: [],
      },
    },
    {
      name: "too many approvals",
      policy: byRolePolicy,
      input: { ...base, approvals: Array.from({ length: 21 }, () => ({})) },
    },
    {
      name: "request too large",
      policy: byRolePolicy,
      input: {
        ...base,
        request: { ...refund, resource: { type: "t", id: "x".repeat(5000) } },
        approvals: [],
      },
    },
    {
      name: "now before the request",
      policy: byRolePolicy,
      input: { ...base, now: "2026-01-15T09:00:00.000Z", approvals: [] },
    },
    // Invalid inputs.
    { name: "input null", policy: byRolePolicy, input: null },
    {
      name: "input not plain",
      policy: byRolePolicy,
      input: { ...base, approvals: [], extra: new Map() },
    },
    { name: "unknown key", policy: byRolePolicy, input: { ...base, approvals: [], extra: 1 } },
    {
      name: "now invalid",
      policy: byRolePolicy,
      input: { ...base, now: "2026-02-30T10:00:00Z", approvals: [] },
    },
    {
      name: "request invalid",
      policy: byRolePolicy,
      input: { ...base, request: { ...refund, action: { name: "" } }, approvals: [] },
    },
    {
      name: "prior request invalid",
      policy: byRolePolicy,
      input: { ...base, priorRequests: [{ principalId: "" }], approvals: [] },
    },
    { name: "approvals not a list", policy: byRolePolicy, input: { ...base, approvals: {} } },
    // Options.
    {
      name: "options not an object",
      policy: byRolePolicy,
      input: { ...base, approvals: [] },
      options: 1,
    },
    {
      name: "unknown option",
      policy: byRolePolicy,
      input: { ...base, approvals: [] },
      options: { verifier: [] },
    },
    {
      name: "verifiers not a list",
      policy: byRolePolicy,
      input: { ...base, approvals: [] },
      options: { verifiers: {} },
    },
    {
      name: "verifier without verify",
      policy: byRolePolicy,
      input: { ...base, approvals: [] },
      options: { verifiers: [{ type: "sig" }] },
    },
    {
      name: "two verifiers of one type",
      policy: byRolePolicy,
      input: { ...base, approvals: [] },
      options: { verifiers: [sig, sig] },
    },
    {
      name: "policy not compiled",
      policy: {} as CompiledPolicy,
      input: { ...base, approvals: [] },
    },
  ];
  return cases;
}

export interface RecordCase {
  readonly name: string;
  readonly policy: CompiledPolicy;
  readonly record: unknown;
}

const sample = (role: string) => requestOf(person("u-r", role), "refund", 500);

/** Records for reevaluate: reproduced, diverged, policy mismatch and not replayable. */
export function recordCases(): RecordCase[] {
  const policy = approvalPolicies.byRole;
  const { record } = decideAndRecord(policy, sample("lead"));
  const forged: DecisionRecord = { ...record, request: sample("approver") };
  const one = decideAndRecord(approvalPolicies.oneRole, requestOf(person("u", "lead"), "read", 1));
  const without = (key: string) => {
    const copy: Record<string, unknown> = { ...record };
    delete copy[key];
    return copy;
  };
  return [
    { name: "reproduced", policy, record },
    { name: "reproduced, one role", policy: approvalPolicies.oneRole, record: one.record },
    { name: "diverged", policy, record: forged },
    { name: "policy mismatch", policy: approvalPolicies.byPermission, record },
    { name: "request null", policy, record: { ...record, request: null } },
    { name: "no request", policy, record: without("request") },
    { name: "no rule", policy, record: without("rule") },
    { name: "other schema", policy, record: { ...record, schema: "permitkit.decision/1" } },
    { name: "unknown key", policy, record: { ...record, extra: 1 } },
    {
      name: "invalid request",
      policy,
      record: { ...record, request: { ...sample("lead"), extra: 1 } },
    },
    { name: "not plain", policy, record: { ...record, rule: new Date(0) } },
    { name: "null", policy, record: null },
    { name: "policy not compiled", policy: {} as CompiledPolicy, record },
  ];
}

/** Requests and their decisions for toDecisionRecord and decideAndRecord. */
export function recordRequests(): {
  policy: CompiledPolicy;
  request: unknown;
  decision: ReturnType<typeof decide>;
}[] {
  const policy = approvalPolicies.byRole;
  const requests: unknown[] = [
    sample("lead"),
    sample("approver"),
    requestOf(person("u", "lead"), "refund", 5),
    { ...sample("lead"), extra: 1 },
    null,
  ];
  return requests.map((request) => ({ policy, request, decision: decide(policy, request) }));
}

export { toDecisionRecord };
