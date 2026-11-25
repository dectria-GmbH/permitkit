// Policies and requests for the tests that replace built-ins after load. The requests are
// generated from a fixed seed, so every run sees the same corpus. They reach every decision step:
// deny rules by role, subject type and scope, grants with scopes and limits, agent grants
// (valid, expired, revoked, issued by someone else, too narrow), separation of duties and
// approval thresholds.
import {
  compilePolicy,
  defineCatalog,
  type AccessRequest,
  type AuthZenRequest,
  type CompiledPolicy,
  type PolicyInput,
  type RoleAssignment,
  type Scope,
  type Subject,
} from "../src/index.js";

export const replacementCatalog = defineCatalog({
  ticket: {
    actions: ["read", "close", "refund", "delete"],
    scopes: ["queue", "project"],
    limits: ["amount"],
  },
  report: { actions: ["read", "export"], scopes: ["project"] },
});

const all: Scope = { kind: "all" };
const sod = { requesterNeverApprovesSameType: false, exclusiveRequestAndApproveRoles: false };

/** Deny rules by subject type, by role and by scope, and a threshold approval rule. */
const first: PolicyInput = {
  schema: 2,
  version: "replace-1",
  roles: {
    support: {
      grants: [
        {
          id: "support-work",
          permissions: ["ticket:read", "ticket:close", "ticket:delete"],
          scope: all,
          limits: { kind: "unlimited" },
        },
        {
          id: "support-refund",
          permissions: ["ticket:refund"],
          scope: { kind: "match", properties: { queue: ["a", "vip"] } },
          limits: { kind: "range", properties: { amount: { min: 0, max: 500 } } },
        },
      ],
    },
    lead: {
      grants: [
        {
          id: "lead-all",
          permissions: ["ticket:read", "ticket:close", "ticket:refund", "ticket:delete"],
          scope: all,
          limits: { kind: "unlimited" },
        },
      ],
    },
    auditor: {
      grants: [
        {
          id: "auditor-read",
          permissions: ["ticket:read", "report:read", "report:export"],
          scope: { kind: "match", properties: { project: ["alpha", "secret"] } },
          limits: { kind: "unlimited" },
        },
      ],
    },
    contractor: {
      grants: [
        {
          id: "contractor-work",
          permissions: ["ticket:read", "ticket:refund"],
          scope: all,
          limits: { kind: "unlimited" },
        },
      ],
    },
  },
  denies: [
    { id: "no-agent-delete", permissions: ["ticket:delete"], subjectTypes: ["agent"], scope: all },
    {
      id: "vip-frozen",
      permissions: ["ticket:close"],
      roles: ["support"],
      scope: { kind: "match", properties: { queue: ["vip"] } },
    },
    {
      id: "no-contractor-refund",
      permissions: ["ticket:refund"],
      roles: ["contractor"],
      scope: all,
    },
    {
      id: "secret-project",
      permissions: ["ticket:read", "report:export"],
      scope: { kind: "match", properties: { project: ["secret"] } },
    },
    {
      id: "no-service-export",
      permissions: ["report:export"],
      subjectTypes: ["service"],
      scope: all,
    },
  ],
  approvalRules: [
    {
      id: "refund-dual",
      permissions: ["ticket:refund"],
      when: { kind: "threshold", properties: { amount: { gte: 100 } } },
      approvers: 2,
      expiresInSeconds: 3600,
      eligibleApprovers: { kind: "permission" },
      requireProof: false,
    },
  ],
  separationOfDuties: sod,
};

/** Exclusive request and approve roles, and an approval rule that always applies. */
const second: PolicyInput = {
  schema: 2,
  version: "replace-2",
  roles: {
    support: {
      grants: [
        {
          id: "s-read",
          permissions: ["ticket:read", "ticket:close"],
          scope: { kind: "match", properties: { queue: ["a", "vip"] } },
          limits: { kind: "unlimited" },
        },
        {
          id: "s-refund",
          permissions: ["ticket:refund"],
          scope: all,
          limits: { kind: "range", properties: { amount: { min: null, max: 200 } } },
        },
      ],
    },
    lead: {
      grants: [
        {
          id: "l-refund",
          permissions: ["ticket:refund", "ticket:delete"],
          scope: all,
          limits: { kind: "unlimited" },
        },
      ],
    },
    approver: {
      grants: [
        { id: "a-read", permissions: ["ticket:read"], scope: all, limits: { kind: "unlimited" } },
      ],
    },
    auditor: {
      grants: [
        {
          id: "au-report",
          permissions: ["report:read", "report:export"],
          scope: all,
          limits: { kind: "unlimited" },
        },
      ],
    },
  },
  denies: [
    {
      id: "no-agent-export",
      permissions: ["report:export"],
      subjectTypes: ["agent", "service"],
      scope: { kind: "match", properties: { project: ["alpha"] } },
    },
  ],
  approvalRules: [
    {
      id: "delete-dual",
      permissions: ["ticket:delete"],
      when: { kind: "always" },
      approvers: 1,
      expiresInSeconds: 600,
      eligibleApprovers: { kind: "roles", roles: ["approver"] },
      requireProof: false,
    },
    {
      id: "refund-roles",
      permissions: ["ticket:refund"],
      when: { kind: "threshold", properties: { amount: { gte: 50 } } },
      approvers: 1,
      expiresInSeconds: 600,
      eligibleApprovers: { kind: "roles", roles: ["approver", "auditor"] },
      requireProof: false,
    },
  ],
  separationOfDuties: {
    requesterNeverApprovesSameType: false,
    exclusiveRequestAndApproveRoles: true,
  },
};

export const replacementPolicyInputs: readonly PolicyInput[] = [first, second];
export const replacementPolicies: readonly CompiledPolicy[] = replacementPolicyInputs.map((input) =>
  compilePolicy(replacementCatalog, input),
);

/** A small deterministic generator (mulberry32). */
function generator(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let value = state;
    value = Math.imul(value ^ (value >>> 15), value | 1);
    value ^= value + Math.imul(value ^ (value >>> 7), value | 61);
    return ((value ^ (value >>> 14)) >>> 0) / 4294967296;
  };
}

const now = "2026-01-15T10:00:00.000Z";
const permissions = [
  "ticket:read",
  "ticket:close",
  "ticket:refund",
  "ticket:delete",
  "report:read",
  "report:export",
  "ticket:archive",
];
const roleNames = ["support", "lead", "auditor", "contractor", "approver", "ghost"];
const scopes: Scope[] = [
  all,
  { kind: "match", properties: { queue: ["a"] } },
  { kind: "match", properties: { queue: ["vip", "a"] } },
  { kind: "match", properties: { project: ["alpha"] } },
];
const queues = [undefined, "a", "vip", "b", 5];
const projects = [undefined, "alpha", "secret"];
const amounts = [undefined, 0, 49, 50, 99, 100, 150, 250, 600, -1, "100"];

/** The fixed requests, then `count` requests generated from `seed`. */
export function replacementRequests(count: number, seed = 20261124): AccessRequest[] {
  const random = generator(seed);
  const pick = <T>(values: readonly T[]): T => values[Math.floor(random() * values.length)] as T;
  const requests: AccessRequest[] = fixedRequests();
  for (let index = 0; index < count; index += 1) {
    const roles: RoleAssignment[] = [];
    const roleCount = Math.floor(random() * 3) + (random() < 0.9 ? 1 : 0);
    for (let item = 0; item < roleCount; item += 1) {
      roles.push({ role: pick(roleNames), scope: pick(scopes) });
    }
    const type = random() < 0.8 ? "human" : "service";
    const id = `u${Math.floor(random() * 3)}`;
    let subject: Subject = { type, id, roles, act: null };
    const agent = random();
    if (agent < 0.35) {
      const variant = pick(["valid", "valid", "expired", "revoked", "other", "narrow", "future"]);
      const entryPermissions =
        variant === "narrow" ? ["ticket:read"] : [pick(permissions), pick(permissions)];
      subject = {
        ...subject,
        act: {
          type: "agent",
          id: "agent-1",
          grant: {
            id: `grant-${index}`,
            principalId: variant === "other" ? "someone-else" : id,
            principalType: type,
            agentId: "agent-1",
            entries: [
              {
                permissions: entryPermissions,
                scope: pick(scopes),
                limits:
                  random() < 0.5
                    ? { kind: "unlimited" }
                    : { kind: "range", properties: { amount: { min: null, max: 120 } } },
              },
            ],
            notBefore: variant === "future" ? "2026-02-01T00:00:00.000Z" : null,
            expiresAt: variant === "expired" ? "2026-01-01T00:00:00.000Z" : "2026-06-01T00:00:00Z",
            revokedAt: variant === "revoked" ? "2026-01-10T00:00:00.000Z" : null,
          },
          act: null,
        },
      };
    }
    const permission = pick(permissions);
    const [resourceType, actionName] = permission.split(":") as [string, string];
    const properties: Record<string, string | number> = {};
    const queue = pick(queues);
    if (queue !== undefined) properties["queue"] = queue;
    const project = pick(projects);
    if (project !== undefined) properties["project"] = project;
    const amount = pick(amounts);
    if (amount !== undefined) properties["amount"] = amount;
    requests.push({
      subject,
      action: { name: actionName },
      resource: { type: resourceType, ...(random() < 0.5 ? { id: `r${index}` } : {}), properties },
      context: { now, ...(random() < 0.1 ? { policyVersion: "replace-1" } : {}) },
    });
  }
  return requests;
}

const human = (...roles: RoleAssignment[]): Subject => ({
  type: "human",
  id: "u0",
  roles,
  act: null,
});

function fixedRequest(
  subject: Subject,
  permission: string,
  properties: Record<string, string | number>,
): AccessRequest {
  const [type, name] = permission.split(":") as [string, string];
  return { subject, action: { name }, resource: { type, properties }, context: { now } };
}

/** Requests that reach approval_required, a deny rule by role and an agent allow. */
function fixedRequests(): AccessRequest[] {
  const lead = human({ role: "lead", scope: all });
  const support = human({ role: "support", scope: all });
  const agent: Subject = {
    ...support,
    act: {
      type: "agent",
      id: "agent-1",
      grant: {
        id: "grant-fixed",
        principalId: "u0",
        principalType: "human",
        agentId: "agent-1",
        entries: [{ permissions: ["ticket:read"], scope: all, limits: { kind: "unlimited" } }],
        notBefore: null,
        expiresAt: "2026-06-01T00:00:00Z",
        revokedAt: null,
      },
      act: null,
    },
  };
  return [
    fixedRequest(lead, "ticket:refund", { queue: "a", amount: 150 }),
    fixedRequest(lead, "ticket:delete", { queue: "a" }),
    fixedRequest(support, "ticket:close", { queue: "vip" }),
    fixedRequest(human({ role: "contractor", scope: all }), "ticket:refund", { amount: 1 }),
    fixedRequest(agent, "ticket:read", { queue: "a" }),
    fixedRequest(agent, "ticket:delete", { queue: "a" }),
  ];
}

/** The same request in the AuthZEN shape that evaluate() reads. */
export function asAuthZen(request: AccessRequest): AuthZenRequest {
  const resource: AuthZenRequest["resource"] = { type: request.resource.type };
  if (request.resource.id !== undefined) resource.id = request.resource.id;
  if (request.resource.properties !== undefined) resource.properties = request.resource.properties;
  const context: Record<string, unknown> = { now: request.context.now };
  if (request.context.policyVersion !== undefined) {
    context["policy_version"] = request.context.policyVersion;
  }
  return {
    subject: {
      type: request.subject.type,
      id: request.subject.id,
      properties: { roles: request.subject.roles, act: request.subject.act },
    },
    action: { name: request.action.name },
    resource,
    context,
  };
}
