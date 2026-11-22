import { compilePolicy, defineCatalog, type PolicyInput } from "../src/index.js";

export const catalog = defineCatalog({
  ticket: {
    actions: ["read", "close", "refund", "delete"],
    scopes: ["queue", "project"],
    limits: ["amount"],
  },
  report: { actions: ["read", "export"], scopes: ["project"] },
});

export const policyInput = {
  schema: 1,
  version: "2026-01-01.1",
  roles: {
    support: {
      grants: [
        { id: "support-work", permissions: ["ticket:read", "ticket:close"] },
        { id: "support-refund", permissions: ["ticket:refund"], limits: { amount: { max: 500 } } },
      ],
    },
    lead: {
      grants: [
        {
          id: "lead-all",
          permissions: ["ticket:read", "ticket:close", "ticket:refund", "ticket:delete"],
        },
      ],
    },
    auditor: {
      grants: [
        {
          id: "auditor-read",
          permissions: ["ticket:read", "report:read"],
          scope: { project: ["alpha"] },
        },
      ],
    },
    approver: { grants: [] },
  },
  denies: [
    { id: "no-delete-by-agents", permissions: ["ticket:delete"], subjectTypes: ["agent"] },
    {
      id: "vip-queue-frozen",
      permissions: ["ticket:close"],
      roles: ["support"],
      scope: { queue: ["vip"] },
    },
  ],
  approvalRules: [
    {
      id: "refund-dual",
      permissions: ["ticket:refund"],
      when: { amount: { gte: 100 } },
      approvers: 2,
      expiresInSeconds: 3600,
    },
  ],
} satisfies PolicyInput;

export const policy = compilePolicy(catalog, policyInput);

/** A deep copy of the fixture input that a test may change. */
export function editablePolicyInput(): PolicyInput & Record<string, unknown> {
  return structuredClone(policyInput) as PolicyInput & Record<string, unknown>;
}
