// The calls that the call-time spy tests watch: decide, explain, evaluate, requestDigest,
// parseRequest, canonicalJson and compilePolicy on valid and invalid input. Everything is built
// before a test installs its spies, so the runner itself only calls functions and reads own
// properties of arrays it built: no iterator, no array method and no inherited property.
import {
  canonicalJson,
  compilePolicy,
  decide,
  digest,
  evaluate,
  explain,
  parseRequest,
  requestDigest,
  type AccessRequest,
  type AuthZenRequest,
  type CompiledPolicy,
} from "../src/index.js";
import {
  asAuthZen,
  replacementCatalog,
  replacementPolicies,
  replacementPolicyInputs,
  replacementRequests,
} from "./replacement-corpus.js";

export const callNames = [
  "decide",
  "explain",
  "evaluate",
  "requestDigest",
  "parseRequest",
  "canonicalJson",
  "compilePolicy",
] as const;
export type CallName = (typeof callNames)[number];

const all = { kind: "all" };
const base = replacementRequests(0)[0];

/** Requests that each fail a different rule of the validator. */
const invalidRequests: unknown[] = [
  null,
  "x",
  [],
  { ...base, extra: 1 },
  { ...base, context: { now: "2026-02-30T10:00:00Z" } },
  { ...base, context: { now: "2026-01-15T10:00:00+24:00" } },
  { ...base, context: { now: "2026-01-15T10:00:00Z", policyDigest: "ABC" } },
  { ...base, action: { name: "" } },
  { ...base, action: { name: "x".repeat(200) } },
  { ...base, resource: { type: "ticket", properties: { amount: { nested: 1 }, zz: 1 } } },
  { ...base, resource: { type: "ticket", properties: { amount: Number.NaN } } },
  { ...base, resource: { type: "ticket", properties: JSON.parse('{"__proto__":1,"a":2}') } },
  {
    ...base,
    subject: { type: "robot", id: "", roles: [{ role: "lead", scope: all, x: 1 }], act: null },
  },
  {
    ...base,
    subject: {
      type: "human",
      id: "u",
      roles: [],
      act: {
        type: "agent",
        id: "a",
        grant: {
          id: "g",
          principalId: "u",
          principalType: "human",
          agentId: "a",
          entries: [],
          notBefore: null,
          expiresAt: "2026-06-01T00:00:00Z",
          revokedAt: null,
        },
        act: null,
      },
    },
  },
];

/** Policy documents that each fail a different rule, after the valid ones. */
const first = replacementPolicyInputs[0] as unknown as Record<string, unknown>;
const policyInputs: unknown[] = [
  ...replacementPolicyInputs,
  { ...first, schema: 3 },
  { ...first, version: "" },
  { ...first, extra: true },
  { ...first, roles: {} },
  { ...first, roles: { r: { grants: [{ id: "g", permissions: [], scope: all }] } } },
  {
    ...first,
    approvalRules: [
      {
        id: "a",
        permissions: ["ticket:refund"],
        when: { kind: "amountAtLeast", property: "amount", gte: -1.5 },
        approvers: 0,
        expiresInSeconds: 0,
        eligibleApprovers: { kind: "roles", roles: [] },
        requireProof: false,
      },
    ],
  },
];

/** AuthZEN requests with an unknown key, a missing property, a wrong type or no context. */
function invalidAuthZen(request: AccessRequest): unknown[] {
  const valid = asAuthZen(request);
  return [
    null,
    { ...valid, extra: 1 },
    { ...valid, subject: { ...valid.subject, properties: { roles: [] } } },
    { ...valid, subject: { ...valid.subject, properties: { roles: "lead", act: null } } },
    { ...valid, action: { name: "read", properties: { x: 1 } } },
    { ...valid, context: {} },
    { ...valid, context: { now: valid.context["now"], policy_version: 7 } },
  ];
}

export interface CallTimeCorpus {
  readonly policies: readonly CompiledPolicy[];
  readonly requests: readonly unknown[];
  readonly authzen: readonly unknown[];
  readonly policyInputs: readonly unknown[];
}

export function callTimeCorpus(count: number): CallTimeCorpus {
  const valid = replacementRequests(count);
  const requests: unknown[] = [...valid, ...invalidRequests];
  return {
    policies: replacementPolicies,
    requests,
    authzen: [...valid.map(asAuthZen), ...invalidAuthZen(valid[0] as AccessRequest)],
    policyInputs,
  };
}

/**
 * Runs every watched call on the corpus. `enter` is called with the call name before each call
 * and `leave` after it, so a spy records only while permitkit runs. Errors are swallowed: a
 * refusal is a result here, the spy only counts built-in calls.
 */
export function runCallTimeCorpus(
  corpus: CallTimeCorpus,
  enter: (name: CallName) => void,
  leave: () => void,
): void {
  const watch = (name: CallName, body: () => unknown): void => {
    enter(name);
    try {
      body();
    } catch {
      // A refusal or a thrown PermitkitError: not what the spy counts.
    }
    leave();
  };
  for (let policyIndex = 0; policyIndex < corpus.policies.length; policyIndex += 1) {
    const policy = corpus.policies[policyIndex] as CompiledPolicy;
    for (let index = 0; index < corpus.requests.length; index += 1) {
      const request = corpus.requests[index];
      watch("decide", () => decide(policy, request));
      watch("explain", () => explain(policy, request));
      watch("requestDigest", () => requestDigest(policy, request));
      watch("parseRequest", () => parseRequest(request));
      watch("canonicalJson", () => [canonicalJson(request), digest(request)]);
    }
    for (let index = 0; index < corpus.authzen.length; index += 1) {
      const request = corpus.authzen[index] as AuthZenRequest;
      watch("evaluate", () => evaluate(policy, request));
    }
  }
  for (let index = 0; index < corpus.policyInputs.length; index += 1) {
    const input = corpus.policyInputs[index];
    watch("compilePolicy", () => compilePolicy(replacementCatalog, input));
  }
}
