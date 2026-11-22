import * as fc from "fast-check";
import { describe, expect, it } from "vitest";

import {
  compilePolicy,
  decide,
  defineCatalog,
  evaluateApprovals,
  requestDigest,
  type AccessRequest,
  type Limits,
  type Outcome,
  type Scalar,
  type PermitkitError,
  type PolicyInput,
  type Scope,
  type Subject,
} from "../src/index.js";

const catalog = defineCatalog({
  ticket: { actions: ["read", "close", "refund"], scopes: ["queue"], limits: ["amount"] },
});
const permissions = ["ticket:read", "ticket:close", "ticket:refund"];
const queues = ["a", "b", "c"];
const roleNames = ["r0", "r1", "r2"];
const now = "2026-01-15T10:00:00.000Z";

const rank: Record<Outcome, number> = { deny: 0, approval_required: 1, allow: 2 };

const subsetOf = <T>(values: T[]) => fc.subarray(values, { minLength: 1 });
const scopeArb: fc.Arbitrary<Scope> = fc.oneof(
  fc.constant<Scope>({ kind: "all" }),
  fc
    .record({ queue: subsetOf(queues) })
    .map((properties): Scope => ({ kind: "match", properties })),
);
const limitsArb: fc.Arbitrary<Limits> = fc.oneof(
  fc.constant<Limits>({ kind: "unlimited" }),
  fc
    .record({ amount: fc.record({ max: fc.integer({ min: 0, max: 100 }) }) })
    .map((properties): Limits => ({ kind: "range", properties })),
);
const withoutUndefined = <T extends object>(value: T): T =>
  Object.fromEntries(Object.entries(value).filter(([, item]) => item !== undefined)) as T;

const grantArb = fc.record({
  permissions: subsetOf(permissions),
  scope: scopeArb,
  limits: limitsArb,
});

const denyArb = fc
  .record({
    permissions: subsetOf(permissions),
    roles: fc.option(subsetOf(roleNames), { nil: undefined }),
    subjectTypes: fc.option(subsetOf(["human", "service", "agent"] as const), { nil: undefined }),
    scope: scopeArb,
  })
  .map(withoutUndefined);

const policyArb = fc
  .record({
    roles: fc.tuple(...roleNames.map(() => fc.array(grantArb, { maxLength: 3 }))),
    denies: fc.array(denyArb, { maxLength: 2 }),
    approval: fc.option(
      fc.record({
        permissions: subsetOf(permissions),
        gte: fc.option(fc.integer({ min: 0, max: 100 }), { nil: undefined }),
        approvers: fc.integer({ min: 1, max: 3 }),
      }),
      { nil: undefined },
    ),
  })
  .map(({ roles, denies, approval }) => {
    const input: PolicyInput = {
      schema: 2,
      version: "p",
      roles: Object.fromEntries(
        roleNames.map((name, roleIndex) => [
          name,
          {
            grants: (roles[roleIndex] ?? []).map((grant, index) => ({
              ...grant,
              id: `${name}-g${index}`,
            })),
          },
        ]),
      ),
      denies: denies.map((deny, index) => ({ ...deny, id: `d${index}` })),
      approvalRules: approval
        ? [
            {
              id: "ap",
              permissions: approval.permissions,
              approvers: approval.approvers,
              expiresInSeconds: 3600,
              when:
                approval.gte === undefined
                  ? { kind: "always" as const }
                  : { kind: "threshold" as const, properties: { amount: { gte: approval.gte } } },
              eligibleApprovers: { kind: "permission" as const },
              requireProof: false,
            },
          ]
        : [],
      separationOfDuties: {
        requesterNeverApprovesSameType: false,
        exclusiveRequestAndApproveRoles: false,
      },
    };
    return input;
  });

const assignmentArb = fc.record({ role: fc.constantFrom(...roleNames, "ghost"), scope: scopeArb });

const principalArb: fc.Arbitrary<Subject> = fc.record({
  type: fc.constantFrom("human" as const, "service" as const),
  id: fc.constantFrom("u1", "u2", "u3"),
  roles: fc.array(assignmentArb, { maxLength: 3 }),
  act: fc.constant(null),
});

const propertiesArb = fc
  .record({
    queue: fc.option(fc.oneof(fc.constantFrom(...queues, "d"), fc.integer()), { nil: undefined }),
    amount: fc.option(fc.oneof(fc.integer({ min: -10, max: 200 }), fc.constant("5")), {
      nil: undefined,
    }),
  })
  .map(withoutUndefined);

const requestArb = (subject: fc.Arbitrary<Subject>) =>
  fc
    .record({
      subject,
      permission: fc.constantFrom(...permissions, "ticket:archive"),
      properties: propertiesArb,
    })
    .map(({ subject: value, permission, properties }): AccessRequest => ({
      subject: value,
      action: { name: permission.split(":")[1]! },
      resource: { type: "ticket", properties: properties as Record<string, Scalar> },
      context: { now },
    }));

const agentGrantArb = fc.record({
  entries: fc.array(grantArb, { minLength: 1, maxLength: 3 }),
  expiresAt: fc.constantFrom(
    "2026-01-15T09:00:00.000Z",
    "2026-01-15T10:00:00.000Z",
    "2026-02-01T00:00:00.000Z",
  ),
  samePrincipal: fc.boolean(),
  sameAgent: fc.boolean(),
});

describe("properties", () => {
  it("adding a deny never widens access", () => {
    fc.assert(
      fc.property(policyArb, denyArb, requestArb(principalArb), (input, extraDeny, request) => {
        const base = compilePolicy(catalog, input);
        const stricter = compilePolicy(catalog, {
          ...input,
          denies: [...(input.denies ?? []), { ...extraDeny, id: "extra" }],
        });
        expect(rank[decide(stricter, request).outcome]).toBeLessThanOrEqual(
          rank[decide(base, request).outcome],
        );
      }),
      { numRuns: 2000 },
    );
  });

  it("an agent never has a permission its principal lacks", () => {
    fc.assert(
      fc.property(policyArb, requestArb(principalArb), agentGrantArb, (input, request, grant) => {
        const compiled = compilePolicy(catalog, input);
        const viaAgent: AccessRequest = {
          ...request,
          subject: {
            ...request.subject,
            act: {
              type: "agent",
              id: "agent-1",
              grant: {
                id: "g",
                principalId: grant.samePrincipal ? request.subject.id : "someone-else",
                principalType: request.subject.type,
                agentId: grant.sameAgent ? "agent-1" : "agent-2",
                entries: grant.entries,
                expiresAt: grant.expiresAt,
                notBefore: null,
                revokedAt: null,
              },
              act: null,
            },
          },
        };
        const agentOutcome = decide(compiled, viaAgent).outcome;
        const principalOutcome = decide(compiled, request).outcome;
        expect(rank[agentOutcome]).toBeLessThanOrEqual(rank[principalOutcome]);
      }),
      { numRuns: 2000 },
    );
  });

  it("a subject without roles is never allowed", () => {
    fc.assert(
      fc.property(
        policyArb,
        requestArb(principalArb.map((subject) => ({ ...subject, roles: [] }))),
        (input, request) => {
          expect(decide(compilePolicy(catalog, input), request).outcome).toBe("deny");
        },
      ),
      { numRuns: 1000 },
    );
  });

  it("no single subject satisfies a dual-approval rule alone", async () => {
    await fc.assert(
      fc.asyncProperty(
        policyArb,
        requestArb(principalArb),
        fc.constantFrom("u1", "u2", "u3"),
        // "same" reuses the requester's roles, so many approvers are eligible peers.
        fc.array(
          fc.oneof(fc.constant("same" as const), fc.array(assignmentArb, { maxLength: 3 })),
          {
            minLength: 2,
            maxLength: 4,
          },
        ),
        async (input, request, approverId, roleSets) => {
          const compiled = compilePolicy(catalog, input);
          const digestValue = requestDigest(compiled, request);
          const result = await evaluateApprovals(compiled, {
            request,
            now: "2026-01-15T10:30:00.000Z",
            approvals: roleSets.map((choice) => ({
              approver: {
                type: "human",
                id: approverId,
                roles: choice === "same" ? request.subject.roles : choice,
                act: null,
              },
              approvedAt: "2026-01-15T10:10:00.000Z",
              requestDigest: digestValue,
            })),
          });
          if (result.reason === "approval_not_required") return;
          const ownRequest = approverId === request.subject.id;
          expect(result.counted.length).toBeLessThanOrEqual(ownRequest ? 0 : 1);
          const allowedAlone = result.outcome === "allow";
          expect(allowedAlone && (ownRequest || result.required !== 1)).toBe(false);
        },
      ),
      { numRuns: 1000 },
    );
  });
});

type GrantValue = typeof grantArb extends fc.Arbitrary<infer T> ? T : never;

/** Every way a scope can be lost, emptied or misspelt. */
const brokenScopes: unknown[] = [
  "remove",
  {},
  null,
  { kind: "match" },
  { kind: "match", properties: {} },
  { queue: ["a"] },
  { kind: "all", properties: { queue: ["a"] } },
  "*",
  { kind: "match", properties: { queue: ["*"] } },
];

/** The request with agent-1 acting under a valid grant with these entries, if any. */
function agentRequest(request: AccessRequest, entries: GrantValue[] | undefined): AccessRequest {
  if (entries === undefined) return request;
  return {
    ...request,
    subject: {
      ...request.subject,
      act: {
        type: "agent",
        id: "agent-1",
        grant: {
          id: "g",
          principalId: request.subject.id,
          principalType: request.subject.type,
          agentId: "agent-1",
          entries,
          notBefore: null,
          expiresAt: "2026-02-01T00:00:00.000Z",
          revokedAt: null,
        },
        act: null,
      },
    },
  };
}

/** Paths of every scope in the policy and the request, as [root, ...keys]. */
function scopePaths(input: PolicyInput, request: AccessRequest): (string | number)[][] {
  const paths: (string | number)[][] = [];
  for (const name of Object.keys(input.roles)) {
    input.roles[name]!.grants.forEach((_, index) =>
      paths.push(["policy", "roles", name, "grants", index]),
    );
  }
  input.denies.forEach((_, index) => paths.push(["policy", "denies", index]));
  request.subject.roles.forEach((_, index) => paths.push(["request", "subject", "roles", index]));
  request.subject.act?.grant?.entries.forEach((_, index) =>
    paths.push(["request", "subject", "act", "grant", "entries", index]),
  );
  return paths;
}

/** Replaces or removes the scope at the path. */
function mutate(target: unknown, keys: (string | number)[], scope: unknown): void {
  let node = target as Record<string | number, unknown>;
  for (const key of keys) node = node[key] as Record<string | number, unknown>;
  if (scope === "remove") delete node["scope"];
  else node["scope"] = scope;
}

/** Decides, and reports a refused policy or request as a deny that was refused. */
function outcomeOf(
  input: PolicyInput,
  request: AccessRequest,
): { outcome: Outcome; refused: boolean; error: unknown } {
  try {
    const decision = decide(compilePolicy(catalog, input), request);
    return {
      outcome: decision.outcome,
      refused: decision.reason === "invalid_request",
      error: null,
    };
  } catch (error) {
    return { outcome: "deny", refused: true, error: (error as PermitkitError).code };
  }
}

/** True if the scope is a match scope that lists the value under queue. */
function listed(scope: Scope, value: unknown): boolean {
  return (
    scope.kind === "match" &&
    typeof value === "string" &&
    scope.properties["queue"]!.includes(value)
  );
}

function hasStar(scopes: Scope[]): boolean {
  return scopes.some((scope) => scope.kind === "match" && scope.properties["queue"]!.includes("*"));
}

const matchValues = fc.oneof(
  { weight: 9, arbitrary: subsetOf(queues) },
  { weight: 1, arbitrary: subsetOf([...queues, "*"]) },
);
const matchScopeArb = fc
  .record({ queue: matchValues })
  .map((properties): Scope => ({ kind: "match", properties }));
const matchGrantArb = fc.record({
  permissions: subsetOf(permissions),
  scope: matchScopeArb,
  limits: limitsArb,
});
const matchPolicyArb = fc
  .record({
    roles: fc.tuple(
      ...roleNames.map(() => fc.array(matchGrantArb, { minLength: 1, maxLength: 3 })),
    ),
  })
  .map(({ roles }): PolicyInput => ({
    schema: 2,
    version: "m",
    roles: Object.fromEntries(
      roleNames.map((name, roleIndex) => [
        name,
        {
          grants: (roles[roleIndex] ?? []).map((grant, index) => ({
            ...grant,
            id: `${name}-g${index}`,
          })),
        },
      ]),
    ),
    denies: [],
    approvalRules: [],
    separationOfDuties: {
      requesterNeverApprovesSameType: false,
      exclusiveRequestAndApproveRoles: false,
    },
  }));
const matchPrincipalArb: fc.Arbitrary<Subject> = fc.record({
  type: fc.constantFrom("human" as const, "service" as const),
  id: fc.constantFrom("u1", "u2"),
  roles: fc.array(fc.record({ role: fc.constantFrom(...roleNames), scope: matchScopeArb }), {
    minLength: 1,
    maxLength: 3,
  }),
  act: fc.constant(null),
});
const matchRequestArb = fc
  .record({
    subject: matchPrincipalArb,
    permission: fc.constantFrom(...permissions),
    queue: fc.option(fc.oneof(fc.constantFrom(...queues, "d", "*"), fc.integer()), {
      nil: undefined,
      freq: 10,
    }),
    amount: fc.integer({ min: 0, max: 100 }),
    entries: fc.option(fc.array(matchGrantArb, { minLength: 1, maxLength: 2 }), {
      nil: undefined,
      freq: 2,
    }),
  })
  .map(({ subject, permission, queue, amount, entries }) =>
    agentRequest(
      {
        subject,
        action: { name: permission.split(":")[1]! },
        resource: {
          type: "ticket",
          properties: queue === undefined ? { amount } : { queue, amount },
        },
        context: { now },
      },
      entries,
    ),
  );

describe("explicit scope properties", () => {
  const agentArb = fc.option(fc.array(grantArb, { minLength: 1, maxLength: 3 }), {
    nil: undefined,
  });

  it("removing or emptying any scope never changes a deny into an allow", () => {
    let allowedBefore = 0;
    let checked = 0;
    fc.assert(
      fc.property(
        policyArb,
        requestArb(principalArb),
        agentArb,
        fc.nat(),
        fc.constantFrom(...brokenScopes),
        (input, plain, entries, pick, broken) => {
          const request = agentRequest(plain, entries);
          const paths = scopePaths(input, request);
          fc.pre(paths.length > 0);
          checked += 1;
          const [root, ...keys] = paths[pick % paths.length]!;
          const before = outcomeOf(input, request);
          if (before.outcome === "allow") allowedBefore += 1;
          const mutatedInput = structuredClone(input);
          const mutatedRequest = structuredClone(request);
          mutate(root === "policy" ? mutatedInput : mutatedRequest, keys, broken);
          const after = outcomeOf(mutatedInput, mutatedRequest);
          // The property: a deny (or approval_required) never becomes an allow.
          expect(before.outcome !== "allow" && after.outcome === "allow").toBe(false);
          // The design is stronger: every broken scope is refused with a coded result.
          expect(after.refused).toBe(true);
          expect([null, "policy_invalid"]).toContain(after.error);
        },
      ),
      { numRuns: 3000 },
    );
    // Control: the generator reaches allowed requests, so the property is not vacuous.
    expect(checked).toBeGreaterThan(1000);
    expect(allowedBefore).toBeGreaterThan(30);
  });

  it("no policy without the explicit marker yields an allow for a resource outside its match scope", () => {
    let allowed = 0;
    fc.assert(
      fc.property(matchPolicyArb, matchRequestArb, (input, request) => {
        const grants = Object.values(input.roles).flatMap((role) => role.grants);
        const requestScopes = [
          ...request.subject.roles.map((assignment) => assignment.scope),
          ...(request.subject.act?.grant?.entries.map((entry) => entry.scope) ?? []),
        ];
        const result = outcomeOf(input, request);
        const starred = hasStar(grants.map((grant) => grant.scope)) || hasStar(requestScopes);
        // A "*" anywhere is refused, never read as a wildcard.
        expect(starred && !result.refused).toBe(false);
        if (result.outcome !== "allow") return;
        allowed += 1;
        const decision = decide(compilePolicy(catalog, input), request);
        const queue = request.resource.properties?.["queue"];
        const rule = decision.rule;
        const grant =
          rule?.kind === "grant"
            ? input.roles[rule.role]?.grants.find((item) => item.id === rule.id)
            : undefined;
        const assignmentCovers = request.subject.roles.some(
          (assignment) =>
            rule?.kind === "grant" &&
            assignment.role === rule.role &&
            listed(assignment.scope, queue),
        );
        const entries = request.subject.act?.grant?.entries;
        const agentCovers =
          entries === undefined || entries.some((entry) => listed(entry.scope, queue));
        expect({
          grantCovers: grant !== undefined && listed(grant.scope, queue),
          assignmentCovers,
          agentCovers,
        }).toEqual({ grantCovers: true, assignmentCovers: true, agentCovers: true });
      }),
      { numRuns: 3000 },
    );
    expect(allowed).toBeGreaterThan(30);
  });
});
