import * as fc from "fast-check";
import { describe, expect, it } from "vitest";

import {
  compilePolicy,
  decide,
  defineCatalog,
  evaluateApprovals,
  requestDigest,
  type AccessRequest,
  type Outcome,
  type Scalar,
  type PolicyInput,
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
const scopeArb = fc.option(fc.record({ queue: subsetOf(queues) }), { nil: undefined });
const limitsArb = fc.option(
  fc.record({ amount: fc.record({ max: fc.integer({ min: 0, max: 100 }) }) }),
  { nil: undefined },
);
const withoutUndefined = <T extends object>(value: T): T =>
  Object.fromEntries(Object.entries(value).filter(([, item]) => item !== undefined)) as T;

const grantArb = fc
  .record({ permissions: subsetOf(permissions), scope: scopeArb, limits: limitsArb })
  .map(withoutUndefined);

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
      schema: 1,
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
              ...(approval.gte === undefined ? {} : { when: { amount: { gte: approval.gte } } }),
            },
          ]
        : [],
    };
    return input;
  });

const assignmentArb = fc
  .record({ role: fc.constantFrom(...roleNames, "ghost"), scope: scopeArb })
  .map(({ role, scope }) => ({ role, scope: scope ?? {} }));

const principalArb: fc.Arbitrary<Subject> = fc.record({
  type: fc.constantFrom("human" as const, "service" as const),
  id: fc.constantFrom("u1", "u2", "u3"),
  roles: fc.array(assignmentArb, { maxLength: 3 }),
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
                agentId: grant.sameAgent ? "agent-1" : "agent-2",
                entries: grant.entries,
                expiresAt: grant.expiresAt,
              },
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
