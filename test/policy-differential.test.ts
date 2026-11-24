// Differential test: the hand-written policy validator against the earlier Zod schema, on valid
// policy documents and near-valid mutations of them. Same verdict on every input, the same
// output on accept, and the same path in the first issue on reject.
import * as fc from "fast-check";
import { describe, expect, it } from "vitest";

import { policyBounds } from "../src/bounds.js";
import { policyDocument } from "../src/policy-document.js";
import { maxApprovalWindowSeconds } from "../src/time.js";
import { policySchema } from "../src/zod-schemas.js";
import {
  compareOnce,
  summaryOf,
  verdictOf,
  identifierArb,
  limitsArb,
  mutate,
  optionalField,
  permissionArb,
  scopeArb,
  stepArb,
  Tally,
  textArb,
  wideBounds,
} from "./differential.js";

const permissionsArb = fc.array(permissionArb, { minLength: 1, maxLength: 3 });
const descriptionArb = optionalField(
  "description",
  fc.oneof(
    { weight: 8, arbitrary: textArb(12) },
    { weight: 1, arbitrary: fc.constant("d".repeat(1000)) },
  ),
);

const grantArb = fc.record({
  id: identifierArb,
  permissions: permissionsArb,
  scope: scopeArb,
  limits: limitsArb,
});

const roleArb = fc
  .tuple(descriptionArb, fc.array(grantArb, { maxLength: 3 }))
  .map(([description, grants]) => ({ ...description, grants }));

const denyArb = fc
  .tuple(
    identifierArb,
    descriptionArb,
    permissionsArb,
    optionalField("roles", fc.array(identifierArb, { minLength: 1, maxLength: 2 })),
    optionalField("subjectTypes", fc.subarray(["human", "service", "agent"], { minLength: 1 })),
    scopeArb,
  )
  .map(([id, description, permissions, roles, subjectTypes, scope]) => ({
    id,
    ...description,
    permissions,
    ...roles,
    ...subjectTypes,
    scope,
  }));

const whenArb = fc.oneof(
  fc.constant({ kind: "always" }),
  fc.record({
    kind: fc.constant("threshold"),
    properties: fc.dictionary(
      identifierArb,
      fc.record({
        gte: fc.oneof(fc.integer(), fc.double({ noNaN: true, noDefaultInfinity: true })),
      }),
      { minKeys: 1, maxKeys: 2 },
    ),
  }),
);

const eligibleArb = fc.oneof(
  fc.constant({ kind: "permission" }),
  fc.record({
    kind: fc.constant("roles"),
    roles: fc.array(identifierArb, { minLength: 1, maxLength: 2 }),
  }),
);

const approvalRuleArb = fc
  .tuple(
    identifierArb,
    descriptionArb,
    permissionsArb,
    whenArb,
    fc.integer({ min: 1, max: 10 }),
    eligibleArb,
    fc.oneof(
      fc.constantFrom(60, maxApprovalWindowSeconds),
      fc.integer({ min: 60, max: maxApprovalWindowSeconds }),
    ),
    fc.boolean(),
    optionalField(
      "proofTypes",
      fc.array(fc.oneof(textArb(8, 1), fc.constant("p".repeat(64))), {
        minLength: 1,
        maxLength: 2,
      }),
    ),
  )
  .map(
    ([
      id,
      description,
      permissions,
      when,
      approvers,
      eligibleApprovers,
      expiresInSeconds,
      requireProof,
      proofTypes,
    ]) => ({
      id,
      ...description,
      permissions,
      when,
      approvers,
      eligibleApprovers,
      expiresInSeconds,
      requireProof,
      ...proofTypes,
    }),
  );

const policyArb = fc.record({
  schema: fc.constant(2),
  version: fc.oneof(textArb(8, 1), fc.constant("v".repeat(128))),
  roles: fc.dictionary(identifierArb, roleArb, { maxKeys: 3 }),
  denies: fc.array(denyArb, { maxLength: 2 }),
  approvalRules: fc.array(approvalRuleArb, { maxLength: 2 }),
  separationOfDuties: fc.record({
    requesterNeverApprovesSameType: fc.boolean(),
    exclusiveRequestAndApproveRoles: fc.boolean(),
  }),
});

const caseArb = fc.record({ base: policyArb, steps: fc.array(stepArb, { maxLength: 3 }) });

// Property runs take several seconds on a slow CI runner; the default 5 s timeout is too short.
const propertyTimeout = { timeout: 60_000 };
export const policyRuns = 3000;

describe("policy validator against the Zod schema", propertyTimeout, () => {
  it("gives the same verdict, output and first issue path", () => {
    const wide = new Tally();
    const production = new Tally();
    fc.assert(
      fc.property(caseArb, ({ base, steps }) => {
        const { input, name } = mutate(base, steps);
        for (const [tally, bounds] of [
          [wide, wideBounds],
          [production, policyBounds],
        ] as const) {
          const result = compareOnce(policySchema, policyDocument, input, bounds);
          tally.add(name, result);
          if (result.skipped) continue;
          expect(summaryOf(result.actual, result.reference)).toEqual({
            verdict: verdictOf(result.reference),
            outputDifference: null,
          });
          // Control: an unmutated document is valid, so the generators produce valid input.
          expect(steps.length === 0 ? result.reference.ok : true).toBe(true);
        }
      }),
      { numRuns: policyRuns },
    );
    wide.report("policy, wide bounds");
    production.report("policy, policy bounds");
    // Health: both verdicts occur often, so the comparison is not one-sided.
    const total = wide.total();
    expect(total.accepted).toBeGreaterThan(total.runs / 10);
    expect(total.rejected).toBeGreaterThan(total.runs / 10);
    expect(total.skipped).toBe(0);
  });
});
