// Differential test: the hand-written approval validators against the earlier Zod schemas, on
// valid approval inputs, approvals and proofs and near-valid mutations of them. Same verdict on
// every input, the same output on accept, and the same path in the first issue on reject.
import * as fc from "fast-check";
import { describe, expect, it } from "vitest";

import { approval, approvalInput, approvalProof } from "../src/approval-input.js";
import { approvalInputBounds } from "../src/bounds.js";
import type { Check } from "../src/validate.js";
import { approvalInputSchema, approvalProofSchema, approvalSchema } from "../src/zod-schemas.js";
import {
  compareOnce,
  latestRequestInstant,
  mutate,
  optionalField,
  permissionArb,
  stepArb,
  summaryOf,
  Tally,
  textArb,
  timestampArb,
  verdictOf,
  wideBounds,
} from "./differential.js";
import { idArb, requestArb, subjectArb, timestamp } from "./request-arbitraries.js";

const digestArb = fc.oneof(
  { weight: 8, arbitrary: fc.stringMatching(/^[0-9a-f]{64}$/) },
  { weight: 1, arbitrary: fc.constant("0".repeat(64)) },
);

const payloadArb = fc.oneof(
  fc.constant(null),
  fc.boolean(),
  fc.integer(),
  textArb(8),
  fc.record({ ok: fc.boolean(), signature: textArb(8) }),
  fc.array(fc.oneof(fc.integer(), textArb(4)), { maxLength: 3 }),
);

export const proofArb = fc
  .tuple(
    fc.oneof(textArb(8, 1), fc.constant("p".repeat(64))),
    idArb,
    digestArb,
    optionalField("payload", payloadArb),
  )
  .map(([type, approverId, requestDigest, payload]) => ({
    type,
    approverId,
    requestDigest,
    ...payload,
  }));

export const approvalArb = fc
  .tuple(subjectArb, timestamp, digestArb, optionalField("proof", proofArb))
  .map(([approver, approvedAt, requestDigest, proof]) => ({
    approver,
    approvedAt,
    requestDigest,
    ...proof,
  }));

const priorRequestArb = fc.record({
  principalId: fc.oneof(textArb(6, 1), idArb),
  permission: fc.oneof(permissionArb, textArb(6, 1)),
});

export const approvalInputArb = fc
  .tuple(
    requestArb,
    fc.array(approvalArb, { maxLength: 3 }),
    timestampArb(latestRequestInstant),
    optionalField("priorRequests", fc.array(priorRequestArb, { maxLength: 3 })),
  )
  .map(([request, approvals, now, priorRequests]) => ({
    request,
    approvals,
    now,
    ...priorRequests,
  }));

// Property runs take several seconds on a slow CI runner; the default 5 s timeout is too short.
const propertyTimeout = { timeout: 60_000 };
export const approvalRuns = 3000;

function run<T>(
  title: string,
  schema: Parameters<typeof compareOnce>[0],
  check: Check<T>,
  base: fc.Arbitrary<unknown>,
  runs: number,
): Tally {
  const wide = new Tally();
  const production = new Tally();
  fc.assert(
    fc.property(fc.record({ base, steps: fc.array(stepArb, { maxLength: 3 }) }), (item) => {
      const { input, name } = mutate(item.base, item.steps);
      for (const [tally, bounds] of [
        [wide, wideBounds],
        [production, approvalInputBounds],
      ] as const) {
        const result = compareOnce(schema, check, input, bounds);
        tally.add(name, result);
        if (result.skipped) continue;
        expect(summaryOf(result.actual, result.reference)).toEqual({
          verdict: verdictOf(result.reference),
          outputDifference: null,
        });
      }
    }),
    { numRuns: runs },
  );
  wide.report(`${title}, wide bounds`);
  production.report(`${title}, approval input bounds`);
  return wide;
}

/** Both verdicts occur often, so the comparison is not one-sided. */
function healthOf(tally: Tally): { accepted: boolean; rejected: boolean; skipped: number } {
  const total = tally.total();
  return {
    accepted: total.accepted > total.runs / 10,
    rejected: total.rejected > total.runs / 10,
    skipped: total.skipped,
  };
}

const healthy = { accepted: true, rejected: true, skipped: 0 };

describe("approval validators against the Zod schemas", propertyTimeout, () => {
  it("approval input: the same verdict, output and first issue path", () => {
    const tally = run("approval input", approvalInputSchema, approvalInput, approvalInputArb, 2000);
    expect(healthOf(tally)).toEqual(healthy);
  });

  it("approval: the same verdict, output and first issue path", () => {
    const tally = run("approval", approvalSchema, approval, approvalArb, approvalRuns);
    expect(healthOf(tally)).toEqual(healthy);
  });

  it("proof: the same verdict, output and first issue path", () => {
    const tally = run("proof", approvalProofSchema, approvalProof, proofArb, 1000);
    expect(healthOf(tally)).toEqual(healthy);
  });
});
