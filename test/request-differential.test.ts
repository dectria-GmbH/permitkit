// Differential test: the hand-written request validator against the earlier Zod schema, on
// valid requests and near-valid mutations of them. Same verdict on every input, the same output
// on accept, and the same path in the first issue on reject.
import * as fc from "fast-check";
import { describe, expect, it } from "vitest";

import { boundedSnapshot, requestBounds } from "../src/bounds.js";
import { parseRequest } from "../src/decide.js";
import { accessRequest, maxActorDepth } from "../src/request.js";
import { accessRequestSchema } from "../src/zod-schemas.js";
import {
  compareOnce,
  summaryOf,
  verdictOf,
  mutate,
  stepArb,
  Tally,
  viaZod,
  wideBounds,
} from "./differential.js";
import { requestArb } from "./request-arbitraries.js";

function actorDepthOf(request: { subject: { act: unknown } }): number {
  let depth = 0;
  for (let act = request.subject.act; act !== null; act = (act as { act: unknown }).act) depth += 1;
  return depth;
}

const caseArb = fc.record({ base: requestArb, steps: fc.array(stepArb, { maxLength: 3 }) });

// Property runs take several seconds on a slow CI runner; the default 5 s timeout is too short.
const propertyTimeout = { timeout: 60_000 };
export const requestRuns = 5000;

describe("request validator against the Zod schema", propertyTimeout, () => {
  it("gives the same verdict, output and first issue path", () => {
    const wide = new Tally();
    const production = new Tally();
    fc.assert(
      fc.property(caseArb, ({ base, steps }) => {
        const { input, name } = mutate(base, steps);
        for (const [tally, bounds] of [
          [wide, wideBounds],
          [production, requestBounds],
        ] as const) {
          const result = compareOnce(accessRequestSchema, accessRequest, input, bounds);
          tally.add(name, result);
          if (result.skipped) continue;
          expect(summaryOf(result.actual, result.reference)).toEqual({
            verdict: verdictOf(result.reference),
            outputDifference: null,
          });
        }
        // Control: an unmutated request is valid, so the generators produce valid input.
        const control = steps.length === 0 && actorDepthOf(base) <= maxActorDepth;
        expect(control ? parseRequest(input).ok : true).toBe(true);
      }),
      { numRuns: requestRuns },
    );
    wide.report("request, wide bounds");
    production.report("request, request bounds");
    // Health: both verdicts occur often, so the comparison is not one-sided.
    const total = wide.total();
    expect(total.accepted).toBeGreaterThan(total.runs / 10);
    expect(total.rejected).toBeGreaterThan(total.runs / 10);
    expect(total.skipped).toBe(0);
  });

  it("parseRequest matches the earlier pipeline, size guard included", () => {
    fc.assert(
      fc.property(caseArb, ({ base, steps }) => {
        const { input } = mutate(base, steps);
        const snapshot = boundedSnapshot(input, requestBounds);
        const parsed = parseRequest(input);
        // The size guard refuses with one issue at the root, before any validator runs.
        // parseRequest joins paths with dots, as it did before.
        const zod = snapshot === undefined ? undefined : viaZod(accessRequestSchema, snapshot);
        const reference =
          zod === undefined
            ? ({ ok: false, firstPath: '""', count: 1 } as const)
            : zod.ok
              ? zod
              : ({
                  ok: false,
                  firstPath: JSON.stringify(
                    (JSON.parse(zod.firstPath) as (string | number)[]).join("."),
                  ),
                  count: zod.count,
                } as const);
        const actual = parsed.ok
          ? ({ ok: true, value: parsed.request } as const)
          : ({
              ok: false,
              firstPath: JSON.stringify(parsed.issues[0]?.path ?? null),
              count: parsed.issues.length,
            } as const);
        expect(summaryOf(actual, reference)).toEqual({
          verdict: verdictOf(reference),
          outputDifference: null,
        });
      }),
      { numRuns: 1000 },
    );
  });
});
