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
  identifierArb,
  latestInstant,
  latestRequestInstant,
  limitsArb,
  mutate,
  optionalField,
  permissionArb,
  scopeArb,
  stepArb,
  Tally,
  textArb,
  timestampArb,
  viaZod,
  wideBounds,
  withKey,
} from "./differential.js";

const idArb = fc.oneof(
  { weight: 10, arbitrary: textArb(8, 1) },
  { weight: 1, arbitrary: fc.constant("i".repeat(256)) },
);
const nameArb = fc.oneof(
  { weight: 10, arbitrary: textArb(8, 1) },
  { weight: 1, arbitrary: fc.constant("n".repeat(128)) },
);
const timestamp = timestampArb(latestInstant);

const grantArb = fc.record({
  id: idArb,
  principalId: fc.constantFrom("u", "s"),
  principalType: fc.constantFrom("human", "service"),
  agentId: idArb,
  entries: fc.array(
    fc.record({
      permissions: fc.array(fc.oneof(permissionArb, textArb(6, 1)), { minLength: 1, maxLength: 3 }),
      scope: scopeArb,
      limits: limitsArb,
    }),
    { minLength: 1, maxLength: 2 },
  ),
  notBefore: fc.option(timestamp, { nil: null }),
  expiresAt: timestamp,
  revokedAt: fc.option(timestamp, { nil: null }),
});

/** Actor chains from 0 to 6 actors, so depth 4 (accepted) and 5 (refused) both occur. */
const actArb = fc
  .array(fc.record({ id: idArb, grant: fc.option(grantArb, { nil: null }) }), { maxLength: 6 })
  .map((actors) => {
    let act: unknown = null;
    for (let index = actors.length - 1; index >= 0; index -= 1) {
      const actor = actors[index];
      if (actor !== undefined) act = { type: "agent", id: actor.id, grant: actor.grant, act };
    }
    return act;
  });

const roleAssignmentArb = fc.record({ role: nameArb, scope: scopeArb });
const rolesArb = fc.oneof(
  { weight: 12, arbitrary: fc.array(roleAssignmentArb, { maxLength: 3 }) },
  {
    weight: 1,
    arbitrary: roleAssignmentArb.map((item) => Array.from({ length: 256 }, () => item)),
  },
);

const scalarArb = fc.oneof(
  textArb(8),
  fc.constant("s".repeat(4096)),
  fc.integer(),
  fc.double({ noNaN: true, noDefaultInfinity: true }),
  fc.boolean(),
  fc.constant(null),
);
const propertiesArb = fc
  .tuple(
    fc.dictionary(fc.oneof(identifierArb, textArb(4)), scalarArb, { maxKeys: 4 }),
    fc.option(scalarArb, { nil: undefined }),
  )
  .map(([properties, proto]) =>
    proto === undefined ? properties : withKey({ ...properties }, "__proto__", proto),
  );

const requestArb = fc
  .record({
    subject: fc.record({
      type: fc.constantFrom("human", "service"),
      id: idArb,
      roles: rolesArb,
      act: actArb,
    }),
    action: fc.record({ name: nameArb }),
    resourceType: nameArb,
    resourceId: optionalField("id", idArb),
    resourceProperties: optionalField("properties", propertiesArb),
    now: timestampArb(latestRequestInstant),
    version: optionalField("policyVersion", nameArb),
    pin: optionalField("policyDigest", fc.stringMatching(/^[0-9a-f]{64}$/)),
  })
  .map((parts) => ({
    subject: parts.subject,
    action: parts.action,
    resource: { type: parts.resourceType, ...parts.resourceId, ...parts.resourceProperties },
    context: { now: parts.now, ...parts.version, ...parts.pin },
  }));

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
