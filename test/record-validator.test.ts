// The decision record validator that reevaluate uses, against the earlier Zod schema: named
// cases for each rule, then valid records and near-valid mutations of them. Same verdict on
// every input, the same output on accept, and the same path in the first issue on reject.
import * as fc from "fast-check";
import { describe, expect, it } from "vitest";

import { wrapperBounds } from "../src/bounds.js";
import { storedRecord } from "../src/record.js";
import { recordShapeSchema } from "../src/zod-schemas.js";
import {
  compareOnce,
  dropAt,
  expectedOf,
  mutate,
  optionalField,
  runCase,
  setAt,
  stepArb,
  summaryOf,
  Tally,
  textArb,
  verdictOf,
  wideBounds,
  type CorpusCase,
} from "./differential.js";
import { idArb, requestArb } from "./request-arbitraries.js";

const digest = "0123456789abcdef".repeat(4);

const recordBase = (): Record<string, unknown> => ({
  schema: "permitkit.decision/2",
  policy: { version: "p1", digest },
  request: {
    subject: { type: "human", id: "u", roles: [], act: null },
    action: { name: "read" },
    resource: { type: "ticket" },
    context: { now: "2026-01-15T10:00:00Z" },
  },
  requestDigest: digest,
  actorChain: [{ type: "human", id: "u", grantId: null }],
  outcome: "allow",
  reason: "granted",
  rule: { kind: "grant", role: "lead", grantId: "g" },
  approval: null,
});

const cases: CorpusCase[] = [
  { name: "a valid record", edit: () => {}, expected: "accept" },
  { name: "request null", edit: (d) => setAt(d, ["request"], null), expected: "accept" },
  { name: "no request", edit: (d) => dropAt(d, ["request"]), expected: "accept" },
  {
    name: "no rule and no approval",
    edit: (d) => {
      dropAt(d, ["rule"]);
      dropAt(d, ["approval"]);
    },
    expected: "accept",
  },
  {
    name: "request of any shape",
    edit: (d) => setAt(d, ["request"], [1, "x"]),
    expected: "accept",
  },
  { name: "unknown key", edit: (d) => setAt(d, ["extra"], 1), expected: [] },
  { name: "__proto__ key", edit: (d) => setAt(d, ["__proto__"], 1), expected: [] },
  {
    name: "other schema",
    edit: (d) => setAt(d, ["schema"], "permitkit.decision/1"),
    expected: ["schema"],
  },
  { name: "no schema", edit: (d) => dropAt(d, ["schema"]), expected: ["schema"] },
  { name: "no policy", edit: (d) => dropAt(d, ["policy"]), expected: ["policy"] },
  {
    name: "policy with an unknown key",
    edit: (d) => setAt(d, ["policy", "x"], 1),
    expected: ["policy"],
  },
  {
    name: "policy version a number",
    edit: (d) => setAt(d, ["policy", "version"], 1),
    expected: ["policy", "version"],
  },
  {
    name: "policy digest empty",
    edit: (d) => setAt(d, ["policy", "digest"], ""),
    expected: "accept",
  },
  {
    name: "requestDigest null",
    edit: (d) => setAt(d, ["requestDigest"], null),
    expected: "accept",
  },
  {
    name: "no requestDigest",
    edit: (d) => dropAt(d, ["requestDigest"]),
    expected: ["requestDigest"],
  },
  { name: "actorChain empty", edit: (d) => setAt(d, ["actorChain"], []), expected: "accept" },
  {
    name: "actorChain of any items",
    edit: (d) => setAt(d, ["actorChain"], [null, 1]),
    expected: "accept",
  },
  {
    name: "actorChain an object",
    edit: (d) => setAt(d, ["actorChain"], {}),
    expected: ["actorChain"],
  },
  { name: "outcome a number", edit: (d) => setAt(d, ["outcome"], 1), expected: ["outcome"] },
  { name: "no reason", edit: (d) => dropAt(d, ["reason"]), expected: ["reason"] },
  { name: "an array", edit: (d) => setAt(d, ["policy"], []), expected: ["policy"] },
];

const recordArb = fc
  .tuple(
    fc.oneof(
      { weight: 8, arbitrary: fc.constant("permitkit.decision/2") },
      { weight: 1, arbitrary: textArb(4) },
    ),
    fc.record({
      version: textArb(6),
      digest: fc.oneof(fc.stringMatching(/^[0-9a-f]{64}$/), textArb(4)),
    }),
    optionalField("request", fc.oneof(requestArb, fc.constant(null))),
    fc.option(fc.stringMatching(/^[0-9a-f]{64}$/), { nil: null }),
    fc.array(
      fc.record({
        type: fc.constantFrom("human", "service", "agent"),
        id: idArb,
        grantId: fc.option(idArb, { nil: null }),
      }),
      { maxLength: 3 },
    ),
    fc.constantFrom("allow", "deny", "approval_required"),
    fc.constantFrom("granted", "no_grant", "approval_required", "invalid_request"),
    optionalField(
      "rule",
      fc.oneof(fc.constant(null), fc.record({ kind: fc.constant("grant"), role: idArb })),
    ),
    optionalField(
      "approval",
      fc.oneof(fc.constant(null), fc.record({ ruleId: idArb, approvers: fc.integer() })),
    ),
  )
  .map(([schema, policy, request, requestDigest, actorChain, outcome, reason, rule, approval]) => ({
    schema,
    policy,
    ...request,
    requestDigest,
    actorChain,
    outcome,
    reason,
    ...rule,
    ...approval,
  }));

// Property runs take several seconds on a slow CI runner; the default 5 s timeout is too short.
const propertyTimeout = { timeout: 60_000 };

describe("record validator rules", () => {
  it.each(cases.map((item) => [item.name, item] as const))("%s", (_name, item) => {
    const { reference, actual, outputDifference } = runCase(
      recordShapeSchema,
      storedRecord,
      recordBase,
      item,
    );
    expect({ zod: reference, handWritten: actual }).toEqual({
      zod: expectedOf(item),
      handWritten: expectedOf(item),
    });
    expect(outputDifference).toBeNull();
  });
});

describe("record validator against the Zod schema", propertyTimeout, () => {
  it("gives the same verdict, output and first issue path", () => {
    const wide = new Tally();
    const production = new Tally();
    fc.assert(
      fc.property(
        fc.record({ base: recordArb, steps: fc.array(stepArb, { maxLength: 3 }) }),
        (item) => {
          const { input, name } = mutate(item.base, item.steps);
          for (const [tally, bounds] of [
            [wide, wideBounds],
            [production, wrapperBounds],
          ] as const) {
            const result = compareOnce(recordShapeSchema, storedRecord, input, bounds);
            tally.add(name, result);
            if (result.skipped) continue;
            expect(summaryOf(result.actual, result.reference)).toEqual({
              verdict: verdictOf(result.reference),
              outputDifference: null,
            });
          }
        },
      ),
      { numRuns: 2000 },
    );
    wide.report("record, wide bounds");
    production.report("record, wrapper bounds");
    const total = wide.total();
    expect(total.accepted).toBeGreaterThan(total.runs / 10);
    expect(total.rejected).toBeGreaterThan(total.runs / 10);
    expect(total.skipped).toBe(0);
  });
});
