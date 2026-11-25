// Named cases for each rule of the decision record validator that reevaluate uses. Each case must
// give the expected verdict and first path, so a failure names the rule. The expected verdicts
// are those of the earlier Zod schema; test/zod-verdicts.test.ts compares a seeded corpus with
// its recorded verdicts.
import { describe, expect, it } from "vitest";

import { storedRecord } from "../src/record.js";
import { dropAt, expectedOf, runCase, setAt, type CorpusCase } from "./differential.js";

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

describe("record validator rules", () => {
  it.each(cases.map((item) => [item.name, item] as const))("%s", (_name, item) => {
    expect(runCase(storedRecord, recordBase, item)).toBe(expectedOf(item));
  });
});
