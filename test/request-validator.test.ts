// Named cases for each rule of the request validator. Each case runs through the hand-written
// validator and the earlier Zod schema; both must give the expected verdict and first path, so a
// failure names the rule.
import { describe, expect, it } from "vitest";

import { accessRequest } from "../src/request.js";
import { latestRequestInstant } from "../src/time.js";
import { accessRequestSchema } from "../src/zod-schemas.js";
import { dropAt, expectedOf, runCase, setAt, type CorpusCase } from "./differential.js";

const grant = () => ({
  id: "g",
  principalId: "u",
  principalType: "human",
  agentId: "a1",
  entries: [
    { permissions: ["ticket:read"], scope: { kind: "all" }, limits: { kind: "unlimited" } },
  ],
  notBefore: null,
  expiresAt: "2027-01-01T00:00:00Z",
  revokedAt: null,
});

/** A chain of `depth` actors; the first holds a grant. */
const chain = (depth: number): unknown => {
  let act: unknown = null;
  for (let level = depth; level >= 1; level -= 1) {
    act = { type: "agent", id: `a${level}`, grant: level === 1 ? grant() : null, act };
  }
  return act;
};

const base = (): Record<string, unknown> => ({
  subject: {
    type: "human",
    id: "u",
    roles: [{ role: "lead", scope: { kind: "match", properties: { queue: ["a", "b"] } } }],
    act: chain(1),
  },
  action: { name: "read" },
  resource: { type: "ticket", id: "t", properties: { queue: "a", amount: 5 } },
  context: { now: "2026-01-15T10:00:00Z" },
});

const scope = ["subject", "roles", 0, "scope"];
const limits = ["subject", "act", "grant", "entries", 0, "limits"];
const now = ["context", "now"];
const props = ["resource", "properties"];
const range = (min: unknown, max: unknown) => ({
  kind: "range",
  properties: { amount: { min, max } },
});

const cases: CorpusCase[] = [
  { name: "a valid request", edit: () => {}, expected: "accept" },
  { name: "no actor", edit: (d) => setAt(d, ["subject", "act"], null), expected: "accept" },
  // Strict objects and required fields.
  { name: "unknown top-level key", edit: (d) => setAt(d, ["extra"], 1), expected: [] },
  {
    name: "__proto__ key on subject",
    edit: (d) => setAt(d, ["subject", "__proto__"], {}),
    expected: ["subject"],
  },
  {
    name: "constructor key in context",
    edit: (d) => setAt(d, ["context", "constructor"], 1),
    expected: ["context"],
  },
  { name: "missing act", edit: (d) => dropAt(d, ["subject", "act"]), expected: ["subject", "act"] },
  {
    name: "act set to undefined",
    edit: (d) => setAt(d, ["subject", "act"], undefined),
    expected: ["subject", "act"],
  },
  {
    name: "missing field before an unknown key",
    edit: (d) => (dropAt(d, ["action", "name"]), setAt(d, ["action", "x"], 1)),
    expected: ["action", "name"],
  },
  { name: "request is an array", edit: (d) => setAt(d, ["subject"], []), expected: ["subject"] },
  // Subject.
  {
    name: "subject type agent",
    edit: (d) => setAt(d, ["subject", "type"], "agent"),
    expected: ["subject", "type"],
  },
  {
    name: "subject type in other case",
    edit: (d) => setAt(d, ["subject", "type"], "Human"),
    expected: ["subject", "type"],
  },
  {
    name: "subject id 256 characters",
    edit: (d) => setAt(d, ["subject", "id"], "i".repeat(256)),
    expected: "accept",
  },
  {
    name: "subject id 257 characters",
    edit: (d) => setAt(d, ["subject", "id"], "i".repeat(257)),
    expected: ["subject", "id"],
  },
  {
    name: "subject id empty",
    edit: (d) => setAt(d, ["subject", "id"], ""),
    expected: ["subject", "id"],
  },
  {
    name: "id length in UTF-16 units: 128 pairs",
    edit: (d) => setAt(d, ["subject", "id"], "\u{1F600}".repeat(128)),
    expected: "accept",
  },
  {
    name: "id length in UTF-16 units: 129 pairs",
    edit: (d) => setAt(d, ["subject", "id"], "\u{1F600}".repeat(129)),
    expected: ["subject", "id"],
  },
  {
    name: "256 role assignments",
    edit: (d) =>
      setAt(
        d,
        ["subject", "roles"],
        Array.from({ length: 256 }, () => ({ role: "r", scope: { kind: "all" } })),
      ),
    expected: "accept",
  },
  {
    name: "257 role assignments",
    edit: (d) =>
      setAt(
        d,
        ["subject", "roles"],
        Array.from({ length: 257 }, () => ({ role: "r", scope: { kind: "all" } })),
      ),
    expected: ["subject", "roles"],
  },
  {
    name: "role name 128 characters",
    edit: (d) => setAt(d, ["subject", "roles", 0, "role"], "r".repeat(128)),
    expected: "accept",
  },
  {
    name: "role name 129 characters",
    edit: (d) => setAt(d, ["subject", "roles", 0, "role"], "r".repeat(129)),
    expected: ["subject", "roles", 0, "role"],
  },
  // Scopes.
  { name: "scope missing", edit: (d) => dropAt(d, scope), expected: scope },
  { name: "scope empty object", edit: (d) => setAt(d, scope, {}), expected: [...scope, "kind"] },
  {
    name: "scope kind null",
    edit: (d) => setAt(d, scope, { kind: null }),
    expected: [...scope, "kind"],
  },
  {
    name: "scope kind empty",
    edit: (d) => setAt(d, scope, { kind: "" }),
    expected: [...scope, "kind"],
  },
  {
    name: "scope kind unknown",
    edit: (d) => setAt(d, scope, { kind: "ALL" }),
    expected: [...scope, "kind"],
  },
  {
    name: "scope kind toString",
    edit: (d) => setAt(d, scope, { kind: "toString" }),
    expected: [...scope, "kind"],
  },
  { name: "scope null", edit: (d) => setAt(d, scope, null), expected: scope },
  {
    name: "scope all with extra keys",
    edit: (d) => setAt(d, scope, { kind: "all", properties: { queue: ["a"] } }),
    expected: scope,
  },
  {
    name: "match scope without properties",
    edit: (d) => setAt(d, scope, { kind: "match" }),
    expected: [...scope, "properties"],
  },
  {
    name: "match scope with empty properties",
    edit: (d) => setAt(d, [...scope, "properties"], {}),
    expected: [...scope, "properties"],
  },
  {
    name: '"*" is not a wildcard',
    edit: (d) => setAt(d, [...scope, "properties", "queue"], ["*"]),
    expected: [...scope, "properties", "queue", 0],
  },
  {
    name: "empty scope value",
    edit: (d) => setAt(d, [...scope, "properties", "queue"], [""]),
    expected: [...scope, "properties", "queue", 0],
  },
  {
    name: "empty scope value list",
    edit: (d) => setAt(d, [...scope, "properties", "queue"], []),
    expected: [...scope, "properties", "queue"],
  },
  {
    name: "1000 scope values",
    edit: (d) =>
      setAt(
        d,
        [...scope, "properties", "queue"],
        Array.from({ length: 1000 }, () => "a"),
      ),
    expected: "accept",
  },
  {
    name: "1001 scope values",
    edit: (d) =>
      setAt(
        d,
        [...scope, "properties", "queue"],
        Array.from({ length: 1001 }, () => "a"),
      ),
    expected: [...scope, "properties", "queue"],
  },
  {
    name: "scope value undefined",
    edit: (d) => setAt(d, [...scope, "properties", "project"], undefined),
    expected: [...scope, "properties", "project"],
  },
  {
    name: "scope property name with underscore first",
    edit: (d) => setAt(d, [...scope, "properties", "_queue"], ["a"]),
    expected: [...scope, "properties", "_queue"],
  },
  {
    name: "scope property name __proto__",
    edit: (d) => setAt(d, [...scope, "properties", "__proto__"], ["a"]),
    expected: [...scope, "properties", "__proto__"],
  },
  {
    name: "scope property name constructor",
    edit: (d) => setAt(d, [...scope, "properties", "constructor"], ["a"]),
    expected: "accept",
  },
  {
    name: "scope property name 128 characters",
    edit: (d) => setAt(d, [...scope, "properties", "p".repeat(128)], ["a"]),
    expected: "accept",
  },
  {
    name: "scope property name 129 characters",
    edit: (d) => setAt(d, [...scope, "properties", "p".repeat(129)], ["a"]),
    expected: [...scope, "properties", "p".repeat(129)],
  },
  // Limits.
  {
    name: "range with min below max",
    edit: (d) => setAt(d, limits, range(1, 5)),
    expected: "accept",
  },
  {
    name: "range with min equal to max",
    edit: (d) => setAt(d, limits, range(5, 5)),
    expected: "accept",
  },
  {
    name: "range with min above max",
    edit: (d) => setAt(d, limits, range(5, 1)),
    expected: [...limits, "properties", "amount"],
  },
  {
    name: "range with both bounds null",
    edit: (d) => setAt(d, limits, range(null, null)),
    expected: [...limits, "properties", "amount"],
  },
  {
    name: "range with min undefined",
    edit: (d) => setAt(d, limits, range(undefined, 5)),
    expected: [...limits, "properties", "amount", "min"],
  },
  {
    name: "range with infinite max",
    edit: (d) => setAt(d, limits, range(null, Number.POSITIVE_INFINITY)),
    expected: [...limits, "properties", "amount", "max"],
  },
  {
    name: "range with NaN min",
    edit: (d) => setAt(d, limits, range(Number.NaN, 5)),
    expected: [...limits, "properties", "amount", "min"],
  },
  {
    name: "range with no properties",
    edit: (d) => setAt(d, limits, { kind: "range", properties: {} }),
    expected: [...limits, "properties"],
  },
  { name: "limits missing", edit: (d) => dropAt(d, limits), expected: limits },
  // Agent grants and actors.
  {
    name: "agent grant without entries",
    edit: (d) => setAt(d, ["subject", "act", "grant", "entries"], []),
    expected: ["subject", "act", "grant", "entries"],
  },
  {
    name: "agent grant entry without permissions",
    edit: (d) => setAt(d, ["subject", "act", "grant", "entries", 0, "permissions"], []),
    expected: ["subject", "act", "grant", "entries", 0, "permissions"],
  },
  {
    name: "agent grant notBefore missing",
    edit: (d) => dropAt(d, ["subject", "act", "grant", "notBefore"]),
    expected: ["subject", "act", "grant", "notBefore"],
  },
  {
    name: "agent grant revokedAt undefined",
    edit: (d) => setAt(d, ["subject", "act", "grant", "revokedAt"], undefined),
    expected: ["subject", "act", "grant", "revokedAt"],
  },
  {
    name: "agent grant principal type agent",
    edit: (d) => setAt(d, ["subject", "act", "grant", "principalType"], "agent"),
    expected: ["subject", "act", "grant", "principalType"],
  },
  {
    name: "agent grant expiry at the last timestamp",
    edit: (d) => setAt(d, ["subject", "act", "grant", "expiresAt"], "9999-12-31T23:59:59.999Z"),
    expected: "accept",
  },
  {
    name: "actor type human",
    edit: (d) => setAt(d, ["subject", "act", "type"], "human"),
    expected: ["subject", "act", "type"],
  },
  {
    name: "actor grant missing",
    edit: (d) => dropAt(d, ["subject", "act", "grant"]),
    expected: ["subject", "act", "grant"],
  },
  {
    name: "actor chain of depth 4",
    edit: (d) => setAt(d, ["subject", "act"], chain(4)),
    expected: "accept",
  },
  {
    name: "actor chain of depth 5",
    edit: (d) => setAt(d, ["subject", "act"], chain(5)),
    expected: ["subject", "act"],
  },
  {
    name: "depth 5 and another issue: the other issue comes first",
    edit: (d) => (setAt(d, ["subject", "act"], chain(5)), setAt(d, ["action", "name"], "")),
    expected: ["action", "name"],
  },
  {
    name: "invalid actor deep in the chain",
    edit: (d) => (
      setAt(d, ["subject", "act"], chain(3)),
      setAt(d, ["subject", "act", "act", "act", "id"], "")
    ),
    expected: ["subject", "act", "act", "act", "id"],
  },
  // Resource.
  {
    name: "resource id set to undefined",
    edit: (d) => setAt(d, ["resource", "id"], undefined),
    expected: "accept",
  },
  { name: "resource id missing", edit: (d) => dropAt(d, ["resource", "id"]), expected: "accept" },
  {
    name: "resource id empty",
    edit: (d) => setAt(d, ["resource", "id"], ""),
    expected: ["resource", "id"],
  },
  {
    name: "resource id null",
    edit: (d) => setAt(d, ["resource", "id"], null),
    expected: ["resource", "id"],
  },
  { name: "resource properties missing", edit: (d) => dropAt(d, props), expected: "accept" },
  { name: "resource properties empty", edit: (d) => setAt(d, props, {}), expected: "accept" },
  {
    name: "resource property __proto__ with a scalar is dropped",
    edit: (d) => setAt(d, [...props, "__proto__"], 1),
    expected: "accept",
  },
  {
    name: "resource property __proto__ with an object",
    edit: (d) => setAt(d, [...props, "__proto__"], {}),
    expected: [...props, "__proto__"],
  },
  {
    name: "resource property constructor",
    edit: (d) => setAt(d, [...props, "constructor"], "x"),
    expected: "accept",
  },
  {
    name: "resource property of 4096 characters",
    edit: (d) => setAt(d, [...props, "note"], "n".repeat(4096)),
    expected: "accept",
  },
  {
    name: "resource property of 4097 characters",
    edit: (d) => setAt(d, [...props, "note"], "n".repeat(4097)),
    expected: [...props, "note"],
  },
  {
    name: "resource property NaN",
    edit: (d) => setAt(d, [...props, "amount"], Number.NaN),
    expected: [...props, "amount"],
  },
  {
    name: "resource property Infinity",
    edit: (d) => setAt(d, [...props, "amount"], Number.POSITIVE_INFINITY),
    expected: [...props, "amount"],
  },
  {
    name: "resource property undefined",
    edit: (d) => setAt(d, [...props, "amount"], undefined),
    expected: [...props, "amount"],
  },
  {
    name: "resource property object",
    edit: (d) => setAt(d, [...props, "amount"], { value: 1 }),
    expected: [...props, "amount"],
  },
  {
    name: "resource property list",
    edit: (d) => setAt(d, [...props, "amount"], [1]),
    expected: [...props, "amount"],
  },
  {
    name: "resource property null and false",
    edit: (d) => (setAt(d, [...props, "a"], null), setAt(d, [...props, "b"], false)),
    expected: "accept",
  },
  // Context and timestamps.
  {
    name: "policy digest pin",
    edit: (d) => setAt(d, ["context", "policyDigest"], "a".repeat(64)),
    expected: "accept",
  },
  {
    name: "policy digest pin in upper case",
    edit: (d) => setAt(d, ["context", "policyDigest"], "A".repeat(64)),
    expected: ["context", "policyDigest"],
  },
  {
    name: "policy digest pin of 63 characters",
    edit: (d) => setAt(d, ["context", "policyDigest"], "a".repeat(63)),
    expected: ["context", "policyDigest"],
  },
  {
    name: "policy version pin empty",
    edit: (d) => setAt(d, ["context", "policyVersion"], ""),
    expected: ["context", "policyVersion"],
  },
  {
    name: "policy version pin undefined",
    edit: (d) => setAt(d, ["context", "policyVersion"], undefined),
    expected: "accept",
  },
  { name: "now missing", edit: (d) => dropAt(d, now), expected: now },
  {
    name: "now on 29 February of a leap year",
    edit: (d) => setAt(d, now, "2024-02-29T00:00:00Z"),
    expected: "accept",
  },
  {
    name: "now on 29 February of another year",
    edit: (d) => setAt(d, now, "2023-02-29T00:00:00Z"),
    expected: now,
  },
  { name: "now on 31 April", edit: (d) => setAt(d, now, "2026-04-31T00:00:00Z"), expected: now },
  {
    name: "now at the earliest instant",
    edit: (d) => setAt(d, now, "0000-01-01T00:00:00Z"),
    expected: "accept",
  },
  {
    name: "now on 29 February of year 0",
    edit: (d) => setAt(d, now, "0000-02-29T00:00:00Z"),
    expected: "accept",
  },
  {
    name: "now one offset before the earliest instant",
    edit: (d) => setAt(d, now, "0000-01-01T00:30:00+01:00"),
    expected: now,
  },
  {
    name: "now at the latest request instant",
    edit: (d) => setAt(d, now, new Date(latestRequestInstant).toISOString()),
    expected: "accept",
  },
  {
    name: "now 1 ms after the latest request instant",
    edit: (d) => setAt(d, now, new Date(latestRequestInstant + 1).toISOString()),
    expected: now,
  },
  {
    name: "now at the last timestamp",
    edit: (d) => setAt(d, now, "9999-12-31T23:59:59.999Z"),
    expected: now,
  },
  {
    name: "now with one fraction digit",
    edit: (d) => setAt(d, now, "2026-01-15T10:00:00.1Z"),
    expected: "accept",
  },
  {
    name: "now with four fraction digits",
    edit: (d) => setAt(d, now, "2026-01-15T10:00:00.1234Z"),
    expected: now,
  },
  {
    name: "now with offset +23:59",
    edit: (d) => setAt(d, now, "2026-01-15T10:00:00+23:59"),
    expected: "accept",
  },
  {
    name: "now with offset +24:00",
    edit: (d) => setAt(d, now, "2026-01-15T10:00:00+24:00"),
    expected: now,
  },
  {
    name: "now with offset without colon",
    edit: (d) => setAt(d, now, "2026-01-15T10:00:00+0100"),
    expected: now,
  },
  {
    name: "now with lower-case z",
    edit: (d) => setAt(d, now, "2026-01-15T10:00:00z"),
    expected: now,
  },
  { name: "now without offset", edit: (d) => setAt(d, now, "2026-01-15T10:00:00"), expected: now },
  { name: "now as a number", edit: (d) => setAt(d, now, 1_768_471_200_000), expected: now },
];

describe("request validator rules", () => {
  it.each(cases.map((item) => [item.name, item] as const))("%s", (_name, item) => {
    const { reference, actual, outputDifference } = runCase(
      accessRequestSchema,
      accessRequest,
      base,
      item,
    );
    expect({ zod: reference, handWritten: actual }).toEqual({
      zod: expectedOf(item),
      handWritten: expectedOf(item),
    });
    expect(outputDifference).toBeNull();
  });

  it("keeps a resource id set to undefined as an own key, as before", () => {
    const doc = base();
    setAt(doc, ["resource", "id"], undefined);
    const issues: never[] = [];
    const result = accessRequest(doc, null, issues);
    expect(typeof result === "object" && Object.hasOwn(result.resource, "id")).toBe(true);
  });

  it("drops a __proto__ resource property from the output, as before", () => {
    const doc = base();
    setAt(doc, ["resource", "properties", "__proto__"], 1);
    const result = accessRequest(doc, null, []);
    expect(typeof result === "object" && Object.keys(result.resource.properties ?? {})).toEqual([
      "queue",
      "amount",
    ]);
  });
});
