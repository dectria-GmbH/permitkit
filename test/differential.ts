// Shared parts of the validator tests: verdicts of a hand-written validator, generators for
// valid documents, and near-valid mutations of them.
import * as fc from "fast-check";

import { snapshotOf, type InputBounds } from "../src/bounds.js";
import {
  earliestInstant,
  latestInstant,
  latestRequestInstant,
  maxApprovalWindowSeconds,
} from "../src/time.js";
import { invalid, type Check, type Issue } from "../src/validate.js";

/** Wide enough that strings and lists at and above every schema limit reach the validators. */
export const wideBounds: InputBounds = Object.freeze({
  maxDepth: 64,
  maxNodes: 1_000_000,
  maxArrayLength: 20_000,
  maxStringLength: 10_000,
});

export type Verdict =
  | { readonly ok: true; readonly value: unknown }
  | { readonly ok: false; readonly firstPath: string; readonly count: number };

/** A hand-written validator. Throws if it accepts and still reports an issue. */
export function viaCheck<T>(check: Check<T>, snapshot: unknown): Verdict {
  const issues: Issue[] = [];
  const value = check(snapshot, null, issues);
  if (value === invalid) {
    if (issues.length === 0) throw new Error("rejected without an issue");
    return { ok: false, firstPath: JSON.stringify(issues[0]?.path ?? null), count: issues.length };
  }
  if (issues.length > 0) throw new Error("accepted with issues");
  return { ok: true, value };
}

/** `"accept"`, or the path of the first issue as JSON. */
export function verdictOf(verdict: Verdict): string {
  return verdict.ok ? "accept" : verdict.firstPath;
}

// Generators for valid parts. Each also yields values at the inclusive limits.

const alnum = "abcxyzABZ019".split("");
const identifierChars = [...alnum, "_", ".", ":", "-"];

export const identifierArb: fc.Arbitrary<string> = fc.oneof(
  {
    weight: 12,
    arbitrary: fc
      .tuple(
        fc.constantFrom(...alnum),
        fc.string({ unit: fc.constantFrom(...identifierChars), maxLength: 6 }),
      )
      .map(([first, rest]) => first + rest),
  },
  {
    weight: 1,
    arbitrary: fc.constantFrom("a".repeat(128), "constructor", "toString", "0", "1", "valueOf"),
  },
);

const lower = "abcz".split("");
const permissionPart = fc
  .tuple(
    fc.constantFrom(...lower),
    fc.string({ unit: fc.constantFrom(...lower, "0", "_", "-"), maxLength: 4 }),
  )
  .map(([first, rest]) => first + rest);
export const permissionArb: fc.Arbitrary<string> = fc
  .tuple(permissionPart, permissionPart)
  .map(([resource, action]) => `${resource}:${action}`);

/** Short text of any characters, including surrogate pairs. */
export const textArb = (maxLength: number, minLength = 0): fc.Arbitrary<string> =>
  fc.string({ unit: "grapheme-composite", minLength, maxLength });

export const scopeValueArb: fc.Arbitrary<string> = fc
  .string({ unit: "grapheme-ascii", minLength: 1, maxLength: 6 })
  .filter((value) => value !== "*");

export const scopeArb = fc.oneof(
  fc.constant({ kind: "all" }),
  fc.record({
    kind: fc.constant("match"),
    properties: fc.dictionary(
      identifierArb,
      fc.array(scopeValueArb, { minLength: 1, maxLength: 3 }),
      {
        minKeys: 1,
        maxKeys: 3,
      },
    ),
  }),
);

const finiteArb = fc.oneof(
  fc.integer({ min: -1000, max: 1000 }),
  fc.double({ noNaN: true, noDefaultInfinity: true }),
);

const boundArb = fc.oneof(
  fc.tuple(finiteArb, finiteArb).map(([a, b]) => ({ min: Math.min(a, b), max: Math.max(a, b) })),
  finiteArb.map((max) => ({ min: null, max })),
  finiteArb.map((min) => ({ min, max: null })),
  finiteArb.map((value) => ({ min: value, max: value })),
);

export const limitsArb = fc.oneof(
  fc.constant({ kind: "unlimited" }),
  fc.record({
    kind: fc.constant("range"),
    properties: fc.dictionary(identifierArb, boundArb, { minKeys: 1, maxKeys: 3 }),
  }),
);

/** Valid timestamps with every accepted form: Z or offset, zero to three fraction digits. */
export function timestampArb(latest: number): fc.Arbitrary<string> {
  const day = 86_400_000;
  const formatted = fc
    .record({
      at: fc.date({
        min: new Date(earliestInstant + day),
        max: new Date(latest - day),
        noInvalidDate: true,
      }),
      offset: fc.integer({ min: -(23 * 60 + 59), max: 23 * 60 + 59 }),
      zulu: fc.boolean(),
      digits: fc.integer({ min: 0, max: 3 }),
    })
    .map(({ at, offset, zulu, digits }) => {
      const shift = zulu ? 0 : offset;
      const local = new Date(at.getTime() + shift * 60_000).toISOString();
      const base = local.slice(0, 19);
      const fraction = digits === 0 ? "" : local.slice(19, 20 + digits);
      if (zulu) return `${base}${fraction}Z`;
      const sign = shift < 0 ? "-" : "+";
      const size = Math.abs(shift);
      const zone = `${sign}${String(Math.floor(size / 60)).padStart(2, "0")}:${String(size % 60).padStart(2, "0")}`;
      return `${base}${fraction}${zone}`;
    });
  const edges = [
    "0000-01-01T00:00:00Z",
    "0000-02-29T00:00:00Z",
    "2024-02-29T23:59:59.999Z",
    "0000-01-01T00:30:00-01:00",
    new Date(latest).toISOString(),
  ];
  return fc.oneof(
    { weight: 8, arbitrary: formatted },
    { weight: 1, arbitrary: fc.constantFrom(...edges) },
  );
}

export { latestInstant, latestRequestInstant };

/** An optional field: absent, present as undefined, or present with a value. */
export function optionalField<T>(
  key: string,
  value: fc.Arbitrary<T>,
): fc.Arbitrary<Record<string, unknown>> {
  return fc.oneof(
    { weight: 2, arbitrary: fc.constant({}) },
    { weight: 1, arbitrary: fc.constant({ [key]: undefined }) },
    { weight: 3, arbitrary: value.map((item) => ({ [key]: item })) },
  );
}

// Near-valid mutations.

export interface Step {
  readonly pick: number;
  readonly op: number;
  readonly choice: number;
}

export const stepArb: fc.Arbitrary<Step> = fc.record({
  pick: fc.nat(),
  op: fc.nat(),
  choice: fc.nat(),
});

export const operations = ["drop", "unknownKey", "replace", "near", "undefined", "null"] as const;
export type Operation = (typeof operations)[number];

const timestampEdges = [
  "2024-02-29T00:00:00Z",
  "2023-02-29T00:00:00Z",
  "2026-04-31T00:00:00Z",
  "2100-02-29T00:00:00Z",
  "2000-02-29T00:00:00Z",
  "0000-02-29T00:00:00Z",
  "0000-01-01T00:00:00Z",
  "0000-01-01T00:00:00.000+00:00",
  "0000-01-01T00:30:00+01:00",
  "0000-01-01T00:30:00-01:00",
  "9999-12-31T23:59:59.999Z",
  "9999-12-31T23:59:59.999-00:01",
  "9999-12-31T22:59:59.999-01:00",
  "9999-12-31T23:59:59.999+00:01",
  new Date(latestRequestInstant).toISOString(),
  new Date(latestRequestInstant - 1).toISOString(),
  new Date(latestRequestInstant + 1).toISOString(),
  "9999-12-01T00:00:00+00:01",
  "2026-01-15T10:00:00.1Z",
  "2026-01-15T10:00:00.12Z",
  "2026-01-15T10:00:00.1234Z",
  "2026-01-15T10:00:00+23:59",
  "2026-01-15T10:00:00-23:59",
  "2026-01-15T10:00:00+24:00",
  "2026-01-15T10:00:00+0100",
  "2026-01-15T10:00:00z",
  "2026-01-15t10:00:00Z",
  "2026-01-15 10:00:00Z",
  "2026-01-15T10:00Z",
  "2026-01-15T24:00:00Z",
  "2026-01-15T10:00:60Z",
  "2026-1-15T10:00:00Z",
  "+02026-01-15T10:00:00Z",
  "2026-01-15T10:00:00.Z",
  "2026-01-15T10:00:00",
  "2026-01-15",
];

const digest = "0123456789abcdef".repeat(4);

/** A fresh value from the pool, so later steps never change a shared object. */
function poolValue(index: number): unknown {
  const pool: (() => unknown)[] = [
    () => undefined,
    () => null,
    () => true,
    () => false,
    () => 0,
    () => -0,
    () => 1,
    () => -1,
    () => 1.5,
    () => 2,
    () => "2",
    () => 10,
    () => 11,
    () => 59,
    () => 60,
    () => maxApprovalWindowSeconds,
    () => maxApprovalWindowSeconds + 1,
    () => Number.NaN,
    () => Number.POSITIVE_INFINITY,
    () => Number.NEGATIVE_INFINITY,
    () => 1e21,
    () => Number.MAX_SAFE_INTEGER + 2,
    () => "",
    () => " ",
    () => "*",
    () => "x",
    () => "all",
    () => "match",
    () => "unlimited",
    () => "range",
    () => "always",
    () => "threshold",
    () => "permission",
    () => "roles",
    () => "human",
    () => "service",
    () => "agent",
    () => "Human",
    () => "ticket:read",
    () => "Ticket:read",
    () => "__proto__",
    () => digest,
    () => digest.toUpperCase(),
    () => `${digest}0`,
    () => "a".repeat(64),
    () => "a".repeat(65),
    () => "a".repeat(128),
    () => "a".repeat(129),
    () => "a".repeat(256),
    () => "a".repeat(257),
    () => "a".repeat(1000),
    () => "a".repeat(1001),
    () => "a".repeat(4096),
    () => "a".repeat(4097),
    () => "\u{1F600}".repeat(64),
    () => "\u{1F600}".repeat(65),
    () => "\uD800",
    () => "2026-01-15T10:00:00Z",
    ...timestampEdges.map((value) => () => value),
    () => [],
    () => [""],
    () => ["*"],
    () => [null],
    () => [undefined],
    () => [{}],
    () => ({}),
    () => ({ kind: "all" }),
    () => ({ kind: "all", properties: {} }),
    () => ({ kind: "match", properties: {} }),
    () => ({ kind: "match", properties: { queue: ["*"] } }),
    () => ({ kind: "match", properties: { queue: ["a"] } }),
    () => ({ kind: "unlimited" }),
    () => ({ kind: "range", properties: { amount: { min: null, max: null } } }),
    () => ({ kind: "range", properties: { amount: { min: 5, max: 1 } } }),
    () => ({ kind: "range", properties: { amount: { min: 1, max: 5 } } }),
    () => ({ kind: "always" }),
    () => ({ kind: "threshold", properties: { amount: { gte: 1 } } }),
    () => ({ kind: "permission" }),
    () => ({ kind: "roles", roles: ["r"] }),
    () => ({ min: null, max: 1 }),
    () => ({ min: null, max: null }),
    () => ({ min: 2, max: 1 }),
    () => ({ gte: 1 }),
    () => ({ gte: Number.NaN }),
    () => withKey({}, "__proto__", { kind: "all" }),
    () => withKey({}, "__proto__", 1),
    () => ({ constructor: 1 }),
    () => ({ constructor: ["a"] }),
  ];
  const make = pool[index % pool.length] ?? (() => undefined);
  return make();
}

export const poolSize = 120;

/** Sets an own data property, also for `__proto__`. */
export function withKey<T extends object>(target: T, key: string, value: unknown): T {
  Object.defineProperty(target, key, {
    value,
    enumerable: true,
    writable: true,
    configurable: true,
  });
  return target;
}

function clone(value: unknown): unknown {
  if (typeof value !== "object" || value === null) return value;
  if (Array.isArray(value)) return value.map(clone);
  const result = {};
  for (const key of Object.keys(value)) withKey(result, key, clone(Reflect.get(value, key)));
  return result;
}

const unknownKeys = [
  "extra",
  "__proto__",
  "constructor",
  "kind",
  "properties",
  "",
  "toString",
  "0",
  "Kind",
  "scopes",
];

/** Values close to a valid one: at and beyond limits, wrong case, wrong type. */
function nearValues(value: unknown): unknown[] {
  if (typeof value === "string") {
    const values: unknown[] = [
      "",
      "*",
      `${value}x`,
      value.slice(1),
      value.toUpperCase(),
      ` ${value}`,
      value.padEnd(64, "a"),
      value.padEnd(65, "a"),
      value.padEnd(128, "a"),
      value.padEnd(129, "a"),
      value.padEnd(256, "a"),
      value.padEnd(257, "a"),
      value.padEnd(1000, "a"),
      value.padEnd(1001, "a"),
      value.padEnd(4096, "a"),
      value.padEnd(4097, "a"),
      value.replace(":", ""),
      value.replace(/[a-z]/, "_"),
      [value],
      1,
    ];
    if (/^\d{4}-/.test(value))
      values.push(
        ...timestampEdges,
        value.replace("Z", "+01:00"),
        value.replace(/(\.\d+)?(Z|[+-]\d\d:\d\d)$/, ".1234Z"),
      );
    return values;
  }
  if (typeof value === "number") {
    return [
      value + 1,
      value - 1,
      value + 0.5,
      -value,
      0,
      1,
      10,
      11,
      59,
      60,
      maxApprovalWindowSeconds,
      maxApprovalWindowSeconds + 1,
      Number.NaN,
      Number.POSITIVE_INFINITY,
      Number.NEGATIVE_INFINITY,
      String(value),
    ];
  }
  if (typeof value === "boolean") return [!value, String(value), 0, 1, null];
  if (Array.isArray(value)) {
    const first: unknown = value[0];
    const filled = (length: number) => Array.from({ length }, () => clone(first));
    const values: unknown[] = [
      [],
      value.slice(1),
      [...value.map(clone), undefined],
      [...value.map(clone), null],
    ];
    if (value.length > 0) {
      values.push(
        [...value.map(clone), clone(first)],
        filled(10),
        filled(11),
        filled(256),
        filled(257),
        filled(1000),
        filled(1001),
      );
    }
    return values;
  }
  if (typeof value === "object" && value !== null) {
    const keys = Object.keys(value);
    const copy = () => clone(value) as Record<string, unknown>;
    const values: unknown[] = [
      {},
      withKey(copy(), "__proto__", 1),
      withKey(copy(), "extra", undefined),
    ];
    if (keys.length > 0) {
      const dropped = copy();
      Reflect.deleteProperty(dropped, keys[0] as string);
      values.push(
        dropped,
        withKey(copy(), keys[0] as string, undefined),
        withKey(copy(), keys[0] as string, null),
      );
    }
    return values;
  }
  return [null, undefined, "", {}, [], 0];
}

interface Position {
  readonly parent: object;
  readonly key: string | number;
}

function positionsOf(holder: { doc: unknown }): Position[] {
  const found: Position[] = [];
  const visit = (parent: object, key: string | number) => {
    found.push({ parent, key });
    const value: unknown = Reflect.get(parent, key);
    if (typeof value !== "object" || value === null) return;
    if (Array.isArray(value)) {
      for (let index = 0; index < value.length; index += 1) visit(value, index);
    } else {
      for (const name of Object.keys(value)) visit(value, name);
    }
  };
  visit(holder, "doc");
  return found;
}

/** Applies the steps to a copy of the document. Returns the input and the mutation class. */
export function mutate(base: unknown, steps: readonly Step[]): { input: unknown; name: string } {
  const holder = { doc: clone(base) };
  const names: Operation[] = [];
  for (const step of steps) {
    const positions = positionsOf(holder);
    const position = positions[step.pick % positions.length];
    if (position === undefined) break;
    const { parent, key } = position;
    const operation = operations[step.op % operations.length] ?? "replace";
    names.push(operation);
    const current: unknown = Reflect.get(parent, key);
    switch (operation) {
      case "drop":
        if (Array.isArray(parent) && typeof key === "number") parent.splice(key, 1);
        else Reflect.deleteProperty(parent, key);
        break;
      case "unknownKey":
        if (typeof current === "object" && current !== null && !Array.isArray(current)) {
          withKey(
            current,
            unknownKeys[step.choice % unknownKeys.length] ?? "extra",
            poolValue(step.choice >> 4),
          );
        } else if (Array.isArray(current)) {
          current.push(poolValue(step.choice));
        } else {
          withKey(parent, String(key), poolValue(step.choice));
        }
        break;
      case "replace":
        withKey(parent, String(key), poolValue(step.choice));
        break;
      case "near": {
        const values = nearValues(current);
        withKey(parent, String(key), values[step.choice % values.length]);
        break;
      }
      case "undefined":
        withKey(parent, String(key), undefined);
        break;
      case "null":
        withKey(parent, String(key), null);
        break;
    }
  }
  const name = names.length <= 1 ? (names[0] ?? "none") : `mixed (${names.length} steps)`;
  return { input: holder.doc, name };
}

// Helpers for the named corpus tests.

type Key = string | number;

function parentOf(doc: object, path: readonly Key[]): object {
  let node: unknown = doc;
  for (const key of path.slice(0, -1)) node = Reflect.get(node as object, key);
  if (typeof node !== "object" || node === null) throw new Error(`no object at ${path.join(".")}`);
  return node;
}

/** Sets a value at a path, as an own data property (also for `__proto__`). */
export function setAt(doc: object, path: readonly Key[], value: unknown): void {
  withKey(parentOf(doc, path), String(path.at(-1)), value);
}

/** Removes the key at a path. */
export function dropAt(doc: object, path: readonly Key[]): void {
  Reflect.deleteProperty(parentOf(doc, path), String(path.at(-1)));
}

/** A named corpus case: an edit of the valid base, and the expected verdict. */
export interface CorpusCase {
  readonly name: string;
  readonly edit: (doc: Record<string, unknown>) => void;
  /** `"accept"`, or the path of the first issue, for example `["subject", "act"]`. */
  readonly expected: "accept" | readonly Key[];
}

/** Runs one corpus case through the validator, with bounds wide enough for every limit. */
export function runCase<T>(
  check: Check<T>,
  base: () => Record<string, unknown>,
  item: CorpusCase,
): string {
  const doc = base();
  item.edit(doc);
  const snapshot = snapshotOf(doc, wideBounds);
  if (!snapshot.ok) throw new Error(`${item.name}: the size guard refused the input`);
  return verdictOf(viaCheck(check, snapshot.value));
}

export function expectedOf(item: CorpusCase): string {
  return item.expected === "accept" ? "accept" : JSON.stringify(item.expected);
}
