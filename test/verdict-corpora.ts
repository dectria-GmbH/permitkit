// The verdict corpora: seeded inputs for each hand-written validator, and the verdict text that
// test/zod-verdicts.test.ts compares with the verdict that the Zod 3 schema of f04df14 gave.
// Zod is no longer a dependency, so the Zod verdicts are recorded files in test/zod-verdicts/.
// They cannot be recorded again: a change to a generator, a seed or a run count changes the
// inputs, and the input digest check fails. Keep the generators as they are.
import { createHash } from "node:crypto";

import * as fc from "fast-check";

import { approval, approvalInput, approvalProof } from "../src/approval-input.js";
import {
  approvalInputBounds,
  policyBounds,
  requestBounds,
  snapshotOf,
  wrapperBounds,
  type InputBounds,
} from "../src/bounds.js";
import { parseRequest } from "../src/decide.js";
import { policyDocument } from "../src/policy-document.js";
import { storedRecord } from "../src/record.js";
import { accessRequest } from "../src/request.js";
import type { Check } from "../src/validate.js";
import {
  approvalArb,
  approvalInputArb,
  policyArb,
  proofArb,
  recordArb,
} from "./corpus-arbitraries.js";
import { mutate, stepArb, viaCheck, wideBounds, type Verdict } from "./differential.js";
import { requestArb } from "./request-arbitraries.js";

export interface VerdictCorpus {
  readonly name: string;
  readonly seed: number;
  readonly runs: number;
  readonly base: fc.Arbitrary<unknown>;
  /** The hand-written validator, or "parseRequest" for the whole pipeline with the size guard. */
  readonly check: Check<unknown> | "parseRequest";
  readonly bounds: readonly InputBounds[];
}

export const verdictCorpora: readonly VerdictCorpus[] = [
  {
    name: "request",
    seed: 1,
    runs: 4000,
    base: requestArb,
    check: accessRequest,
    bounds: [wideBounds, requestBounds],
  },
  {
    name: "parse-request",
    seed: 2,
    runs: 1000,
    base: requestArb,
    check: "parseRequest",
    bounds: [],
  },
  {
    name: "policy",
    seed: 3,
    runs: 2000,
    base: policyArb,
    check: policyDocument,
    bounds: [wideBounds, policyBounds],
  },
  {
    name: "approval-input",
    seed: 4,
    runs: 2000,
    base: approvalInputArb,
    check: approvalInput,
    bounds: [wideBounds, approvalInputBounds],
  },
  {
    name: "approval",
    seed: 5,
    runs: 2000,
    base: approvalArb,
    check: approval,
    bounds: [wideBounds, approvalInputBounds],
  },
  {
    name: "proof",
    seed: 6,
    runs: 1000,
    base: proofArb,
    check: approvalProof,
    bounds: [wideBounds, approvalInputBounds],
  },
  {
    name: "record",
    seed: 7,
    runs: 1000,
    base: recordArb,
    check: storedRecord,
    bounds: [wideBounds, wrapperBounds],
  },
];

/** The inputs of a corpus: generated from its seed, then mutated by 0 to 3 steps. */
export function corpusInputs(corpus: VerdictCorpus): unknown[] {
  const cases = fc.sample(
    fc.record({ base: corpus.base, steps: fc.array(stepArb, { maxLength: 3 }) }),
    {
      seed: corpus.seed,
      numRuns: corpus.runs,
    },
  );
  return cases.map(({ base, steps }) => mutate(base, steps).input);
}

/**
 * A text for a value that differs whenever two values are not the same data: primitives by
 * Object.is, arrays and objects with their prototype, own keys in order (also keys set to
 * undefined) and values.
 */
export function shapeText(value: unknown): string {
  if (value === undefined) return "u";
  if (value === null) return "n";
  if (typeof value === "number") return Object.is(value, -0) ? "-0" : `#${String(value)}`;
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "boolean") return value ? "t" : "f";
  if (typeof value !== "object") return `?${typeof value}`;
  const prototype: unknown = Object.getPrototypeOf(value);
  const mark =
    prototype === null
      ? "0"
      : prototype === Object.prototype
        ? "o"
        : prototype === Array.prototype
          ? "a"
          : "?";
  const keys = Reflect.ownKeys(value).filter((key) => !(Array.isArray(value) && key === "length"));
  const parts = keys.map(
    (key) => `${JSON.stringify(String(key))}:${shapeText(Reflect.get(value, key))}`,
  );
  return `{${mark}${parts.join(",")}}`;
}

const hash = (text: string, length: number): string =>
  createHash("sha256").update(text).digest("hex").slice(0, length);

/** "a <hash of the output>", or "r <first issue path as JSON>". */
export function verdictText(verdict: Verdict): string {
  return verdict.ok ? `a ${hash(shapeText(verdict.value), 10)}` : `r ${verdict.firstPath}`;
}

/** How a verdict is reached: the hand-written validator, or a recorded reference. */
export type Judge = (corpus: VerdictCorpus, snapshot: unknown) => Verdict;

export const handWritten: Judge = (corpus, snapshot) => {
  if (corpus.check === "parseRequest") throw new Error("parseRequest has no snapshot");
  return viaCheck(corpus.check, snapshot);
};

/** The verdict of parseRequest on the raw input, with paths as parseRequest joins them. */
export function parseRequestVerdict(input: unknown): Verdict {
  const parsed = parseRequest(input);
  if (parsed.ok) return { ok: true, value: parsed.request };
  return {
    ok: false,
    firstPath: JSON.stringify(parsed.issues[0]?.path ?? null),
    count: parsed.issues.length,
  };
}

/**
 * One line per input: the verdict under each bounds, "-" where the size guard refused the input.
 * A later bound is left out where it gives the same text as the first.
 */
export function corpusLines(
  corpus: VerdictCorpus,
  inputs: readonly unknown[],
  judge: Judge,
  parse: (input: unknown) => Verdict = parseRequestVerdict,
): string[] {
  return inputs.map((input) => {
    if (corpus.check === "parseRequest") return verdictText(parse(input));
    const texts = corpus.bounds.map((bounds) => {
      const snapshot = snapshotOf(input, bounds);
      return snapshot.ok ? verdictText(judge(corpus, snapshot.value)) : "-";
    });
    const first = texts[0] ?? "-";
    const rest = texts.slice(1).filter((text) => text !== first);
    return rest.length === 0 ? first : `${first}\t${texts.slice(1).join("\t")}`;
  });
}

/** A digest of the inputs, so a changed generator is found before any verdict is compared. */
export function inputDigest(inputs: readonly unknown[]): string {
  return hash(inputs.map(shapeText).join("\n"), 64);
}

export const headerOf = (corpus: VerdictCorpus, digest: string): string =>
  `# ${corpus.name}: seed ${corpus.seed}, runs ${corpus.runs}, inputs ${digest}`;
