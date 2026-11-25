// Each hand-written validator against the verdicts that the Zod 3 schemas of f04df14 gave on the
// same seeded inputs: valid inputs and near-valid mutations of them. Same verdict on every input,
// the same output on accept (by a hash of its shape), and the same path in the first issue on
// reject, under wide bounds and under the production bounds. Zod is no longer a dependency, so
// the verdicts are recorded in test/zod-verdicts/; see verdict-corpora.ts.
import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  corpusInputs,
  corpusLines,
  handWritten,
  headerOf,
  inputDigest,
  verdictCorpora,
} from "./verdict-corpora.js";

function recorded(name: string): { header: string; lines: string[] } {
  const text = readFileSync(new URL(`./zod-verdicts/${name}.txt`, import.meta.url), "utf8");
  const [header = "", ...lines] = text.trimEnd().split("\n");
  return { header, lines };
}

// Generating and checking the larger corpora takes several seconds alone, and over a minute on
// a loaded machine (seen at load 380 on the portable path).
const timeout = { timeout: 180_000 };

describe("hand-written validators against the recorded Zod verdicts", timeout, () => {
  it.each(verdictCorpora.map((corpus) => [corpus.name, corpus] as const))("%s", (_name, corpus) => {
    const inputs = corpusInputs(corpus);
    const reference = recorded(corpus.name);
    // The inputs are the recorded ones: a changed generator fails here, not on a verdict.
    expect(headerOf(corpus, inputDigest(inputs))).toBe(reference.header);
    const actual = corpusLines(corpus, inputs, handWritten);
    const differing: string[] = [];
    for (let index = 0; index < actual.length; index += 1) {
      if (actual[index] !== reference.lines[index] && differing.length < 10) {
        differing.push(`#${index}: ${actual[index]} vs Zod ${reference.lines[index]}`);
      }
    }
    expect({ count: actual.length, differing }).toEqual({
      count: reference.lines.length,
      differing: [],
    });
    // Health: both verdicts occur often, so the comparison is not one-sided.
    const accepted = actual.filter((line) => line.startsWith("a ")).length;
    const rejected = actual.filter((line) => line.startsWith("r ")).length;
    expect({
      accepted: accepted > actual.length / 5,
      rejected: rejected > actual.length / 5,
    }).toEqual({ accepted: true, rejected: true });
  });
});
