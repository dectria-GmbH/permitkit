import { describe, expect, it } from "vitest";

import { canonicalJson, decide, PermitkitError } from "../src/index.js";
import { accessRequest, everywhere, human, role } from "../src/testing/index.js";
import { policy } from "./fixtures.js";
import { expectedRuntime } from "./runtime.js";

/**
 * A swapped typed array or boxed string has one own key per element. The slot checks must
 * refuse it before its keys are listed, on both paths. Listing 1e7 keys took seconds and about
 * 2 GB.
 */
const size = 10_000_000;
const budgetMs = 250;

const huge: [string, () => object][] = [
  ["typed array", () => Object.setPrototypeOf(new Uint8Array(size), Object.prototype)],
  ["boxed string", () => Object.setPrototypeOf(Object("x".repeat(size)), Object.prototype)],
];

function timed(run: () => unknown): { result: unknown; ms: number } {
  const start = performance.now();
  const result = run();
  return { result, ms: performance.now() - start };
}

function codeOf(run: () => unknown): unknown {
  try {
    run();
    return "ok";
  } catch (error) {
    return error instanceof PermitkitError ? error.code : "raw error";
  }
}

describe(`huge built-ins with a swapped prototype (${expectedRuntime} path)`, () => {
  const lead = human("u-lead", role("lead", everywhere));

  it("deny in decide() without listing their keys", () => {
    for (const [label, make] of huge) {
      const blob = make();
      const request = accessRequest(lead, "ticket:read", {
        properties: { queue: "a", blob } as never,
      });
      const { result, ms } = timed(() => decide(policy, request).reason);
      expect({ label, result, fast: ms < budgetMs }).toEqual({
        label,
        result: "invalid_request",
        fast: true,
      });
    }
  });

  it("are refused by canonicalJson without listing their keys", () => {
    for (const [label, make] of huge) {
      const blob = make();
      const { result, ms } = timed(() => codeOf(() => canonicalJson({ blob })));
      expect({ label, result, fast: ms < budgetMs }).toEqual({
        label,
        result: "not_canonical",
        fast: true,
      });
    }
  });
});
