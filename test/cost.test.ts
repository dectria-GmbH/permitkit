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

/** CPU time, not wall time: other test runs on the same machine must not fail a budget. */
function timed(run: () => unknown): { result: unknown; ms: number } {
  const start = process.cpuUsage();
  const result = run();
  const used = process.cpuUsage(start);
  return { result, ms: (used.user + used.system) / 1000 };
}

function codeOf(run: () => unknown): unknown {
  try {
    run();
    return "ok";
  } catch (error) {
    return error instanceof PermitkitError ? error.code : "raw error";
  }
}

/** A request from JSON text with 19 x 1,000 copies of `item` in its properties. */
function jsonRequestWith(item: () => unknown): unknown {
  const lead = human("u-lead", role("lead", everywhere));
  const request = accessRequest(lead, "ticket:read", { properties: { queue: "a" } });
  const blob = Array.from({ length: 19 }, () => Array.from({ length: 1000 }, item));
  return JSON.parse(
    JSON.stringify({
      ...request,
      resource: { ...request.resource, properties: { queue: "a", blob } },
    }),
  );
}

describe(`many small plain JSON objects (${expectedRuntime} path)`, () => {
  // Node takes about 15 ms of CPU for each case below. The portable path took 894 ms with
  // {length: 0} (d6eba0a) and 1.8 s with {} (5b09c79), when it ran brand checks that throw for a
  // plain object. JSON can produce `length` only as an enumerable key.
  const cases: [string, () => unknown][] = [
    ["{length: 0}", () => ({ length: 0 })],
    ["{}", () => ({})],
  ];

  it("go through decide() at about the Node cost", () => {
    for (const [label, item] of cases) {
      const parsed = jsonRequestWith(item);
      decide(policy, parsed);
      const { result, ms } = timed(() => decide(policy, parsed).reason);
      expect({ label, result, fast: ms < budgetMs }).toEqual({
        label,
        result: "invalid_request",
        fast: true,
      });
    }
  });
});

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
