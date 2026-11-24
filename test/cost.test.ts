import { describe, expect, it, vi } from "vitest";

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

interface PathApi {
  readonly runtime: string;
  readonly decide: (input: unknown) => string;
  readonly canonicalJson: (input: unknown) => number;
}

/**
 * A fresh copy of src on the given path. src/plain.ts picks its path when it loads, so the
 * portable copy loads while process.getBuiltinModule is hidden, as in test/setup.
 */
async function loadPath(path: "node" | "portable"): Promise<PathApi> {
  const descriptor = Object.getOwnPropertyDescriptor(process, "getBuiltinModule");
  if (descriptor === undefined) throw new Error("process.getBuiltinModule is missing");
  vi.resetModules();
  if (path === "portable") Reflect.deleteProperty(process, "getBuiltinModule");
  try {
    const api = await import("../src/index.js");
    const plain = await import("../src/plain.js");
    const catalog = api.defineCatalog({ ticket: { actions: ["read"], scopes: ["queue"] } });
    const compiled = api.compilePolicy(catalog, {
      schema: 2,
      version: "cost",
      roles: {
        lead: {
          grants: [
            {
              id: "g",
              permissions: ["ticket:read"],
              scope: { kind: "all" },
              limits: { kind: "unlimited" },
            },
          ],
        },
      },
      denies: [],
      approvalRules: [],
      separationOfDuties: {
        requesterNeverApprovesSameType: false,
        exclusiveRequestAndApproveRoles: false,
      },
    });
    return {
      runtime: plain.plainDataRuntime,
      decide: (input) => api.decide(compiled, input).reason,
      canonicalJson: (input) => api.canonicalJson(input).length,
    };
  } finally {
    Object.defineProperty(process, "getBuiltinModule", descriptor);
  }
}

describe(`many small plain JSON objects (${expectedRuntime} project)`, () => {
  /**
   * The portable path must cost about what the Node path costs, measured in the same run, so
   * that load on the machine changes both sides. With brand checks that throw for a plain object,
   * decide() with 19,000 {} took about 1.8 s of CPU on the portable path against 13 ms on Node
   * (5b09c79). One throw per object still gave about 180 ms for decide() and 870 ms against
   * 80 ms for canonicalJson. Without throws, the portable path costs less than the Node path.
   */
  const ratio = 2;
  const slackMs = 10;
  const rounds = 5;
  const lengthRequest = jsonRequestWith(() => ({ length: 0 }));
  const emptyRequest = jsonRequestWith(() => ({}));
  const emptyObjects: unknown = JSON.parse(
    JSON.stringify(Array.from({ length: 200 }, () => Array.from({ length: 1000 }, () => ({})))),
  );
  const cases: [string, (api: PathApi) => unknown, unknown][] = [
    ["decide(), 19,000 {length: 0}", (api) => api.decide(lengthRequest), "invalid_request"],
    ["decide(), 19,000 {}", (api) => api.decide(emptyRequest), "invalid_request"],
    ["canonicalJson, 200,000 {}", (api) => api.canonicalJson(emptyObjects), 600_401],
  ];

  it("cost at most twice the Node path on the portable path", { timeout: 120_000 }, async () => {
    const node = await loadPath("node");
    const portable = await loadPath("portable");
    expect([node.runtime, portable.runtime]).toEqual(["node", "portable"]);
    for (const [label, run, expected] of cases) {
      expect({ label, node: run(node), portable: run(portable) }).toEqual({
        label,
        node: expected,
        portable: expected,
      });
      // The lowest of several runs is the one least disturbed by load. The paths alternate, so
      // that a burst of load hits both.
      let nodeMs = Infinity;
      let portableMs = Infinity;
      for (let round = 0; round < rounds; round += 1) {
        nodeMs = Math.min(nodeMs, timed(() => run(node)).ms);
        portableMs = Math.min(portableMs, timed(() => run(portable)).ms);
      }
      const limitMs = ratio * nodeMs + slackMs;
      // Soft, so that a failure reports every case.
      expect
        .soft(
          portableMs,
          `${label}: portable ${portableMs.toFixed(1)} ms, Node ${nodeMs.toFixed(1)} ms of CPU`,
        )
        .toBeLessThanOrEqual(limitMs);
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
