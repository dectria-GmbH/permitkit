// An accessor or a read-only value on Array.prototype at index 0, 1 or 2, installed after
// permitkit loads, changes no result. V8's toSorted writes the item of a one-item array with an
// ordinary assignment, which such a property catches: the sorted copy came back empty, so
// canonicalJson({ a: 1 }) failed and every decision was invalid_request. Each case records while
// the property is in place and asserts after it is removed.
import { describe, expect, it } from "vitest";

import {
  canonicalJson,
  compilePolicy,
  decide,
  defineCatalog,
  explain,
  requestDigest,
  type CompiledPolicy,
} from "../src/index.js";
import { callTimeCorpus } from "./call-time-corpus.js";

const define = Object.defineProperty;
const deleteKey = Reflect.deleteProperty;
const stringify = JSON.stringify;

const catalog = defineCatalog({ ticket: { actions: ["read"] } });
const all = { kind: "all" } as const;
const singleRole = {
  schema: 2,
  version: "v",
  denies: [],
  approvalRules: [],
  roles: {
    reader: {
      grants: [
        { id: "g", permissions: ["ticket:read"], scope: all, limits: { kind: "unlimited" } },
      ],
    },
  },
  separationOfDuties: {
    requesterNeverApprovesSameType: false,
    exclusiveRequestAndApproveRoles: false,
  },
} as const;
const policy = compilePolicy(catalog, singleRole);
const request = {
  subject: { type: "human", id: "u", roles: [{ role: "reader", scope: all }], act: null },
  action: { name: "read" },
  resource: { type: "ticket" },
  context: { now: "2026-01-15T10:00:00Z" },
};
const values: unknown[] = [{ a: 1 }, { a: 1, b: 2 }, { b: [1], a: { c: null } }, [1], [], {}];

function results(): string[] {
  const found: string[] = [];
  const add = (run: () => unknown) => {
    let text: string;
    try {
      text = stringify(run()) ?? "undefined";
    } catch (error) {
      text = `threw ${String((error as { code?: unknown }).code)}`;
    }
    // By length, not push: the property under test sits on Array.prototype.
    define(found, found.length, {
      value: text,
      writable: true,
      enumerable: true,
      configurable: true,
    });
  };
  for (let index = 0; index < values.length; index += 1) add(() => canonicalJson(values[index]));
  add(() => decide(policy, request));
  add(() => compilePolicy(catalog, singleRole).digest);
  return found;
}

const variants: [label: string, descriptor: () => PropertyDescriptor][] = [
  ["an accessor that drops writes", () => ({ get: () => "a", set: () => {}, configurable: true })],
  ["a read-only value", () => ({ value: "x", writable: false, configurable: true })],
];

describe("a property on Array.prototype at a low index", () => {
  const clean = results();

  it("the clean run grants and serializes", () => {
    expect(clean[0]).toBe(stringify('{"a":1}'));
    expect(clean[values.length]).toContain('"outcome":"allow"');
  });

  for (const index of ["0", "1", "2"]) {
    for (const [label, descriptor] of variants) {
      it(`${label} at index ${index} changes no result`, () => {
        define(Array.prototype, index, descriptor());
        let polluted: string[];
        try {
          polluted = results();
        } finally {
          deleteKey(Array.prototype, index);
        }
        expect(polluted).toEqual(clean);
      });
    }
  }

  it("decide, explain and requestDigest give the same results on the corpus", () => {
    const corpus = callTimeCorpus(8);
    const run = (): string[] => {
      const found: string[] = [];
      const add = (body: () => unknown) => {
        let text: string;
        try {
          text = stringify(body()) ?? "undefined";
        } catch (error) {
          text = `threw ${String((error as { code?: unknown }).code)}`;
        }
        define(found, found.length, {
          value: text,
          writable: true,
          enumerable: true,
          configurable: true,
        });
      };
      for (let policyIndex = 0; policyIndex < corpus.policies.length; policyIndex += 1) {
        const compiled = corpus.policies[policyIndex] as CompiledPolicy;
        for (let index = 0; index < corpus.requests.length; index += 1) {
          const item = corpus.requests[index];
          add(() => decide(compiled, item));
          add(() => explain(compiled, item));
          add(() => requestDigest(compiled, item));
        }
      }
      return found;
    };
    const cleanRun = run();
    expect(cleanRun.length).toBeGreaterThan(100);
    for (const index of ["0", "1", "2"]) {
      for (const [, descriptor] of variants) {
        define(Array.prototype, index, descriptor());
        let pollutedRun: string[];
        try {
          pollutedRun = run();
        } finally {
          deleteKey(Array.prototype, index);
        }
        expect(pollutedRun).toEqual(cleanRun);
      }
    }
  });
});
