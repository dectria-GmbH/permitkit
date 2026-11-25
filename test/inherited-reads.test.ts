// No call on the decision path reads a key that its object does not have. Such a read walks to
// Object.prototype or Array.prototype, where caller code can install a getter after permitkit
// loads. A getter for `key` that returned a function once ran inside the validator and emptied
// its issue list, so an invalid request was granted. This test installs a recording getter on
// both prototypes for every name that appears in src, runs the watched calls, and expects no
// read. The names come from the source, so a new property read is covered without a list.
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

import { compilePolicy, decide, defineCatalog } from "../src/index.js";
import { callTimeCorpus, runCallTimeCorpus, type CallName } from "./call-time-corpus.js";

const define = Object.defineProperty;
const hasOwn = Object.hasOwn;
const deleteKey = Reflect.deleteProperty;
const bareDescriptor = (): PropertyDescriptor => Object.create(null) as PropertyDescriptor;

function sourceFiles(directory: string): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) found.push(...sourceFiles(path));
    else if (entry.name.endsWith(".ts")) found.push(path);
  }
  return found;
}

/** Every identifier and every quoted word in src, plus the first array indexes. */
function sourceNames(): string[] {
  const names = new Set<string>(["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]);
  const source = join(import.meta.dirname, "..", "src");
  for (const file of sourceFiles(source)) {
    const text = readFileSync(file, "utf8");
    for (const match of text.matchAll(/[A-Za-z_$][\w$]*/g)) names.add(match[0]);
  }
  names.delete("__proto__");
  return [...names];
}

const extraSymbols: symbol[] = [
  Symbol.iterator,
  Symbol.asyncIterator,
  Symbol.toPrimitive,
  Symbol.toStringTag,
  Symbol.isConcatSpreadable,
  Symbol.species,
];

const owners: [label: string, owner: object][] = [
  ["Object.prototype", Object.prototype],
  ["Array.prototype", Array.prototype],
];

type Reads = Record<string, number>;

/** Installs the getters, runs the body, removes them, and returns the reads per call. */
function recordReads(keys: readonly PropertyKey[], body: (hit: Hit) => void): Reads {
  const reads: Reads = Object.create(null) as Reads;
  const hit: Hit = { active: "" };
  const installed: [object, PropertyKey][] = [];
  try {
    for (const [label, owner] of owners) {
      for (const key of keys) {
        if (hasOwn(owner, key)) continue;
        const name = `${label}[${String(key)}]`;
        // A descriptor without a prototype: the getters below would otherwise make every
        // descriptor literal inherit `value` and `writable`.
        const descriptor = bareDescriptor();
        descriptor.configurable = true;
        descriptor.enumerable = false;
        descriptor.get = () => {
          if (hit.active !== "") {
            const entry = `${hit.active} ${name}`;
            reads[entry] = (reads[entry] ?? 0) + 1;
          }
          return undefined;
        };
        descriptor.set = function set(this: object, value: unknown) {
          // An assignment to a missing key: define it on the receiver, as without the getter.
          const data = bareDescriptor();
          data.value = value;
          data.writable = true;
          data.enumerable = true;
          data.configurable = true;
          define(this, key, data);
        };
        define(owner, key, descriptor);
        installed.push([owner, key]);
      }
    }
    body(hit);
  } finally {
    for (let index = installed.length - 1; index >= 0; index -= 1) {
      const [owner, key] = installed[index] as [object, PropertyKey];
      deleteKey(owner, key);
    }
  }
  return reads;
}

interface Hit {
  active: CallName | "";
}

const keys: PropertyKey[] = [...sourceNames(), ...extraSymbols];
const corpus = callTimeCorpus(24);

describe("no inherited reads on the decision path", () => {
  it("reads no key through Object.prototype or Array.prototype", () => {
    expect(keys.length).toBeGreaterThan(500);
    const reads = recordReads(keys, (hit) => {
      runCallTimeCorpus(
        corpus,
        (name) => {
          hit.active = name;
        },
        () => {
          hit.active = "";
        },
      );
    });
    expect(reads).toEqual({});
  });

  it("the spy sees an inherited read (control)", () => {
    const reads = recordReads(["pattern", "0"], (hit) => {
      hit.active = "decide";
      const empty: unknown[] = [];
      const value: Record<string, unknown> = {};
      void value["pattern"];
      void empty[0];
      hit.active = "";
    });
    expect(reads).toEqual({
      "decide Object.prototype[pattern]": 1,
      "decide Array.prototype[0]": 1,
    });
  });

  it("a getter on Object.prototype.key cannot clear the issues of an invalid request", () => {
    const catalog = defineCatalog({ ticket: { actions: ["read"], limits: ["amount"] } });
    const all = { kind: "all" } as const;
    const policy = compilePolicy(catalog, {
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
    });
    const request = {
      subject: { type: "human", id: "u", roles: [{ role: "reader", scope: all }], act: null },
      action: { name: "read" },
      // amount is not a scalar, so the request is invalid.
      resource: { type: "ticket", properties: { amount: { nested: 1 }, zz: 1 } },
      context: { now: "2026-01-15T10:00:00Z" },
    };
    const clean = decide(policy, request).reason;
    let calls = 0;
    define(Object.prototype, "key", {
      configurable: true,
      get() {
        return (_key: string, _path: unknown, issues: unknown[]) => {
          calls += 1;
          issues.length = 0;
        };
      },
    });
    let polluted: string;
    try {
      polluted = decide(policy, request).reason;
    } finally {
      deleteKey(Object.prototype, "key");
    }
    expect([clean, polluted, calls]).toEqual(["invalid_request", "invalid_request", 0]);
  });
});
