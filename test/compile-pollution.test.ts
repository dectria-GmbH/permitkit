// compilePolicy under data-valued pollution of built-in methods. Every built-in it calls is
// captured at load, so the pollution changes no outcome: the invalid document, the fake catalogue
// and schema 3 are refused with their own codes, and the valid document compiles. Its catch block
// (any other failure is policy_invalid with a fixed text) is tested in catch-paths.test.ts. The
// pollution also breaks the test framework, so each case captures first and asserts after
// clean-up.
import { describe, expect, it } from "vitest";

import { compilePolicy, defineCatalog, PermitkitError } from "../src/index.js";

const catalog = defineCatalog({ ticket: { actions: ["read"] } });
const invalidDocument = { schema: 2 };
const validDocument = {
  schema: 2,
  version: "v",
  roles: {
    reader: {
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
  denies: [{ id: "d", permissions: ["ticket:read"], roles: ["reader"], scope: { kind: "all" } }],
  approvalRules: [],
  separationOfDuties: {
    requesterNeverApprovesSameType: false,
    exclusiveRequestAndApproveRoles: false,
  },
};

function outcomeOf(run: () => unknown): string {
  try {
    run();
    return "compiled";
  } catch (error) {
    if (!(error instanceof PermitkitError)) return `raw ${String(error)}`;
    const text = JSON.stringify({ message: error.message, issues: error.issues });
    return text.includes("is not a function") ? `${error.code} with raw text` : error.code;
  }
}

/** Outcomes for: an invalid document, a valid one, a fake catalogue, and schema 3. */
function outcomes(): string[] {
  return [
    outcomeOf(() => compilePolicy(catalog, invalidDocument)),
    outcomeOf(() => compilePolicy(catalog, validDocument)),
    outcomeOf(() => compilePolicy({} as never, validDocument)),
    outcomeOf(() => compilePolicy(catalog, { ...validDocument, schema: 3 })),
  ];
}

const cases: [target: string, method: string, valid: string][] = [
  ["Array", "map", "compiled"],
  ["Array", "forEach", "compiled"],
  ["Array", "join", "compiled"],
  // Called through a copy captured at load. Until then the compile failed with policy_invalid.
  ["Array", "toSorted", "compiled"],
  ["Set", "has", "compiled"],
];

const prototypes: Record<string, object> = { Array: Array.prototype, Set: Set.prototype };

describe("compilePolicy under a polluted prototype", () => {
  it.each(cases)("%s.prototype.%s = 1 changes no outcome", (target, method, valid) => {
    const prototype = prototypes[target] as object;
    const saved = Object.getOwnPropertyDescriptor(prototype, method);
    // The test simulates a prototype-pollution bug elsewhere in the process.
    // oxlint-disable-next-line no-extend-native
    Object.defineProperty(prototype, method, { value: 1, configurable: true, writable: true });
    let result: string[];
    try {
      result = outcomes();
    } finally {
      if (saved !== undefined) Object.defineProperty(prototype, method, saved);
    }
    expect(result).toEqual([
      "policy_invalid",
      valid,
      "catalog_invalid",
      "policy_schema_unsupported",
    ]);
  });
});

describe("compilePolicy under accessor pollution", () => {
  // The compile used to call Set.prototype.has, and the catch turned what the getter threw into
  // policy_invalid (now in catch-paths.test.ts). The getter no longer runs.
  it("never reads Set.prototype.has", () => {
    class ThrowingCode extends PermitkitError {
      constructor() {
        super("policy_invalid", "made by the caller");
        Object.defineProperty(this, "code", {
          get(): never {
            throw new Error("raw error from the code getter");
          },
        });
      }
    }
    const saved = Object.getOwnPropertyDescriptor(Set.prototype, "has");
    let calls = 0;
    // The test simulates accessor pollution of a built-in prototype elsewhere in the process.
    // oxlint-disable-next-line no-extend-native
    Object.defineProperty(Set.prototype, "has", {
      get() {
        calls += 1;
        throw new ThrowingCode();
      },
      configurable: true,
    });
    let result: string;
    try {
      compilePolicy(catalog, validDocument);
      result = "compiled";
    } catch (error) {
      if (PermitkitError.is(error)) {
        const code = Object.getOwnPropertyDescriptor(error, "code");
        result = code !== undefined && "value" in code ? String(code.value) : "spoof";
      } else {
        result = "raw";
      }
    } finally {
      // Restores the original method.
      // oxlint-disable-next-line no-extend-native
      if (saved !== undefined) Object.defineProperty(Set.prototype, "has", saved);
    }
    expect([result, calls]).toEqual(["compiled", 0]);
  });
});

// compilePolicy calls Object.hasOwn and Reflect.getOwnPropertyDescriptor through copies captured
// at load, so replacing them changes no outcome. Until then, each case failed the compile with
// policy_invalid, also for schema 3.
const statics: [label: string, target: object, key: string][] = [
  ["Object.hasOwn", Object, "hasOwn"],
  ["Reflect.getOwnPropertyDescriptor", Reflect, "getOwnPropertyDescriptor"],
];
const replacements: [label: string, descriptor: () => PropertyDescriptor][] = [
  ["= 1", () => ({ value: 1, configurable: true, writable: true })],
  ["= undefined", () => ({ value: undefined, configurable: true, writable: true })],
  [
    "as a getter that throws a raw error",
    () => ({
      get(): never {
        throw new Error("raw error from a static");
      },
      configurable: true,
    }),
  ],
  [
    "as a getter that throws policy_unknown",
    () => ({
      get(): never {
        throw new PermitkitError("policy_unknown", "made by the caller");
      },
      configurable: true,
    }),
  ],
];
const staticCases = statics.flatMap(([name, target, key]) =>
  replacements.map(([how, descriptor]) => [`${name} ${how}`, target, key, descriptor] as const),
);

describe("compilePolicy under a replaced static", () => {
  it.each(staticCases)("%s changes no outcome", (_label, target, key, descriptor) => {
    const saved = Object.getOwnPropertyDescriptor(target, key);
    Object.defineProperty(target, key, descriptor());
    let result: string[];
    try {
      result = outcomes();
    } finally {
      if (saved !== undefined) Object.defineProperty(target, key, saved);
    }
    expect(result).toEqual([
      "policy_invalid",
      "compiled",
      "catalog_invalid",
      "policy_schema_unsupported",
    ]);
  });
});
