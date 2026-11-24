// compilePolicy under data-valued pollution of built-in methods. It may refuse the document,
// but only with a PermitkitError, never a raw error. Its own codes (catalog_invalid,
// policy_invalid, policy_schema_unsupported) pass through unchanged; any other failure is
// policy_invalid with a fixed text. The pollution also breaks the test framework, so each case
// captures first and asserts after clean-up.
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
  // No such call on the compile path any more, so the valid document compiles.
  ["Array", "map", "compiled"],
  ["Array", "forEach", "compiled"],
  // Still used by compilePolicy and the canonical digest; the failure becomes policy_invalid.
  ["Array", "toSorted", "policy_invalid"],
  ["Array", "join", "policy_invalid"],
  // Used by checkReferences. The check of the error code itself must not use it.
  ["Set", "has", "policy_invalid"],
];

const prototypes: Record<string, object> = { Array: Array.prototype, Set: Set.prototype };

describe("compilePolicy under a polluted prototype", () => {
  it.each(cases)("%s.prototype.%s = 1 gives no raw error", (target, method, valid) => {
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
  it("gives no raw error for a thrown PermitkitError with a throwing code getter", () => {
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
    expect(calls).toBeGreaterThan(0);
    expect(result).toBe("policy_invalid");
  });
});
