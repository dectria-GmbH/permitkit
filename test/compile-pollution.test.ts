// compilePolicy under data-valued pollution of Array.prototype methods. It may refuse the
// document, but only with PermitkitError policy_invalid and a fixed text, never a raw error.
// The pollution also breaks the test framework, so each case captures first and asserts after.
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

function outcomeOf(document: unknown): string {
  try {
    compilePolicy(catalog, document);
    return "compiled";
  } catch (error) {
    if (!(error instanceof PermitkitError)) return `raw ${String(error)}`;
    const text = JSON.stringify({ message: error.message, issues: error.issues });
    return text.includes("is not a function") ? `${error.code} with raw text` : error.code;
  }
}

/** Each method: the outcome for an invalid and for a valid document. */
const cases: [method: string, valid: string][] = [
  // No array method on the compile path any more, so the valid document compiles.
  ["map", "compiled"],
  ["forEach", "compiled"],
  // Still used by compilePolicy and the canonical digest; the error becomes policy_invalid.
  ["toSorted", "policy_invalid"],
  ["join", "policy_invalid"],
];

describe("compilePolicy under a polluted Array.prototype", () => {
  it.each(cases)("Array.prototype.%s = 1 gives no raw error", (method, valid) => {
    const saved: unknown = Reflect.get(Array.prototype, method);
    // The test simulates a prototype-pollution bug elsewhere in the process.
    // oxlint-disable-next-line no-extend-native
    Object.defineProperty(Array.prototype, method, {
      value: 1,
      configurable: true,
      writable: true,
    });
    let outcomes: string[];
    try {
      outcomes = [outcomeOf(invalidDocument), outcomeOf(validDocument)];
    } finally {
      // oxlint-disable-next-line no-extend-native
      Object.defineProperty(Array.prototype, method, {
        value: saved,
        configurable: true,
        writable: true,
      });
    }
    expect(outcomes).toEqual(["policy_invalid", valid]);
  });
});
