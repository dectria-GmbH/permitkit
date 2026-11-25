// The error for an unsupported policy schema prints the value only if it is a string, number,
// boolean or null. For an array or object it names the type. JSON.stringify on a copied array
// looks up toJSON, which the array inherits from Array.prototype and Object.prototype, so a getter
// installed there after load could write the error message. Each case records while the getter is
// in place and asserts after it is removed.
import { describe, expect, it } from "vitest";

import { compilePolicy, defineCatalog, PermitkitError } from "../src/index.js";

const catalog = defineCatalog({ ticket: { actions: ["read"] } });
const define = Object.defineProperty;
const deleteKey = Reflect.deleteProperty;

interface Refusal {
  readonly code: string;
  readonly message: string;
  readonly issue: string;
}

function refusal(input: unknown): Refusal {
  try {
    compilePolicy(catalog, input);
  } catch (error) {
    if (PermitkitError.is(error)) {
      return { code: error.code, message: error.message, issue: error.issues[0]?.message ?? "" };
    }
    return { code: "not a PermitkitError", message: String(error), issue: "" };
  }
  return { code: "compiled", message: "", issue: "" };
}

describe("an unsupported schema value", () => {
  it("prints a scalar value and the type of an array or object", () => {
    expect(refusal({ schema: 3 }).message).toBe(
      "The policy document has schema 3. This release reads only schema 2.",
    );
    expect(refusal({ schema: "2" }).message).toBe(
      'The policy document has schema "2". This release reads only schema 2.',
    );
    expect(refusal({ schema: null }).issue).toBe(
      "Schema null is not supported. There is no automatic migration.",
    );
    expect(refusal({ schema: [1] })).toEqual({
      code: "policy_schema_unsupported",
      message: "The policy document has schema of type array. This release reads only schema 2.",
      issue: "Schema of type array is not supported. There is no automatic migration.",
    });
    expect(refusal({ schema: { v: 2 } }).message).toBe(
      "The policy document has schema of type object. This release reads only schema 2.",
    );
  });

  it("a toJSON getter on Object.prototype is never read and cannot write the message", () => {
    let reads = 0;
    define(Object.prototype, "toJSON", {
      configurable: true,
      get() {
        reads += 1;
        return () => "forged";
      },
    });
    let found: Refusal[];
    try {
      found = [refusal({ schema: [1] }), refusal({ schema: { v: 2 } }), refusal({ schema: 3 })];
    } finally {
      deleteKey(Object.prototype, "toJSON");
    }
    expect(reads).toBe(0);
    expect(found.map((item) => item.message)).toEqual([
      "The policy document has schema of type array. This release reads only schema 2.",
      "The policy document has schema of type object. This release reads only schema 2.",
      "The policy document has schema 3. This release reads only schema 2.",
    ]);
  });
});
