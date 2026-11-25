// PermitkitError under a polluted Error.prototype, and its brand check against thrown Proxies.
// How the catch blocks treat a thrown Proxy is in catch-paths.test.ts.
// The pollution can also break the test framework, so each case captures first and asserts
// after clean-up.
import { describe, expect, it } from "vitest";

import { compilePolicy, PermitkitError } from "../src/index.js";

/** Replaces a property for the duration of run, then puts the original back. */
function withProperty<T>(
  target: object,
  key: string,
  descriptor: PropertyDescriptor,
  run: () => T,
) {
  const saved = Object.getOwnPropertyDescriptor(target, key);
  // The test simulates a prototype-pollution bug elsewhere in the process.
  // oxlint-disable-next-line no-extend-native
  Object.defineProperty(target, key, descriptor);
  try {
    return run();
  } finally {
    if (saved === undefined) Reflect.deleteProperty(target, key);
    else Object.defineProperty(target, key, saved);
  }
}

/** The code and name of the error that compilePolicy throws for a fake catalogue. */
function catalogError(): string {
  try {
    compilePolicy({} as never, {});
    return "compiled";
  } catch (error) {
    return PermitkitError.is(error) ? `${error.code} ${error.name}` : `raw ${String(error)}`;
  }
}

/** A thrown value whose getPrototypeOf trap throws, so instanceof on it throws too. */
function trapProxy(): object {
  return new Proxy(
    {},
    {
      getPrototypeOf() {
        throw new Error("from the trap");
      },
    },
  );
}

describe("PermitkitError", () => {
  it("keeps its name when Error.prototype.name is read-only", () => {
    const result = withProperty(
      Error.prototype,
      "name",
      { value: "x", writable: false, configurable: true },
      catalogError,
    );
    expect(result).toBe("catalog_invalid PermitkitError");
  });

  it("keeps its name when Error.prototype.name is a getter", () => {
    const result = withProperty(
      Error.prototype,
      "name",
      { get: () => "x", configurable: true },
      catalogError,
    );
    expect(result).toBe("catalog_invalid PermitkitError");
  });

  it("recognizes its own instances only, without running Proxy traps", () => {
    const real = new PermitkitError("policy_invalid", "m");
    const lookalike = Object.create(PermitkitError.prototype) as unknown;
    expect([
      PermitkitError.is(real),
      PermitkitError.is(lookalike),
      PermitkitError.is(trapProxy()),
      PermitkitError.is(null),
      PermitkitError.is("PermitkitError"),
    ]).toEqual([true, false, false, false, false]);
  });
});
