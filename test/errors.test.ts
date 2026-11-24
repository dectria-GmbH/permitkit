// PermitkitError under a polluted Error.prototype, and its brand check against thrown Proxies.
// The pollution can also break the test framework, so each case captures first and asserts
// after clean-up.
import { describe, expect, it } from "vitest";

import { compilePolicy, decide, defineCatalog, PermitkitError } from "../src/index.js";
import { accessRequest, everywhere, human, role } from "../src/testing/index.js";

const catalog = defineCatalog({ ticket: { actions: ["read"] } });
const policy = compilePolicy(catalog, {
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
  denies: [],
  approvalRules: [],
  separationOfDuties: {
    requesterNeverApprovesSameType: false,
    exclusiveRequestAndApproveRoles: false,
  },
});

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

  it("compilePolicy turns a thrown Proxy into policy_invalid", () => {
    const thrown = trapProxy();
    const result = withProperty(
      Array.prototype,
      "toSorted",
      {
        get() {
          throw thrown;
        },
        configurable: true,
      },
      () => {
        try {
          compilePolicy(catalog, { ...policy.document });
          return "compiled";
        } catch (error) {
          if (error === thrown) return "the thrown Proxy";
          return PermitkitError.is(error) ? error.code : `raw ${String(error)}`;
        }
      },
    );
    expect(result).toBe("policy_invalid");
  });

  it("decide turns a thrown Proxy into the internal-failure deny", () => {
    const thrown = trapProxy();
    const request = accessRequest(human("u", role("reader", everywhere)), "ticket:read");
    // decide() calls map only after validation, so the Proxy reaches the guard in decide().
    const result = withProperty(
      Array.prototype,
      "map",
      {
        get() {
          throw thrown;
        },
        configurable: true,
      },
      () => {
        try {
          const decision = decide(policy, request);
          return [decision.reason, decision.rule, decision.requestDigest];
        } catch (error) {
          return error === thrown ? "the thrown Proxy" : `raw ${String(error)}`;
        }
      },
    );
    expect(result).toEqual(["invalid_request", null, null]);
  });
});
