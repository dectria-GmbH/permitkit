// The catch blocks of compilePolicy, decide, explain and evaluate. Replacing a built-in after load
// no longer reaches them (see replacement-fuzz.test.ts), so this file makes permitkit's own digest
// and size guard throw a chosen value through a module mock. Each catch must give the documented
// result without reading the thrown value: no instanceof on it, no Proxy trap, no getter.
import { afterEach, describe, expect, it, vi } from "vitest";

import {
  compilePolicy,
  decide,
  defineCatalog,
  evaluate,
  explain,
  PermitkitError,
} from "../src/index.js";
import { accessRequest, everywhere, human, role } from "../src/testing/index.js";

const fault = vi.hoisted(() => ({
  digest: undefined as (() => unknown) | undefined,
  snapshot: undefined as (() => unknown) | undefined,
}));

vi.mock("../src/canonical.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("../src/canonical.js")>();
  return {
    ...original,
    digest: (value: unknown) => {
      if (fault.digest !== undefined) throw fault.digest();
      return original.digest(value);
    },
  };
});

vi.mock("../src/bounds.js", async (importOriginal) => {
  const original = await importOriginal<typeof import("../src/bounds.js")>();
  return {
    ...original,
    boundedSnapshot: (value: unknown, bounds: import("../src/bounds.js").InputBounds) => {
      if (fault.snapshot !== undefined) throw fault.snapshot();
      return original.boundedSnapshot(value, bounds);
    },
  };
});

afterEach(() => {
  fault.digest = undefined;
  fault.snapshot = undefined;
});

const catalog = defineCatalog({ ticket: { actions: ["read"] } });
const document = {
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
};
const policy = compilePolicy(catalog, document);
const request = () => accessRequest(human("u", role("reader", everywhere)), "ticket:read");
const authzen = () => ({
  subject: {
    type: "human",
    id: "u",
    properties: { roles: [{ role: "reader", scope: { kind: "all" } }], act: null },
  },
  action: { name: "read" },
  resource: { type: "ticket" },
  context: { now: "2026-01-15T10:00:00Z" },
});

/** A thrown value whose traps count their calls and throw, so instanceof on it throws too. */
function trapProxy(): { value: object; traps: () => number } {
  let traps = 0;
  const trap = () => {
    traps += 1;
    throw new Error("from the trap");
  };
  const value = new Proxy({}, { getPrototypeOf: trap, get: trap, getOwnPropertyDescriptor: trap });
  return { value, traps: () => traps };
}

/** A PermitkitError whose code getter throws a raw error, and counts its calls. */
function throwingCode(): { value: PermitkitError; reads: () => number } {
  let reads = 0;
  const value = new PermitkitError("policy_unknown", "made by the caller");
  Object.defineProperty(value, "code", {
    get(): never {
      reads += 1;
      throw new Error("raw error from the code getter");
    },
  });
  return { value, reads: () => reads };
}

/** The code of a thrown PermitkitError, read without running a getter. */
function codeOf(run: () => unknown): string {
  try {
    run();
    return "no throw";
  } catch (error) {
    if (!PermitkitError.is(error)) return "raw";
    const code = Object.getOwnPropertyDescriptor(error, "code");
    return code !== undefined && "value" in code ? String(code.value) : "spoof";
  }
}

const internalFailure = {
  outcome: "deny",
  reason: "invalid_request",
  rule: null,
  requestDigest: null,
};

describe("catch paths", () => {
  it("compilePolicy turns a thrown Proxy into policy_invalid", () => {
    const thrown = trapProxy();
    fault.digest = () => thrown.value;
    const result = codeOf(() => compilePolicy(catalog, document));
    expect([result, thrown.traps()]).toEqual(["policy_invalid", 0]);
  });

  it("compilePolicy turns a PermitkitError with a throwing code getter into policy_invalid", () => {
    const thrown = throwingCode();
    fault.digest = () => thrown.value;
    const result = codeOf(() => compilePolicy(catalog, document));
    expect([result, thrown.reads()]).toEqual(["policy_invalid", 0]);
  });

  it("compilePolicy passes its own codes through", () => {
    fault.digest = () => new PermitkitError("policy_schema_unsupported", "made inside");
    expect(codeOf(() => compilePolicy(catalog, document))).toBe("policy_schema_unsupported");
  });

  it("decide and explain turn a thrown Proxy into the internal-failure deny", () => {
    const thrown = trapProxy();
    fault.digest = () => thrown.value;
    expect(decide(policy, request())).toMatchObject(internalFailure);
    expect(explain(policy, request()).decision).toMatchObject(internalFailure);
    expect(thrown.traps()).toBe(0);
  });

  it.each([
    ["a caller-made policy_unknown", () => new PermitkitError("policy_unknown", "spoof")],
    ["a PermitkitError with a throwing code getter", () => throwingCode().value],
  ])("decide and explain deny %s", (_label, make) => {
    fault.digest = make;
    expect(decide(policy, request())).toMatchObject(internalFailure);
    expect(explain(policy, request()).decision).toMatchObject(internalFailure);
  });

  it.each([
    ["a thrown Proxy", () => trapProxy().value],
    ["a caller-made policy_unknown", () => new PermitkitError("policy_unknown", "spoof")],
    ["a PermitkitError with a throwing code getter", () => throwingCode().value],
  ])("evaluate denies %s", (_label, make) => {
    fault.snapshot = make;
    const response = evaluate(policy, authzen());
    expect([response.decision, response.context.reason_codes]).toEqual([
      false,
      ["invalid_request"],
    ]);
  });

  it("decides normally without a fault", () => {
    expect(decide(policy, request()).reason).toBe("granted");
    expect(evaluate(policy, authzen()).decision).toBe(true);
  });
});
