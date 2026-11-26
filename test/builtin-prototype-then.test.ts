// A `then` on a built-in prototype other than Object.prototype, Array.prototype and
// Function.prototype. An async verifier that returns, for example, an Error resolves its own
// promise through Error.prototype.then, and that then chooses the value permitkit reads. The
// settled value does not show which chain was read, so permitkit checks every built-in
// prototype that it captured at load for an own `then`, before and after each verifier call.
// An object with a `then` put between such a prototype and its parent gives no prototype an own
// `then`, so permitkit also compares the parent of each captured prototype with the one at load.
import { afterEach, describe, expect, it } from "vitest";

import {
  compilePolicy,
  defineCatalog,
  evaluateApprovals,
  requestDigest,
  type ApprovalDecision,
  type ApprovalProofVerifier,
} from "../src/index.js";

const define = Reflect.defineProperty;
const deleteKey = Reflect.deleteProperty;

const all = { kind: "all" } as const;
const catalog = defineCatalog({ ticket: { actions: ["refund"] } });
const policy = compilePolicy(catalog, {
  schema: 2,
  version: "p",
  denies: [],
  roles: {
    lead: {
      grants: [
        { id: "lead", permissions: ["ticket:refund"], scope: all, limits: { kind: "unlimited" } },
      ],
    },
    approver: { grants: [] },
  },
  approvalRules: [
    {
      id: "r",
      permissions: ["ticket:refund"],
      when: { kind: "always" },
      approvers: 1,
      expiresInSeconds: 3600,
      eligibleApprovers: { kind: "roles", roles: ["approver"] },
      requireProof: true,
      proofTypes: ["sig"],
    },
  ],
  separationOfDuties: {
    requesterNeverApprovesSameType: false,
    exclusiveRequestAndApproveRoles: false,
  },
});
const request = {
  subject: { type: "human" as const, id: "req", roles: [{ role: "lead", scope: all }], act: null },
  action: { name: "refund" },
  resource: { type: "ticket", id: "t" },
  context: { now: "2026-01-15T10:00:00.000Z" },
};
const digest = requestDigest(policy, request);
const input = {
  request,
  now: "2026-01-15T10:10:00.000Z",
  approvals: [
    {
      approver: { type: "human", id: "bob", roles: [{ role: "approver", scope: all }], act: null },
      approvedAt: "2026-01-15T10:05:00.000Z",
      requestDigest: digest,
      proof: { type: "sig", approverId: "bob", requestDigest: digest, payload: {} },
    },
  ],
};

const hooksChanged =
  "a then on, or a changed parent of, a built-in prototype, or a replaced " +
  "Promise.prototype.then, Promise.prototype.constructor or Promise[Symbol.species]";

let fired = 0;
const polluted: object[] = [];
const reparented: (readonly [object, object | null])[] = [];

afterEach(() => {
  for (const prototype of polluted) deleteKey(prototype, "then");
  polluted.length = 0;
  for (const [prototype, parent] of reparented) Reflect.setPrototypeOf(prototype, parent);
  reparented.length = 0;
});

/** Resolves any value with a confirmed verification, in an object without a prototype. */
function forgingThen(resolve: (value: unknown) => void): void {
  fired += 1;
  resolve(
    Object.assign(Object.create(null) as object, {
      valid: true,
      approverId: "bob",
      requestDigest: digest,
    }),
  );
}

/** An async verifier that rejects the proof with a result made by `make`. */
function rejecting(make: () => object): ApprovalProofVerifier {
  return {
    type: "sig",
    verify: async () => {
      await Promise.resolve();
      return Object.assign(make(), { valid: false, reason: "bad signature" }) as never;
    },
  };
}

const summary = (decision: ApprovalDecision) => ({
  outcome: `${decision.outcome} counted=${decision.counted.length}`,
  detail: decision.rejected[0]?.detail,
});

/** The decision without a hook, and with a forging `then` own on `prototype`. */
async function attack(prototype: object, make: () => object) {
  const verifier = rejecting(make);
  const clean = summary(await evaluateApprovals(policy, input, { verifiers: [verifier] }));
  fired = 0;
  // oxlint-disable-next-line unicorn/no-thenable
  define(prototype, "then", { value: forgingThen, writable: true, configurable: true });
  polluted.push(prototype);
  let hooked: ReturnType<typeof summary>;
  try {
    hooked = summary(await evaluateApprovals(policy, input, { verifiers: [verifier] }));
  } finally {
    deleteKey(prototype, "then");
  }
  return { clean, hooked, fired };
}

/**
 * The decision without a hook, and with an object that has a forging `then` put between
 * `prototype` and its parent. No prototype gets an own `then`.
 */
async function reparent(prototype: object, make: () => object) {
  const verifier = rejecting(make);
  const clean = summary(await evaluateApprovals(policy, input, { verifiers: [verifier] }));
  fired = 0;
  const parent = Reflect.getPrototypeOf(prototype);
  const evil: object = Object.create(parent) as object;
  // oxlint-disable-next-line unicorn/no-thenable
  define(evil, "then", { value: forgingThen, writable: true, configurable: true });
  Reflect.setPrototypeOf(prototype, evil);
  reparented.push([prototype, parent]);
  let hooked: ReturnType<typeof summary>;
  try {
    hooked = summary(await evaluateApprovals(policy, input, { verifiers: [verifier] }));
  } finally {
    Reflect.setPrototypeOf(prototype, parent);
  }
  return { clean, hooked, fired };
}

const refused = {
  clean: { outcome: "pending counted=0", detail: "bad signature" },
  hooked: { outcome: "pending counted=0", detail: hooksChanged },
  fired: 0,
};

/** The hooked decision is refused, and the forging then never runs. */
const parentRefused = (detail: string) => ({
  clean: { outcome: "pending counted=0", detail },
  hooked: { outcome: "pending counted=0", detail: hooksChanged },
  fired: 0,
});

const typedArrayPrototype = Object.getPrototypeOf(Uint8Array.prototype) as object;
const arrayIteratorPrototype = Object.getPrototypeOf([].values()) as object;
const iteratorPrototype = Object.getPrototypeOf(arrayIteratorPrototype) as object;
// What Iterator.from returns for an object that is not an Iterator; a prototype-less source
// keeps the Symbol.iterator lookup out of the way.
const makeWrapped = () =>
  Iterator.from(Object.assign(Object.create(null) as object, { next: () => ({}) })) as object;
const wrapForValidIteratorPrototype = Object.getPrototypeOf(makeWrapped()) as object;

describe("a then on a built-in prototype of the verifier result", () => {
  it("Error.prototype, with an Error result", async () => {
    expect(await attack(Error.prototype, () => new Error("bad"))).toEqual(refused);
  });

  it("TypeError.prototype, with a TypeError result", async () => {
    expect(await attack(TypeError.prototype, () => new TypeError("bad"))).toEqual(refused);
  });

  it("RegExp.prototype, with a RegExp result", async () => {
    expect(await attack(RegExp.prototype, () => /bad/)).toEqual(refused);
  });

  it("Map.prototype, with a Map result", async () => {
    expect(await attack(Map.prototype, () => new Map())).toEqual(refused);
  });

  it("%TypedArray%.prototype, with a Uint8Array result", async () => {
    expect(await attack(typedArrayPrototype, () => new Uint8Array(1))).toEqual(refused);
  });

  it("Uint8Array.prototype, with a Uint8Array result", async () => {
    expect(await attack(Uint8Array.prototype, () => new Uint8Array(1))).toEqual(refused);
  });

  it("%ArrayIteratorPrototype%, with an array iterator result", async () => {
    expect(await attack(arrayIteratorPrototype, () => [].values())).toEqual(refused);
  });

  it("%IteratorPrototype%, with a Set iterator result", async () => {
    expect(await attack(iteratorPrototype, () => new Set().values())).toEqual(refused);
  });

  it("%WrapForValidIteratorPrototype%, with an Iterator.from result", async () => {
    expect(await attack(wrapForValidIteratorPrototype, makeWrapped)).toEqual(refused);
  });

  it("Intl.NumberFormat.prototype, with a NumberFormat result", async () => {
    expect(await attack(Intl.NumberFormat.prototype, () => new Intl.NumberFormat("en"))).toEqual(
      refused,
    );
  });

  it("Intl.Locale.prototype, with a Locale result", async () => {
    expect(await attack(Intl.Locale.prototype, () => new Intl.Locale("en"))).toEqual(refused);
  });
});

describe("an object with a then put into the prototype chain of a built-in prototype", () => {
  it("Error.prototype, with an Error result", async () => {
    expect(await reparent(Error.prototype, () => new Error("bad"))).toEqual(
      parentRefused("bad signature"),
    );
  });

  it("TypeError.prototype, with a TypeError result", async () => {
    expect(await reparent(TypeError.prototype, () => new TypeError("bad"))).toEqual(
      parentRefused("bad signature"),
    );
  });

  it("Map.prototype, with a Map result", async () => {
    expect(await reparent(Map.prototype, () => new Map())).toEqual(parentRefused("bad signature"));
  });

  it("%TypedArray%.prototype, with a Uint8Array result", async () => {
    expect(await reparent(typedArrayPrototype, () => new Uint8Array(1))).toEqual(
      parentRefused("bad signature"),
    );
  });

  it("Array.prototype, with an array result", async () => {
    expect(await reparent(Array.prototype, () => [])).toEqual(parentRefused("bad signature"));
  });

  it("Function.prototype, with a function result", async () => {
    // A function result is not an object result, so the clean decision has no reason.
    expect(await reparent(Function.prototype, () => () => undefined)).toEqual(
      parentRefused("verifier did not confirm"),
    );
  });

  it("%IteratorPrototype%, with an array iterator result", async () => {
    expect(await reparent(iteratorPrototype, () => [].values())).toEqual(
      parentRefused("bad signature"),
    );
  });

  it("%WrapForValidIteratorPrototype%, with an Iterator.from result", async () => {
    expect(await reparent(wrapForValidIteratorPrototype, makeWrapped)).toEqual(
      parentRefused("bad signature"),
    );
  });

  it("Date.prototype, with a Date result", async () => {
    expect(await reparent(Date.prototype, () => new Date(0))).toEqual(
      parentRefused("bad signature"),
    );
  });

  it("Object.prototype cannot get another parent", () => {
    expect(Reflect.setPrototypeOf(Object.prototype, Object.create(null) as object)).toBe(false);
  });
});

/**
 * An async verifier that plants a hook with `plant` during its own I/O, after the check before
 * the call, and then rejects the proof with a result made by `make`.
 */
function plantingDuringIo(plant: () => void, make: () => object): ApprovalProofVerifier {
  return {
    type: "sig",
    verify: async () => {
      setTimeout(plant, 1);
      await new Promise((resolve) => setTimeout(resolve, 10));
      return Object.assign(make(), { valid: false, reason: "bad signature" }) as never;
    },
  };
}

/** The decision when `plant` runs during the verifier's I/O. */
async function plantedDuringIo(plant: () => void, make: () => object) {
  fired = 0;
  const verifier = plantingDuringIo(plant, make);
  return {
    hooked: summary(await evaluateApprovals(policy, input, { verifiers: [verifier] })),
    fired,
  };
}

/** Defines a lasting forging `then` own on `prototype`. */
const lastingThen = (prototype: object) => () => {
  // oxlint-disable-next-line unicorn/no-thenable
  define(prototype, "then", { value: forgingThen, writable: true, configurable: true });
  polluted.push(prototype);
};

/** Puts an object with a forging `then` between Map.prototype and its parent. */
const reparentMap = () => {
  const parent = Reflect.getPrototypeOf(Map.prototype);
  const evil: object = Object.create(parent) as object;
  // oxlint-disable-next-line unicorn/no-thenable
  define(evil, "then", { value: forgingThen, writable: true, configurable: true });
  Reflect.setPrototypeOf(Map.prototype, evil);
  reparented.push([Map.prototype, parent]);
};

describe("a hook planted during the verifier's I/O, after the check before the call", () => {
  // The forging then runs when the verifier's promise resolves, but the check after the result
  // settles refuses the proof.
  const afterRefused = { hooked: { outcome: "pending counted=0", detail: hooksChanged }, fired: 1 };

  it("a lasting then on Map.prototype, with a Map result", async () => {
    expect(await plantedDuringIo(lastingThen(Map.prototype), () => new Map())).toEqual(
      afterRefused,
    );
  });

  it("a lasting then on Error.prototype, with an Error result", async () => {
    expect(await plantedDuringIo(lastingThen(Error.prototype), () => new Error("bad"))).toEqual(
      afterRefused,
    );
  });

  it("an object with a then put between Map.prototype and its parent", async () => {
    expect(await plantedDuringIo(reparentMap, () => new Map())).toEqual(afterRefused);
  });
});

describe("limit: a then on the prototype of a class of caller code", () => {
  it("is not seen, so the result counts; return a result without a prototype instead", async () => {
    class Result {
      readonly source = "lookup";
    }
    // A known limit, recorded here so that a change in it shows up. See README, "Approval proofs".
    expect(await attack(Result.prototype, () => new Result())).toEqual({
      clean: { outcome: "pending counted=0", detail: "bad signature" },
      hooked: { outcome: "allow counted=1", detail: undefined },
      fired: 1,
    });
  });
});
