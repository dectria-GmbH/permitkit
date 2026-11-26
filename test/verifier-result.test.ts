// The verifier is caller code, and so is its result. How permitkit reads that result is not:
// `await` on it reads `then` through the prototype chain, and on a native promise it reads
// `constructor`. Up to f04df14, a polluted Object.prototype.then (with a synchronous verifier)
// or a replaced Promise.prototype.constructor and then (with an asynchronous one), set after
// load, could turn a failed verification into a counted approval, and the same replacement could
// change the decision that a caller's `await` on evaluateApprovals reads.
import { describe, expect, it } from "vitest";

import {
  compilePolicy,
  defineCatalog,
  evaluateApprovals,
  requestDigest,
  type ApprovalDecision,
  type ApprovalProofVerifier,
} from "../src/index.js";

const apply = Reflect.apply;
const define = Reflect.defineProperty;
const deleteKey = Reflect.deleteProperty;
const thenDescriptor = Object.getOwnPropertyDescriptor(Promise.prototype, "then");
const originalThen: unknown = thenDescriptor?.value;
const constructorDescriptor = Object.getOwnPropertyDescriptor(Promise.prototype, "constructor");

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
// Plain objects on purpose: these tests check that permitkit counts no proof when a hook can
// reach a result with a prototype. A real verifier returns its result without a prototype
// (README, "Approval proofs"), as in "counts no proof when the verifier result has no prototype".
const forged = { valid: true, approverId: "bob", requestDigest: digest };
const failing = { valid: false as const, reason: "bad signature" };

const syncVerifier: ApprovalProofVerifier = { type: "sig", verify: () => ({ ...failing }) };
const asyncVerifier: ApprovalProofVerifier = {
  type: "sig",
  verify: () => Promise.resolve({ ...failing }),
};

let fired = 0;

/** A then that resolves a failed verification with the forged one. */
function forgingThen(this: unknown, resolve: (value: unknown) => void): void {
  const failed = typeof this === "object" && this !== null && Reflect.get(this, "valid") === false;
  if (failed) fired += 1;
  // A copy without a prototype, so resolving with it does not call this then again.
  resolve(Object.assign(Object.create(null) as object, failed ? forged : this));
}

/** Promise.prototype.then that hands a failed verification on as the forged one. */
function forgingPromiseThen(
  this: Promise<unknown>,
  ok?: (value: unknown) => unknown,
  err?: unknown,
) {
  const swap = (value: unknown) => {
    const failed =
      typeof value === "object" && value !== null && Reflect.get(value, "valid") === false;
    if (failed) fired += 1;
    const result = failed ? forged : value;
    return ok === undefined ? result : ok(result);
  };
  const result: unknown = apply(originalThen as (...args: unknown[]) => unknown, this, [swap, err]);
  return result;
}

function FakePromise(): void {}

/** The detail of a proof that is not counted because a promise hook changed. */
const hooksChanged =
  "a then on a built-in prototype, or a replaced Promise.prototype.then, " +
  "Promise.prototype.constructor or Promise[Symbol.species]";
const speciesDescriptor = Object.getOwnPropertyDescriptor(Promise, Symbol.species);

const confirming: ApprovalProofVerifier = {
  type: "sig",
  verify: async (_proof, expected) => {
    await Promise.resolve();
    return { valid: true, approverId: "bob", requestDigest: expected.requestDigest };
  },
};

/** Promise.prototype.then that changes nothing, but is not the original. */
function passingThen(this: Promise<unknown>, ok?: unknown, err?: unknown): unknown {
  const result: unknown = apply(originalThen as (...args: unknown[]) => unknown, this, [ok, err]);
  return result;
}

/** The short form and the first rejection detail of a decision, under the given key. */
function outcomeOf(key: string, decision: ApprovalDecision | undefined): Record<string, unknown> {
  return {
    [key]: decision === undefined ? "none" : short(decision),
    detail: decision?.rejected[0]?.detail,
  };
}

/** A consumer wrapper that returns the promise without await. */
async function wrapper(): Promise<ApprovalDecision> {
  return evaluateApprovals(policy, input, { verifiers: [syncVerifier] });
}

/** Promise.prototype.then that hands a pending decision on as an allowed one. */
function allowingThen(this: Promise<unknown>, ok?: (value: unknown) => unknown, err?: unknown) {
  const swap = (value: unknown) => {
    const pending =
      typeof value === "object" && value !== null && Reflect.get(value, "outcome") === "pending";
    if (pending) fired += 1;
    const result = pending ? { ...value, outcome: "allow", allowed: true } : value;
    return ok === undefined ? result : ok(result);
  };
  const settled: unknown = apply(originalThen as (...args: unknown[]) => unknown, this, [
    swap,
    err,
  ]);
  return settled;
}

const short = (decision: ApprovalDecision): string =>
  `${decision.outcome} counted=${decision.counted.length}`;

describe("the verifier result under replaced then and constructor", () => {
  it("a polluted Object.prototype.then does not forge a synchronous result", async () => {
    fired = 0;
    const clean = short(await evaluateApprovals(policy, input, { verifiers: [syncVerifier] }));
    // oxlint-disable-next-line unicorn/no-thenable
    define(Object.prototype, "then", { value: forgingThen, writable: true, configurable: true });
    let polluted: string;
    try {
      polluted = short(await evaluateApprovals(policy, input, { verifiers: [syncVerifier] }));
    } finally {
      deleteKey(Object.prototype, "then");
    }
    expect({ clean, polluted, fired }).toEqual({
      clean: "pending counted=0",
      polluted: "pending counted=0",
      fired: 0,
    });
  });

  it("a replaced Promise constructor and then do not forge an asynchronous result", async () => {
    fired = 0;
    const clean = short(await evaluateApprovals(policy, input, { verifiers: [asyncVerifier] }));
    define(Promise.prototype, "constructor", {
      value: FakePromise,
      writable: true,
      configurable: true,
    });
    define(Promise.prototype, "then", {
      value: forgingPromiseThen,
      writable: true,
      configurable: true,
    });
    let replaced: Promise<ApprovalDecision>;
    try {
      replaced = evaluateApprovals(policy, input, { verifiers: [asyncVerifier] });
      // Let the evaluation finish while the replacements are in place.
      await new Promise((resolve) => {
        setTimeout(resolve, 20);
      });
    } finally {
      if (thenDescriptor !== undefined) define(Promise.prototype, "then", thenDescriptor);
      if (constructorDescriptor !== undefined) {
        define(Promise.prototype, "constructor", constructorDescriptor);
      }
    }
    expect({ clean, replaced: short(await replaced), fired }).toEqual({
      clean: "pending counted=0",
      replaced: "pending counted=0",
      fired: 0,
    });
  });

  it("a replaced Promise constructor and then do not change the decision that await reads", async () => {
    fired = 0;
    const clean = short(await evaluateApprovals(policy, input, { verifiers: [syncVerifier] }));
    let replaced = "";
    define(Promise.prototype, "constructor", {
      value: FakePromise,
      writable: true,
      configurable: true,
    });
    define(Promise.prototype, "then", { value: allowingThen, writable: true, configurable: true });
    try {
      replaced = short(await evaluateApprovals(policy, input, { verifiers: [syncVerifier] }));
    } finally {
      if (thenDescriptor !== undefined) define(Promise.prototype, "then", thenDescriptor);
      if (constructorDescriptor !== undefined) {
        define(Promise.prototype, "constructor", constructorDescriptor);
      }
    }
    expect({ clean, replaced, fired }).toEqual({
      clean: "pending counted=0",
      replaced: "pending counted=0",
      fired: 0,
    });
  });

  it("an asynchronous verifier that confirms still counts", async () => {
    const confirmingPromise: ApprovalProofVerifier = {
      type: "sig",
      verify: (_proof, expected) =>
        Promise.resolve({ valid: true, approverId: "bob", requestDigest: expected.requestDigest }),
    };
    expect(short(await evaluateApprovals(policy, input, { verifiers: [confirmingPromise] }))).toBe(
      "allow counted=1",
    );
  });

  it("a thenable result that is not a native promise is not awaited, and does not count", async () => {
    const thenable: ApprovalProofVerifier = {
      type: "sig",
      // oxlint-disable-next-line unicorn/no-thenable
      verify: () => ({ then: (resolve: (value: unknown) => void) => resolve(forged) }) as never,
    };
    const decision = await evaluateApprovals(policy, input, { verifiers: [thenable] });
    expect({
      outcome: decision.outcome,
      reason: decision.rejected[0]?.reason,
      detail: decision.rejected[0]?.detail,
    }).toEqual({
      outcome: "pending",
      reason: "proof_invalid",
      detail: "verifier returned a thenable that is not a native promise",
    });
  });

  it("a polluted Object.prototype.then does not forge the result of an async verifier", async () => {
    fired = 0;
    const asyncFunction: ApprovalProofVerifier = {
      type: "sig",
      // The documented shape: an async function that returns a plain verification object.
      verify: async () => {
        await Promise.resolve();
        return { ...failing };
      },
    };
    const clean = short(await evaluateApprovals(policy, input, { verifiers: [asyncFunction] }));
    // oxlint-disable-next-line unicorn/no-thenable
    define(Object.prototype, "then", { value: forgingThen, writable: true, configurable: true });
    let polluted: ApprovalDecision | undefined;
    try {
      polluted = await evaluateApprovals(policy, input, { verifiers: [asyncFunction] });
    } finally {
      deleteKey(Object.prototype, "then");
    }
    expect({ clean, ...outcomeOf("polluted", polluted) }).toEqual({
      clean: "pending counted=0",
      polluted: "pending counted=0",
      detail: hooksChanged,
    });
  });

  it.each([
    ["Object.prototype", Object.prototype],
    ["Array.prototype", Array.prototype],
    ["Function.prototype", Function.prototype],
  ] as const)("a then on %s counts no proof, also a confirmed one", async (_name, owner) => {
    const clean = short(await evaluateApprovals(policy, input, { verifiers: [confirming] }));
    // oxlint-disable-next-line unicorn/no-thenable
    define(owner, "then", { value: forgingThen, writable: true, configurable: true });
    let polluted: ApprovalDecision | undefined;
    try {
      polluted = await evaluateApprovals(policy, input, { verifiers: [confirming] });
    } finally {
      deleteKey(owner, "then");
    }
    expect({ clean, ...outcomeOf("polluted", polluted) }).toEqual({
      clean: "allow counted=1",
      polluted: "pending counted=0",
      detail: hooksChanged,
    });
  });

  it("a replaced Promise.prototype.then counts no proof, also a confirmed one", async () => {
    const clean = short(await evaluateApprovals(policy, input, { verifiers: [confirming] }));
    define(Promise.prototype, "then", { value: passingThen, writable: true, configurable: true });
    let replaced: ApprovalDecision | undefined;
    try {
      replaced = await evaluateApprovals(policy, input, { verifiers: [confirming] });
    } finally {
      if (thenDescriptor !== undefined) define(Promise.prototype, "then", thenDescriptor);
    }
    expect({ clean, ...outcomeOf("replaced", replaced) }).toEqual({
      clean: "allow counted=1",
      replaced: "pending counted=0",
      detail: hooksChanged,
    });
  });

  // A consumer that does not await the result directly: the promise has an own then, so these
  // read the captured one, not Promise.prototype.then.
  it.each([
    ["returned from an async function", () => wrapper()],
    [
      "read through .then",
      () => evaluateApprovals(policy, input, { verifiers: [syncVerifier] }).then((d) => d),
    ],
    [
      "read through Promise.all",
      // One promise on purpose: the case is what Promise.all does with permitkit's promise.
      // oxlint-disable-next-line unicorn/no-single-promise-in-promise-methods
      () => Promise.all([evaluateApprovals(policy, input, { verifiers: [syncVerifier] })]),
    ],
  ] as const)(
    "a replaced Promise.prototype.then does not change a decision %s",
    async (_name, run) => {
      fired = 0;
      let pending: Promise<unknown> | undefined;
      define(Promise.prototype, "then", {
        value: allowingThen,
        writable: true,
        configurable: true,
      });
      try {
        pending = run();
        // Let the evaluation finish while the replacement is in place.
        await new Promise((resolve) => {
          setTimeout(resolve, 20);
        });
      } finally {
        if (thenDescriptor !== undefined) define(Promise.prototype, "then", thenDescriptor);
      }
      const settled: unknown = await pending;
      const decision = (Array.isArray(settled) ? settled[0] : settled) as ApprovalDecision;
      expect({ decision: short(decision), fired }).toEqual({
        decision: "pending counted=0",
        fired: 0,
      });
    },
  );
});

/** Restores Promise.prototype.then, Promise.prototype.constructor and Promise[Symbol.species]. */
function restorePromise(): void {
  if (thenDescriptor !== undefined) define(Promise.prototype, "then", thenDescriptor);
  if (constructorDescriptor !== undefined) {
    define(Promise.prototype, "constructor", constructorDescriptor);
  }
  if (speciesDescriptor !== undefined) define(Promise, Symbol.species, speciesDescriptor);
}

/**
 * A getter on Promise.prototype.constructor. The captured then reads `constructor` of the
 * verifier's promise, so the getter runs with that promise as `this`. It gives the promise the
 * fields of a confirmed verification, removes itself and makes then throw.
 */
function armConstructorGetter(): void {
  let armed = true;
  define(Promise.prototype, "constructor", {
    configurable: true,
    get(this: object) {
      if (!armed) return Promise;
      armed = false;
      define(this, "valid", { value: true });
      define(this, "approverId", { value: "bob" });
      define(this, "requestDigest", { value: digest });
      if (constructorDescriptor !== undefined) {
        define(Promise.prototype, "constructor", constructorDescriptor);
      }
      // Not a constructor, so then throws a TypeError.
      return { [Symbol.species]: 1 };
    },
  });
}

/** A species whose instance is a thenable that hands on an allowed decision. */
function FakeSpecies(executor: (resolve: unknown, reject: unknown) => void): object {
  executor(
    () => {},
    () => {},
  );
  return {
    // oxlint-disable-next-line unicorn/no-thenable
    then(ok: (value: unknown) => void) {
      fired += 1;
      ok({ outcome: "allow", allowed: true, reason: "approved", counted: ["bob"], rejected: [] });
    },
  };
}

const failingAsync: ApprovalProofVerifier = { type: "sig", verify: async () => ({ ...failing }) };

describe("the verifier result under a replaced constructor or species", () => {
  it("a getter on Promise.prototype.constructor does not forge an async result", async () => {
    const clean = short(await evaluateApprovals(policy, input, { verifiers: [failingAsync] }));
    armConstructorGetter();
    let attacked: ApprovalDecision | undefined;
    try {
      attacked = await evaluateApprovals(policy, input, { verifiers: [failingAsync] });
    } finally {
      restorePromise();
    }
    expect({ clean, ...outcomeOf("attacked", attacked) }).toEqual({
      clean: "pending counted=0",
      attacked: "pending counted=0",
      detail: hooksChanged,
    });
  });

  it("a constructor getter set while the verifier runs is refused, not read", async () => {
    // The check before the call sees clean prototypes, and the getter removes itself before the
    // check after it. Only the refusal of a promise whose then throws stops it.
    const meddling: ApprovalProofVerifier = {
      type: "sig",
      verify: () => {
        const result = Promise.resolve({ ...failing });
        armConstructorGetter();
        return result;
      },
    };
    let attacked: ApprovalDecision | undefined;
    try {
      attacked = await evaluateApprovals(policy, input, { verifiers: [meddling] });
    } finally {
      restorePromise();
    }
    expect(outcomeOf("attacked", attacked)).toEqual({
      attacked: "pending counted=0",
      detail: hooksChanged,
    });
  });

  it.each([
    [
      "a Promise.prototype.constructor getter",
      () => {
        define(Promise.prototype, "constructor", { configurable: true, get: () => Promise });
      },
    ],
    [
      "another Promise.prototype.constructor value",
      () => {
        define(Promise.prototype, "constructor", {
          configurable: true,
          writable: true,
          value: FakePromise,
        });
      },
    ],
    [
      "a Promise[Symbol.species] getter",
      () => {
        define(Promise, Symbol.species, { configurable: true, get: () => Promise });
      },
    ],
  ] as const)("%s counts no proof, also a confirmed one", async (_name, replace) => {
    const clean = short(await evaluateApprovals(policy, input, { verifiers: [confirming] }));
    replace();
    let replaced: ApprovalDecision | undefined;
    try {
      replaced = await evaluateApprovals(policy, input, { verifiers: [confirming] });
    } finally {
      restorePromise();
    }
    expect({ clean, ...outcomeOf("replaced", replaced) }).toEqual({
      clean: "allow counted=1",
      replaced: "pending counted=0",
      detail: hooksChanged,
    });
  });

  it("a thenable that is not a native promise does not count, even with confirmed fields", async () => {
    const thenable: ApprovalProofVerifier = {
      type: "sig",
      verify: () =>
        // oxlint-disable-next-line unicorn/no-thenable
        ({ then: () => {}, valid: true, approverId: "bob", requestDigest: digest }) as never,
    };
    const decision = await evaluateApprovals(policy, input, { verifiers: [thenable] });
    expect(outcomeOf("decision", decision)).toEqual({
      decision: "pending counted=0",
      detail: "verifier returned a thenable that is not a native promise",
    });
  });
});

/** Ways a caller reads the decision through a promise that `.then` returned. */
const derivedReads = [
  ["await p.then(d => d)", (p: Promise<ApprovalDecision>) => p.then((d) => d)],
  [
    "await p.then(d => d).then(d => d)",
    (p: Promise<ApprovalDecision>) => p.then((d) => d).then((d) => d),
  ],
  [
    "await p.then(undefined, e => e)",
    (p: Promise<ApprovalDecision>) => p.then(undefined, (error: unknown) => error),
  ],
] as const;

/** Ways a caller passes permitkit's promises to Promise.all and Promise.race. */
const combinedReads = [
  [
    "Promise.all([p])",
    // oxlint-disable-next-line unicorn/no-single-promise-in-promise-methods
    async (p: Promise<ApprovalDecision>) => (await Promise.all([p]))[0],
  ],
  [
    "Promise.all([p.then(d => d)])",
    // oxlint-disable-next-line unicorn/no-single-promise-in-promise-methods
    async (p: Promise<ApprovalDecision>) => (await Promise.all([p.then((d) => d)]))[0],
  ],
  [
    "Promise.race([p.then(d => d)])",
    // oxlint-disable-next-line unicorn/no-single-promise-in-promise-methods
    (p: Promise<ApprovalDecision>) => Promise.race([p.then((d) => d)]),
  ],
] as const;

describe("promises that .then on the result returns", () => {
  it.each([...derivedReads, ...combinedReads])(
    "a replaced Promise[Symbol.species] does not change the decision: %s",
    async (_name, read) => {
      fired = 0;
      const clean = short(
        (await read(
          evaluateApprovals(policy, input, { verifiers: [syncVerifier] }),
        )) as ApprovalDecision,
      );
      define(Promise, Symbol.species, { configurable: true, get: () => FakeSpecies });
      let replaced: string;
      try {
        // Armed for the whole read, also while the caller awaits.
        replaced = short(
          (await read(
            evaluateApprovals(policy, input, { verifiers: [syncVerifier] }),
          )) as ApprovalDecision,
        );
      } finally {
        restorePromise();
      }
      expect({ clean, replaced, fired }).toEqual({
        clean: "pending counted=0",
        replaced: "pending counted=0",
        fired: 0,
      });
    },
  );

  it.each(derivedReads)(
    "a replaced Promise.prototype.constructor and then do not change the decision: %s",
    async (_name, read) => {
      fired = 0;
      define(Promise.prototype, "constructor", {
        value: FakePromise,
        writable: true,
        configurable: true,
      });
      define(Promise.prototype, "then", {
        value: allowingThen,
        writable: true,
        configurable: true,
      });
      let replaced: string;
      try {
        replaced = short(
          (await read(
            evaluateApprovals(policy, input, { verifiers: [syncVerifier] }),
          )) as ApprovalDecision,
        );
      } finally {
        restorePromise();
      }
      expect({ replaced, fired }).toEqual({ replaced: "pending counted=0", fired: 0 });
    },
  );

  it.each(combinedReads)(
    "a replaced Promise.prototype.then does not change the decision: %s",
    async (_name, read) => {
      fired = 0;
      let pending: Promise<unknown> | undefined;
      define(Promise.prototype, "then", {
        value: allowingThen,
        writable: true,
        configurable: true,
      });
      try {
        pending = read(evaluateApprovals(policy, input, { verifiers: [syncVerifier] }));
        // Let the evaluation finish while the replacement is in place.
        await new Promise((resolve) => {
          setTimeout(resolve, 20);
        });
      } finally {
        restorePromise();
      }
      // The promise that Promise.all or Promise.race returns is not permitkit's; read it clean.
      expect({ decision: short((await pending) as ApprovalDecision), fired }).toEqual({
        decision: "pending counted=0",
        fired: 0,
      });
    },
  );

  it("a promise that .then returns carries the own constructor and then", () => {
    const first = evaluateApprovals(policy, input, { verifiers: [syncVerifier] });
    const derived = first.then((d) => d);
    const second = derived.then((d) => d);
    const marks = (promise: Promise<unknown>) => ({
      constructor: Object.getOwnPropertyDescriptor(promise, "constructor")?.value === Promise,
      ownThen: Object.hasOwn(promise, "then") && promise.then === first.then,
    });
    expect([marks(first), marks(derived), marks(second)]).toEqual([
      { constructor: true, ownThen: true },
      { constructor: true, ownThen: true },
      { constructor: true, ownThen: true },
    ]);
  });
});

/** A call with an unknown option, which rejects with options_invalid. */
const failingOptions = () => evaluateApprovals(policy, input, { unknown: true } as never);
const codeOf = (error: unknown): unknown =>
  typeof error === "object" && error !== null ? Reflect.get(error, "code") : error;

describe("the own then keeps the semantics of the native then", () => {
  it("hands on a rejection, also without a handler and through .catch", async () => {
    const results = await Promise.all([
      failingOptions().then(undefined, codeOf),
      failingOptions()
        .then((d) => d)
        .then(undefined, codeOf),
      failingOptions().catch(codeOf),
    ]);
    expect(results).toEqual(["options_invalid", "options_invalid", "options_invalid"]);
  });

  it("rejects the derived promise with what a callback throws", async () => {
    const thrown = new Error("from the callback");
    const decision = evaluateApprovals(policy, input, { verifiers: [syncVerifier] });
    // A plain await, not expect().rejects: that reads the result through the own then again.
    let caught: unknown = "nothing";
    try {
      await decision.then(() => {
        throw thrown;
      });
    } catch (error) {
      caught = error;
    }
    expect(caught).toBe(thrown);
  });

  it("passes the value on if the callback is not a function", async () => {
    const decision = evaluateApprovals(policy, input, { verifiers: [syncVerifier] });
    expect(short(await decision.then(null))).toBe("pending counted=0");
  });

  it("calls the callback in the same job as the native then", async () => {
    const order: string[] = [];
    const ours = evaluateApprovals(policy, input, { verifiers: [syncVerifier] });
    await ours;
    const native = Promise.resolve();
    const done = Promise.all([
      ours.then(() => order.push("ours")),
      native.then(() => order.push("native")),
    ]);
    await done;
    expect(order).toEqual(["ours", "native"]);
  });

  it("is the native then on a promise that permitkit did not mark", async () => {
    const ownThen = Reflect.get(
      evaluateApprovals(policy, input, { verifiers: [syncVerifier] }),
      "then",
    ) as (...args: unknown[]) => unknown;
    const value: unknown = await Reflect.apply(ownThen, Promise.resolve(7), [(n: number) => n + 1]);
    expect(value).toBe(8);
    // As the native then: a receiver that is not a promise throws at once.
    expect(() => Reflect.apply(ownThen, {}, [])).toThrow(TypeError);
  });
});

describe("the expected object that the verifier gets", () => {
  it("is frozen and has no prototype", async () => {
    let seen: unknown;
    const recording: ApprovalProofVerifier = {
      type: "sig",
      verify: (_proof, expected) => {
        seen = expected;
        return { ...failing };
      },
    };
    await evaluateApprovals(policy, input, { verifiers: [recording] });
    expect({
      prototype: Object.getPrototypeOf(seen),
      frozen: Object.isFrozen(seen),
      fields: { ...(seen as object) },
    }).toEqual({
      prototype: null,
      frozen: true,
      fields: { approverId: "bob", requestDigest: digest },
    });
  });

  it("runs no inherited getter when the verifier serialises it", async () => {
    // A toJSON getter on Object.prototype would run inside JSON.stringify(expected) and could set
    // a then there that forges the async result after the check before the call.
    const serialising: ApprovalProofVerifier = {
      type: "sig",
      verify: async (_proof, expected) => {
        JSON.stringify(expected);
        return { ...failing };
      },
    };
    let reads = 0;
    define(Object.prototype, "toJSON", {
      configurable: true,
      get() {
        reads += 1;
        deleteKey(Object.prototype, "toJSON");
        // oxlint-disable-next-line unicorn/no-thenable
        define(Object.prototype, "then", {
          configurable: true,
          writable: true,
          value(this: unknown, resolve: (value: unknown) => void) {
            deleteKey(Object.prototype, "then");
            resolve(Object.assign(Object.create(null) as object, forged));
          },
        });
        return undefined;
      },
    });
    let attacked: ApprovalDecision | undefined;
    try {
      attacked = await evaluateApprovals(policy, input, { verifiers: [serialising] });
    } finally {
      deleteKey(Object.prototype, "then");
      deleteKey(Object.prototype, "toJSON");
    }
    expect({ reads, ...outcomeOf("attacked", attacked) }).toEqual({
      reads: 0,
      attacked: "pending counted=0",
      detail: "bad signature",
    });
  });
});

/** Stand-in for a crypto call that says the signature is bad. */
const checkSignature = async (): Promise<boolean> => false;

describe("a replaced global Symbol does not hide a replaced Promise[Symbol.species]", () => {
  const speciesKey = Symbol.species;
  const RealSymbol = Symbol;
  const original = Object.getOwnPropertyDescriptor(Promise, speciesKey);

  /** Moves the real species accessor to another key and points a stand-in Symbol at it. */
  function swapSymbol(): void {
    if (original === undefined) throw new Error("Promise[Symbol.species] has no descriptor.");
    define(Promise, "__species", original);
    Object.defineProperty(globalThis, "Symbol", {
      configurable: true,
      writable: true,
      value: { species: "__species" },
    });
  }

  function restoreSymbol(): void {
    Object.defineProperty(globalThis, "Symbol", {
      configurable: true,
      writable: true,
      value: RealSymbol,
    });
    deleteKey(Promise, "__species");
    deleteKey(Object.prototype, "then");
    restorePromise();
  }

  /** A species getter that sets Object.prototype.then for one read, then lets it go. */
  function armSpeciesHook(): void {
    let armed = true;
    define(Promise, speciesKey, {
      configurable: true,
      get(this: unknown) {
        if (armed) {
          armed = false;
          define(Object.prototype, "then", {
            configurable: true,
            writable: true,
            value(resolve: (value: unknown) => void) {
              deleteKey(Object.prototype, "then");
              resolve(Object.assign(Object.create(null) as object, forged));
            },
          });
        }
        return this;
      },
    });
  }

  /** The decision that a caller reads under the species getter and the swapped Symbol. */
  async function attack(verifier: ApprovalProofVerifier): Promise<ApprovalDecision> {
    armSpeciesHook();
    swapSymbol();
    try {
      return await evaluateApprovals(policy, input, { verifiers: [verifier] });
    } finally {
      restoreSymbol();
    }
  }

  it("counts no proof when the verifier result has a prototype", async () => {
    await Promise.resolve();
    const verifier: ApprovalProofVerifier = {
      type: "sig",
      verify: async () => {
        await Promise.resolve();
        return { ...failing };
      },
    };
    const decision = await attack(verifier);
    expect(decision.counted).toHaveLength(0);
    expect(decision.outcome).toBe("pending");
  });

  it("counts no proof when the verifier result has no prototype", async () => {
    // Let the runner attach its callbacks to this test's promise before a hook is set.
    await Promise.resolve();
    // The getter cannot reach the result. It hijacks the next await inside the verifier instead,
    // so the check on the signature reads true. The verifier is yours; the entry is the species
    // check that the swapped Symbol bypassed.
    const verifier: ApprovalProofVerifier = {
      type: "sig",
      verify: async (_proof, expected) => {
        await Promise.resolve();
        const ok = await checkSignature();
        return Object.assign(
          Object.create(null) as object,
          ok ? { valid: true, approverId: "bob", requestDigest: expected.requestDigest } : failing,
        ) as typeof failing;
      },
    };
    let armed = true;
    let hits = 0;
    define(Promise, speciesKey, {
      configurable: true,
      get(this: unknown) {
        if (armed) {
          armed = false;
          define(Promise.prototype, "constructor", { configurable: true, get: () => Object });
          define(Promise.prototype, "then", {
            configurable: true,
            writable: true,
            value(resolve: (value: unknown) => void) {
              hits += 1;
              restorePromise();
              resolve(true);
            },
          });
        }
        return this;
      },
    });
    swapSymbol();
    let decision: ApprovalDecision | undefined;
    try {
      decision = await evaluateApprovals(policy, input, { verifiers: [verifier] });
    } finally {
      restoreSymbol();
    }
    expect({ hits, counted: decision.counted.length, outcome: decision.outcome }).toEqual({
      hits: 0,
      counted: 0,
      outcome: "pending",
    });
  });
});
