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
const hooksChanged = "a then on a built-in prototype, or a replaced Promise.prototype.then";

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
});
