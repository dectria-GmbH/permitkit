// Regression tests for findings of the fourteenth cold security review.
import { describe, expect, it } from "vitest";

import { evaluateApprovals, type ApprovalDecision } from "../src/index.js";
import { accessRequest, everywhere, human, role } from "../src/testing/index.js";
import { policy } from "./fixtures.js";

describe("the promise that evaluateApprovals returns", () => {
  it("keeps a pending result when the caller awaits it under a replaced then", async () => {
    const request = accessRequest(human("u-b", role("lead", everywhere)), "ticket:refund", {
      id: "t-1",
      properties: { amount: 900 },
    });
    const input = { request, now: "2026-01-15T10:30:00.000Z", approvals: [] };
    const clean = await evaluateApprovals(policy, input);
    const prototype = Promise.prototype;
    const originalThen = prototype.then;
    const originalConstructor = Object.getOwnPropertyDescriptor(prototype, "constructor")!;
    let ownConstructor = false;
    let forged: ApprovalDecision | undefined;
    // Caller code replaces both after load. `await` on a promise without an own constructor
    // reads them, and the replaced then rewrites every decision it passes on.
    // oxlint-disable-next-line no-extend-native
    Object.defineProperty(prototype, "constructor", {
      value: function Replaced() {},
      configurable: true,
      writable: true,
    });
    prototype.then = function (
      this: Promise<unknown>,
      onFulfilled?: ((value: unknown) => unknown) | null,
      onRejected?: ((reason: unknown) => unknown) | null,
    ) {
      const widen = (value: unknown): unknown => {
        const widened =
          typeof value === "object" && value !== null && "outcome" in value
            ? { ...value, outcome: "allow", allowed: true, reason: "approved" }
            : value;
        return onFulfilled ? onFulfilled(widened) : widened;
      };
      return Reflect.apply(originalThen, this, [widen, onRejected]);
    } as typeof originalThen;
    try {
      const pending = evaluateApprovals(policy, input);
      ownConstructor = Object.hasOwn(pending, "constructor");
      forged = await pending;
    } finally {
      prototype.then = originalThen;
      Object.defineProperty(prototype, "constructor", originalConstructor);
    }
    expect(clean.outcome).toBe("pending");
    expect(forged?.outcome).toBe("pending");
    expect(forged?.allowed).toBe(false);
    expect(ownConstructor).toBe(true);
  });
});
