// Regression tests for findings of the eleventh cold security review. These pollutions also
// break the test framework, so each test captures outcomes first and asserts after clean-up.
import { describe, expect, it } from "vitest";

import {
  canonicalJson,
  decide,
  decideAndRecord,
  evaluate,
  evaluateApprovals,
  explain,
  reevaluate,
} from "../src/index.js";
import { detach } from "../src/bounds.js";
import { accessRequest, everywhere, human, role, viaAgent } from "../src/testing/index.js";
import { policy } from "./fixtures.js";

function withPollution<T>(target: object, key: string, value: unknown, run: () => T): T {
  // The test simulates a prototype-pollution bug elsewhere in the process.
  // oxlint-disable-next-line no-extend-native
  Object.defineProperty(target, key, { value, configurable: true, writable: true });
  try {
    return run();
  } finally {
    delete (target as Record<string, unknown>)[key];
  }
}

const lead = human("u-lead", role("lead", everywhere));

describe("Object.prototype.return", () => {
  it("does not make reevaluate or canonicalJson throw", () => {
    const request = accessRequest(lead, "ticket:read");
    const { record } = decideAndRecord(policy, request);
    const clean = canonicalJson({ b: 1, a: [1, 2] });
    const outcome = withPollution(Object.prototype, "return", 1, () => {
      const result: { status?: string; canonical?: string; error?: string } = {};
      try {
        result.status = reevaluate(policy, record).status;
        result.canonical = canonicalJson({ b: 1, a: [1, 2] });
      } catch (error) {
        result.error = String(error);
      }
      return result;
    });
    expect(outcome.error).toBeUndefined();
    expect(["reproduced", "not_replayable"]).toContain(outcome.status);
    expect(outcome.canonical).toBe(clean);
  });
});

describe("detach under Object.prototype.return", () => {
  it("copies without destructuring pairs", () => {
    const outcome = withPollution(Object.prototype, "return", 1, () => {
      try {
        return JSON.stringify(detach({ b: 1, a: { c: [1] } }));
      } catch (error) {
        return `threw ${String(error)}`;
      }
    });
    expect(outcome).toBe('{"b":1,"a":{"c":[1]}}');
  });
});

describe("Array.prototype.constructor", () => {
  // decide, explain, evaluate, decideAndRecord and evaluateApprovals create no arrays through
  // species, so they give the clean decisions. Up to f04df14, evaluateApprovals denied here:
  // Zod, which validated its input, used Array.prototype methods that read the constructor.
  it("changes no decision, also not in evaluateApprovals", async () => {
    const request = accessRequest(lead, "ticket:read");
    const refund = accessRequest(lead, "ticket:refund", { properties: { amount: 500 } });
    const authzen = {
      subject: {
        type: "human",
        id: "u-lead",
        properties: { roles: [{ role: "lead", scope: { kind: "all" } }] },
      },
      action: { name: "read" },
      resource: { type: "ticket", id: "t" },
      context: { now: "2026-01-15T10:00:00.000Z" },
    };
    // oxlint-disable-next-line no-extend-native
    Object.defineProperty(Array.prototype, "constructor", {
      value: 1,
      configurable: true,
      writable: true,
    });
    const outcomes: unknown[] = [];
    try {
      for (const run of [
        () => decide(policy, request).outcome,
        () => explain(policy, request).decision.outcome,
        () => evaluate(policy, authzen).decision,
        () => decideAndRecord(policy, request).decision.outcome,
      ]) {
        try {
          outcomes.push(run());
        } catch (error) {
          outcomes.push(`threw ${String(error)}`);
        }
      }
      try {
        const result = await evaluateApprovals(policy, {
          request: refund,
          now: "2026-01-15T10:30:00.000Z",
          approvals: [],
        });
        outcomes.push(result.outcome);
      } catch (error) {
        outcomes.push(`threw ${String(error)}`);
      }
    } finally {
      // oxlint-disable-next-line no-extend-native
      Object.defineProperty(Array.prototype, "constructor", {
        value: Array,
        configurable: true,
        writable: true,
      });
    }
    // The clean evaluateApprovals result: no approvals yet, so pending.
    expect(outcomes).toEqual(["allow", "allow", false, "allow", "pending"]);
    const clean = await evaluateApprovals(policy, {
      request: refund,
      now: "2026-01-15T10:30:00.000Z",
      approvals: [],
    });
    expect(clean.outcome).toBe("pending");
  });
});

describe("prior actor grants", () => {
  it("denies a prior actor whose grant names another agent", () => {
    const current = viaAgent(lead, "bot1", {
      entries: [
        { permissions: ["ticket:read"], scope: { kind: "all" }, limits: { kind: "unlimited" } },
      ],
    });
    const prior = viaAgent(lead, "bot0", {
      entries: [
        { permissions: ["ticket:read"], scope: { kind: "all" }, limits: { kind: "unlimited" } },
      ],
    });
    const subject = {
      ...current,
      act: { ...current.act!, act: { ...prior.act!, id: "someone-else" } },
    };
    expect(decide(policy, accessRequest(subject, "ticket:read")).reason).toBe(
      "agent_grant_principal_mismatch",
    );
  });
});
