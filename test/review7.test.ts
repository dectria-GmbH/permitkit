// Regression tests for findings of the seventh cold security review.
import { afterEach, describe, expect, it } from "vitest";

import { compilePolicy, decide } from "../src/index.js";
import { accessRequest, human, role, viaAgent } from "../src/testing/index.js";
import { catalog, editablePolicyInput, policy } from "./fixtures.js";

const polluted: string[] = [];

function pollute(key: string, value: unknown): void {
  polluted.push(key);
  // The test simulates a prototype-pollution bug elsewhere in the process.
  // oxlint-disable-next-line no-extend-native
  Object.defineProperty(Object.prototype, key, { value, configurable: true, writable: true });
}

afterEach(() => {
  for (const key of polluted.splice(0)) delete (Object.prototype as Record<string, unknown>)[key];
});

describe("limits under a polluted prototype", () => {
  it("rejects an empty limit in a policy even when max is inherited", () => {
    const input = editablePolicyInput();
    input.roles["support"]!.grants[1]!.limits = { amount: {} };
    pollute("max", 0);
    expect(() => compilePolicy(catalog, input)).toThrow(/not valid/);
  });

  it("rejects an empty limit in an agent grant even when min or max is inherited", () => {
    const subject = viaAgent(human("u-lead", role("lead")), "bot", {
      entries: [{ permissions: ["ticket:refund"], limits: { amount: {} } }],
    });
    const request = accessRequest(subject, "ticket:refund", { properties: { amount: 50 } });
    for (const key of ["max", "min"]) {
      pollute(key, 0);
      expect(decide(policy, request).reason).toBe("invalid_request");
    }
  });
});

describe("proxies", () => {
  it("denies a scope proxy that reports no keys or a plain prototype", () => {
    const base = accessRequest(human("u", role("lead", { queue: ["billing"] })), "ticket:read", {
      properties: { queue: "other" },
    });
    const scopes = [
      new Proxy({ queue: ["billing"] }, { ownKeys: () => [] }),
      new Proxy(new Map([["queue", ["billing"]]]), { getPrototypeOf: () => Object.prototype }),
    ];
    for (const scope of scopes) {
      const request = { ...base, subject: { ...base.subject, roles: [{ role: "lead", scope }] } };
      expect(decide(policy, request).outcome).toBe("deny");
    }
  });
});
