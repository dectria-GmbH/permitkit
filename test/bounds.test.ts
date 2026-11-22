import { describe, expect, it } from "vitest";

import { boundedSnapshot, requestBounds } from "../src/bounds.js";
import { compilePolicy, decide, evaluateApprovals, explain, PermitkitError } from "../src/index.js";
import { accessRequest, human, role } from "../src/testing/index.js";
import { catalog, editablePolicyInput, policy } from "./fixtures.js";

const lead = human("u-lead", role("lead"));

describe("input size bounds", () => {
  it("denies a request with an oversized array before schema validation", () => {
    const request = accessRequest(lead, "ticket:read");
    const roles = Array.from({ length: 1_000_000 }, () => ({ role: 1 }));
    const started = performance.now();
    const result = explain(policy, { ...request, subject: { ...request.subject, roles } });
    expect(result.decision.reason).toBe("invalid_request");
    expect(result.steps[0]).toMatchObject({ step: "validate", ok: false });
    expect(performance.now() - started).toBeLessThan(1_000);
  });

  it("denies deeply nested and oversized string input", () => {
    let nested: unknown = "x";
    for (let index = 0; index < 100; index += 1) nested = { act: nested };
    expect(decide(policy, nested).reason).toBe("invalid_request");
    const request = accessRequest(lead, "ticket:read", { properties: { note: "x".repeat(5_000) } });
    expect(decide(policy, request).reason).toBe("invalid_request");
  });

  it("rejects oversized approval input and policies", async () => {
    const request = accessRequest(lead, "ticket:refund", { properties: { amount: 500 } });
    const approvals = Array.from({ length: 5_000 }, () => ({}));
    const result = await evaluateApprovals(policy, {
      request,
      now: "2026-01-15T10:30:00.000Z",
      approvals,
    });
    expect(result.reason).toBe("invalid_input");
    const input = editablePolicyInput();
    input.roles["support"]!.grants[0]!.permissions = Array.from(
      { length: 20_000 },
      () => "ticket:read",
    );
    expect(() => compilePolicy(catalog, input)).toThrow(PermitkitError);
  });

  it("keeps a __proto__ key as data and copies into a null-prototype object", () => {
    const raw: unknown = JSON.parse('{"__proto__": {"polluted": true}, "queue": "a"}');
    const copy = boundedSnapshot(raw, requestBounds) as Record<string, unknown>;
    expect(Object.getPrototypeOf(copy)).toBeNull();
    expect(Object.hasOwn(copy, "__proto__")).toBe(true);
    expect(({} as Record<string, unknown>)["polluted"]).toBeUndefined();
  });

  it("does not let a __proto__ property match a scope", () => {
    const scoped = human("u-s", role("support", { queue: ["billing"] }));
    const properties = JSON.parse('{"__proto__": {"queue": "billing"}}') as Record<string, string>;
    const request = accessRequest(scoped, "ticket:read", { properties });
    expect(decide(policy, request).outcome).toBe("deny");
  });
});
