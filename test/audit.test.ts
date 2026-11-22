import { describe, expect, it } from "vitest";

import {
  canonicalJson,
  compilePolicy,
  decide,
  digest,
  evaluate,
  PermitkitError,
  explain,
  reasonCodes,
  reasonHints,
  reevaluate,
  toDecisionRecord,
} from "../src/index.js";
import { accessRequest, everywhere, human, role, viaAgent, within } from "../src/testing/index.js";
import { catalog, editablePolicyInput, policy } from "./fixtures.js";

const lead = human("u-lead", role("lead", everywhere));

describe("audit records", () => {
  it("records the decision with the actor chain and reproduces it", () => {
    const subject = viaAgent(lead, "agent-1", {
      entries: [
        { permissions: ["ticket:read"], scope: { kind: "all" }, limits: { kind: "unlimited" } },
      ],
    });
    const request = accessRequest(subject, "ticket:read", { id: "t-1" });
    const record = toDecisionRecord(request, decide(policy, request));
    expect(record.actorChain).toEqual([
      { type: "human", id: "u-lead", grantId: null },
      { type: "agent", id: "agent-1", grantId: "grant-agent-1" },
    ]);
    const stored = JSON.parse(JSON.stringify(record)) as typeof record;
    expect(reevaluate(policy, stored).status).toBe("reproduced");
  });

  it("refuses to re-evaluate under another policy version or digest", () => {
    const request = accessRequest(lead, "ticket:read");
    const record = toDecisionRecord(request, decide(policy, request));
    const input = editablePolicyInput();
    input.version = "2026-01-02.1";
    expect(reevaluate(compilePolicy(catalog, input), record).status).toBe("policy_mismatch");
    const sameLabel = editablePolicyInput();
    sameLabel.roles["lead"]!.grants[0]!.permissions = ["ticket:read"];
    expect(reevaluate(compilePolicy(catalog, sameLabel), record).status).toBe("policy_mismatch");
  });

  it("reports a tampered record as diverged", () => {
    const request = accessRequest(human("u-none"), "ticket:read");
    const record = toDecisionRecord(request, decide(policy, request));
    expect(reevaluate(policy, { ...record, outcome: "allow", reason: "granted" }).status).toBe(
      "diverged",
    );
  });

  it("marks records of invalid requests as not replayable", () => {
    const record = toDecisionRecord({ bad: true }, decide(policy, { bad: true }));
    expect(record.request).toBeNull();
    expect(reevaluate(policy, record).status).toBe("not_replayable");
  });
});

describe("AuthZEN evaluate", () => {
  it("maps an AuthZEN request and returns the permitkit context profile", () => {
    const response = evaluate(policy, {
      subject: {
        type: "human",
        id: "u-lead",
        properties: { roles: [{ role: "lead", scope: { kind: "all" } }], act: null },
      },
      action: { name: "refund" },
      resource: { type: "ticket", id: "t-1", properties: { amount: 1000 } },
      context: { now: "2026-01-15T10:00:00.000Z", policy_version: "2026-01-01.1" },
    });
    expect(response).toMatchObject({
      decision: false,
      context: { outcome: "approval_required", reason_codes: ["approval_required"] },
    });
    expect(response.context.approval?.ruleId).toBe("refund-dual");
  });

  it("returns decision true for allow and false for malformed input", () => {
    const base = {
      subject: {
        type: "human",
        id: "u-lead",
        properties: { roles: [{ role: "lead", scope: { kind: "all" } }], act: null },
      },
      action: { name: "read" },
      resource: { type: "ticket", id: "t-1" },
      context: { now: "2026-01-15T10:00:00.000Z" },
    };
    expect(evaluate(policy, base).decision).toBe(true);
    expect(evaluate(policy, { ...base, context: {} }).context.reason_codes).toEqual([
      "invalid_request",
    ]);
    expect(evaluate(policy, { ...base, subject: { type: "human", id: "u-lead" } }).decision).toBe(
      false,
    );
  });
});

describe("explain", () => {
  it("shows why a scoped grant did not match", () => {
    const subject = human("u-s", role("support", within({ queue: ["billing"] })));
    const result = explain(
      policy,
      accessRequest(subject, "ticket:read", { properties: { queue: "legal" } }),
    );
    expect(result.decision.reason).toBe("scope_mismatch");
    expect(result.hint).toBe(reasonHints.scope_mismatch);
    expect(result.steps).toContainEqual({
      step: "grant",
      role: "support",
      id: "support-work",
      result: "assignment_scope_mismatch",
      detail: { ok: false, property: "queue", allowed: ["billing"], actual: "legal" },
    });
  });

  it("lists validation issues", () => {
    const result = explain(policy, { subject: {} });
    expect(result.steps[0]).toMatchObject({ step: "validate", ok: false });
  });

  it("returns the same decision as decide", () => {
    const request = accessRequest(lead, "ticket:refund", { properties: { amount: 5000 } });
    expect(explain(policy, request).decision).toEqual(decide(policy, request));
  });

  it("has a hint for every reason code", () => {
    for (const code of Object.keys(reasonCodes)) {
      expect(reasonHints[code as keyof typeof reasonHints]).toBeTruthy();
    }
  });
});

describe("canonical JSON", () => {
  it("sorts keys and drops undefined", () => {
    expect(canonicalJson({ b: 1, a: [true, null, "x"], c: undefined })).toBe(
      '{"a":[true,null,"x"],"b":1}',
    );
    expect(digest({ a: 1, b: 2 })).toBe(digest({ b: 2, a: 1 }));
    expect(digest("")).toBe("12ae32cb1ec02d01eda3581b127c1fee3b0dc53572ed6baf239721a03d82e126");
  });

  it("rejects values without an exact JSON form", () => {
    const cyclic: Record<string, unknown> = {};
    cyclic["self"] = cyclic;
    for (const value of [Number.NaN, Infinity, () => 1, new Date(0), cyclic, 1n]) {
      expect(() => canonicalJson(value)).toThrow(PermitkitError);
    }
  });
});
