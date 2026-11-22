import { describe, expect, it } from "vitest";

import { decide } from "../src/index.js";
import { accessRequest, human, role, viaAgent } from "../src/testing/index.js";
import { policy } from "./fixtures.js";

const support = human("u-support", role("support", { queue: ["billing", "general"] }));
const readBilling = [{ permissions: ["ticket:read"], scope: { queue: ["billing"] } }];

describe("agents acting for a principal", () => {
  it("allows what both the principal and the grant cover", () => {
    const subject = viaAgent(support, "agent-1", { entries: readBilling });
    const request = accessRequest(subject, "ticket:read", { properties: { queue: "billing" } });
    expect(decide(policy, request)).toMatchObject({ outcome: "allow", reason: "granted" });
  });

  it("denies an agent action that the grant does not cover", () => {
    const subject = viaAgent(support, "agent-1", { entries: readBilling });
    const request = accessRequest(subject, "ticket:close", { properties: { queue: "billing" } });
    expect(decide(policy, request)).toMatchObject({
      outcome: "deny",
      reason: "agent_grant_insufficient",
    });
  });

  it("denies outside the grant scope even inside the principal scope", () => {
    const subject = viaAgent(support, "agent-1", { entries: readBilling });
    const request = accessRequest(subject, "ticket:read", { properties: { queue: "general" } });
    expect(decide(policy, request).reason).toBe("agent_grant_insufficient");
  });

  it("denies above a grant limit even inside the principal limit", () => {
    const subject = viaAgent(support, "agent-1", {
      entries: [{ permissions: ["ticket:refund"], limits: { amount: { max: 20 } } }],
    });
    const ok = accessRequest(subject, "ticket:refund", {
      properties: { amount: 20, queue: "billing" },
    });
    const over = accessRequest(subject, "ticket:refund", {
      properties: { amount: 21, queue: "billing" },
    });
    expect(decide(policy, ok).outcome).toBe("allow");
    expect(decide(policy, over).reason).toBe("agent_grant_insufficient");
  });

  it("denies when the grant names a permission that the principal lacks", () => {
    const subject = viaAgent(support, "agent-1", { entries: [{ permissions: ["ticket:delete"] }] });
    const request = accessRequest(subject, "ticket:delete", { properties: { queue: "billing" } });
    expect(decide(policy, request).outcome).toBe("deny");
    const wide = viaAgent(support, "agent-1", { entries: [{ permissions: ["ticket:read"] }] });
    const outside = accessRequest(wide, "ticket:read", { properties: { queue: "legal" } });
    expect(decide(policy, outside).reason).toBe("scope_mismatch");
  });

  it("denies when the agent has no grant", () => {
    const request = accessRequest(
      { ...support, act: { type: "agent", id: "agent-1" } },
      "ticket:read",
      { properties: { queue: "billing" } },
    );
    expect(decide(policy, request).reason).toBe("agent_grant_missing");
  });

  it("denies when the grant belongs to another principal", () => {
    const other = viaAgent(human("u-other", role("support")), "agent-1", { entries: readBilling });
    const subject = { ...support, act: other.act };
    const request = accessRequest(subject, "ticket:read", { properties: { queue: "billing" } });
    expect(decide(policy, request).reason).toBe("agent_grant_principal_mismatch");
  });

  it("denies at and after grant expiry", () => {
    const subject = viaAgent(support, "agent-1", {
      entries: readBilling,
      expiresAt: "2026-01-15T10:00:00.000Z",
    });
    const atExpiry = accessRequest(subject, "ticket:read", { properties: { queue: "billing" } });
    expect(decide(policy, atExpiry).reason).toBe("agent_grant_expired");
    const before = accessRequest(
      subject,
      "ticket:read",
      { properties: { queue: "billing" } },
      { now: "2026-01-15T09:59:59.999Z" },
    );
    expect(decide(policy, before).outcome).toBe("allow");
  });

  it("denies before notBefore and after revocation", () => {
    const early = viaAgent(support, "agent-1", {
      entries: readBilling,
      notBefore: "2026-01-15T10:00:00.001Z",
    });
    expect(
      decide(policy, accessRequest(early, "ticket:read", { properties: { queue: "billing" } }))
        .reason,
    ).toBe("agent_grant_not_yet_valid");
    const revoked = viaAgent(support, "agent-1", {
      entries: readBilling,
      revokedAt: "2026-01-15T10:00:00.000Z",
    });
    expect(
      decide(policy, accessRequest(revoked, "ticket:read", { properties: { queue: "billing" } }))
        .reason,
    ).toBe("agent_grant_revoked");
  });

  it("applies deny rules for agents to the principal's own rights", () => {
    const lead = human("u-lead", role("lead"));
    const subject = viaAgent(lead, "agent-1", { entries: [{ permissions: ["ticket:delete"] }] });
    expect(decide(policy, accessRequest(lead, "ticket:delete")).outcome).toBe("allow");
    expect(decide(policy, accessRequest(subject, "ticket:delete"))).toMatchObject({
      reason: "denied_by_rule",
      rule: { kind: "deny", id: "no-delete-by-agents" },
    });
  });

  it("decides on the current actor and rejects deep chains", () => {
    const subject = viaAgent(support, "agent-2", { entries: readBilling });
    const withPrior = {
      ...subject,
      act: { ...subject.act!, act: { type: "agent" as const, id: "agent-1" } },
    };
    const request = accessRequest(withPrior, "ticket:read", { properties: { queue: "billing" } });
    expect(decide(policy, request).outcome).toBe("allow");

    let deep: { type: "agent"; id: string; act?: unknown } = { type: "agent", id: "a0" };
    for (let index = 1; index <= 5; index += 1)
      deep = { type: "agent", id: `a${index}`, act: deep };
    const tooDeep = { ...subject, act: { ...subject.act!, act: deep } };
    expect(
      decide(
        policy,
        accessRequest(tooDeep as never, "ticket:read", { properties: { queue: "billing" } }),
      ).reason,
    ).toBe("invalid_request");
  });

  it("does not accept an agent as the top-level subject", () => {
    const request = accessRequest(support, "ticket:read", { properties: { queue: "billing" } });
    const forged = { ...request, subject: { ...request.subject, type: "agent" } };
    expect(decide(policy, forged).reason).toBe("invalid_request");
  });
});
