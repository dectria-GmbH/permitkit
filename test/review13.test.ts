// Regression tests for findings of the thirteenth cold security review.
import { describe, expect, it } from "vitest";

import { decide } from "../src/index.js";
import { accessRequest, human, role, viaAgent } from "../src/testing/index.js";
import { policy } from "./fixtures.js";

const lead = human("u-lead", role("lead"));

describe("prior actor grants", () => {
  it("ends the chain when an upstream grant is revoked, expired or not yet valid", () => {
    const current = viaAgent(lead, "bot-b", { entries: [{ permissions: ["ticket:close"] }] });
    const cases: [Record<string, string>, string][] = [
      [{ revokedAt: "2020-01-01T00:00:00Z" }, "agent_grant_revoked"],
      [{ expiresAt: "2021-01-01T00:00:00Z" }, "agent_grant_expired"],
      [{ notBefore: "2099-01-01T00:00:00Z" }, "agent_grant_not_yet_valid"],
    ];
    for (const [times, reason] of cases) {
      const prior = viaAgent(lead, "bot-a", {
        entries: [{ permissions: ["ticket:read"] }],
        ...times,
      });
      const subject = { ...current, act: { ...current.act!, act: prior.act } };
      expect(decide(policy, accessRequest(subject, "ticket:close")).reason).toBe(reason);
    }
  });
});
