// Zod 3 caches enum values on first use. This file parses nothing before the pollution, so a
// z.enum here would read the polluted cache. The literal unions in permitkit must still reject.
import { afterEach, describe, expect, it } from "vitest";

import { compilePolicy, decide, defineCatalog } from "../src/index.js";

afterEach(() => {
  delete (Object.prototype as Record<string, unknown>)["_cache"];
});

describe("first parse under a polluted prototype", () => {
  it("does not accept other subject types when Zod's cache key is polluted", () => {
    // The test simulates a prototype-pollution bug elsewhere in the process.
    // oxlint-disable-next-line no-extend-native
    Object.defineProperty(Object.prototype, "_cache", {
      value: { has: () => true },
      configurable: true,
      writable: true,
    });
    const catalog = defineCatalog({ ticket: { actions: ["read"] } });
    expect(() =>
      compilePolicy(catalog, {
        schema: 2,
        version: "v",
        roles: {},
        denies: [
          {
            id: "d",
            permissions: ["ticket:read"],
            subjectTypes: ["typo" as never],
            scope: { kind: "all" },
          },
        ],
        approvalRules: [],
        separationOfDuties: {
          requesterNeverApprovesSameType: false,
          exclusiveRequestAndApproveRoles: false,
        },
      }),
    ).toThrow(/not valid/);
    const policy = compilePolicy(catalog, {
      schema: 2,
      version: "v",
      roles: {
        reader: {
          grants: [
            {
              id: "g",
              permissions: ["ticket:read"],
              scope: { kind: "all" },
              limits: { kind: "unlimited" },
            },
          ],
        },
      },
      denies: [],
      approvalRules: [],
      separationOfDuties: {
        requesterNeverApprovesSameType: false,
        exclusiveRequestAndApproveRoles: false,
      },
    });
    const decision = decide(policy, {
      subject: { type: "Human", id: "u", roles: [{ role: "reader", scope: { kind: "all" } }] },
      action: { name: "read" },
      resource: { type: "ticket" },
      context: { now: "2026-01-15T10:00:00Z" },
    });
    expect(decision.reason).toBe("invalid_request");
  });
});
