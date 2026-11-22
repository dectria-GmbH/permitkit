import { describe, expect, it } from "vitest";

import { compilePolicy, defineCatalog, PermitkitError, type PolicyIssue } from "../src/index.js";
import { catalog, editablePolicyInput, policy } from "./fixtures.js";

function issuesOf(fn: () => unknown): PolicyIssue[] {
  try {
    fn();
  } catch (error) {
    if (error instanceof PermitkitError) return [...error.issues];
    throw error;
  }
  throw new Error("expected a PermitkitError");
}

function bad(definition: unknown): PolicyIssue[] {
  return issuesOf(() => defineCatalog(definition as Parameters<typeof defineCatalog>[0]));
}

describe("catalogue", () => {
  it("lists permissions and resources", () => {
    expect(catalog.permissions).toContain("ticket:refund");
    expect(catalog.isPermission("ticket:refund")).toBe(true);
    expect(catalog.isPermission("ticket:archive")).toBe(false);
    expect(catalog.resourceOf("report:read")?.scopes).toEqual(["project"]);
    expect(Object.isFrozen(catalog.permissions)).toBe(true);
  });

  it("rejects invalid definitions", () => {
    expect(bad({})).toHaveLength(1);
    expect(bad({ Ticket: { actions: ["read"] } })[0]?.message).toMatch(/not valid/);
    expect(bad({ ticket: { actions: [] } })).toHaveLength(1);
    expect(bad({ ticket: { actions: ["read", "read"] } })[0]?.message).toMatch(/twice/);
    expect(bad({ ticket: { actions: ["read"], scopes: ["x"], limits: ["x"] } })).toHaveLength(1);
  });

  it("has a digest that changes with the definition", () => {
    const same = defineCatalog({
      report: { actions: ["export", "read"], scopes: ["project"] },
      ticket: {
        actions: ["delete", "refund", "close", "read"],
        scopes: ["project", "queue"],
        limits: ["amount"],
      },
    });
    expect(same.digest).toBe(catalog.digest);
    expect(defineCatalog({ ticket: { actions: ["read"] } }).digest).not.toBe(catalog.digest);
  });
});

describe("policy validation", () => {
  it("rejects unknown keys anywhere", () => {
    const input = editablePolicyInput();
    (input.roles["support"]!.grants[0] as Record<string, unknown>)["scopes"] = { queue: ["x"] };
    const issues = issuesOf(() => compilePolicy(catalog, input));
    expect(issues[0]?.path).toBe("roles.support.grants.0");
  });

  it("rejects permissions outside the catalogue", () => {
    const input = editablePolicyInput();
    input.roles["support"]!.grants[0]!.permissions = ["ticket:archive"];
    expect(issuesOf(() => compilePolicy(catalog, input))[0]?.path).toBe(
      "roles.support.grants.0.permissions.0",
    );
  });

  it("rejects scope and limit names that the resource type does not declare", () => {
    const input = editablePolicyInput();
    input.roles["auditor"]!.grants[0]!.scope = { kind: "match", properties: { queue: ["x"] } };
    input.roles["support"]!.grants[1]!.limits = {
      kind: "range",
      properties: { weight: { min: null, max: 1 } },
    };
    const paths = issuesOf(() => compilePolicy(catalog, input)).map((item) => item.path);
    expect(paths).toContain("roles.auditor.grants.0.scope.properties.queue");
    expect(paths).toContain("roles.support.grants.1.limits.properties.weight");
  });

  it("rejects duplicate rule ids and unknown role references", () => {
    const input = editablePolicyInput();
    input.denies[0]!.id = "support-work";
    input.denies[1]!.roles = ["ghost"];
    const messages = issuesOf(() => compilePolicy(catalog, input)).map((item) => item.message);
    expect(messages.some((message) => message.includes("also used"))).toBe(true);
    expect(messages.some((message) => message.includes("ghost"))).toBe(true);
  });

  it("rejects two approval rules for one permission", () => {
    const input = editablePolicyInput();
    input.approvalRules.push({ ...input.approvalRules[0]!, id: "refund-other" });
    expect(issuesOf(() => compilePolicy(catalog, input))[0]?.message).toMatch(/already has/);
  });

  it("requires approver roles when exclusive roles are switched on", () => {
    const input = editablePolicyInput();
    input.separationOfDuties = {
      exclusiveRequestAndApproveRoles: true,
      requesterNeverApprovesSameType: false,
    };
    expect(issuesOf(() => compilePolicy(catalog, input))[0]?.path).toBe(
      "approvalRules.0.eligibleApprovers",
    );
  });

  it("rejects approval rules with no approvers or a too short window", () => {
    const input = editablePolicyInput();
    input.approvalRules[0]!.approvers = 0;
    input.approvalRules[0]!.expiresInSeconds = 10;
    expect(issuesOf(() => compilePolicy(catalog, input))).toHaveLength(2);
  });

  it("rejects an empty scope value list", () => {
    const input = editablePolicyInput();
    input.roles["auditor"]!.grants[0]!.scope = { kind: "match", properties: { project: [] } };
    expect(issuesOf(() => compilePolicy(catalog, input))).toHaveLength(1);
  });

  it("rejects role names that start with an underscore", () => {
    const input = editablePolicyInput();
    input.roles = { ...input.roles, __proto__x: { grants: [] } };
    expect(issuesOf(() => compilePolicy(catalog, input)).length).toBeGreaterThan(0);
  });
});

describe("compiled policy", () => {
  it("is frozen and detached from its input", () => {
    const input = editablePolicyInput();
    const compiled = compilePolicy(catalog, input);
    input.roles["support"]!.grants[0]!.permissions.push("ticket:delete");
    expect(compiled.document.roles["support"]?.grants[0]?.permissions).not.toContain(
      "ticket:delete",
    );
    expect(Object.isFrozen(compiled.document.roles["support"]?.grants[0]?.permissions)).toBe(true);
    expect(() => {
      compiled.document.roles["support"]!.grants[0]!.permissions.push("ticket:delete");
    }).toThrow(TypeError);
  });

  it("has a stable digest that changes with any rule", () => {
    expect(compilePolicy(catalog, editablePolicyInput()).digest).toBe(policy.digest);
    const input = editablePolicyInput();
    input.roles["support"]!.grants[1]!.limits = {
      kind: "range",
      properties: { amount: { min: null, max: 501 } },
    };
    expect(compilePolicy(catalog, input).digest).not.toBe(policy.digest);
  });

  it("applies schema defaults", () => {
    const minimal = compilePolicy(catalog, {
      schema: 2,
      version: "v1",
      roles: {},
      denies: [],
      approvalRules: [],
      separationOfDuties: {
        requesterNeverApprovesSameType: false,
        exclusiveRequestAndApproveRoles: false,
      },
    });
    expect(minimal.document.denies).toEqual([]);
    expect(minimal.document.separationOfDuties).toEqual({
      requesterNeverApprovesSameType: false,
      exclusiveRequestAndApproveRoles: false,
    });
  });
});
