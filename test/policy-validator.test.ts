// Named cases for each rule of the policy validator. Each case runs through the hand-written
// validator and the earlier Zod schema; both must give the expected verdict and first path, so a
// failure names the rule. Cross-references (catalogue, roles, ids, proofTypes with requireProof)
// are checked in compilePolicy after the validator and are tested in policy.test.ts.
import { describe, expect, it } from "vitest";

import { policyDocument } from "../src/policy-document.js";
import { maxApprovalWindowSeconds } from "../src/time.js";
import { policySchema } from "../src/zod-schemas.js";
import { dropAt, expectedOf, runCase, setAt, type CorpusCase } from "./differential.js";

const base = (): Record<string, unknown> => ({
  schema: 2,
  version: "v1",
  roles: {
    lead: {
      description: "Team lead",
      grants: [
        {
          id: "g1",
          permissions: ["ticket:read", "ticket:refund"],
          scope: { kind: "match", properties: { queue: ["a"] } },
          limits: { kind: "range", properties: { amount: { min: null, max: 100 } } },
        },
      ],
    },
  },
  denies: [
    {
      id: "d1",
      permissions: ["ticket:refund"],
      roles: ["lead"],
      subjectTypes: ["agent"],
      scope: { kind: "all" },
    },
  ],
  approvalRules: [
    {
      id: "a1",
      permissions: ["ticket:refund"],
      when: { kind: "threshold", properties: { amount: { gte: 50 } } },
      approvers: 1,
      eligibleApprovers: { kind: "roles", roles: ["lead"] },
      expiresInSeconds: 3600,
      requireProof: true,
      proofTypes: ["webauthn"],
    },
  ],
  separationOfDuties: {
    requesterNeverApprovesSameType: false,
    exclusiveRequestAndApproveRoles: false,
  },
});

const grant = ["roles", "lead", "grants", 0];
const rule = ["approvalRules", 0];
const deny = ["denies", 0];

const cases: CorpusCase[] = [
  { name: "a valid policy", edit: () => {}, expected: "accept" },
  {
    name: "empty lists and no roles",
    edit: (d) => (
      setAt(d, ["roles"], {}),
      setAt(d, ["denies"], []),
      setAt(d, ["approvalRules"], [])
    ),
    expected: "accept",
  },
  // Document.
  { name: "schema as a string", edit: (d) => setAt(d, ["schema"], "2"), expected: ["schema"] },
  { name: "schema missing", edit: (d) => dropAt(d, ["schema"]), expected: ["schema"] },
  { name: "unknown top-level key", edit: (d) => setAt(d, ["rules"], []), expected: [] },
  { name: "version empty", edit: (d) => setAt(d, ["version"], ""), expected: ["version"] },
  {
    name: "version 128 characters",
    edit: (d) => setAt(d, ["version"], "v".repeat(128)),
    expected: "accept",
  },
  {
    name: "version 129 characters",
    edit: (d) => setAt(d, ["version"], "v".repeat(129)),
    expected: ["version"],
  },
  { name: "denies missing", edit: (d) => dropAt(d, ["denies"]), expected: ["denies"] },
  {
    name: "approvalRules undefined",
    edit: (d) => setAt(d, ["approvalRules"], undefined),
    expected: ["approvalRules"],
  },
  {
    name: "separationOfDuties flag missing",
    edit: (d) => dropAt(d, ["separationOfDuties", "exclusiveRequestAndApproveRoles"]),
    expected: ["separationOfDuties", "exclusiveRequestAndApproveRoles"],
  },
  {
    name: "separationOfDuties flag as a string",
    edit: (d) => setAt(d, ["separationOfDuties", "requesterNeverApprovesSameType"], "true"),
    expected: ["separationOfDuties", "requesterNeverApprovesSameType"],
  },
  // Roles.
  {
    name: "role name __proto__",
    edit: (d) => setAt(d, ["roles", "__proto__"], { grants: [] }),
    expected: ["roles", "__proto__"],
  },
  {
    name: "role name constructor",
    edit: (d) => setAt(d, ["roles", "constructor"], { grants: [] }),
    expected: "accept",
  },
  {
    name: "role name with underscore first",
    edit: (d) => setAt(d, ["roles", "_lead"], { grants: [] }),
    expected: ["roles", "_lead"],
  },
  {
    name: "role name 128 characters",
    edit: (d) => setAt(d, ["roles", "r".repeat(128)], { grants: [] }),
    expected: "accept",
  },
  {
    name: "role name 129 characters",
    edit: (d) => setAt(d, ["roles", "r".repeat(129)], { grants: [] }),
    expected: ["roles", "r".repeat(129)],
  },
  {
    name: "role name empty",
    edit: (d) => setAt(d, ["roles", ""], { grants: [] }),
    expected: ["roles", ""],
  },
  {
    name: "role name with a space",
    edit: (d) => setAt(d, ["roles", "team lead"], { grants: [] }),
    expected: ["roles", "team lead"],
  },
  {
    name: "role without grants",
    edit: (d) => dropAt(d, ["roles", "lead", "grants"]),
    expected: ["roles", "lead", "grants"],
  },
  {
    name: "role description 1000 characters",
    edit: (d) => setAt(d, ["roles", "lead", "description"], "d".repeat(1000)),
    expected: "accept",
  },
  {
    name: "role description 1001 characters",
    edit: (d) => setAt(d, ["roles", "lead", "description"], "d".repeat(1001)),
    expected: ["roles", "lead", "description"],
  },
  {
    name: "role description undefined",
    edit: (d) => setAt(d, ["roles", "lead", "description"], undefined),
    expected: "accept",
  },
  {
    name: "role description null",
    edit: (d) => setAt(d, ["roles", "lead", "description"], null),
    expected: ["roles", "lead", "description"],
  },
  // Grants.
  {
    name: "grant id with a slash",
    edit: (d) => setAt(d, [...grant, "id"], "g/1"),
    expected: [...grant, "id"],
  },
  {
    name: "grant without permissions",
    edit: (d) => setAt(d, [...grant, "permissions"], []),
    expected: [...grant, "permissions"],
  },
  {
    name: "permission in upper case",
    edit: (d) => setAt(d, [...grant, "permissions", 0], "Ticket:read"),
    expected: [...grant, "permissions", 0],
  },
  {
    name: "permission without action",
    edit: (d) => setAt(d, [...grant, "permissions", 0], "ticket"),
    expected: [...grant, "permissions", 0],
  },
  {
    name: "permission name has no length limit of its own",
    edit: (d) => setAt(d, [...grant, "permissions", 0], `ticket:${"r".repeat(4000)}`),
    expected: "accept",
  },
  {
    name: "grant with an unknown key",
    edit: (d) => setAt(d, [...grant, "scopes"], {}),
    expected: grant,
  },
  {
    name: "grant scope missing",
    edit: (d) => dropAt(d, [...grant, "scope"]),
    expected: [...grant, "scope"],
  },
  {
    name: "grant scope empty",
    edit: (d) => setAt(d, [...grant, "scope"], {}),
    expected: [...grant, "scope", "kind"],
  },
  {
    name: '"*" in a grant scope',
    edit: (d) => setAt(d, [...grant, "scope", "properties", "queue"], ["a", "*"]),
    expected: [...grant, "scope", "properties", "queue", 1],
  },
  {
    name: "grant match scope with empty properties",
    edit: (d) => setAt(d, [...grant, "scope", "properties"], {}),
    expected: [...grant, "scope", "properties"],
  },
  {
    name: "grant match scope value undefined",
    edit: (d) => setAt(d, [...grant, "scope", "properties", "project"], undefined),
    expected: [...grant, "scope", "properties", "project"],
  },
  {
    name: "grant limits missing",
    edit: (d) => dropAt(d, [...grant, "limits"]),
    expected: [...grant, "limits"],
  },
  {
    name: "range without properties",
    edit: (d) => setAt(d, [...grant, "limits", "properties"], {}),
    expected: [...grant, "limits", "properties"],
  },
  {
    name: "range with both bounds null",
    edit: (d) => setAt(d, [...grant, "limits", "properties", "amount"], { min: null, max: null }),
    expected: [...grant, "limits", "properties", "amount"],
  },
  {
    name: "range with min above max",
    edit: (d) => setAt(d, [...grant, "limits", "properties", "amount"], { min: 2, max: 1 }),
    expected: [...grant, "limits", "properties", "amount"],
  },
  {
    name: "range with max undefined",
    edit: (d) => setAt(d, [...grant, "limits", "properties", "amount", "max"], undefined),
    expected: [...grant, "limits", "properties", "amount", "max"],
  },
  {
    name: "range bound -Infinity",
    edit: (d) =>
      setAt(d, [...grant, "limits", "properties", "amount", "min"], Number.NEGATIVE_INFINITY),
    expected: [...grant, "limits", "properties", "amount", "min"],
  },
  {
    name: "range property __proto__",
    edit: (d) => setAt(d, [...grant, "limits", "properties", "__proto__"], { min: 1, max: 2 }),
    expected: [...grant, "limits", "properties", "__proto__"],
  },
  {
    name: "unlimited with properties",
    edit: (d) => setAt(d, [...grant, "limits"], { kind: "unlimited", properties: {} }),
    expected: [...grant, "limits"],
  },
  {
    name: "limits kind all",
    edit: (d) => setAt(d, [...grant, "limits"], { kind: "all" }),
    expected: [...grant, "limits", "kind"],
  },
  // Deny rules.
  {
    name: "deny without roles and subject types",
    edit: (d) => (dropAt(d, [...deny, "roles"]), dropAt(d, [...deny, "subjectTypes"])),
    expected: "accept",
  },
  {
    name: "deny roles empty",
    edit: (d) => setAt(d, [...deny, "roles"], []),
    expected: [...deny, "roles"],
  },
  {
    name: "deny subject types empty",
    edit: (d) => setAt(d, [...deny, "subjectTypes"], []),
    expected: [...deny, "subjectTypes"],
  },
  {
    name: "deny subject type in other case",
    edit: (d) => setAt(d, [...deny, "subjectTypes"], ["Agent"]),
    expected: [...deny, "subjectTypes", 0],
  },
  {
    name: "deny scope missing",
    edit: (d) => dropAt(d, [...deny, "scope"]),
    expected: [...deny, "scope"],
  },
  {
    name: "deny with limits",
    edit: (d) => setAt(d, [...deny, "limits"], { kind: "unlimited" }),
    expected: deny,
  },
  // Approval rules.
  {
    name: "approvers 0",
    edit: (d) => setAt(d, [...rule, "approvers"], 0),
    expected: [...rule, "approvers"],
  },
  { name: "approvers 10", edit: (d) => setAt(d, [...rule, "approvers"], 10), expected: "accept" },
  {
    name: "approvers 11",
    edit: (d) => setAt(d, [...rule, "approvers"], 11),
    expected: [...rule, "approvers"],
  },
  {
    name: "approvers 1.5",
    edit: (d) => setAt(d, [...rule, "approvers"], 1.5),
    expected: [...rule, "approvers"],
  },
  {
    name: "approvers Infinity",
    edit: (d) => setAt(d, [...rule, "approvers"], Number.POSITIVE_INFINITY),
    expected: [...rule, "approvers"],
  },
  {
    name: "expiresInSeconds 59",
    edit: (d) => setAt(d, [...rule, "expiresInSeconds"], 59),
    expected: [...rule, "expiresInSeconds"],
  },
  {
    name: "expiresInSeconds 60",
    edit: (d) => setAt(d, [...rule, "expiresInSeconds"], 60),
    expected: "accept",
  },
  {
    name: "expiresInSeconds at the maximum",
    edit: (d) => setAt(d, [...rule, "expiresInSeconds"], maxApprovalWindowSeconds),
    expected: "accept",
  },
  {
    name: "expiresInSeconds above the maximum",
    edit: (d) => setAt(d, [...rule, "expiresInSeconds"], maxApprovalWindowSeconds + 1),
    expected: [...rule, "expiresInSeconds"],
  },
  {
    name: "two numeric rule errors give two issues",
    edit: (d) => (setAt(d, [...rule, "approvers"], 0), setAt(d, [...rule, "expiresInSeconds"], 10)),
    expected: [...rule, "approvers"],
  },
  {
    name: "requireProof missing",
    edit: (d) => dropAt(d, [...rule, "requireProof"]),
    expected: [...rule, "requireProof"],
  },
  {
    name: "proofTypes without requireProof passes the shape check",
    edit: (d) => setAt(d, [...rule, "requireProof"], false),
    expected: "accept",
  },
  {
    name: "requireProof without proofTypes passes the shape check",
    edit: (d) => dropAt(d, [...rule, "proofTypes"]),
    expected: "accept",
  },
  {
    name: "proofTypes empty",
    edit: (d) => setAt(d, [...rule, "proofTypes"], []),
    expected: [...rule, "proofTypes"],
  },
  {
    name: "proof type of 64 characters",
    edit: (d) => setAt(d, [...rule, "proofTypes", 0], "p".repeat(64)),
    expected: "accept",
  },
  {
    name: "proof type of 65 characters",
    edit: (d) => setAt(d, [...rule, "proofTypes", 0], "p".repeat(65)),
    expected: [...rule, "proofTypes", 0],
  },
  { name: "when missing", edit: (d) => dropAt(d, [...rule, "when"]), expected: [...rule, "when"] },
  {
    name: "threshold without properties",
    edit: (d) => setAt(d, [...rule, "when", "properties"], {}),
    expected: [...rule, "when", "properties"],
  },
  {
    name: "threshold gte NaN",
    edit: (d) => setAt(d, [...rule, "when", "properties", "amount", "gte"], Number.NaN),
    expected: [...rule, "when", "properties", "amount", "gte"],
  },
  {
    name: "threshold with an extra key",
    edit: (d) => setAt(d, [...rule, "when", "properties", "amount", "lte"], 1),
    expected: [...rule, "when", "properties", "amount"],
  },
  {
    name: "always with properties",
    edit: (d) => setAt(d, [...rule, "when"], { kind: "always", properties: {} }),
    expected: [...rule, "when"],
  },
  {
    name: "eligible approvers roles empty",
    edit: (d) => setAt(d, [...rule, "eligibleApprovers", "roles"], []),
    expected: [...rule, "eligibleApprovers", "roles"],
  },
  {
    name: "eligible approvers kind missing",
    edit: (d) => setAt(d, [...rule, "eligibleApprovers"], { roles: ["lead"] }),
    expected: [...rule, "eligibleApprovers", "kind"],
  },
  {
    name: "eligible approvers permission",
    edit: (d) => setAt(d, [...rule, "eligibleApprovers"], { kind: "permission" }),
    expected: "accept",
  },
];

describe("policy validator rules", () => {
  it.each(cases.map((item) => [item.name, item] as const))("%s", (_name, item) => {
    const { reference, actual, outputDifference } = runCase(
      policySchema,
      policyDocument,
      base,
      item,
    );
    expect({ zod: reference, handWritten: actual }).toEqual({
      zod: expectedOf(item),
      handWritten: expectedOf(item),
    });
    expect(outputDifference).toBeNull();
  });
});
