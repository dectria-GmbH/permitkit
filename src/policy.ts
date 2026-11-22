import { z } from "zod";

import { boundedSnapshot, detach, policyBounds } from "./bounds.js";
import { compareText, digest } from "./canonical.js";
import { isCatalog, type Catalog } from "./catalog.js";
import { PermitkitError, type PolicyIssue } from "./errors.js";
import { safeParse } from "./parse.js";

const identifier = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9][A-Za-z0-9_.:-]*$/, "Use letters, digits, and _ . : - only.");
const permissionName = z
  .string()
  .regex(/^[a-z][a-z0-9_-]*:[a-z][a-z0-9_-]*$/, "Use the form <resource>:<action>.");

/** Scope: property name to the list of allowed string values. An absent property is not restricted. */
export const scopeSchema = z.record(identifier, z.array(z.string().min(1)).min(1).max(1000));
/** A scope on a grant or deny rule. It must restrict something; leave it out for "everywhere". */
export const restrictionScopeSchema = scopeSchema.refine(
  (scope) => Object.keys(scope).length > 0,
  "An empty scope restricts nothing. Leave the field out instead.",
);
/** Limits: property name to an inclusive numeric range. Give `min`, `max` or both. */
const limitSchema = z
  .object({ min: z.number().finite().optional(), max: z.number().finite().optional() })
  .strict()
  // Own keys only: Zod's output object has a prototype, and an inherited `max` must not count.
  .refine(
    (limit) => Object.hasOwn(limit, "min") || Object.hasOwn(limit, "max"),
    "Give min, max or both.",
  )
  .refine((limit) => {
    const min = Object.hasOwn(limit, "min") ? limit.min : undefined;
    const max = Object.hasOwn(limit, "max") ? limit.max : undefined;
    return min === undefined || max === undefined || min <= max;
  }, "min must not be greater than max.");
export const limitsSchema = z
  .record(identifier, limitSchema)
  .refine(
    (limits) => Object.keys(limits).length > 0,
    "Empty limits restrict nothing. Leave the field out instead.",
  );

export const grantSchema = z
  .object({
    id: identifier,
    permissions: z.array(permissionName).min(1),
    scope: restrictionScopeSchema.optional(),
    limits: limitsSchema.optional(),
  })
  .strict();

export const roleSchema = z
  .object({
    description: z.string().max(1000).optional(),
    grants: z.array(grantSchema),
  })
  .strict();

// Literals, not z.enum: Zod 3 caches enum values on the instance through a lazy property.
export const subjectTypeSchema = z.union([
  z.literal("human"),
  z.literal("service"),
  z.literal("agent"),
]);

export const denySchema = z
  .object({
    id: identifier,
    description: z.string().max(1000).optional(),
    permissions: z.array(permissionName).min(1),
    /** The rule applies only to subjects that hold one of these roles. Absent: everyone. */
    roles: z.array(identifier).min(1).optional(),
    /** The rule applies only to these subject types. `agent` means an agent acts. Absent: all. */
    subjectTypes: z.array(subjectTypeSchema).min(1).optional(),
    /** The rule applies only to resources inside this scope. A missing property counts as inside. */
    scope: restrictionScopeSchema.optional(),
  })
  .strict();

export const approvalRuleSchema = z
  .object({
    id: identifier,
    description: z.string().max(1000).optional(),
    permissions: z.array(permissionName).min(1),
    /**
     * The rule applies if any listed numeric property is at least `gte`, or is missing.
     * Absent: the rule always applies.
     */
    when: z
      .record(identifier, z.object({ gte: z.number().finite() }).strict())
      .refine((when) => Object.keys(when).length > 0, "Leave out an empty when.")
      .optional(),
    /** Number of distinct approvers besides the requester. */
    approvers: z.number().int().min(1).max(10),
    /** Each approver must hold one of these roles in a scope that covers the resource. */
    approverRoles: z.array(identifier).min(1).optional(),
    /** Approvals count only inside this window after the request time. */
    expiresInSeconds: z
      .number()
      .int()
      .min(60)
      .max(31 * 24 * 3600),
    /** Each approval must carry a proof that a registered verifier accepts. */
    requireProof: z.boolean().default(false),
    /** With requireProof: the proof types that count. Absent: any registered type. */
    proofTypes: z.array(z.string().min(1).max(64)).min(1).optional(),
  })
  .strict();

export const separationOfDutiesSchema = z
  .object({
    /** Who requested an action of a type before may never approve an action of that type. */
    requesterNeverApprovesSameType: z.boolean().default(false),
    /** Nobody may hold both a requesting and an approving role for the same permission. */
    exclusiveRequestAndApproveRoles: z.boolean().default(false),
  })
  .strict();

export const policySchema = z
  .object({
    /** Format version of the policy document. */
    schema: z.literal(1),
    /** Operator-chosen version label. Decisions and audit records carry it. */
    version: z.string().min(1).max(128),
    roles: z.record(identifier, roleSchema),
    denies: z.array(denySchema).default([]),
    approvalRules: z.array(approvalRuleSchema).default([]),
    // The default is a null-prototype object, so Zod cannot read inherited flags into it.
    separationOfDuties: separationOfDutiesSchema.default(nullObject),
  })
  .strict();

export type PolicyInput = z.input<typeof policySchema>;
export type PolicyDocument = z.output<typeof policySchema>;
export type Scope = z.output<typeof scopeSchema>;
export type Limits = z.output<typeof limitsSchema>;
export type GrantRule = z.output<typeof grantSchema>;
export type DenyRule = z.output<typeof denySchema>;
export type ApprovalRule = z.output<typeof approvalRuleSchema>;

export interface CompiledRole {
  readonly name: string;
  readonly grants: readonly GrantRule[];
}

/**
 * A validated, frozen policy bound to its catalogue. Only compilePolicy creates one.
 * The digest covers the catalogue and the normalized policy document. The lookup tables that
 * decide() uses are module-private, so code that holds the policy cannot change them.
 */
export interface CompiledPolicy {
  readonly version: string;
  readonly digest: string;
  readonly catalog: Catalog;
  /** The normalized, deeply frozen policy document. */
  readonly document: PolicyDocument;
}

/** A read-only view of a map. A Map itself cannot be frozen. */
export interface Lookup<V> {
  get(key: string): V | undefined;
  values(): IterableIterator<V>;
}

function lookup<V>(map: Map<string, V>): Lookup<V> {
  return Object.freeze({
    get: (key: string) => map.get(key),
    values: () => map.values(),
  });
}

/** Lookup tables built from the frozen document. Not exported from the package. */
export interface PolicyInternals {
  readonly roles: Lookup<CompiledRole>;
  readonly denies: readonly DenyRule[];
  readonly approvalRules: Lookup<ApprovalRule>;
  readonly separationOfDuties: PolicyDocument["separationOfDuties"];
}

const internals = new WeakMap<object, PolicyInternals>();

/** The lookup tables of a compiled policy, or undefined for any other value. */
export function internalsOf(value: unknown): PolicyInternals | undefined {
  if (typeof value !== "object" || value === null) return undefined;
  return internals.get(value);
}

/** True only for objects that compilePolicy returned in this process. */
export function isCompiledPolicy(value: unknown): value is CompiledPolicy {
  return internalsOf(value) !== undefined;
}

/**
 * Validates a policy document against the schema and the catalogue and returns a frozen,
 * compiled policy. Throws PermitkitError with code `policy_invalid` and a list of issues.
 */
export function compilePolicy(catalog: Catalog, input: unknown): CompiledPolicy {
  if (!isCatalog(catalog)) {
    throw new PermitkitError(
      "catalog_invalid",
      "compilePolicy() needs a catalogue from defineCatalog().",
    );
  }
  const snapshot = boundedSnapshot(input, policyBounds);
  if (snapshot === undefined) {
    throw new PermitkitError("policy_invalid", "The policy document is too large.", [
      {
        path: "",
        message: "The document exceeds the size bounds (depth, nodes, array or string length).",
        hint: "Split very large scope lists, or raise the bounds in a fork if you need more.",
      },
    ]);
  }
  const parsed = safeParse(policySchema, snapshot);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((item) => ({
      path: item.path.join("."),
      message: item.message,
      hint: "Fix the field shape. Unknown keys are rejected, so check the spelling.",
    }));
    throw new PermitkitError("policy_invalid", "The policy document is not valid.", issues);
  }
  const document = detach(parsed.data);
  const issues = checkReferences(catalog, document);
  if (issues.length > 0) {
    throw new PermitkitError("policy_invalid", "The policy document is not valid.", issues);
  }

  const roles = new Map<string, CompiledRole>();
  for (const name of Object.keys(document.roles).toSorted(compareText)) {
    const role = document.roles[name];
    if (role !== undefined) roles.set(name, Object.freeze({ name, grants: role.grants }));
  }
  const approvalRules = new Map<string, ApprovalRule>();
  for (const rule of document.approvalRules) {
    for (const permission of rule.permissions) approvalRules.set(permission, rule);
  }

  deepFreeze(document);
  const policy: CompiledPolicy = Object.freeze({
    version: document.version,
    digest: digest({ catalog: catalog.digest, policy: document }),
    catalog,
    document,
  });
  internals.set(
    policy,
    Object.freeze({
      roles: lookup(roles),
      denies: document.denies,
      approvalRules: lookup(approvalRules),
      separationOfDuties: document.separationOfDuties,
    }),
  );
  return policy;
}

function checkReferences(catalog: Catalog, document: PolicyDocument): PolicyIssue[] {
  const issues: PolicyIssue[] = [];
  const ids = new Map<string, string>();
  const claimId = (id: string, path: string) => {
    const first = ids.get(id);
    if (first !== undefined) {
      issues.push({ path, message: `Rule id ${id} is also used at ${first}.`, hint: uniqueHint });
    } else {
      ids.set(id, path);
    }
  };
  const roleNames = new Set(Object.keys(document.roles));

  const checkPermissions = (
    permissions: readonly string[],
    path: string,
    properties: { scope?: Record<string, unknown>; limits?: Record<string, unknown> },
  ) => {
    permissions.forEach((permission, index) => {
      const resource = catalog.resourceOf(permission);
      if (resource === undefined) {
        issues.push({
          path: `${path}.permissions.${index}`,
          message: `Permission ${permission} is not in the catalogue.`,
          hint: "Add the action to the catalogue in code, or fix the spelling.",
        });
        return;
      }
      for (const name of Object.keys(ownObject(properties, "scope"))) {
        if (!resource.scopes.includes(name)) {
          issues.push({
            path: `${path}.scope.${name}`,
            message: `Resource type ${resource.type} has no scope property ${name}.`,
            hint: `Use one of: ${resource.scopes.join(", ") || "(none)"}.`,
          });
        }
      }
      for (const name of Object.keys(ownObject(properties, "limits"))) {
        if (!resource.limits.includes(name)) {
          issues.push({
            path: `${path}.limits.${name}`,
            message: `Resource type ${resource.type} has no limit property ${name}.`,
            hint: `Use one of: ${resource.limits.join(", ") || "(none)"}.`,
          });
        }
      }
    });
  };

  for (const roleName of Object.keys(document.roles)) {
    const role = document.roles[roleName];
    if (role === undefined) continue;
    role.grants.forEach((grant, index) => {
      const path = `roles.${roleName}.grants.${index}`;
      claimId(grant.id, path);
      checkPermissions(grant.permissions, path, {
        ...(grant.scope ? { scope: grant.scope } : {}),
        ...(grant.limits ? { limits: grant.limits } : {}),
      });
    });
  }

  document.denies.forEach((deny, index) => {
    const path = `denies.${index}`;
    claimId(deny.id, path);
    checkPermissions(deny.permissions, path, deny.scope ? { scope: deny.scope } : {});
    deny.roles?.forEach((role, roleIndex) => {
      if (!roleNames.has(role)) {
        issues.push({
          path: `${path}.roles.${roleIndex}`,
          message: `Role ${role} is not defined.`,
          hint: "Define the role under roles, or fix the spelling.",
        });
      }
    });
  });

  const ruled = new Map<string, string>();
  document.approvalRules.forEach((rule, index) => {
    const path = `approvalRules.${index}`;
    claimId(rule.id, path);
    checkPermissions(rule.permissions, path, rule.when ? { limits: rule.when } : {});
    for (const permission of rule.permissions) {
      const first = ruled.get(permission);
      if (first !== undefined) {
        issues.push({
          path: `${path}.permissions`,
          message: `Permission ${permission} already has an approval rule at ${first}.`,
          hint: "Use one approval rule per permission.",
        });
      }
      ruled.set(permission, path);
    }
    rule.approverRoles?.forEach((role, roleIndex) => {
      if (!roleNames.has(role)) {
        issues.push({
          path: `${path}.approverRoles.${roleIndex}`,
          message: `Role ${role} is not defined.`,
          hint: "Define the role under roles, or fix the spelling.",
        });
      }
    });
    if (rule.proofTypes !== undefined && !rule.requireProof) {
      issues.push({
        path: `${path}.proofTypes`,
        message: "proofTypes has no effect without requireProof.",
        hint: "Set requireProof: true, or remove proofTypes.",
      });
    }
    if (document.separationOfDuties.exclusiveRequestAndApproveRoles && !rule.approverRoles) {
      issues.push({
        path: `${path}.approverRoles`,
        message: "Exclusive request and approve roles need explicit approver roles on every rule.",
        hint: "Name the approver roles, or switch off exclusiveRequestAndApproveRoles.",
      });
    }
  });

  return issues;
}

const uniqueHint = "Give every grant, deny rule and approval rule its own id.";

function deepFreeze(value: unknown): void {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return;
  Object.freeze(value);
  for (const item of Object.values(value)) deepFreeze(item);
}

function ownObject(value: object, key: string): object {
  const item: unknown = Object.hasOwn(value, key) ? Reflect.get(value, key) : undefined;
  return typeof item === "object" && item !== null ? item : {};
}

function nullObject(): Record<string, never> {
  const empty: Record<string, never> = Object.create(null);
  return empty;
}
