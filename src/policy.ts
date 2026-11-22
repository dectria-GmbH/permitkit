import { z } from "zod";

import { boundedSnapshot, detach, policyBounds } from "./bounds.js";
import { compareText, digest } from "./canonical.js";
import { isCatalog, type Catalog } from "./catalog.js";
import { PermitkitError, type PolicyIssue } from "./errors.js";
import { safeParse } from "./parse.js";
import { maxApprovalWindowSeconds } from "./time.js";

/** The policy document format that this release reads. Older formats are refused. */
export const policySchemaVersion = 2;

const identifier = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9][A-Za-z0-9_.:-]*$/, "Use letters, digits, and _ . : - only.");
const permissionName = z
  .string()
  .regex(/^[a-z][a-z0-9_-]*:[a-z][a-z0-9_-]*$/, "Use the form <resource>:<action>.");

/**
 * A discriminated union on `kind` whose error names the accepted shapes. A missing, null, empty
 * or misspelt value is refused; no shape is ever read as the wide case by default.
 */
function explicit<
  Options extends [
    z.ZodDiscriminatedUnionOption<"kind">,
    ...z.ZodDiscriminatedUnionOption<"kind">[],
  ],
>(what: string, shapes: string, options: Options) {
  const message = `State the ${what} explicitly: ${shapes}. A missing, null, empty or unknown ${what} is refused.`;
  return z.discriminatedUnion("kind", options, {
    errorMap: (issue, context) =>
      issue.code === z.ZodIssueCode.invalid_type || issue.code === "invalid_union_discriminator"
        ? { message }
        : { message: context.defaultError },
  });
}

const scopeValue = z
  .string()
  .min(1)
  .refine((value) => value !== "*", '"*" is not a wildcard. Use { kind: "all" } for everywhere.');

/** Property name to the list of allowed string values. At least one property. */
const scopeValueLists = z
  .record(identifier, z.array(scopeValue).min(1).max(1000))
  .refine(
    (properties) => Object.keys(properties).length > 0,
    'A match scope needs at least one property. Use { kind: "all" } for everywhere.',
  );

/**
 * Where a grant, role assignment, agent grant entry or deny rule applies.
 * `{ kind: "all" }` is the only way to say "everywhere". `{ kind: "match", properties }` lists
 * the allowed string values per resource property.
 */
export const scopeSchema = explicit(
  "scope",
  '{ kind: "all" } or { kind: "match", properties: { <property>: [<values>] } }',
  [
    z.object({ kind: z.literal("all") }).strict(),
    z.object({ kind: z.literal("match"), properties: scopeValueLists }).strict(),
  ],
);

/**
 * An inclusive numeric range. Both bounds are required: a number, or `null` for "no bound on
 * this side". A lost bound is refused, never read as open. At least one bound is a number.
 */
const limitSchema = z
  .object({ min: z.number().finite().nullable(), max: z.number().finite().nullable() })
  .strict()
  .refine(
    (limit) => limit.min !== null || limit.max !== null,
    "Give at least one bound as a number. Both bounds null restrict nothing.",
  )
  .refine(
    (limit) => limit.min === null || limit.max === null || limit.min <= limit.max,
    "min must not be greater than max.",
  );

/**
 * Numeric limits of a grant or agent grant entry. `{ kind: "unlimited" }` is the only way to
 * say "no limit". `{ kind: "range", properties }` gives a range per numeric resource property.
 */
export const limitsSchema = explicit(
  "limits",
  '{ kind: "unlimited" } or { kind: "range", properties: { <property>: { min, max } } } with each bound a number or null',
  [
    z.object({ kind: z.literal("unlimited") }).strict(),
    z
      .object({
        kind: z.literal("range"),
        properties: z
          .record(identifier, limitSchema)
          .refine(
            (properties) => Object.keys(properties).length > 0,
            'A range needs at least one property. Use { kind: "unlimited" } for no limit.',
          ),
      })
      .strict(),
  ],
);

/**
 * When an approval rule applies. `{ kind: "always" }` applies to every covered request.
 * `{ kind: "threshold", properties }` applies if any listed property is at least `gte`, is
 * missing, or is not a finite number.
 */
export const whenSchema = explicit(
  "when condition",
  '{ kind: "always" } or { kind: "threshold", properties: { <property>: { gte } } }',
  [
    z.object({ kind: z.literal("always") }).strict(),
    z
      .object({
        kind: z.literal("threshold"),
        properties: z
          .record(identifier, z.object({ gte: z.number().finite() }).strict())
          .refine(
            (properties) => Object.keys(properties).length > 0,
            'A threshold needs at least one property. Use { kind: "always" } instead.',
          ),
      })
      .strict(),
  ],
);

/**
 * Who may approve. `{ kind: "roles", roles }`: a holder of one of these roles whose assignment
 * scope covers the resource. `{ kind: "permission" }`: a holder of the permission itself.
 */
export const eligibleApproversSchema = explicit(
  "approver eligibility",
  '{ kind: "roles", roles: [<role>] } or { kind: "permission" }',
  [
    z.object({ kind: z.literal("permission") }).strict(),
    z.object({ kind: z.literal("roles"), roles: z.array(identifier).min(1) }).strict(),
  ],
);

export const grantSchema = z
  .object({
    id: identifier,
    permissions: z.array(permissionName).min(1),
    scope: scopeSchema,
    limits: limitsSchema,
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
    /**
     * The resources the rule applies to. In a match scope, a property that is missing on the
     * resource or is not a string counts as inside, so leaving out a property never escapes it.
     */
    scope: scopeSchema,
  })
  .strict();

export const approvalRuleSchema = z
  .object({
    id: identifier,
    description: z.string().max(1000).optional(),
    permissions: z.array(permissionName).min(1),
    when: whenSchema,
    /** Number of distinct approvers besides the requester. */
    approvers: z.number().int().min(1).max(10),
    eligibleApprovers: eligibleApproversSchema,
    /** Approvals count only inside this window after the request time. */
    expiresInSeconds: z.number().int().min(60).max(maxApprovalWindowSeconds),
    /** Each approval must carry a proof that a registered verifier accepts. */
    requireProof: z.boolean(),
    /** The proof types that count. Required with requireProof, refused without it. */
    proofTypes: z.array(z.string().min(1).max(64)).min(1).optional(),
  })
  .strict();

export const separationOfDutiesSchema = z
  .object({
    /** Who requested an action of a type before may never approve an action of that type. */
    requesterNeverApprovesSameType: z.boolean(),
    /** Nobody may hold both a requesting and an approving role for the same permission. */
    exclusiveRequestAndApproveRoles: z.boolean(),
  })
  .strict();

export const policySchema = z
  .object({
    /** Format version of the policy document. */
    schema: z.literal(policySchemaVersion),
    /** Operator-chosen version label. Decisions and audit records carry it. */
    version: z.string().min(1).max(128),
    roles: z.record(identifier, roleSchema),
    // Required, also when empty: a lost list must not read as "no deny rules".
    denies: z.array(denySchema),
    approvalRules: z.array(approvalRuleSchema),
    separationOfDuties: separationOfDutiesSchema,
  })
  .strict();

export type PolicyInput = z.input<typeof policySchema>;
export type PolicyDocument = z.output<typeof policySchema>;
export type Scope = z.output<typeof scopeSchema>;
export type Limits = z.output<typeof limitsSchema>;
export type When = z.output<typeof whenSchema>;
export type EligibleApprovers = z.output<typeof eligibleApproversSchema>;
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
 * compiled policy. Throws PermitkitError with code `policy_schema_unsupported` for a document
 * in another format version, and `policy_invalid` with a list of issues for any other error.
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
    throw new PermitkitError(
      "policy_invalid",
      "The policy document is too large or not plain data.",
      [
        {
          path: "",
          message:
            "The document exceeds the size bounds, or holds values that are not plain data (getters, class instances, proxies).",
          hint: "Split very large scope lists, or raise the bounds in a fork if you need more.",
        },
      ],
    );
  }
  const format: unknown =
    typeof snapshot === "object" && snapshot !== null && Object.hasOwn(snapshot, "schema")
      ? Reflect.get(snapshot, "schema")
      : undefined;
  if (format !== undefined && format !== policySchemaVersion) {
    throw new PermitkitError(
      "policy_schema_unsupported",
      `The policy document has schema ${JSON.stringify(format)}. This release reads only schema ${policySchemaVersion}.`,
      [
        {
          path: "schema",
          message: `Schema ${JSON.stringify(format)} is not supported. There is no automatic migration.`,
          hint: "Rewrite the document for schema 2: every scope, limit, when condition and approver eligibility states its kind, and denies, approvalRules, separationOfDuties and requireProof are required.",
        },
      ],
    );
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

/** The property names that a scope restricts. `all` restricts none. */
export function scopeProperties(scope: Scope): readonly string[] {
  return scope.kind === "match" ? Object.keys(scope.properties) : [];
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
  const checkRoles = (roles: readonly string[], path: string) => {
    roles.forEach((role, roleIndex) => {
      if (!roleNames.has(role)) {
        issues.push({
          path: `${path}.${roleIndex}`,
          message: `Role ${role} is not defined.`,
          hint: "Define the role under roles, or fix the spelling.",
        });
      }
    });
  };

  const checkPermissions = (
    permissions: readonly string[],
    path: string,
    properties: { scope: readonly string[]; limits: readonly string[]; limitsKey: string },
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
      for (const name of properties.scope) {
        if (!resource.scopes.includes(name)) {
          issues.push({
            path: `${path}.scope.properties.${name}`,
            message: `Resource type ${resource.type} has no scope property ${name}.`,
            hint: `Use one of: ${resource.scopes.join(", ") || "(none)"}.`,
          });
        }
      }
      for (const name of properties.limits) {
        if (!resource.limits.includes(name)) {
          issues.push({
            path: `${path}.${properties.limitsKey}.properties.${name}`,
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
        scope: scopeProperties(grant.scope),
        limits: grant.limits.kind === "range" ? Object.keys(grant.limits.properties) : [],
        limitsKey: "limits",
      });
    });
  }

  document.denies.forEach((deny, index) => {
    const path = `denies.${index}`;
    claimId(deny.id, path);
    checkPermissions(deny.permissions, path, {
      scope: scopeProperties(deny.scope),
      limits: [],
      limitsKey: "limits",
    });
    if (deny.roles !== undefined) checkRoles(deny.roles, `${path}.roles`);
  });

  const ruled = new Map<string, string>();
  document.approvalRules.forEach((rule, index) => {
    const path = `approvalRules.${index}`;
    claimId(rule.id, path);
    checkPermissions(rule.permissions, path, {
      scope: [],
      limits: rule.when.kind === "threshold" ? Object.keys(rule.when.properties) : [],
      limitsKey: "when",
    });
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
    if (rule.eligibleApprovers.kind === "roles") {
      checkRoles(rule.eligibleApprovers.roles, `${path}.eligibleApprovers.roles`);
    }
    if (rule.requireProof && rule.proofTypes === undefined) {
      issues.push({
        path: `${path}.proofTypes`,
        message: "requireProof needs the list of proof types that count.",
        hint: 'Name the proof types, for example ["webauthn"]. A missing list would accept any registered verifier.',
      });
    }
    if (rule.proofTypes !== undefined && !rule.requireProof) {
      issues.push({
        path: `${path}.proofTypes`,
        message: "proofTypes has no effect without requireProof.",
        hint: "Set requireProof: true, or remove proofTypes.",
      });
    }
    if (
      document.separationOfDuties.exclusiveRequestAndApproveRoles &&
      rule.eligibleApprovers.kind !== "roles"
    ) {
      issues.push({
        path: `${path}.eligibleApprovers`,
        message: "Exclusive request and approve roles need approver roles on every rule.",
        hint: 'Use eligibleApprovers: { kind: "roles", roles: [...] }, or switch off exclusiveRequestAndApproveRoles.',
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
