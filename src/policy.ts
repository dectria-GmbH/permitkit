import { boundedSnapshot, policyBounds } from "./bounds.js";
import { compareText, digest } from "./canonical.js";
import { isCatalog, type Catalog } from "./catalog.js";
import { PermitkitError, type ErrorCode, type PolicyIssue } from "./errors.js";
import {
  policyDocument,
  policySchemaVersion,
  type ApprovalRule,
  type DenyRule,
  type GrantRule,
  type PolicyDocument,
  type Scope,
} from "./policy-document.js";
import { mapGet, mapSet } from "./intrinsics.js";
import { invalid, joined, type Issue } from "./validate.js";

export { policySchemaVersion } from "./policy-document.js";
export type {
  ApprovalRule,
  DenyRule,
  EligibleApprovers,
  GrantRule,
  Limits,
  PolicyDocument,
  PolicyInput,
  Scope,
  When,
} from "./policy-document.js";

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
  return mapGet(internals, value);
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
  try {
    return compileChecked(catalog, input);
  } catch (error) {
    if (PermitkitError.is(error) && isCompileCode(error.code)) throw error;
    // Data-valued pollution of built-in prototypes can make internals throw, for example a
    // replaced Array.prototype.toSorted. The caller still gets a PermitkitError, never the raw
    // error, whose text could come from the polluted value.
    throw new PermitkitError("policy_invalid", "The policy document could not be compiled.", [
      {
        path: "",
        message: "Compiling the policy failed inside permitkit.",
        hint: "Check for changed built-in prototypes in this process, then compile again.",
      },
    ]);
  }
}

/**
 * The error codes that compilePolicy itself throws. Any other error becomes policy_invalid.
 * Plain comparisons, no Set: a polluted Set.prototype.has would throw here.
 */
function isCompileCode(code: ErrorCode): boolean {
  return (
    code === "catalog_invalid" || code === "policy_invalid" || code === "policy_schema_unsupported"
  );
}

function compileChecked(catalog: Catalog, input: unknown): CompiledPolicy {
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
  const found: Issue[] = [];
  const document = validated(snapshot, found);
  if (document === invalid) {
    const issues: PolicyIssue[] = [];
    for (let index = 0; index < found.length; index += 1) {
      const item = found[index];
      if (item === undefined) continue;
      issues.push({
        path: joined(item.path, "."),
        message: item.message,
        hint: "Fix the field shape. Unknown keys are rejected, so check the spelling.",
      });
    }
    throw new PermitkitError("policy_invalid", "The policy document is not valid.", issues);
  }
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
  mapSet(
    internals,
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

/**
 * The validated document, a fresh copy in objects without a prototype, or `invalid` with at
 * least one issue. Never throws: an input that breaks validation counts as invalid.
 */
function validated(snapshot: unknown, issues: Issue[]): PolicyDocument | typeof invalid {
  try {
    return policyDocument(snapshot, null, issues);
  } catch {
    issues.length = 0;
    issues.push({ path: [], message: "The input could not be validated." });
    return invalid;
  }
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
    for (let roleIndex = 0; roleIndex < roles.length; roleIndex += 1) {
      const role = roles[roleIndex];
      if (role === undefined || !roleNames.has(role)) {
        issues.push({
          path: `${path}.${roleIndex}`,
          message: `Role ${String(role)} is not defined.`,
          hint: "Define the role under roles, or fix the spelling.",
        });
      }
    }
  };

  const checkPermissions = (
    permissions: readonly string[],
    path: string,
    properties: { scope: readonly string[]; limits: readonly string[]; limitsKey: string },
  ) => {
    for (let index = 0; index < permissions.length; index += 1) {
      const permission = permissions[index];
      const resource = permission === undefined ? undefined : catalog.resourceOf(permission);
      if (resource === undefined) {
        issues.push({
          path: `${path}.permissions.${index}`,
          message: `Permission ${String(permission)} is not in the catalogue.`,
          hint: "Add the action to the catalogue in code, or fix the spelling.",
        });
        continue;
      }
      for (const name of properties.scope) {
        if (!resource.scopes.includes(name)) {
          issues.push({
            path: `${path}.scope.properties.${name}`,
            message: `Resource type ${resource.type} has no scope property ${name}.`,
            hint: `Use one of: ${joined(resource.scopes, ", ") || "(none)"}.`,
          });
        }
      }
      for (const name of properties.limits) {
        if (!resource.limits.includes(name)) {
          issues.push({
            path: `${path}.${properties.limitsKey}.properties.${name}`,
            message: `Resource type ${resource.type} has no limit property ${name}.`,
            hint: `Use one of: ${joined(resource.limits, ", ") || "(none)"}.`,
          });
        }
      }
    }
  };

  for (const roleName of Object.keys(document.roles)) {
    const role = document.roles[roleName];
    if (role === undefined) continue;
    for (let index = 0; index < role.grants.length; index += 1) {
      const grant = role.grants[index];
      if (grant === undefined) continue;
      const path = `roles.${roleName}.grants.${index}`;
      claimId(grant.id, path);
      checkPermissions(grant.permissions, path, {
        scope: scopeProperties(grant.scope),
        limits: grant.limits.kind === "range" ? Object.keys(grant.limits.properties) : [],
        limitsKey: "limits",
      });
    }
  }

  for (let index = 0; index < document.denies.length; index += 1) {
    const deny = document.denies[index];
    if (deny === undefined) continue;
    const path = `denies.${index}`;
    claimId(deny.id, path);
    checkPermissions(deny.permissions, path, {
      scope: scopeProperties(deny.scope),
      limits: [],
      limitsKey: "limits",
    });
    if (deny.roles !== undefined) checkRoles(deny.roles, `${path}.roles`);
  }

  const ruled = new Map<string, string>();
  for (let index = 0; index < document.approvalRules.length; index += 1) {
    const rule = document.approvalRules[index];
    if (rule === undefined) continue;
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
  }

  return issues;
}

const uniqueHint = "Give every grant, deny rule and approval rule its own id.";

function deepFreeze(value: unknown): void {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) return;
  Object.freeze(value);
  for (const item of Object.values(value)) deepFreeze(item);
}
