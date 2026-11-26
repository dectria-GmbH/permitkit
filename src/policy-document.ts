/**
 * The policy document format (schema 2): its types and its validator. Every rule here has a
 * named test in `test/policy-validator.test.ts` and is compared with the verdicts of the earlier
 * Zod schema in `test/zod-verdicts.test.ts`.
 */

import { hasOwn } from "./intrinsics.js";
import { maxApprovalWindowSeconds } from "./time.js";
import {
  at,
  bare,
  bool,
  dictionary,
  fail,
  finiteNumber,
  invalid,
  isObject,
  knownKeys,
  list,
  nullable,
  oneOf,
  optional,
  own,
  required,
  text,
  type Check,
  type Checked,
  type Issue,
  type Path,
} from "./validate.js";

/** The policy document format that this release reads. Older formats are refused. */
export const policySchemaVersion = 2;

/**
 * Where a grant, role assignment, agent grant entry or deny rule applies.
 * `{ kind: "all" }` is the only way to say "everywhere". `{ kind: "match", properties }` lists
 * the allowed string values per resource property.
 */
export type Scope = { kind: "all" } | { kind: "match"; properties: Record<string, string[]> };

/**
 * Numeric limits of a grant or agent grant entry. `{ kind: "unlimited" }` is the only way to
 * say "no limit". `{ kind: "range", properties }` gives an inclusive range per numeric resource
 * property; each bound is a number, or `null` for "no bound on this side".
 */
export type Limits =
  | { kind: "unlimited" }
  | { kind: "range"; properties: Record<string, { min: number | null; max: number | null }> };

/**
 * When an approval rule applies. `{ kind: "always" }` applies to every covered request.
 * `{ kind: "threshold", properties }` applies if any listed property is at least `gte`, is
 * missing, or is not a finite number.
 */
export type When =
  { kind: "always" } | { kind: "threshold"; properties: Record<string, { gte: number }> };

/**
 * Who may approve. `{ kind: "roles", roles }`: a holder of one of these roles whose assignment
 * scope covers the resource. `{ kind: "permission" }`: a holder of the permission itself.
 */
export type EligibleApprovers = { kind: "permission" } | { kind: "roles"; roles: string[] };

export type GrantRule = {
  id: string;
  permissions: string[];
  scope: Scope;
  limits: Limits;
};

export type RoleDefinition = {
  description?: string | undefined;
  grants: GrantRule[];
};

export type DenyRule = {
  id: string;
  description?: string | undefined;
  permissions: string[];
  /** The rule applies only to subjects that hold one of these roles. Absent: everyone. */
  roles?: string[] | undefined;
  /** The rule applies only to these subject types. `agent` means an agent acts. Absent: all. */
  subjectTypes?: ("human" | "service" | "agent")[] | undefined;
  /**
   * The resources the rule applies to. In a match scope, a property that is missing on the
   * resource or is not a string counts as inside, so leaving out a property never escapes it.
   */
  scope: Scope;
};

export type ApprovalRule = {
  id: string;
  description?: string | undefined;
  permissions: string[];
  when: When;
  /**
   * Number of distinct approvers. The requester is never one of them, unless the separation
   * rule of the request allows self-approval; the number stays the same then.
   */
  approvers: number;
  eligibleApprovers: EligibleApprovers;
  /** Approvals count only inside this window after the request time. */
  expiresInSeconds: number;
  /** Each approval must carry a proof that a registered verifier accepts. */
  requireProof: boolean;
  /** The proof types that count. Required with requireProof, refused without it. */
  proofTypes?: string[] | undefined;
};

export type SeparationOfDuties = {
  /** An approver whom `priorRequests` lists with the requested permission may not approve. */
  requesterNeverApprovesSameType: boolean;
  /** Nobody may hold both a requesting and an approving role for the same permission. */
  exclusiveRequestAndApproveRoles: boolean;
  /**
   * `"required"`: an evaluateApprovals input for a request that needs approval must carry a
   * separation rule, and an input without one is refused (`separation_rule_missing`). A request
   * that needs no approval is not affected. Absent: an input without a rule is evaluated as
   * before, with the requester refused and the two flags above. Such an input skips the
   * contributor check silently, so set `"required"` where contributors are used.
   */
  perRequestRule?: "required" | undefined;
};

/** A validated policy document. */
export type PolicyDocument = {
  /** Format version of the policy document. */
  schema: 2;
  /** Operator-chosen version label. Decisions and audit records carry it. */
  version: string;
  roles: Record<string, RoleDefinition>;
  // Required, also when empty: a lost list must not read as "no deny rules".
  denies: DenyRule[];
  approvalRules: ApprovalRule[];
  separationOfDuties: SeparationOfDuties;
};

/** A policy document as you write it. The validator changes nothing, so it equals the output. */
export type PolicyInput = PolicyDocument;

const identifier = text({
  min: 1,
  max: 128,
  pattern: /^[A-Za-z0-9][A-Za-z0-9_.:-]*$/,
  patternMessage: "Use letters, digits, and _ . : - only.",
});

// No length limit of its own: the size guard bounds every string.
const permissionName = text({
  pattern: /^[a-z][a-z0-9_-]*:[a-z][a-z0-9_-]*$/,
  patternMessage: "Use the form <resource>:<action>.",
});

const description = text({ max: 1000 });
const permissions = list(permissionName, { min: 1 });
const identifiers = list(identifier, { min: 1 });

/**
 * A value whose `kind` says which shape it has. A missing, null, empty or unknown `kind` is
 * refused; no shape is ever read as the wide case by default.
 */
function explicit<T>(
  what: string,
  shapes: string,
  options: Readonly<Record<string, (value: object, path: Path, issues: Issue[]) => Checked<T>>>,
): Check<T> {
  const message = `State the ${what} explicitly: ${shapes}. A missing, null, empty or unknown ${what} is refused.`;
  return (value, path, issues) => {
    if (!isObject(value)) return fail(issues, path, message);
    const kind = own(value, "kind");
    // Own keys of the option table only, so `constructor` or `toString` is no shape.
    const option = typeof kind === "string" && hasOwn(options, kind) ? options[kind] : undefined;
    if (option === undefined) return fail(issues, at(path, "kind"), message);
    return option(value, path, issues);
  };
}

/** A shape that has nothing but its `kind`. */
function kindOnly<const K extends string>(kind: K) {
  return (value: object, path: Path, issues: Issue[]): Checked<{ kind: K }> =>
    knownKeys(value, ["kind"], path, issues) ? bare({ kind }) : invalid;
}

/** A shape with `kind` and `properties`. */
function withProperties<const K extends string, P>(kind: K, properties: Check<P>) {
  return (value: object, path: Path, issues: Issue[]): Checked<{ kind: K; properties: P }> => {
    const checked = required(value, "properties", path, issues, properties);
    const known = knownKeys(value, ["kind", "properties"], path, issues);
    return checked === invalid || !known ? invalid : bare({ kind, properties: checked });
  };
}

const nonEmptyText = text({ min: 1 });

const scopeValue: Check<string> = (value, path, issues) => {
  const checked = nonEmptyText(value, path, issues);
  if (checked === "*") {
    return fail(issues, path, '"*" is not a wildcard. Use { kind: "all" } for everywhere.');
  }
  return checked;
};

/** Property name to the list of allowed string values. At least one property. */
const scopeValueLists = dictionary(list(scopeValue, { min: 1, max: 1000 }), {
  key: identifier,
  nonEmpty: 'A match scope needs at least one property. Use { kind: "all" } for everywhere.',
});

export const scope: Check<Scope> = explicit<Scope>(
  "scope",
  '{ kind: "all" } or { kind: "match", properties: { <property>: [<values>] } }',
  { all: kindOnly("all"), match: withProperties("match", scopeValueLists) },
);

const bound = nullable(finiteNumber({}));

/**
 * An inclusive numeric range. Both bounds are required: a number, or `null` for "no bound on
 * this side". A lost bound is refused, never read as open. At least one bound is a number.
 */
const limit: Check<{ min: number | null; max: number | null }> = (value, path, issues) => {
  if (!isObject(value)) return fail(issues, path, "Expected { min, max }.");
  const min = required(value, "min", path, issues, bound);
  const max = required(value, "max", path, issues, bound);
  const known = knownKeys(value, ["min", "max"], path, issues);
  if (min === invalid || max === invalid || !known) return invalid;
  if (min === null && max === null) {
    return fail(
      issues,
      path,
      "Give at least one bound as a number. Both bounds null restrict nothing.",
    );
  }
  if (min !== null && max !== null && min > max) {
    return fail(issues, path, "min must not be greater than max.");
  }
  return bare({ min, max });
};

export const limits: Check<Limits> = explicit<Limits>(
  "limits",
  '{ kind: "unlimited" } or { kind: "range", properties: { <property>: { min, max } } } with each bound a number or null',
  {
    unlimited: kindOnly("unlimited"),
    range: withProperties(
      "range",
      dictionary(limit, {
        key: identifier,
        nonEmpty: 'A range needs at least one property. Use { kind: "unlimited" } for no limit.',
      }),
    ),
  },
);

const gteNumber = finiteNumber({});

const threshold: Check<{ gte: number }> = (value, path, issues) => {
  if (!isObject(value)) return fail(issues, path, "Expected { gte }.");
  const gte = required(value, "gte", path, issues, gteNumber);
  const known = knownKeys(value, ["gte"], path, issues);
  return gte === invalid || !known ? invalid : bare({ gte });
};

const when: Check<When> = explicit<When>(
  "when condition",
  '{ kind: "always" } or { kind: "threshold", properties: { <property>: { gte } } }',
  {
    always: kindOnly("always"),
    threshold: withProperties(
      "threshold",
      dictionary(threshold, {
        key: identifier,
        nonEmpty: 'A threshold needs at least one property. Use { kind: "always" } instead.',
      }),
    ),
  },
);

const eligibleApprovers: Check<EligibleApprovers> = explicit<EligibleApprovers>(
  "approver eligibility",
  '{ kind: "roles", roles: [<role>] } or { kind: "permission" }',
  {
    permission: kindOnly("permission"),
    roles: (value, path, issues) => {
      const roles = required(value, "roles", path, issues, identifiers);
      const known = knownKeys(value, ["kind", "roles"], path, issues);
      return roles === invalid || !known ? invalid : bare({ kind: "roles" as const, roles });
    },
  },
);

const grant: Check<GrantRule> = (value, path, issues) => {
  if (!isObject(value)) return fail(issues, path, "Expected a grant object.");
  const id = required(value, "id", path, issues, identifier);
  const granted = required(value, "permissions", path, issues, permissions);
  const where = required(value, "scope", path, issues, scope);
  const bounds = required(value, "limits", path, issues, limits);
  const known = knownKeys(value, ["id", "permissions", "scope", "limits"], path, issues);
  if (id === invalid || granted === invalid || where === invalid || bounds === invalid || !known) {
    return invalid;
  }
  return bare({ id, permissions: granted, scope: where, limits: bounds });
};

const grantList = list(grant);

const role: Check<RoleDefinition> = (value, path, issues) => {
  if (!isObject(value)) return fail(issues, path, "Expected a role object.");
  const about = optional(value, "description", path, issues, description);
  const grants = required(value, "grants", path, issues, grantList);
  const known = knownKeys(value, ["description", "grants"], path, issues);
  if (about.value === invalid || grants === invalid || !known) return invalid;
  return bare({ ...(about.present ? { description: about.value } : {}), grants });
};

const subjectType = oneOf(["human", "service", "agent"]);
const subjectTypes = list(subjectType, { min: 1 });

const deny: Check<DenyRule> = (value, path, issues) => {
  if (!isObject(value)) return fail(issues, path, "Expected a deny rule object.");
  const id = required(value, "id", path, issues, identifier);
  const about = optional(value, "description", path, issues, description);
  const denied = required(value, "permissions", path, issues, permissions);
  const roles = optional(value, "roles", path, issues, identifiers);
  const types = optional(value, "subjectTypes", path, issues, subjectTypes);
  const where = required(value, "scope", path, issues, scope);
  const known = knownKeys(
    value,
    ["id", "description", "permissions", "roles", "subjectTypes", "scope"],
    path,
    issues,
  );
  if (
    id === invalid ||
    about.value === invalid ||
    denied === invalid ||
    roles.value === invalid ||
    types.value === invalid ||
    where === invalid ||
    !known
  ) {
    return invalid;
  }
  return bare({
    id,
    ...(about.present ? { description: about.value } : {}),
    permissions: denied,
    ...(roles.present ? { roles: roles.value } : {}),
    ...(types.present ? { subjectTypes: types.value } : {}),
    scope: where,
  });
};

const approvers = finiteNumber({ integer: true, min: 1, max: 10 });
const window = finiteNumber({ integer: true, min: 60, max: maxApprovalWindowSeconds });
const proofTypes = list(text({ min: 1, max: 64 }), { min: 1 });

/** The `proofTypes` rules (required with `requireProof`, refused without) run after this. */
const approvalRule: Check<ApprovalRule> = (value, path, issues) => {
  if (!isObject(value)) return fail(issues, path, "Expected an approval rule object.");
  const id = required(value, "id", path, issues, identifier);
  const about = optional(value, "description", path, issues, description);
  const ruled = required(value, "permissions", path, issues, permissions);
  const condition = required(value, "when", path, issues, when);
  const count = required(value, "approvers", path, issues, approvers);
  const eligible = required(value, "eligibleApprovers", path, issues, eligibleApprovers);
  const expiresInSeconds = required(value, "expiresInSeconds", path, issues, window);
  const requireProof = required(value, "requireProof", path, issues, bool);
  const types = optional(value, "proofTypes", path, issues, proofTypes);
  const known = knownKeys(
    value,
    [
      "id",
      "description",
      "permissions",
      "when",
      "approvers",
      "eligibleApprovers",
      "expiresInSeconds",
      "requireProof",
      "proofTypes",
    ],
    path,
    issues,
  );
  if (
    id === invalid ||
    about.value === invalid ||
    ruled === invalid ||
    condition === invalid ||
    count === invalid ||
    eligible === invalid ||
    expiresInSeconds === invalid ||
    requireProof === invalid ||
    types.value === invalid ||
    !known
  ) {
    return invalid;
  }
  return bare({
    id,
    ...(about.present ? { description: about.value } : {}),
    permissions: ruled,
    when: condition,
    approvers: count,
    eligibleApprovers: eligible,
    expiresInSeconds,
    requireProof,
    ...(types.present ? { proofTypes: types.value } : {}),
  });
};

const perRequestRule = oneOf(["required"]);

const separationOfDuties: Check<SeparationOfDuties> = (value, path, issues) => {
  if (!isObject(value)) return fail(issues, path, "Expected the separation of duties flags.");
  const never = required(value, "requesterNeverApprovesSameType", path, issues, bool);
  const exclusive = required(value, "exclusiveRequestAndApproveRoles", path, issues, bool);
  const perRequest = optional(value, "perRequestRule", path, issues, perRequestRule);
  const known = knownKeys(
    value,
    ["requesterNeverApprovesSameType", "exclusiveRequestAndApproveRoles", "perRequestRule"],
    path,
    issues,
  );
  if (never === invalid || exclusive === invalid || perRequest.value === invalid || !known) {
    return invalid;
  }
  // The key is in the output only with its one value, so a document without it keeps its digest.
  return bare({
    requesterNeverApprovesSameType: never,
    exclusiveRequestAndApproveRoles: exclusive,
    ...(perRequest.value === undefined ? {} : { perRequestRule: perRequest.value }),
  });
};

const schemaVersion: Check<2> = (value, path, issues) =>
  value === policySchemaVersion ? policySchemaVersion : fail(issues, path, "Use schema 2.");

/**
 * Validates a policy document as the size guard copied it. The cross-references (catalogue,
 * role names, rule ids, proof types) are checked in compilePolicy after this.
 */
const versionLabel = text({ min: 1, max: 128 });
const roleTable = dictionary(role, { key: identifier });
const denyList = list(deny);
const approvalRuleList = list(approvalRule);

export const policyDocument: Check<PolicyDocument> = (value, path, issues) => {
  if (!isObject(value)) return fail(issues, path, "Expected a policy document object.");
  const schema = required(value, "schema", path, issues, schemaVersion);
  const version = required(value, "version", path, issues, versionLabel);
  const roles = required(value, "roles", path, issues, roleTable);
  const denies = required(value, "denies", path, issues, denyList);
  const rules = required(value, "approvalRules", path, issues, approvalRuleList);
  const duties = required(value, "separationOfDuties", path, issues, separationOfDuties);
  const known = knownKeys(
    value,
    ["schema", "version", "roles", "denies", "approvalRules", "separationOfDuties"],
    path,
    issues,
  );
  if (
    schema === invalid ||
    version === invalid ||
    roles === invalid ||
    denies === invalid ||
    rules === invalid ||
    duties === invalid ||
    !known
  ) {
    return invalid;
  }
  return bare({
    schema,
    version,
    roles,
    denies,
    approvalRules: rules,
    separationOfDuties: duties,
  });
};
