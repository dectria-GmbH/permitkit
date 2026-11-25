import { boundedSnapshot, requestBounds } from "./bounds.js";
import { digest } from "./canonical.js";
import {
  limitsHold,
  scopeCovers,
  scopeTouches,
  whenApplies,
  type LimitResult,
  type ScopeResult,
} from "./engine/conditions.js";
import { PermitkitError } from "./errors.js";
import { internalsOf, type CompiledPolicy, type DenyRule, type PolicyInternals } from "./policy.js";
import { reasonHints, type ReasonCode } from "./reasons.js";
import {
  accessRequest,
  type AccessRequest,
  type Actor,
  type Scalar,
  type Subject,
} from "./request.js";
import { instant } from "./time.js";
import {
  append,
  contains,
  isoOf,
  newSet,
  setAdd,
  setHas,
  weakMapGet,
  weakMapSet,
} from "./intrinsics.js";
import { invalid, joined, type Issue } from "./validate.js";

export type Outcome = "allow" | "deny" | "approval_required";

export type MatchedRule =
  | { readonly kind: "grant"; readonly role: string; readonly id: string }
  | { readonly kind: "deny"; readonly id: string };

export interface ApprovalRequirement {
  readonly ruleId: string;
  readonly approvers: number;
  readonly approverRoles: readonly string[] | null;
  readonly requireProof: boolean;
  /** End of the approval window, as ISO 8601 UTC. */
  readonly expiresAt: string;
}

export interface Decision {
  readonly outcome: Outcome;
  /** True only for `allow`. `approval_required` is not allowed yet. */
  readonly allowed: boolean;
  readonly reason: ReasonCode;
  /** The deny rule that matched, or the grant that covered the request. */
  readonly rule: MatchedRule | null;
  readonly approval: ApprovalRequirement | null;
  readonly policy: { readonly version: string; readonly digest: string };
  /** Digest of the request, see requestDigest(). Null if the request was not valid. */
  readonly requestDigest: string | null;
}

export type TraceStep =
  | { step: "validate"; ok: boolean; issues: { path: string; message: string }[] }
  | { step: "policy_version"; ok: boolean; pinned: string | null; loaded: string }
  | { step: "permission"; ok: boolean; permission: string }
  | { step: "agent_grant"; ok: boolean; reason: ReasonCode | null; grantId: string | null }
  | { step: "deny_rule"; id: string; matched: boolean }
  | { step: "role"; role: string; known: boolean }
  | {
      step: "grant";
      role: string;
      id: string;
      result: "matched" | "assignment_scope_mismatch" | "scope_mismatch" | "limit_exceeded";
      detail: ScopeResult | LimitResult;
    }
  | {
      step: "agent_grant_entry";
      index: number;
      result: "matched" | "no_permission" | "scope_mismatch" | "limit_exceeded";
    }
  | { step: "separation_of_duties"; ok: boolean; conflictingRoles: string[] }
  | { step: "approval_rule"; id: string; applies: boolean };

export interface Explanation {
  readonly decision: Decision;
  readonly hint: string;
  readonly steps: readonly TraceStep[];
}

/**
 * Decides a request against a compiled policy. The result depends only on the policy and the
 * request (including context.now), so the same inputs always give the same decision.
 * Deny by default: without a covering grant the outcome is `deny`.
 */
export function decide(policy: CompiledPolicy, request: unknown): Decision {
  return guarded(policy, () => run(policy, request, undefined));
}

/** Like decide(), plus every evaluation step and a fix hint for the reason code. */
export function explain(policy: CompiledPolicy, request: unknown): Explanation {
  const steps: TraceStep[] = [];
  const decision = guarded(policy, () => run(policy, request, steps));
  return { decision, hint: reasonHints[decision.reason], steps };
}

/** The permission name of a request: `<resource.type>:<action.name>`. */
export function permissionOf(request: Pick<AccessRequest, "action" | "resource">): string {
  return `${request.resource.type}:${request.action.name}`;
}

/**
 * SHA-256 that identifies one request instance under one policy: principal, every actor with
 * the content of its grant (without revokedAt, which may change later), action, resource and
 * request time. Role assignments are not part of it; evaluateApprovals checks the requester's
 * roles again at evaluation time. Approvals and approval proofs bind to this value.
 * Throws PermitkitError `request_invalid` if the request does not match the schema.
 */
export function requestDigest(policy: CompiledPolicy, request: unknown): string {
  if (internalsOf(policy) === undefined) {
    throw new PermitkitError(
      "policy_unknown",
      "requestDigest() needs a policy from compilePolicy().",
    );
  }
  const parsed = parseRequest(request);
  if (!parsed.ok) {
    throw new PermitkitError("request_invalid", "requestDigest() needs a valid request.");
  }
  try {
    return digestOfRequest(policy, parsed.request);
  } catch {
    throw new PermitkitError("request_invalid", "requestDigest() could not hash the request.");
  }
}

export type ParsedRequest =
  { ok: true; request: AccessRequest } | { ok: false; issues: { path: string; message: string }[] };

/** Size guard plus validation. Never throws, also not for hostile getters or proxies. */
export function parseRequest(input: unknown): ParsedRequest {
  try {
    return parseRequestUnguarded(input);
  } catch {
    // Polluted built-in prototypes can break array methods used below. Built without them.
    return { ok: false, issues: [{ path: "", message: "The input could not be validated." }] };
  }
}

function parseRequestUnguarded(input: unknown): ParsedRequest {
  const snapshot = boundedSnapshot(input, requestBounds);
  if (snapshot === undefined) return { ok: false, issues: [{ path: "", message: oversized }] };
  const found: Issue[] = [];
  const request = accessRequest(snapshot, null, found);
  if (request !== invalid) return { ok: true, request };
  const issues: { path: string; message: string }[] = [];
  for (let index = 0; index < found.length; index += 1) {
    const item = found[index];
    if (item !== undefined) append(issues, { path: joined(item.path, "."), message: item.message });
  }
  return { ok: false, issues };
}

/**
 * True if a deny rule applies to the subject for this permission and resource. Index loops and
 * captured Set methods only: a replaced Array.prototype.some or includes, or a replaced Set
 * method, must not let a request pass a deny rule.
 */
export function denyRuleMatches(
  rule: DenyRule,
  subject: Subject,
  permission: string,
  properties: Readonly<Record<string, Scalar>> | undefined,
): boolean {
  if (!contains(rule.permissions, permission) || !scopeTouches(rule.scope, properties)) {
    return false;
  }
  const facts = factsOf(subject);
  return (
    (rule.roles === undefined || holdsAny(facts.held, rule.roles)) &&
    (rule.subjectTypes === undefined || holdsAny(facts.types, rule.subjectTypes))
  );
}

/** True if the set holds one of the values. */
function holdsAny(set: Set<string>, values: readonly string[]): boolean {
  for (let index = 0; index < values.length; index += 1) {
    const value = values[index];
    if (value !== undefined && setHas(set, value)) return true;
  }
  return false;
}

/** The role names of a validated subject. */
function heldRolesOf(subject: Subject): Set<string> {
  const held = newSet<string>();
  for (let index = 0; index < subject.roles.length; index += 1) {
    const assignment = subject.roles[index];
    if (assignment !== undefined) setAdd(held, assignment.role);
  }
  return held;
}

const subjectFacts = new WeakMap<Subject, { types: Set<string>; held: Set<string> }>();

/** Subject types and held roles, computed once per validated subject object. */
function factsOf(subject: Subject): { types: Set<string>; held: Set<string> } {
  let facts = weakMapGet(subjectFacts, subject);
  if (facts === undefined) {
    const types = newSet<string>();
    setAdd(types, subject.type);
    if (subject.act !== null) setAdd(types, "agent");
    facts = { types, held: heldRolesOf(subject) };
    weakMapSet(subjectFacts, subject, facts);
  }
  return facts;
}

function digestOfRequest(policy: CompiledPolicy, request: AccessRequest): string {
  const actors: unknown[] = [];
  for (let actor = request.subject.act; actor !== null; actor = actor.act) {
    const grant = actor.grant;
    append(actors, {
      id: actor.id,
      grant:
        grant === null
          ? null
          : {
              id: grant.id,
              principalId: grant.principalId,
              principalType: grant.principalType,
              agentId: grant.agentId,
              entries: grant.entries,
              notBefore: grant.notBefore === null ? null : utc(grant.notBefore),
              expiresAt: utc(grant.expiresAt),
            },
    });
  }
  return digest({
    schema: "permitkit.request/2",
    policy: { version: policy.version, digest: policy.digest },
    principal: { type: request.subject.type, id: request.subject.id },
    actors,
    action: request.action,
    resource: {
      type: request.resource.type,
      id: request.resource.id ?? null,
      properties: request.resource.properties ?? {},
    },
    requestedAt: utc(request.context.now),
  });
}

function utc(value: string): string {
  return isoOf(instant(value));
}

const oversized = "The input exceeds the size bounds (depth, nodes, array or string length).";

function run(policy: CompiledPolicy, input: unknown, trace: TraceStep[] | undefined): Decision {
  const internal: PolicyInternals | undefined = internalsOf(policy);
  if (internal === undefined) {
    throw new PermitkitError("policy_unknown", "decide() needs a policy from compilePolicy().");
  }
  const policyRef = { version: policy.version, digest: policy.digest };
  const deny = (
    reason: ReasonCode,
    requestDigestValue: string | null,
    rule: MatchedRule | null = null,
  ): Decision => ({
    outcome: "deny",
    allowed: false,
    reason,
    rule,
    approval: null,
    policy: policyRef,
    requestDigest: requestDigestValue,
  });

  // Each trace step is appended, not pushed: see append in intrinsics.ts.
  const record = (step: TraceStep): void => {
    if (trace !== undefined) append(trace, step);
  };

  const parsed = parseRequest(input);
  record({ step: "validate", ok: parsed.ok, issues: parsed.ok ? [] : parsed.issues });
  if (!parsed.ok) return deny("invalid_request", null);
  const request = parsed.request;
  const requestDigestValue = digestOfRequest(policy, request);
  const now = instant(request.context.now);

  const pinned = request.context.policyVersion ?? null;
  const pinnedDigest = request.context.policyDigest ?? null;
  const versionOk =
    (pinned === null || pinned === policy.version) &&
    (pinnedDigest === null || pinnedDigest === policy.digest);
  record({ step: "policy_version", ok: versionOk, pinned, loaded: policy.version });
  if (!versionOk) return deny("policy_version_mismatch", requestDigestValue);

  const permission = permissionOf(request);
  const known = policy.catalog.isPermission(permission);
  record({ step: "permission", ok: known, permission });
  if (!known) return deny("unknown_permission", requestDigestValue);

  const actor = request.subject.act;
  if (actor !== null) {
    const reason = agentGrantValidity(actor, request.subject, now);
    record({
      step: "agent_grant",
      ok: reason === null,
      reason,
      grantId: actor.grant?.id ?? null,
    });
    if (reason !== null) return deny(reason, requestDigestValue);
    // A chain acts for one principal. A prior actor's grant from someone else would hide that
    // person behind the request, where the requester exclusion of dual approval cannot see them.
    // A revoked or expired grant upstream also ends the chain. Prior grants grant nothing, so
    // their coverage is not checked.
    for (let prior = actor.act; prior !== null; prior = prior.act) {
      if (prior.grant === null) continue;
      const priorReason = agentGrantValidity(prior, request.subject, now);
      if (priorReason !== null) {
        const mapped =
          priorReason === "agent_grant_actor_mismatch"
            ? "agent_grant_principal_mismatch"
            : priorReason;
        return deny(mapped, requestDigestValue);
      }
    }
  }

  const properties = request.resource.properties;
  const heldRoles = heldRolesOf(request.subject);
  // Index loops, no for-of: an early exit closes an iterator, and closing reads `return`
  // through the prototype chain, which a polluted Object.prototype supplies.
  for (let index = 0; index < internal.denies.length; index += 1) {
    const rule = internal.denies[index];
    // An unreadable deny rule is an internal failure: guarded() turns it into the documented
    // deny with reason invalid_request. It is never skipped.
    if (rule === undefined) throw new Error("A deny rule could not be read.");
    const matched = denyRuleMatches(rule, request.subject, permission, properties);
    record({ step: "deny_rule", id: rule.id, matched });
    if (matched) return deny("denied_by_rule", requestDigestValue, { kind: "deny", id: rule.id });
  }

  let matchedGrant: MatchedRule | null = null;
  let closestFailure: "scope_mismatch" | "limit_exceeded" | null = null;
  search: for (let index = 0; index < request.subject.roles.length; index += 1) {
    const assignment = request.subject.roles[index];
    if (assignment === undefined) continue;
    const role = internal.roles.get(assignment.role);
    record({ step: "role", role: assignment.role, known: role !== undefined });
    if (role === undefined) continue;
    for (let grantIndex = 0; grantIndex < role.grants.length; grantIndex += 1) {
      const grant = role.grants[grantIndex];
      if (grant === undefined || !contains(grant.permissions, permission)) continue;
      const assignmentScope = scopeCovers(assignment.scope, properties);
      if (!assignmentScope.ok) {
        record({
          step: "grant",
          role: role.name,
          id: grant.id,
          result: "assignment_scope_mismatch",
          detail: assignmentScope,
        });
        closestFailure ??= "scope_mismatch";
        continue;
      }
      const grantScope = scopeCovers(grant.scope, properties);
      if (!grantScope.ok) {
        record({
          step: "grant",
          role: role.name,
          id: grant.id,
          result: "scope_mismatch",
          detail: grantScope,
        });
        closestFailure ??= "scope_mismatch";
        continue;
      }
      const limits = limitsHold(grant.limits, properties);
      if (!limits.ok) {
        record({
          step: "grant",
          role: role.name,
          id: grant.id,
          result: "limit_exceeded",
          detail: limits,
        });
        closestFailure = "limit_exceeded";
        continue;
      }
      record({
        step: "grant",
        role: role.name,
        id: grant.id,
        result: "matched",
        detail: limits,
      });
      matchedGrant = { kind: "grant", role: role.name, id: grant.id };
      break search;
    }
  }
  if (matchedGrant === null) return deny(closestFailure ?? "no_grant", requestDigestValue);

  if (actor !== null && actor.grant !== null) {
    let covered = false;
    const entries = actor.grant.entries;
    for (let index = 0; index < entries.length && !covered; index += 1) {
      const entry = entries[index];
      if (entry === undefined) continue;
      let result: "matched" | "no_permission" | "scope_mismatch" | "limit_exceeded";
      if (!contains(entry.permissions, permission)) result = "no_permission";
      else if (!scopeCovers(entry.scope, properties).ok) result = "scope_mismatch";
      else if (!limitsHold(entry.limits, properties).ok) result = "limit_exceeded";
      else result = "matched";
      record({ step: "agent_grant_entry", index, result });
      covered = result === "matched";
    }
    if (!covered) return deny("agent_grant_insufficient", requestDigestValue);
  }

  const approvalRule = internal.approvalRules.get(permission);
  const approverRoles =
    approvalRule?.eligibleApprovers.kind === "roles" ? approvalRule.eligibleApprovers.roles : null;
  if (internal.separationOfDuties.exclusiveRequestAndApproveRoles && approvalRule !== undefined) {
    const conflicting: string[] = [];
    const candidates = approverRoles ?? [];
    for (let index = 0; index < candidates.length; index += 1) {
      const role = candidates[index];
      if (role !== undefined && setHas(heldRoles, role)) append(conflicting, role);
    }
    record({
      step: "separation_of_duties",
      ok: conflicting.length === 0,
      conflictingRoles: conflicting,
    });
    if (conflicting.length > 0) return deny("sod_role_conflict", requestDigestValue);
  }

  if (approvalRule !== undefined) {
    const applies = whenApplies(approvalRule.when, properties);
    record({ step: "approval_rule", id: approvalRule.id, applies });
    if (applies) {
      return {
        outcome: "approval_required",
        allowed: false,
        reason: "approval_required",
        rule: matchedGrant,
        approval: {
          ruleId: approvalRule.id,
          approvers: approvalRule.approvers,
          approverRoles,
          requireProof: approvalRule.requireProof,
          expiresAt: isoOf(now + approvalRule.expiresInSeconds * 1000),
        },
        policy: policyRef,
        requestDigest: requestDigestValue,
      };
    }
  }

  return {
    outcome: "allow",
    allowed: true,
    reason: "granted",
    rule: matchedGrant,
    approval: null,
    policy: policyRef,
    requestDigest: requestDigestValue,
  };
}

/** Every time check is written so that an unreadable time counts as a failed check. */
function agentGrantValidity(actor: Actor, principal: Subject, now: number): ReasonCode | null {
  const grant = actor.grant;
  if (grant === null) return "agent_grant_missing";
  if (grant.principalId !== principal.id || grant.principalType !== principal.type) {
    return "agent_grant_principal_mismatch";
  }
  if (grant.agentId !== actor.id) return "agent_grant_actor_mismatch";
  if (grant.revokedAt !== null && !(instant(grant.revokedAt) > now)) {
    return "agent_grant_revoked";
  }
  if (grant.notBefore !== null && !(instant(grant.notBefore) <= now)) {
    return "agent_grant_not_yet_valid";
  }
  if (!(instant(grant.expiresAt) > now)) return "agent_grant_expired";
  return null;
}

/**
 * Runs a decision and turns any failure into a deny. Pollution of built-in prototypes can make
 * library internals throw; the result must still be a deny, built here without array methods
 * that such pollution can break.
 */
function guarded(policy: CompiledPolicy, evaluate: () => Decision): Decision {
  // The documented error of decide() and explain(), decided before the try from the registry
  // alone. Inside the try, no error can become a throw.
  if (internalsOf(policy) === undefined) {
    throw new PermitkitError("policy_unknown", "decide() needs a policy from compilePolicy().");
  }
  try {
    return evaluate();
  } catch {
    // Every error denies, also a PermitkitError, and no property of it is read. Under accessor
    // pollution, internals can throw a caller-made error whose code getter lies or throws.
    return {
      outcome: "deny",
      allowed: false,
      reason: "invalid_request",
      rule: null,
      approval: null,
      policy: { version: policy.version, digest: policy.digest },
      requestDigest: null,
    };
  }
}
