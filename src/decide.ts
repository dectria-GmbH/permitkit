import { boundedSnapshot, requestBounds } from "./bounds.js";
import { digest } from "./canonical.js";
import {
  limitsHold,
  scopeCovers,
  scopeTouches,
  thresholdApplies,
  type LimitResult,
  type ScopeResult,
} from "./engine/conditions.js";
import { PermitkitError } from "./errors.js";
import { isCompiledPolicy, type CompiledPolicy } from "./policy.js";
import { reasonHints, type ReasonCode } from "./reasons.js";
import { accessRequestSchema, type AccessRequest, type Actor, type Subject } from "./request.js";

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
  return run(policy, request, undefined);
}

/** Like decide(), plus every evaluation step and a fix hint for the reason code. */
export function explain(policy: CompiledPolicy, request: unknown): Explanation {
  const steps: TraceStep[] = [];
  const decision = run(policy, request, steps);
  return { decision, hint: reasonHints[decision.reason], steps };
}

/** The permission name of a request: `<resource.type>:<action.name>`. */
export function permissionOf(request: Pick<AccessRequest, "action" | "resource">): string {
  return `${request.resource.type}:${request.action.name}`;
}

/**
 * SHA-256 that identifies one request instance under one policy: principal, actor chain,
 * action, resource and request time. Approvals and approval proofs bind to this value.
 */
export function requestDigest(policy: CompiledPolicy, request: AccessRequest): string {
  const actors: { id: string; grantId: string | null }[] = [];
  for (let actor = request.subject.act; actor !== undefined; actor = actor.act) {
    actors.push({ id: actor.id, grantId: actor.grant?.id ?? null });
  }
  return digest({
    schema: "permitkit.request/1",
    policy: { version: policy.version, digest: policy.digest },
    principal: { type: request.subject.type, id: request.subject.id },
    actors,
    action: request.action,
    resource: {
      type: request.resource.type,
      id: request.resource.id ?? null,
      properties: request.resource.properties ?? {},
    },
    requestedAt: new Date(Date.parse(request.context.now)).toISOString(),
  });
}

const oversized = "The input exceeds the size bounds (depth, nodes, array or string length).";

function run(policy: CompiledPolicy, input: unknown, trace: TraceStep[] | undefined): Decision {
  if (!isCompiledPolicy(policy)) {
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

  const snapshot = boundedSnapshot(input, requestBounds);
  if (snapshot === undefined) {
    trace?.push({ step: "validate", ok: false, issues: [{ path: "", message: oversized }] });
    return deny("invalid_request", null);
  }
  const parsed = accessRequestSchema.safeParse(snapshot);
  trace?.push({
    step: "validate",
    ok: parsed.success,
    issues: parsed.success
      ? []
      : parsed.error.issues.map((item) => ({ path: item.path.join("."), message: item.message })),
  });
  if (!parsed.success) return deny("invalid_request", null);
  const request = parsed.data;
  const requestDigestValue = requestDigest(policy, request);
  const now = Date.parse(request.context.now);

  const pinned = request.context.policyVersion ?? null;
  const versionOk = pinned === null || pinned === policy.version;
  trace?.push({ step: "policy_version", ok: versionOk, pinned, loaded: policy.version });
  if (!versionOk) return deny("policy_version_mismatch", requestDigestValue);

  const permission = permissionOf(request);
  const known = policy.catalog.isPermission(permission);
  trace?.push({ step: "permission", ok: known, permission });
  if (!known) return deny("unknown_permission", requestDigestValue);

  const actor = request.subject.act;
  if (actor !== undefined) {
    const reason = agentGrantValidity(actor, request.subject, now);
    trace?.push({
      step: "agent_grant",
      ok: reason === null,
      reason,
      grantId: actor.grant?.id ?? null,
    });
    if (reason !== null) return deny(reason, requestDigestValue);
  }

  const properties = request.resource.properties;
  const subjectTypes = new Set<string>([request.subject.type]);
  if (actor !== undefined) subjectTypes.add("agent");
  const heldRoles = new Set(request.subject.roles.map((assignment) => assignment.role));
  for (const rule of policy.denies) {
    const matched =
      rule.permissions.includes(permission) &&
      (rule.roles === undefined || rule.roles.some((role) => heldRoles.has(role))) &&
      (rule.subjectTypes === undefined ||
        rule.subjectTypes.some((type) => subjectTypes.has(type))) &&
      scopeTouches(rule.scope, properties);
    trace?.push({ step: "deny_rule", id: rule.id, matched });
    if (matched) return deny("denied_by_rule", requestDigestValue, { kind: "deny", id: rule.id });
  }

  let matchedGrant: MatchedRule | null = null;
  let closestFailure: "scope_mismatch" | "limit_exceeded" | null = null;
  search: for (const assignment of request.subject.roles) {
    const role = policy.roles.get(assignment.role);
    trace?.push({ step: "role", role: assignment.role, known: role !== undefined });
    if (role === undefined) continue;
    for (const grant of role.grants) {
      if (!grant.permissions.includes(permission)) continue;
      const assignmentScope = scopeCovers(assignment.scope, properties);
      if (!assignmentScope.ok) {
        trace?.push({
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
        trace?.push({
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
        trace?.push({
          step: "grant",
          role: role.name,
          id: grant.id,
          result: "limit_exceeded",
          detail: limits,
        });
        closestFailure = "limit_exceeded";
        continue;
      }
      trace?.push({
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

  if (actor?.grant !== undefined) {
    let covered = false;
    actor.grant.entries.forEach((entry, index) => {
      if (covered) return;
      let result: "matched" | "no_permission" | "scope_mismatch" | "limit_exceeded";
      if (!entry.permissions.includes(permission)) result = "no_permission";
      else if (!scopeCovers(entry.scope, properties).ok) result = "scope_mismatch";
      else if (!limitsHold(entry.limits, properties).ok) result = "limit_exceeded";
      else result = "matched";
      trace?.push({ step: "agent_grant_entry", index, result });
      covered = result === "matched";
    });
    if (!covered) return deny("agent_grant_insufficient", requestDigestValue);
  }

  const approvalRule = policy.approvalRules.get(permission);
  if (policy.separationOfDuties.exclusiveRequestAndApproveRoles && approvalRule !== undefined) {
    const conflicting = (approvalRule.approverRoles ?? []).filter((role) => heldRoles.has(role));
    trace?.push({
      step: "separation_of_duties",
      ok: conflicting.length === 0,
      conflictingRoles: conflicting,
    });
    if (conflicting.length > 0) return deny("sod_role_conflict", requestDigestValue);
  }

  if (approvalRule !== undefined) {
    const applies = thresholdApplies(approvalRule.when, properties);
    trace?.push({ step: "approval_rule", id: approvalRule.id, applies });
    if (applies) {
      return {
        outcome: "approval_required",
        allowed: false,
        reason: "approval_required",
        rule: matchedGrant,
        approval: {
          ruleId: approvalRule.id,
          approvers: approvalRule.approvers,
          approverRoles: approvalRule.approverRoles ?? null,
          requireProof: approvalRule.requireProof,
          expiresAt: new Date(now + approvalRule.expiresInSeconds * 1000).toISOString(),
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

function agentGrantValidity(actor: Actor, principal: Subject, now: number): ReasonCode | null {
  const grant = actor.grant;
  if (grant === undefined) return "agent_grant_missing";
  if (grant.principalId !== principal.id) return "agent_grant_principal_mismatch";
  if (grant.revokedAt !== undefined && Date.parse(grant.revokedAt) <= now)
    return "agent_grant_revoked";
  if (grant.notBefore !== undefined && Date.parse(grant.notBefore) > now)
    return "agent_grant_not_yet_valid";
  if (Date.parse(grant.expiresAt) <= now) return "agent_grant_expired";
  return null;
}
