/**
 * Test helpers for code that uses permitkit. They throw plain errors, so they work with any
 * test runner. Nothing here is needed at run time, and the defaults are for tests only:
 * `role(name)` has the scope `{}` (everywhere), and `accessRequest` uses the fixed `fixedNow`.
 */

import { compareText } from "../canonical.js";
import { decide, explain, permissionOf, type Decision, type Outcome } from "../decide.js";
import type { CompiledPolicy, Scope } from "../policy.js";
import type { ReasonCode } from "../reasons.js";
import type {
  AccessRequest,
  AgentGrant,
  AgentGrantEntry,
  RoleAssignment,
  Scalar,
  Subject,
} from "../request.js";

/** A fixed evaluation time for tests. */
export const fixedNow = "2026-01-15T10:00:00.000Z";

export function role(name: string, scope: Scope = {}): RoleAssignment {
  return { role: name, scope };
}

export function human(id: string, ...roles: RoleAssignment[]): Subject {
  return { type: "human", id, roles };
}

export function service(id: string, ...roles: RoleAssignment[]): Subject {
  return { type: "service", id, roles };
}

export interface AgentGrantOptions {
  id?: string;
  entries: AgentGrantEntry[];
  expiresAt?: string;
  notBefore?: string;
  revokedAt?: string;
}

/** The principal with an agent as the current actor, holding a grant from that principal. */
export function viaAgent(principal: Subject, agentId: string, options: AgentGrantOptions): Subject {
  const grant: AgentGrant = {
    id: options.id ?? `grant-${agentId}`,
    principalId: principal.id,
    principalType: principal.type,
    agentId,
    entries: options.entries,
    expiresAt: options.expiresAt ?? "2099-01-01T00:00:00.000Z",
    ...(options.notBefore === undefined ? {} : { notBefore: options.notBefore }),
    ...(options.revokedAt === undefined ? {} : { revokedAt: options.revokedAt }),
  };
  return { ...principal, act: { type: "agent", id: agentId, grant } };
}

/** Builds a request from a permission name such as `ticket:close`. */
export function accessRequest(
  subject: Subject,
  permission: string,
  resource: { id?: string; properties?: Record<string, Scalar> } = {},
  context: { now?: string; policyVersion?: string } = {},
): AccessRequest {
  const separator = permission.indexOf(":");
  if (separator < 1)
    throw new Error(`Permission ${permission} is not of the form <resource>:<action>.`);
  return {
    subject,
    action: { name: permission.slice(separator + 1) },
    resource: {
      type: permission.slice(0, separator),
      ...(resource.id === undefined ? {} : { id: resource.id }),
      ...(resource.properties === undefined ? {} : { properties: resource.properties }),
    },
    context: {
      now: context.now ?? fixedNow,
      ...(context.policyVersion === undefined ? {} : { policyVersion: context.policyVersion }),
    },
  };
}

export class DecisionAssertionError extends Error {
  readonly explanation: unknown;
  constructor(message: string, explanation: unknown) {
    super(message);
    this.name = "DecisionAssertionError";
    this.explanation = explanation;
  }
}

/**
 * Asserts the outcome (and optionally the reason) of a request. On failure the error message
 * holds the full explain() trace, so a failing test shows why.
 */
export function assertDecision(
  policy: CompiledPolicy,
  request: AccessRequest,
  expected: { outcome: Outcome; reason?: ReasonCode },
): Decision {
  const decision = decide(policy, request);
  const outcomeOk = decision.outcome === expected.outcome;
  const reasonOk = expected.reason === undefined || decision.reason === expected.reason;
  if (!outcomeOk || !reasonOk) {
    const explanation = explain(policy, request);
    throw new DecisionAssertionError(
      `Expected ${expected.outcome}${expected.reason ? ` (${expected.reason})` : ""} for ${permissionOf(request)}, ` +
        `got ${decision.outcome} (${decision.reason}).\n${JSON.stringify(explanation, null, 2)}`,
      explanation,
    );
  }
  return decision;
}

export interface MatrixCase {
  permission: string;
  properties?: Record<string, Scalar>;
  label?: string;
}

export interface MatrixRow {
  subject: string;
  case: string;
  outcome: Outcome;
  reason: ReasonCode;
}

/**
 * Decides every subject against every case and returns a flat, sorted table. Commit the result
 * as a snapshot: a change to the policy then shows up as a reviewable diff.
 */
export function permissionMatrix(
  policy: CompiledPolicy,
  subjects: Readonly<Record<string, Subject>>,
  cases: readonly MatrixCase[],
  now: string = fixedNow,
): MatrixRow[] {
  const rows: MatrixRow[] = [];
  for (const label of Object.keys(subjects).toSorted(compareText)) {
    const subject = subjects[label];
    if (subject === undefined) continue;
    for (const item of cases) {
      const decision = decide(
        policy,
        accessRequest(
          subject,
          item.permission,
          item.properties ? { properties: item.properties } : {},
          { now },
        ),
      );
      rows.push({
        subject: label,
        case: item.label ?? item.permission,
        outcome: decision.outcome,
        reason: decision.reason,
      });
    }
  }
  return rows;
}
