import { boundedSnapshot, requestBounds } from "./bounds.js";
import { decide, type ApprovalRequirement, type MatchedRule, type Outcome } from "./decide.js";
import type { CompiledPolicy } from "./policy.js";
import type { ReasonCode } from "./reasons.js";

/**
 * An access evaluation request in the shape of the OpenID AuthZEN Authorization API 1.0.
 * permitkit reads `subject.properties.roles` and `subject.properties.act`, and needs
 * `context.now` because it never reads the clock.
 */
export interface AuthZenRequest {
  subject: { type: string; id: string; properties?: Record<string, unknown> };
  action: { name: string; properties?: Record<string, unknown> };
  resource: { type: string; id?: string; properties?: Record<string, unknown> };
  context?: Record<string, unknown>;
}

/**
 * AuthZEN response. `decision` is true only for allow. The `context` object is the permitkit
 * profile: AuthZEN 1.0 defines no reason fields, so these names are permitkit's own.
 */
export interface AuthZenResponse {
  decision: boolean;
  context: {
    outcome: Outcome;
    reason_codes: ReasonCode[];
    rule: MatchedRule | null;
    approval: ApprovalRequirement | null;
    policy_version: string;
    policy_digest: string;
    request_digest: string | null;
  };
}

export function evaluate(policy: CompiledPolicy, input: AuthZenRequest): AuthZenResponse {
  // Read the caller's object once, through the size guard, then map the plain copy.
  const copy = boundedSnapshot(input, requestBounds);
  const request = (
    typeof copy === "object" && copy !== null ? copy : {}
  ) as Partial<AuthZenRequest>;
  const subjectProperties = request.subject?.properties ?? {};
  const context = request.context ?? {};
  const native = {
    subject: {
      type: request.subject?.type,
      id: request.subject?.id,
      roles: subjectProperties["roles"],
      ...(subjectProperties["act"] === undefined ? {} : { act: subjectProperties["act"] }),
    },
    action: { name: request.action?.name },
    resource: {
      type: request.resource?.type,
      ...(request.resource?.id === undefined ? {} : { id: request.resource.id }),
      ...(request.resource?.properties === undefined
        ? {}
        : { properties: request.resource.properties }),
    },
    context: {
      now: context["now"],
      ...(context["policy_version"] === undefined
        ? {}
        : { policyVersion: context["policy_version"] }),
      ...(context["policy_digest"] === undefined ? {} : { policyDigest: context["policy_digest"] }),
    },
  };
  const decision = decide(policy, native);
  return {
    decision: decision.allowed,
    context: {
      outcome: decision.outcome,
      reason_codes: [decision.reason],
      rule: decision.rule,
      approval: decision.approval,
      policy_version: decision.policy.version,
      policy_digest: decision.policy.digest,
      request_digest: decision.requestDigest,
    },
  };
}
