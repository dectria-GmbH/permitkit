import { boundedSnapshot, requestBounds } from "./bounds.js";
import { PermitkitError } from "./errors.js";
import {
  decide,
  type Decision,
  type ApprovalRequirement,
  type MatchedRule,
  type Outcome,
} from "./decide.js";
import type { CompiledPolicy } from "./policy.js";
import type { ReasonCode } from "./reasons.js";

/**
 * An access evaluation request in the shape of the OpenID AuthZEN Authorization API 1.0.
 * permitkit reads `subject.properties.roles` and `subject.properties.act` (required, `null`
 * if no agent acts), and needs `context.now` because it never reads the clock.
 */
export interface AuthZenRequest {
  subject: { type: string; id: string; properties?: Record<string, unknown> };
  action: { name: string; properties?: Record<string, unknown> };
  resource: { type: string; id?: string; properties?: Record<string, unknown> };
  /** Required: `context.now` carries the evaluation time. */
  context: Record<string, unknown>;
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

const allowed = {
  top: ["subject", "action", "resource", "context"],
  subject: ["type", "id", "properties"],
  subjectProperties: ["roles", "act"],
  action: ["name", "properties"],
  resource: ["type", "id", "properties"],
  context: ["now", "policy_version", "policy_digest"],
} as const;

/** Own property of a plain value, never an inherited one. */
function own(value: unknown, key: string): unknown {
  if (typeof value !== "object" || value === null || !Object.hasOwn(value, key)) return undefined;
  const item: unknown = Reflect.get(value, key);
  return item;
}

/** True if the value is absent, or an object whose own keys are all in the list. */
function onlyKeys(value: unknown, keys: readonly string[]): boolean {
  if (value === undefined) return true;
  if (typeof value !== "object" || value === null || Array.isArray(value)) return false;
  return Object.keys(value).every((key) => keys.includes(key));
}

/**
 * Evaluates an AuthZEN access evaluation request. Input keys that permitkit does not map are
 * rejected with `invalid_request` instead of being ignored, so a misspelt actor or pin cannot
 * widen access. Recognized keys: `subject.properties.roles`, `subject.properties.act`,
 * `context.now`, `context.policy_version`, `context.policy_digest`. `action.properties` is
 * accepted and not used.
 */
export function evaluate(policy: CompiledPolicy, input: AuthZenRequest): AuthZenResponse {
  try {
    return evaluateUnsafe(policy, input);
  } catch (error) {
    // Programming errors (a policy from elsewhere) still throw. Anything else denies.
    if (PermitkitError.is(error)) throw error;
    return responseOf(decide(policy, null));
  }
}

function evaluateUnsafe(policy: CompiledPolicy, input: AuthZenRequest): AuthZenResponse {
  // Read the caller's object once, through the size guard. The copy has no prototype.
  const request = boundedSnapshot(input, requestBounds);
  const subject = own(request, "subject");
  const subjectProperties = own(subject, "properties");
  const action = own(request, "action");
  const resource = own(request, "resource");
  const context = own(request, "context");
  const shapeOk =
    typeof request === "object" &&
    request !== null &&
    onlyKeys(request, allowed.top) &&
    onlyKeys(subject, allowed.subject) &&
    onlyKeys(subjectProperties, allowed.subjectProperties) &&
    onlyKeys(action, allowed.action) &&
    onlyKeys(resource, allowed.resource) &&
    onlyKeys(context, allowed.context);
  const act = own(subjectProperties, "act");
  const resourceId = own(resource, "id");
  const resourceProperties = own(resource, "properties");
  const policyVersion = own(context, "policy_version");
  const policyDigest = own(context, "policy_digest");
  const native = shapeOk
    ? {
        subject: {
          type: own(subject, "type"),
          id: own(subject, "id"),
          roles: own(subjectProperties, "roles"),
          // Passed as read: a missing act is refused by the request schema, never read as
          // "the principal acts directly". Send null for no actor.
          act,
        },
        action: { name: own(action, "name") },
        resource: {
          type: own(resource, "type"),
          ...(resourceId === undefined ? {} : { id: resourceId }),
          ...(resourceProperties === undefined ? {} : { properties: resourceProperties }),
        },
        context: {
          now: own(context, "now"),
          ...(policyVersion === undefined ? {} : { policyVersion }),
          ...(policyDigest === undefined ? {} : { policyDigest }),
        },
      }
    : null;
  return responseOf(decide(policy, native));
}

function responseOf(decision: Decision): AuthZenResponse {
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
