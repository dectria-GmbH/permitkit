import { boundedSnapshot, requestBounds } from "./bounds.js";
import { canonicalJson } from "./canonical.js";
import { decide, type Decision } from "./decide.js";
import { accessRequestSchema, type AccessRequest } from "./request.js";
import type { CompiledPolicy } from "./policy.js";

export interface ActorChainEntry {
  readonly type: "human" | "service" | "agent";
  readonly id: string;
  readonly grantId: string | null;
}

/**
 * Everything needed to log a decision and to re-evaluate it later: the request as evaluated,
 * the policy version and digest, and the result. The record is plain JSON.
 */
export interface DecisionRecord {
  readonly schema: "permitkit.decision/1";
  readonly policy: { readonly version: string; readonly digest: string };
  readonly request: AccessRequest | null;
  readonly requestDigest: string | null;
  /** Principal first, then the current actor, then prior actors. */
  readonly actorChain: readonly ActorChainEntry[];
  readonly outcome: Decision["outcome"];
  readonly reason: Decision["reason"];
  readonly rule: Decision["rule"];
  readonly approval: Decision["approval"];
}

export function toDecisionRecord(request: unknown, decision: Decision): DecisionRecord {
  const snapshot = boundedSnapshot(request, requestBounds);
  const parsed = accessRequestSchema.safeParse(snapshot);
  const evaluated = parsed.success ? parsed.data : null;
  const actorChain: ActorChainEntry[] = [];
  if (evaluated !== null) {
    actorChain.push({ type: evaluated.subject.type, id: evaluated.subject.id, grantId: null });
    for (let actor = evaluated.subject.act; actor !== undefined; actor = actor.act) {
      actorChain.push({ type: "agent", id: actor.id, grantId: actor.grant?.id ?? null });
    }
  }
  return {
    schema: "permitkit.decision/1",
    policy: decision.policy,
    request: evaluated,
    requestDigest: decision.requestDigest,
    actorChain,
    outcome: decision.outcome,
    reason: decision.reason,
    rule: decision.rule,
    approval: decision.approval,
  };
}

export type ReevaluationResult =
  | { readonly status: "reproduced"; readonly decision: Decision }
  | { readonly status: "diverged"; readonly decision: Decision }
  | {
      readonly status: "policy_mismatch";
      readonly expected: DecisionRecord["policy"];
      readonly loaded: DecisionRecord["policy"];
    }
  | { readonly status: "not_replayable" };

/**
 * Re-runs a recorded decision. The policy must have the same version and digest as the
 * record; otherwise the result is `policy_mismatch` and nothing is evaluated. A `diverged`
 * result means the record does not match what permitkit decides for the same inputs.
 */
export function reevaluate(policy: CompiledPolicy, record: DecisionRecord): ReevaluationResult {
  const loaded = { version: policy.version, digest: policy.digest };
  if (record.policy.version !== loaded.version || record.policy.digest !== loaded.digest) {
    return { status: "policy_mismatch", expected: record.policy, loaded };
  }
  if (record.request === null) return { status: "not_replayable" };
  const decision = decide(policy, record.request);
  const same =
    canonicalJson({
      outcome: decision.outcome,
      reason: decision.reason,
      rule: decision.rule,
      approval: decision.approval,
      requestDigest: decision.requestDigest,
    }) ===
    canonicalJson({
      outcome: record.outcome,
      reason: record.reason,
      rule: record.rule,
      approval: record.approval,
      requestDigest: record.requestDigest,
    });
  return { status: same ? "reproduced" : "diverged", decision };
}
