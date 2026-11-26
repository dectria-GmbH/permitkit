import { boundedSnapshot, wrapperBounds } from "./bounds.js";
import { canonicalJson } from "./canonical.js";
import { decide, parseRequest, type Decision } from "./decide.js";
import { isPermitkitError, PermitkitError } from "./errors.js";
import { append } from "./intrinsics.js";
import { isCompiledPolicy, type CompiledPolicy } from "./policy.js";
import { storedRecord } from "./record.js";
import type { AccessRequest } from "./request.js";
import { invalid, type Issue } from "./validate.js";

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
  readonly schema: "permitkit.decision/2";
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

function actorChainOf(request: AccessRequest | null): ActorChainEntry[] {
  const chain: ActorChainEntry[] = [];
  if (request === null) return chain;
  append(chain, { type: request.subject.type, id: request.subject.id, grantId: null });
  for (let actor = request.subject.act; actor !== null; actor = actor.act) {
    append(chain, { type: "agent", id: actor.id, grantId: actor.grant?.id ?? null });
  }
  return chain;
}

/**
 * Builds the audit record for a decision. Pass the same plain data that was decided; if the
 * object has getters, use decideAndRecord() so both read one copy.
 */
export function toDecisionRecord(request: unknown, decision: Decision): DecisionRecord {
  const parsed = parseRequest(request);
  try {
    return buildRecord(parsed.ok ? parsed.request : null, decision);
  } catch {
    return buildRecord(null, decision);
  }
}

function buildRecord(evaluated: AccessRequest | null, decision: Decision): DecisionRecord {
  const actorChain = actorChainOf(evaluated);
  return {
    schema: "permitkit.decision/2",
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
 * result means the record does not match what permitkit decides for the same request.
 *
 * This checks consistency, not integrity: the digests are not keyed, so whoever can write the
 * log can also write a consistent forged record. For tamper evidence, sign or chain the
 * records in the audit log.
 */
export function reevaluate(policy: CompiledPolicy, record: DecisionRecord): ReevaluationResult {
  if (!isCompiledPolicy(policy)) {
    throw new PermitkitError("policy_unknown", "reevaluate() needs a policy from compilePolicy().");
  }
  try {
    return reevaluateChecked(policy, record);
  } catch (error) {
    if (isPermitkitError(error) && error.code === "policy_unknown") throw error;
    // Internals can fail under polluted built-in prototypes; such a record cannot be replayed.
    return { status: "not_replayable" };
  }
}

function reevaluateChecked(policy: CompiledPolicy, record: DecisionRecord): ReevaluationResult {
  const loaded = { version: policy.version, digest: policy.digest };
  const snapshot = boundedSnapshot(record, wrapperBounds);
  // A hand-written validator on the plain-data copy. Its output holds objects without a
  // prototype, so a missing key reads as undefined, never as an inherited value.
  const issues: Issue[] = [];
  const stored = storedRecord(snapshot, null, issues);
  if (stored === invalid) return { status: "not_replayable" };
  if (stored.policy.version !== loaded.version || stored.policy.digest !== loaded.digest) {
    return { status: "policy_mismatch", expected: stored.policy, loaded };
  }
  const storedRequest = stored.request;
  if (storedRequest === null) return { status: "not_replayable" };
  const parsed = parseRequest(storedRequest);
  if (!parsed.ok) return { status: "not_replayable" };
  const decision = decide(policy, parsed.request);
  let same: boolean;
  try {
    same =
      canonicalJson({
        outcome: decision.outcome,
        reason: decision.reason,
        rule: decision.rule,
        approval: decision.approval,
        requestDigest: decision.requestDigest,
        actorChain: actorChainOf(parsed.request),
      }) ===
      canonicalJson({
        outcome: stored.outcome,
        reason: stored.reason,
        rule: stored.rule,
        approval: stored.approval,
        requestDigest: stored.requestDigest,
        actorChain: stored.actorChain,
      });
  } catch {
    // The stored record holds values without a JSON form, so it cannot match a decision.
    return { status: "not_replayable" };
  }
  return { status: same ? "reproduced" : "diverged", decision };
}

/**
 * Decides and builds the audit record from the same validated copy of the request. Prefer this
 * over decide() plus toDecisionRecord(): the record then holds exactly the request that was
 * decided, even if the caller's object changes between two reads.
 */
export function decideAndRecord(
  policy: CompiledPolicy,
  request: unknown,
): { decision: Decision; record: DecisionRecord } {
  let evaluated: AccessRequest | null = null;
  try {
    const parsed = parseRequest(request);
    evaluated = parsed.ok ? parsed.request : null;
  } catch {
    // Treat an input that cannot be read as invalid; decide(policy, null) denies.
    evaluated = null;
  }
  // On a parse failure, do not read the caller's object again: decide on null, which denies.
  const decision = decide(policy, evaluated);
  return { decision, record: buildRecord(evaluated, decision) };
}
