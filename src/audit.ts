import { z } from "zod";

import { boundedSnapshot, requestBounds } from "./bounds.js";
import { canonicalJson } from "./canonical.js";
import { decide, parseRequest, type Decision } from "./decide.js";
import type { AccessRequest } from "./request.js";

const recordShapeSchema = z
  .object({
    schema: z.literal("permitkit.decision/1"),
    policy: z.object({ version: z.string(), digest: z.string() }).strict(),
    request: z.unknown(),
    requestDigest: z.string().nullable(),
    actorChain: z.array(z.unknown()),
    outcome: z.string(),
    reason: z.string(),
    rule: z.unknown(),
    approval: z.unknown(),
  })
  .strict();
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

function actorChainOf(request: AccessRequest | null): ActorChainEntry[] {
  const chain: ActorChainEntry[] = [];
  if (request === null) return chain;
  chain.push({ type: request.subject.type, id: request.subject.id, grantId: null });
  for (let actor = request.subject.act; actor !== undefined; actor = actor.act) {
    chain.push({ type: "agent", id: actor.id, grantId: actor.grant?.id ?? null });
  }
  return chain;
}

export function toDecisionRecord(request: unknown, decision: Decision): DecisionRecord {
  const parsed = parseRequest(request);
  const evaluated = parsed.ok ? parsed.request : null;
  const actorChain = actorChainOf(evaluated);
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
 * result means the record does not match what permitkit decides for the same request.
 *
 * This checks consistency, not integrity: the digests are not keyed, so whoever can write the
 * log can also write a consistent forged record. For tamper evidence, sign or chain the
 * records in the audit log.
 */
export function reevaluate(policy: CompiledPolicy, record: DecisionRecord): ReevaluationResult {
  const loaded = { version: policy.version, digest: policy.digest };
  const shape = recordShapeSchema.safeParse(boundedSnapshot(record, requestBounds));
  if (!shape.success) return { status: "not_replayable" };
  const stored = shape.data;
  if (stored.policy.version !== loaded.version || stored.policy.digest !== loaded.digest) {
    return { status: "policy_mismatch", expected: stored.policy, loaded };
  }
  if (stored.request === null) return { status: "not_replayable" };
  const parsed = parseRequest(stored.request);
  if (!parsed.ok) return { status: "not_replayable" };
  const decision = decide(policy, parsed.request);
  const same =
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
  return { status: same ? "reproduced" : "diverged", decision };
}
