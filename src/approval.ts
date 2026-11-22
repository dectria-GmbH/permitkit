import { z } from "zod";

import { boundedSnapshot, detach, requestBounds } from "./bounds.js";
import { decide, denyRuleMatches, permissionOf, requestDigest, type Decision } from "./decide.js";
import { scopeCovers } from "./engine/conditions.js";
import { safeParse } from "./parse.js";
import { PermitkitError } from "./errors.js";
import { internalsOf, type CompiledPolicy } from "./policy.js";
import type { ApprovalReasonCode, ApprovalRejectionCode } from "./reasons.js";
import { accessRequestSchema, subjectSchema } from "./request.js";
import { instant, timestampSchema } from "./time.js";

const hexDigest = z.string().regex(/^[0-9a-f]{64}$/, "Use a lowercase hex SHA-256 digest.");
const timestamp = timestampSchema;

/**
 * Evidence that a specific person approved a specific request, for example a WebAuthn
 * assertion whose challenge is the request digest. permitkit does not interpret `payload`;
 * a verifier for the proof `type` does.
 */
export const approvalProofSchema = z
  .object({
    type: z.string().min(1).max(64),
    approverId: z.string().min(1).max(256),
    requestDigest: hexDigest,
    payload: z.unknown(),
  })
  .strict();

export type ApprovalProof = z.output<typeof approvalProofSchema>;

export type ProofVerification =
  | { readonly valid: true; readonly approverId: string; readonly requestDigest: string }
  | { readonly valid: false; readonly reason: string };

/**
 * Verifies one proof type. A verifier must check that the proof was made by `expected.approverId`
 * over `expected.requestDigest`, and must echo both values on success. permitkit compares the
 * echo with what it expects, so a verifier that checks only the signature cannot pass a proof
 * that was made for another request.
 */
export interface ApprovalProofVerifier {
  readonly type: string;
  verify(
    proof: ApprovalProof,
    expected: { readonly approverId: string; readonly requestDigest: string },
  ): ProofVerification | Promise<ProofVerification>;
}

export const approvalSchema = z
  .object({
    /** The approving principal, as one identity with its roles. */
    approver: subjectSchema,
    approvedAt: timestamp,
    /** The digest of the request this approval is for. */
    requestDigest: hexDigest,
    proof: approvalProofSchema.optional(),
  })
  .strict();

export type Approval = z.output<typeof approvalSchema>;

export const approvalInputSchema = z
  .object({
    /** The original request. Its context.now is the request time. */
    request: accessRequestSchema,
    approvals: z.array(z.unknown()).max(100),
    /** Evaluation time. The requester's rights and the window are checked at this time. */
    now: timestamp,
    /**
     * Earlier requests by the approvers, as the consumer's records show them. Required if the
     * operator switched on requesterNeverApprovesSameType.
     */
    priorRequests: z
      .array(z.object({ principalId: z.string().min(1), permission: z.string().min(1) }).strict())
      .optional(),
  })
  .strict();

export type ApprovalInput = z.input<typeof approvalInputSchema>;

export interface ApprovalRejection {
  readonly index: number;
  readonly approverId: string | null;
  readonly reason: ApprovalRejectionCode;
  readonly detail?: string;
}

export interface ApprovalDecision {
  readonly outcome: "allow" | "deny" | "pending";
  readonly allowed: boolean;
  readonly reason: ApprovalReasonCode;
  readonly ruleId: string | null;
  readonly required: number;
  /** Ids of the approvers that count, in input order. */
  readonly counted: readonly string[];
  readonly rejected: readonly ApprovalRejection[];
  /** The requester's decision at evaluation time. */
  readonly requesterDecision: Decision | null;
  readonly policy: { readonly version: string; readonly digest: string };
  readonly requestDigest: string | null;
}

export interface ApprovalOptions {
  readonly verifiers?: readonly ApprovalProofVerifier[];
}

/**
 * Decides whether a request that needs dual approval may now run. Rules:
 * the requester still holds the permission; each approver is a distinct human who acts
 * directly, is not the requester, approved this exact request digest inside the window,
 * is eligible under the rule, passes the operator's separation-of-duties settings and, if the
 * rule says so, has a verified proof. The function does not track single use: the consumer
 * must mark a request as executed once.
 */
export async function evaluateApprovals(
  policy: CompiledPolicy,
  input: unknown,
  options: ApprovalOptions = {},
): Promise<ApprovalDecision> {
  const internal = internalsOf(policy);
  if (internal === undefined) {
    throw new PermitkitError(
      "policy_unknown",
      "evaluateApprovals() needs a policy from compilePolicy().",
    );
  }
  const policyRef = { version: policy.version, digest: policy.digest };
  const result = (
    outcome: ApprovalDecision["outcome"],
    reason: ApprovalReasonCode,
    rest: Partial<ApprovalDecision> = {},
  ): ApprovalDecision =>
    // A null prototype: an inherited `then` on Object.prototype must not turn the result into a
    // thenable, which would keep the returned promise pending forever.
    Object.assign(emptyDecision(), {
      outcome,
      allowed: outcome === "allow",
      reason,
      ruleId: null,
      required: 0,
      counted: [],
      rejected: [],
      requesterDecision: null,
      policy: policyRef,
      requestDigest: null,
      ...rest,
    });

  const snapshot = boundedSnapshot(input, requestBounds);
  if (snapshot === undefined) return result("deny", "invalid_input");
  const parsed = safeParse(approvalInputSchema, snapshot);
  if (!parsed.success) return result("deny", "invalid_input");
  const data = detach(parsed.data);
  const { request, now: nowText, priorRequests } = data;
  const now = instant(nowText);
  const requestedAt = instant(request.context.now);
  // Written so that an unreadable time fails the check.
  if (!(now >= requestedAt)) return result("deny", "invalid_input");

  const digestValue = requestDigest(policy, request);
  const requesterDecision = decide(policy, {
    ...request,
    context: { ...request.context, now: nowText },
  });
  const base = { requesterDecision, requestDigest: digestValue };
  if (requesterDecision.outcome === "deny") return result("deny", "requester_denied", base);
  if (requesterDecision.outcome === "allow") return result("allow", "approval_not_required", base);
  // The request must also have been a valid approval request when it was made.
  const requestTimeDecision = decide(policy, request);
  if (
    requestTimeDecision.outcome !== "approval_required" ||
    requestTimeDecision.approval?.ruleId !== requesterDecision.approval?.ruleId
  ) {
    return result("deny", "not_approvable_at_request_time", base);
  }

  const permission = permissionOf(request);
  const rule = internal.approvalRules.get(permission);
  if (rule === undefined) return result("deny", "invalid_input", base);
  const ruleBase = { ...base, ruleId: rule.id, required: rule.approvers };
  const windowEnd = requestedAt + rule.expiresInSeconds * 1000;
  if (!(now <= windowEnd)) return result("deny", "approval_window_expired", ruleBase);

  const sod = internal.separationOfDuties;
  if (sod.requesterNeverApprovesSameType && priorRequests === undefined) {
    return result("deny", "sod_history_missing", ruleBase);
  }
  const requestingRoles = new Set(
    [...internal.roles.values()]
      .filter((role) => role.grants.some((grant) => grant.permissions.includes(permission)))
      .map((role) => role.name),
  );
  const properties = request.resource.properties;
  // The requester is the principal and every agent in its actor chain.
  const requesterIds = new Set<string>([request.subject.id]);
  for (let actor = request.subject.act; actor !== undefined; actor = actor.act) {
    requesterIds.add(actor.id);
  }
  let verifiers: ReadonlyMap<string, ApprovalProofVerifier>;
  try {
    verifiers = verifierMap(options);
  } catch (error) {
    if (error instanceof PermitkitError) throw error;
    // A hostile options object (proxy, throwing getter) is still a programming error.
    throw new PermitkitError("options_invalid", "The options could not be read.");
  }

  const counted: string[] = [];
  const rejected: ApprovalRejection[] = [];
  for (const [index, raw] of data.approvals.entries()) {
    const parsedApproval = safeParse(approvalSchema, raw);
    if (!parsedApproval.success) {
      rejected.push({ index, approverId: null, reason: "approval_invalid" });
      continue;
    }
    const approval = detach(parsedApproval.data);
    const approver = approval.approver;
    const reject = (reason: ApprovalRejectionCode, detail?: string) => {
      rejected.push({ index, approverId: approver.id, reason, ...(detail ? { detail } : {}) });
    };
    if (approver.type !== "human") {
      reject("approver_not_human");
      continue;
    }
    if (approver.act !== undefined) {
      reject("approver_is_delegated");
      continue;
    }
    if (requesterIds.has(approver.id)) {
      reject("requester_cannot_approve");
      continue;
    }
    if (counted.includes(approver.id)) {
      reject("duplicate_approver");
      continue;
    }
    if (approval.requestDigest !== digestValue) {
      reject("digest_mismatch");
      continue;
    }
    const approvedAt = instant(approval.approvedAt);
    if (!(approvedAt >= requestedAt)) {
      reject("approved_before_request");
      continue;
    }
    if (!(approvedAt <= windowEnd)) {
      reject("approved_after_expiry");
      continue;
    }
    if (!(approvedAt <= now)) {
      reject("approved_in_future");
      continue;
    }
    const denyRule = internal.denies.find((candidate) =>
      denyRuleMatches(candidate, approver, permission, properties),
    );
    if (denyRule !== undefined) {
      reject("approver_denied_by_rule", denyRule.id);
      continue;
    }
    if (rule.approverRoles !== undefined) {
      const approverRoles = rule.approverRoles;
      const eligible = approver.roles.some(
        (assignment) =>
          approverRoles.includes(assignment.role) && scopeCovers(assignment.scope, properties).ok,
      );
      if (!eligible) {
        reject("approver_role_missing");
        continue;
      }
    } else {
      const peer = decide(policy, {
        subject: approver,
        action: request.action,
        resource: request.resource,
        context: { ...request.context, now: nowText },
      });
      if (peer.outcome === "deny") {
        reject("approver_not_permitted", peer.reason);
        continue;
      }
    }
    if (sod.exclusiveRequestAndApproveRoles) {
      const conflict = approver.roles.find((assignment) => requestingRoles.has(assignment.role));
      if (conflict !== undefined) {
        reject("sod_role_conflict", conflict.role);
        continue;
      }
    }
    if (
      sod.requesterNeverApprovesSameType &&
      (priorRequests ?? []).some(
        (prior) => prior.principalId === approver.id && prior.permission === permission,
      )
    ) {
      reject("sod_prior_request");
      continue;
    }
    if (rule.requireProof) {
      const proofRejection = await checkProof(approval, approver.id, digestValue, verifiers);
      if (proofRejection !== null) {
        reject(proofRejection.reason, proofRejection.detail);
        continue;
      }
    }
    counted.push(approver.id);
  }

  const rest = { ...ruleBase, counted, rejected };
  if (counted.length >= rule.approvers) return result("allow", "approved", rest);
  return result("pending", "approvals_pending", rest);
}

async function checkProof(
  approval: Approval,
  approverId: string,
  digestValue: string,
  verifiers: ReadonlyMap<string, ApprovalProofVerifier>,
): Promise<{ reason: ApprovalRejectionCode; detail?: string } | null> {
  const proof = approval.proof;
  if (proof === undefined) return { reason: "proof_missing" };
  if (proof.approverId !== approverId || proof.requestDigest !== digestValue) {
    return { reason: "proof_mismatch" };
  }
  const verifier = verifiers.get(proof.type);
  if (verifier === undefined) return { reason: "proof_verifier_missing", detail: proof.type };
  try {
    const verification: unknown = await verifier.verify(proof, {
      approverId,
      requestDigest: digestValue,
    });
    // Count only the exact success shape. Anything else, also a truthy string, is a rejection.
    // Own properties only: an inherited `valid` or echo must never count.
    if (ownValue(verification, "valid") !== true) {
      const reason = ownValue(verification, "reason");
      return {
        reason: "proof_invalid",
        detail: typeof reason === "string" ? reason : "verifier did not confirm",
      };
    }
    if (
      ownValue(verification, "approverId") !== approverId ||
      ownValue(verification, "requestDigest") !== digestValue
    ) {
      return { reason: "proof_invalid", detail: "verifier echo does not match" };
    }
    return null;
  } catch {
    // The verifier threw, or its result or error object threw when read. Never count it.
    return { reason: "proof_invalid", detail: "verifier failed" };
  }
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function failOptions(message: string): never {
  throw new PermitkitError("options_invalid", message);
}

function isVerifier(value: unknown): value is ApprovalProofVerifier {
  return (
    isRecord(value) && typeof value["type"] === "string" && typeof value["verify"] === "function"
  );
}

/**
 * Validates the options once. Bad options are a programming error, so they throw a coded error.
 * Two verifiers for one type are rejected, because the second would silently replace the first.
 */
function verifierMap(options: unknown): ReadonlyMap<string, ApprovalProofVerifier> {
  if (!isRecord(options)) return failOptions("The options must be an object.");
  const list: unknown = Object.hasOwn(options, "verifiers") ? options["verifiers"] : undefined;
  if (list === undefined) return new Map();
  if (!Array.isArray(list)) return failOptions("options.verifiers must be an array.");
  const map = new Map<string, ApprovalProofVerifier>();
  for (const item of list as unknown[]) {
    if (!isVerifier(item)) {
      return failOptions("Each verifier needs a string type and a verify function.");
    }
    if (map.has(item.type)) return failOptions(`Two verifiers have the type ${item.type}.`);
    map.set(item.type, item);
  }
  return map;
}

function ownValue(value: unknown, key: string): unknown {
  if (!isRecord(value) || !Object.hasOwn(value, key)) return undefined;
  return value[key];
}

function emptyDecision(): ApprovalDecision {
  const empty: ApprovalDecision = Object.create(null);
  return empty;
}
