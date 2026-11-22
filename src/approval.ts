import { z } from "zod";

import { boundedSnapshot, requestBounds } from "./bounds.js";
import { decide, permissionOf, requestDigest, type Decision } from "./decide.js";
import { scopeCovers } from "./engine/conditions.js";
import { PermitkitError } from "./errors.js";
import { isCompiledPolicy, type CompiledPolicy } from "./policy.js";
import type { ApprovalReasonCode, ApprovalRejectionCode } from "./reasons.js";
import { accessRequestSchema, subjectSchema } from "./request.js";

const hexDigest = z.string().regex(/^[0-9a-f]{64}$/, "Use a lowercase hex SHA-256 digest.");
const timestamp = z.string().datetime({ offset: true });

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
  if (!isCompiledPolicy(policy)) {
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
  ): ApprovalDecision => ({
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
  const parsed = approvalInputSchema.safeParse(snapshot);
  if (!parsed.success) return result("deny", "invalid_input");
  const { request, now: nowText, priorRequests } = parsed.data;
  const now = Date.parse(nowText);
  const requestedAt = Date.parse(request.context.now);
  if (now < requestedAt) return result("deny", "invalid_input");

  const digestValue = requestDigest(policy, request);
  const requesterDecision = decide(policy, {
    ...request,
    context: { ...request.context, now: nowText },
  });
  const base = { requesterDecision, requestDigest: digestValue };
  if (requesterDecision.outcome === "deny") return result("deny", "requester_denied", base);
  if (requesterDecision.outcome === "allow") return result("allow", "approval_not_required", base);

  const permission = permissionOf(request);
  const rule = policy.approvalRules.get(permission);
  if (rule === undefined) return result("deny", "invalid_input", base);
  const ruleBase = { ...base, ruleId: rule.id, required: rule.approvers };
  const windowEnd = requestedAt + rule.expiresInSeconds * 1000;
  if (now > windowEnd) return result("deny", "approval_window_expired", ruleBase);

  const sod = policy.separationOfDuties;
  if (sod.requesterNeverApprovesSameType && priorRequests === undefined) {
    return result("deny", "sod_history_missing", ruleBase);
  }
  const requestingRoles = new Set(
    [...policy.roles.values()]
      .filter((role) => role.grants.some((grant) => grant.permissions.includes(permission)))
      .map((role) => role.name),
  );
  const properties = request.resource.properties;
  const verifiers = new Map((options.verifiers ?? []).map((verifier) => [verifier.type, verifier]));

  const counted: string[] = [];
  const rejected: ApprovalRejection[] = [];
  for (const [index, raw] of parsed.data.approvals.entries()) {
    const parsedApproval = approvalSchema.safeParse(raw);
    if (!parsedApproval.success) {
      rejected.push({ index, approverId: null, reason: "approval_invalid" });
      continue;
    }
    const approval = parsedApproval.data;
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
    if (approver.id === request.subject.id) {
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
    const approvedAt = Date.parse(approval.approvedAt);
    if (approvedAt < requestedAt) {
      reject("approved_before_request");
      continue;
    }
    if (approvedAt > windowEnd) {
      reject("approved_after_expiry");
      continue;
    }
    if (approvedAt > now) {
      reject("approved_in_future");
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
  let verification: ProofVerification;
  try {
    verification = await verifier.verify(proof, { approverId, requestDigest: digestValue });
  } catch (error) {
    return {
      reason: "proof_invalid",
      detail: error instanceof Error ? error.message : "verifier threw",
    };
  }
  if (!verification.valid) {
    return { reason: "proof_invalid", detail: verification.reason };
  }
  if (verification.approverId !== approverId || verification.requestDigest !== digestValue) {
    return { reason: "proof_invalid", detail: "verifier echo does not match" };
  }
  return null;
}
