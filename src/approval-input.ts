/**
 * The input of evaluateApprovals: its types and its validators. They replace the Zod 3 schemas
 * of the earlier version rule for rule, with the conventions of `src/validate.ts`, and run on the
 * plain-data copy that the size guard made. Every rule here has a named test in
 * `test/approval-validator.test.ts`.
 */

import { detach, maxApprovals } from "./bounds.js";
import { defineData, hasOwn } from "./intrinsics.js";
import { accessRequest, subject, type AccessRequest, type Subject } from "./request.js";
import { requestTime, timestamp } from "./time.js";
import {
  bare,
  fail,
  invalid,
  isObject,
  knownKeys,
  list,
  optional,
  own,
  required,
  text,
  type Check,
} from "./validate.js";

/**
 * Evidence that a specific person approved a specific request, for example a WebAuthn
 * assertion whose challenge is the request digest. permitkit does not interpret `payload`;
 * a verifier for the proof `type` does.
 */
export type ApprovalProof = {
  type: string;
  approverId: string;
  requestDigest: string;
  payload?: unknown;
};

export type Approval = {
  /** The approving principal, as one identity with its roles. */
  approver: Subject;
  approvedAt: string;
  /** The digest of the request this approval is for. */
  requestDigest: string;
  proof?: ApprovalProof | undefined;
};

/** An earlier request by an approver, as the consumer's records show it. */
export type PriorRequest = {
  principalId: string;
  permission: string;
};

export type ApprovalInput = {
  /** The original request. Its context.now is the request time. */
  request: AccessRequest;
  /** Each approval is validated on its own; an invalid one is rejected, not the whole input. */
  approvals: unknown[];
  /** Evaluation time. The requester's rights and the window are checked at this time. */
  now: string;
  /**
   * Earlier requests by the approvers, as the consumer's records show them. Required if the
   * operator switched on requesterNeverApprovesSameType.
   */
  priorRequests?: PriorRequest[] | undefined;
};

const hexDigest = text({
  pattern: /^[0-9a-f]{64}$/,
  patternMessage: "Use a lowercase hex SHA-256 digest.",
});
const proofType = text({ min: 1, max: 64 });
const approverId = text({ min: 1, max: 256 });
const nonEmpty = text({ min: 1 });

/**
 * A proof. `payload` may be any plain data or absent; the output has the key exactly if the
 * input has it, as before, and holds a copy of the value.
 */
export const approvalProof: Check<ApprovalProof> = (value, path, issues) => {
  if (!isObject(value)) return fail(issues, path, "Expected a proof object.");
  const type = required(value, "type", path, issues, proofType);
  const proofApprover = required(value, "approverId", path, issues, approverId);
  const digest = required(value, "requestDigest", path, issues, hexDigest);
  const known = knownKeys(value, ["type", "approverId", "requestDigest", "payload"], path, issues);
  if (type === invalid || proofApprover === invalid || digest === invalid || !known) {
    return invalid;
  }
  const proof = bare({ type, approverId: proofApprover, requestDigest: digest });
  if (hasOwn(value, "payload")) defineData(proof, "payload", detach(own(value, "payload")));
  return proof;
};

/** One approval. Its approver is a subject with the rules of a request subject. */
export const approval: Check<Approval> = (value, path, issues) => {
  if (!isObject(value)) return fail(issues, path, "Expected an approval object.");
  const approver = required(value, "approver", path, issues, subject);
  const approvedAt = required(value, "approvedAt", path, issues, timestamp);
  const digest = required(value, "requestDigest", path, issues, hexDigest);
  const proof = optional(value, "proof", path, issues, approvalProof);
  const known = knownKeys(
    value,
    ["approver", "approvedAt", "requestDigest", "proof"],
    path,
    issues,
  );
  if (
    approver === invalid ||
    approvedAt === invalid ||
    digest === invalid ||
    proof.value === invalid ||
    !known
  ) {
    return invalid;
  }
  return bare({
    approver,
    approvedAt,
    requestDigest: digest,
    ...(proof.present ? { proof: proof.value } : {}),
  });
};

const priorRequest: Check<PriorRequest> = (value, path, issues) => {
  if (!isObject(value)) return fail(issues, path, "Expected a prior request object.");
  const principalId = required(value, "principalId", path, issues, nonEmpty);
  const permission = required(value, "permission", path, issues, nonEmpty);
  const known = knownKeys(value, ["principalId", "permission"], path, issues);
  if (principalId === invalid || permission === invalid || !known) return invalid;
  return bare({ principalId, permission });
};

/** Any value. The approvals are checked one by one later, so one bad approval is a rejection. */
const anything: Check<unknown> = (value) => value;

const approvalList = list(anything, { max: maxApprovals });
const priorRequestList = list(priorRequest);

/** The whole input. The request follows the rules of `accessRequest`, depth limit included. */
export const approvalInput: Check<ApprovalInput> = (value, path, issues) => {
  if (!isObject(value)) return fail(issues, path, "Expected an approval input object.");
  const request = required(value, "request", path, issues, accessRequest);
  const approvals = required(value, "approvals", path, issues, approvalList);
  const now = required(value, "now", path, issues, requestTime);
  const prior = optional(value, "priorRequests", path, issues, priorRequestList);
  const known = knownKeys(value, ["request", "approvals", "now", "priorRequests"], path, issues);
  if (
    request === invalid ||
    approvals === invalid ||
    now === invalid ||
    prior.value === invalid ||
    !known
  ) {
    return invalid;
  }
  return bare({
    request,
    approvals,
    now,
    ...(prior.present ? { priorRequests: prior.value } : {}),
  });
};
