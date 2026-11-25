/**
 * The input of evaluateApprovals: its types and its validators. They replace the Zod 3 schemas
 * of the earlier version rule for rule, with the conventions of `src/validate.ts`, and run on the
 * plain-data copy that the size guard made. Every rule here has a named test in
 * `test/approval-validator.test.ts`.
 */

import { detach, maxApprovals } from "./bounds.js";
import { defineData, freeze, hasOwn } from "./intrinsics.js";
import { accessRequest, subject, type AccessRequest, type Subject } from "./request.js";
import { requestTime, timestamp } from "./time.js";
import {
  bare,
  bool,
  fail,
  invalid,
  isObject,
  knownKeys,
  list,
  optional,
  oneOf,
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

/**
 * The separation rule of one request, as the consumer stored it with the request. permitkit
 * applies it as given and never looks it up; the consumer checks that `version` is still the
 * current version of its rule.
 */
export type SeparationRule = {
  /** The consumer's version label of the rule. The result carries it. */
  version: string;
  /** Rule A off: the requester may be one of the distinct approvers. Only `true` allows it. */
  requesterMayApprove: boolean;
  /**
   * Rule B. `"simple"`: an approver whom `priorRequests` lists with the requested permission,
   * and a contributor, may not approve. `"strict"`: the same, and an approver may hold no role that
   * grants the permission, and the requester no approver role. `"off"`: neither.
   */
  roleSeparation: "off" | "simple" | "strict";
  /**
   * The principals who contributed to the subject of the request, from the consumer's records.
   * Required: an empty list means "no contributors".
   */
  contributors: readonly string[];
};

export type ApprovalInput = {
  /** The original request. Its context.now is the request time. */
  request: AccessRequest;
  /** Each approval is validated on its own; an invalid one is rejected, not the whole input. */
  approvals: unknown[];
  /** Evaluation time. The requester's rights and the window are checked at this time. */
  now: string;
  /**
   * Earlier requests by the approvers, as the consumer's records show them, in the scope the
   * consumer chooses (for example only requests for the same subject). An entry counts if it
   * has the approver's id and the requested permission. Required if the operator switched on
   * requesterNeverApprovesSameType, and with a separation rule.
   */
  priorRequests?: PriorRequest[] | undefined;
  /**
   * The separation rule of this request. Validated on its own: an invalid rule refuses the
   * input with `separation_invalid`. Without it, the requester never approves and only the
   * policy's separationOfDuties flags apply, unless the policy requires a rule.
   */
  separation?: SeparationRule | undefined;
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

/**
 * A separation rule as the validator returns it. `contributors` stays optional here, because a
 * caller in plain JavaScript can omit it, and the evaluation refuses that with its own reason.
 */
export type CheckedSeparationRule = Omit<SeparationRule, "contributors"> & {
  contributors?: readonly string[] | undefined;
};

const ruleVersion = text({ min: 1, max: 128 });
const roleSeparation = oneOf(["off", "simple", "strict"]);
const contributorList = list(approverId);

/**
 * A separation rule, copied into a frozen object without a prototype. Unknown keys are refused.
 * `contributors` is optional in the shape so that its absence gets its own reason later.
 */
export const separationRule: Check<CheckedSeparationRule> = (value, path, issues) => {
  if (!isObject(value)) return fail(issues, path, "Expected a separation rule object.");
  const version = required(value, "version", path, issues, ruleVersion);
  const mayApprove = required(value, "requesterMayApprove", path, issues, bool);
  const separation = required(value, "roleSeparation", path, issues, roleSeparation);
  const contributors = optional(value, "contributors", path, issues, contributorList);
  const known = knownKeys(
    value,
    ["version", "requesterMayApprove", "roleSeparation", "contributors"],
    path,
    issues,
  );
  if (
    version === invalid ||
    mayApprove === invalid ||
    separation === invalid ||
    contributors.value === invalid ||
    !known
  ) {
    return invalid;
  }
  const rule = bare({
    version,
    requesterMayApprove: mayApprove,
    roleSeparation: separation,
    ...(contributors.value === undefined ? {} : { contributors: freeze(contributors.value) }),
  });
  return freeze(rule);
};

/** Any value. The approvals are checked one by one later, so one bad approval is a rejection. */
const anything: Check<unknown> = (value) => value;

const approvalList = list(anything, { max: maxApprovals });
const priorRequestList = list(priorRequest);

/** The input after the first pass: the separation rule is not checked yet. */
export type CheckedApprovalInput = Omit<ApprovalInput, "separation"> & { separation?: unknown };

/** The whole input. The request follows the rules of `accessRequest`, depth limit included. */
export const approvalInput: Check<CheckedApprovalInput> = (value, path, issues) => {
  if (!isObject(value)) return fail(issues, path, "Expected an approval input object.");
  const request = required(value, "request", path, issues, accessRequest);
  const approvals = required(value, "approvals", path, issues, approvalList);
  const now = required(value, "now", path, issues, requestTime);
  const prior = optional(value, "priorRequests", path, issues, priorRequestList);
  // Checked later with separationRule, so that a bad rule has its own reason.
  const separation = optional(value, "separation", path, issues, anything);
  const known = knownKeys(
    value,
    ["request", "approvals", "now", "priorRequests", "separation"],
    path,
    issues,
  );
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
    ...(separation.value === undefined ? {} : { separation: separation.value }),
  });
};
