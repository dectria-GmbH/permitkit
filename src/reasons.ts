/**
 * Stable reason codes. A code never changes its meaning once released. New codes may be added
 * in a minor release, so consumers must treat an unknown code as a deny.
 */
export const reasonCodes = Object.freeze({
  granted: "A grant of one of the subject's roles covers the request.",
  approval_required: "A grant covers the request, but a dual-approval rule applies to it.",
  invalid_request: "The request does not match the request schema.",
  policy_version_mismatch:
    "The request pins a policy version or digest that does not match the loaded policy.",
  unknown_permission: "The permission is not in the catalogue.",
  no_grant: "No grant of the subject's roles includes the permission.",
  scope_mismatch: "A grant includes the permission, but its scope does not cover the resource.",
  limit_exceeded: "A grant includes the permission, but a limit does not cover the resource.",
  denied_by_rule: "A deny rule matches the request. Deny rules win over grants.",
  agent_grant_missing: "An agent acts, but the request carries no agent grant.",
  agent_grant_principal_mismatch:
    "An agent grant in the chain belongs to another principal, or a prior actor's grant names another agent.",
  agent_grant_actor_mismatch: "The agent grant was issued to another agent.",
  agent_grant_not_yet_valid: "The agent grant starts after the request time.",
  agent_grant_expired: "The agent grant expired at or before the request time.",
  agent_grant_revoked: "The agent grant was revoked at or before the request time.",
  agent_grant_insufficient: "The agent grant does not cover the request.",
  sod_role_conflict:
    "Separation of duties: the subject holds both a requesting and an approving role for this permission.",
} as const);

export type ReasonCode = keyof typeof reasonCodes;

export const reasonHints: Record<ReasonCode, string> = Object.freeze({
  granted: "No action needed.",
  approval_required:
    "Record the request with its requestDigest and collect approvals, then call evaluateApprovals.",
  invalid_request: "Read the issues in explain() output and fix the request shape.",
  policy_version_mismatch:
    "Load the pinned policy version, or drop context.policyVersion to use the current policy.",
  unknown_permission:
    "Add the action to the catalogue in code, or fix the action or resource type.",
  no_grant: "Assign a role whose grants include this permission, if the subject should have it.",
  scope_mismatch:
    "Compare the resource properties with the role assignment scope and the grant scope in explain() output.",
  limit_exceeded: "Compare the resource property with the grant limit in explain() output.",
  denied_by_rule: "Check the deny rule named in decision.rule. A grant cannot override it.",
  agent_grant_missing: "Pass the grant in subject.act.grant. Agents never act without a grant.",
  agent_grant_principal_mismatch: "Use a grant that the principal of this request issued.",
  agent_grant_actor_mismatch: "Use the grant that the principal issued to this agent id.",
  agent_grant_not_yet_valid: "Wait until the grant's notBefore time, or issue a new grant.",
  agent_grant_expired: "Ask the principal to issue a new grant.",
  agent_grant_revoked: "Ask the principal to issue a new grant.",
  agent_grant_insufficient:
    "Ask the principal to extend the grant, within the principal's own rights.",
  sod_role_conflict:
    "Remove either the requesting or the approving role from the subject, or change the operator's separation-of-duties setting.",
});

/** Reasons why one approval does not count toward a dual-approval rule. */
export const approvalRejectionCodes = Object.freeze({
  approval_invalid: "The approval does not match the approval schema.",
  approver_not_human: "Only a human principal can approve.",
  approver_is_delegated: "An approval given through an agent does not count.",
  requester_cannot_approve:
    "The principal who requested the action, or an agent in its actor chain, cannot approve it.",
  duplicate_approver: "This approver was already counted for the request.",
  digest_mismatch: "The approval names another request digest.",
  approved_before_request: "The approval time is before the request time.",
  approved_after_expiry: "The approval time is after the approval window closed.",
  approved_in_future: "The approval time is after the evaluation time.",
  approver_role_missing: "The approver holds none of the approver roles for this resource.",
  approver_denied_by_rule: "A deny rule for this permission matches the approver.",
  approver_not_permitted: "The approver does not hold the permission that the rule requires.",
  sod_role_conflict: "Separation of duties: the approver also holds a requesting role.",
  sod_prior_request: "Separation of duties: the approver requested an action of this type before.",
  proof_missing: "The rule requires an approval proof and the approval has none.",
  proof_type_not_allowed: "The rule does not accept this proof type.",
  proof_mismatch: "The proof names another approver or another request digest.",
  proof_verifier_missing: "No verifier is registered for the proof type.",
  proof_invalid: "The verifier rejected the proof.",
} as const);

export type ApprovalRejectionCode = keyof typeof approvalRejectionCodes;

/** Reasons for the overall result of evaluateApprovals. */
export const approvalReasonCodes = Object.freeze({
  approved: "Enough distinct, eligible approvals exist.",
  approvals_pending: "Fewer eligible approvals exist than the rule requires.",
  approval_window_expired: "The approval window closed before the evaluation time.",
  approval_not_required: "No dual-approval rule applies; the request decision is allow.",
  requester_denied: "The requester no longer holds the permission. Read requesterDecision.",
  not_approvable_at_request_time:
    "At its request time, the request was not an approval_required decision under this rule.",
  sod_history_missing:
    "The operator requires the prior-request check, but the input has no priorRequests.",
  too_many_approvals: "The input holds more approvals than one evaluation reads (20).",
  input_too_large: "The request or the whole approval input exceeds the size bounds.",
  invalid_input:
    "The approval input does not match the schema, is not plain data, or is inconsistent.",
} as const);

export type ApprovalReasonCode = keyof typeof approvalReasonCodes;
