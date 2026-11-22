export { defineCatalog } from "./catalog.js";
export type { Catalog, CatalogDefinition, ResourceDefinition, ResourceEntry } from "./catalog.js";

export { compilePolicy, isCompiledPolicy, policySchema } from "./policy.js";
export type {
  ApprovalRule,
  CompiledPolicy,
  CompiledRole,
  DenyRule,
  GrantRule,
  Limits,
  PolicyDocument,
  PolicyInput,
  Scope,
} from "./policy.js";

export { accessRequestSchema, maxActorDepth } from "./request.js";
export type {
  AccessRequest,
  Actor,
  AgentGrant,
  AgentGrantEntry,
  RoleAssignment,
  Scalar,
  Subject,
} from "./request.js";

export { decide, explain, permissionOf, requestDigest } from "./decide.js";
export type {
  ApprovalRequirement,
  Decision,
  Explanation,
  MatchedRule,
  Outcome,
  TraceStep,
} from "./decide.js";

export { evaluateApprovals } from "./approval.js";
export type {
  Approval,
  ApprovalDecision,
  ApprovalInput,
  ApprovalOptions,
  ApprovalProof,
  ApprovalProofVerifier,
  ApprovalRejection,
  ProofVerification,
} from "./approval.js";

export { evaluate } from "./authzen.js";
export type { AuthZenRequest, AuthZenResponse } from "./authzen.js";

export { reevaluate, toDecisionRecord } from "./audit.js";
export type { ActorChainEntry, DecisionRecord, ReevaluationResult } from "./audit.js";

export { canonicalJson, digest } from "./canonical.js";

export { PermitkitError } from "./errors.js";
export type { ErrorCode, PolicyIssue } from "./errors.js";

export {
  approvalReasonCodes,
  approvalRejectionCodes,
  reasonCodes,
  reasonHints,
} from "./reasons.js";
export type { ApprovalReasonCode, ApprovalRejectionCode, ReasonCode } from "./reasons.js";
