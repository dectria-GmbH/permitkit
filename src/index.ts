export { defineCatalog, isCatalog } from "./catalog.js";
export type { Catalog, CatalogDefinition, ResourceDefinition, ResourceEntry } from "./catalog.js";

export { compilePolicy, isCompiledPolicy, policySchemaVersion } from "./policy.js";
export type {
  ApprovalRule,
  CompiledPolicy,
  CompiledRole,
  DenyRule,
  EligibleApprovers,
  GrantRule,
  Limits,
  PolicyDocument,
  PolicyInput,
  Scope,
  When,
} from "./policy.js";

export { maxActorDepth } from "./request.js";
export type {
  AccessRequest,
  Actor,
  AgentGrant,
  AgentGrantEntry,
  RoleAssignment,
  Scalar,
  Subject,
} from "./request.js";

export { decide, explain, parseRequest, permissionOf, requestDigest } from "./decide.js";
export type {
  ApprovalRequirement,
  Decision,
  Explanation,
  MatchedRule,
  Outcome,
  ParsedRequest,
  TraceStep,
} from "./decide.js";

export { evaluateApprovals } from "./approval.js";
export type {
  AppliedSeparation,
  Approval,
  ApprovalDecision,
  ApprovalInput,
  ApprovalOptions,
  ApprovalProof,
  ApprovalProofVerifier,
  ApprovalRejection,
  ApprovalWaiver,
  ProofVerification,
  SeparationCheck,
  SeparationRule,
} from "./approval.js";

export { evaluate } from "./authzen.js";
export type { AuthZenRequest, AuthZenResponse } from "./authzen.js";

export { decideAndRecord, reevaluate, toDecisionRecord } from "./audit.js";
export type { ActorChainEntry, DecisionRecord, ReevaluationResult } from "./audit.js";

export { canonicalJson, digest } from "./canonical.js";

export { plainDataRuntime } from "./plain.js";

export { PermitkitError } from "./errors.js";
export type { ErrorCode, PolicyIssue } from "./errors.js";

export {
  approvalReasonCodes,
  approvalRejectionCodes,
  reasonCodes,
  reasonHints,
} from "./reasons.js";
export type { ApprovalReasonCode, ApprovalRejectionCode, ReasonCode } from "./reasons.js";
