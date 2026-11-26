import {
  approval as approvalCheck,
  approvalInput,
  type Approval,
  type ApprovalProof,
} from "./approval-input.js";
import {
  approvalInputBounds,
  maxApprovals,
  ownArrayLength,
  ownDataValue,
  requestBounds,
  snapshotOf,
} from "./bounds.js";
import { decide, denyRuleMatches, permissionOf, requestDigest, type Decision } from "./decide.js";
import { scopeCovers } from "./engine/conditions.js";
import { isPermitkitError, PermitkitError } from "./errors.js";
import {
  append,
  apply,
  awaitable,
  bareObject,
  contains,
  defineData,
  field,
  freeze,
  hasOwn,
  isArray,
  mapGet,
  mapSet,
  newMap,
  newSet,
  objectKeys,
  setAdd,
  hasThen,
  promiseHooksIntact,
  setHas,
  settledValue,
} from "./intrinsics.js";
import { internalsOf, type CompiledPolicy, type DenyRule } from "./policy.js";
import type { ApprovalReasonCode, ApprovalRejectionCode } from "./reasons.js";
import { instant } from "./time.js";
import { invalid, type Checked, type Issue } from "./validate.js";

export type { Approval, ApprovalInput, ApprovalProof, PriorRequest } from "./approval-input.js";

export type ProofVerification =
  | { readonly valid: true; readonly approverId: string; readonly requestDigest: string }
  | { readonly valid: false; readonly reason: string };

/**
 * Verifies one proof type. On success, a verifier returns the approver id and the request digest
 * that the verified evidence itself covers: for a WebAuthn assertion, the owner of the credential
 * and the signed challenge. permitkit compares these with what it expects. Never copy them from
 * `expected`; that turns the comparison into a no-op, and a valid assertion for one request then
 * passes for another. `expected` is for lookups, for example to load the approver's credentials.
 * `expected` is frozen and has no prototype, so methods such as `hasOwnProperty` are not on it.
 * The verifier should also time out on its own: permitkit waits for its promise.
 *
 * Rule: return every result, also `{ valid: false }`, as an object without a prototype, for
 * example `Object.assign(Object.create(null), { valid: true, approverId, requestDigest })`.
 * Resolving the verifier's promise reads `then` through the prototype chain of the result, and a
 * `then` that caller code sets there, on any prototype, can turn the result into another value.
 * permitkit cannot see a `then` that is set and removed while the verifier runs. Return a native
 * promise or a plain value: any other thenable, for example a query builder, never counts.
 */
export interface ApprovalProofVerifier {
  readonly type: string;
  verify(
    proof: ApprovalProof,
    expected: { readonly approverId: string; readonly requestDigest: string },
  ): ProofVerification | Promise<ProofVerification>;
}

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
export function evaluateApprovals(
  policy: CompiledPolicy,
  input: unknown,
  options: ApprovalOptions = {},
): Promise<ApprovalDecision> {
  // A plain function, not async: the promise of an async function has no own constructor, so
  // the caller's `await` would read Promise.prototype.constructor and then, which caller code
  // can replace. awaitable gives the returned promise an own constructor and an own then.
  return awaitable(evaluateApprovalsGuarded(policy, input, options));
}

async function evaluateApprovalsGuarded(
  policy: CompiledPolicy,
  input: unknown,
  options: ApprovalOptions,
): Promise<ApprovalDecision> {
  try {
    return await awaitable(evaluateApprovalsUnguarded(policy, input, options));
  } catch (error) {
    if (isPermitkitError(error)) throw error;
    // Internals can fail under polluted built-in prototypes. Deny, built without array methods.
    return decisionOf({
      outcome: "deny",
      allowed: false,
      reason: "invalid_input",
      ruleId: null,
      required: 0,
      counted: [],
      rejected: [],
      requesterDecision: null,
      policy: { version: policy.version, digest: policy.digest },
      requestDigest: null,
    });
  }
}

async function evaluateApprovalsUnguarded(
  policy: CompiledPolicy,
  input: unknown,
  options: ApprovalOptions,
): Promise<ApprovalDecision> {
  const internal = internalsOf(policy);
  if (internal === undefined) {
    throw new PermitkitError(
      "policy_unknown",
      "evaluateApprovals() needs a policy from compilePolicy().",
    );
  }
  // Options are checked first, so bad options fail on every path, not only on proof checks.
  let verifiers: ReadonlyMap<string, BoundVerifier>;
  try {
    verifiers = verifierMap(options);
  } catch (error) {
    if (isPermitkitError(error)) throw error;
    // A hostile options object (proxy, throwing getter) is still a programming error.
    throw new PermitkitError("options_invalid", "The options could not be read.");
  }
  const policyRef = { version: policy.version, digest: policy.digest };
  const result = (
    outcome: ApprovalDecision["outcome"],
    reason: ApprovalReasonCode,
    rest: Partial<ApprovalDecision> = {},
  ): ApprovalDecision =>
    decisionOf({
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

  // Cost bounds before any other work: the number of approvals is read without copying, and
  // the request must meet the same bounds as a request passed to decide().
  const approvalCount = ownArrayLength(input, "approvals");
  if (approvalCount !== undefined && approvalCount > maxApprovals) {
    return result("deny", "too_many_approvals");
  }
  const requestCheck = snapshotOf(ownDataValue(input, "request"), requestBounds);
  if (!requestCheck.ok) {
    return result(
      "deny",
      requestCheck.reason === "too_large" ? "input_too_large" : "invalid_input",
    );
  }
  const whole = snapshotOf(input, approvalInputBounds);
  if (!whole.ok) {
    return result("deny", whole.reason === "too_large" ? "input_too_large" : "invalid_input");
  }
  const snapshot = whole.value;
  // Hand-written validators on the plain-data copy: every value below is read from it, and no
  // built-in runs that caller code could have replaced after load.
  const issues: Issue[] = [];
  const data = approvalInput(snapshot, null, issues);
  if (data === invalid) return result("deny", "invalid_input");
  const request = data.request;
  const nowText = data.now;
  const priorRequests = data.priorRequests;
  // Every approval is validated into a new object before any further step and before any
  // verifier runs, so no caller code runs between the check of a value and its use.
  const approvals: Checked<Approval>[] = [];
  for (let index = 0; index < data.approvals.length; index += 1) {
    append(approvals, approvalCheck(data.approvals[index], null, []));
  }
  const now = instant(nowText);
  const requestedAt = instant(request.context.now);
  // Written so that an unreadable time fails the check.
  if (!(now >= requestedAt)) return result("deny", "invalid_input");

  let digestValue: string;
  try {
    digestValue = requestDigest(policy, request);
  } catch (error) {
    // requestDigest throws only PermitkitErrors that it built, so `code` is its own data.
    if (isPermitkitError(error) && error.code === "request_invalid") {
      return result("deny", "invalid_input");
    }
    throw error;
  }
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
  // A misspelt permission in the history would match nothing and let a prior requester approve.
  const history = priorRequests ?? [];
  if (sod.requesterNeverApprovesSameType) {
    for (let index = 0; index < history.length; index += 1) {
      const prior = history[index];
      if (prior === undefined || !policy.catalog.isPermission(prior.permission)) {
        return result("deny", "invalid_input", ruleBase);
      }
    }
  }
  // Roles with a grant for the permission. Index loops over the compiled role list.
  const requestingRoles = newSet<string>();
  const roleList = internal.roles.list;
  for (let index = 0; index < roleList.length; index += 1) {
    const role = roleList[index];
    if (role === undefined) continue;
    for (let grantIndex = 0; grantIndex < role.grants.length; grantIndex += 1) {
      const grant = role.grants[grantIndex];
      if (grant !== undefined && contains(grant.permissions, permission)) {
        setAdd(requestingRoles, role.name);
        break;
      }
    }
  }
  const properties = request.resource.properties;
  // The requester is the principal and every agent in its actor chain.
  const requesterIds = newSet<string>();
  setAdd(requesterIds, request.subject.id);
  for (let actor = request.subject.act; actor !== null; actor = actor.act) {
    setAdd(requesterIds, actor.id);
  }

  const counted: string[] = [];
  const rejected: ApprovalRejection[] = [];
  for (let index = 0; index < approvals.length; index += 1) {
    const approval = approvals[index];
    if (approval === undefined || approval === invalid) {
      append(rejected, { index, approverId: null, reason: "approval_invalid" });
      continue;
    }
    const approver = approval.approver;
    const reject = (reason: ApprovalRejectionCode, detail?: string) => {
      append(rejected, { index, approverId: approver.id, reason, ...(detail ? { detail } : {}) });
    };
    if (approver.type !== "human") {
      reject("approver_not_human");
      continue;
    }
    if (approver.act !== null) {
      reject("approver_is_delegated");
      continue;
    }
    if (setHas(requesterIds, approver.id)) {
      reject("requester_cannot_approve");
      continue;
    }
    if (contains(counted, approver.id)) {
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
    let denyRule: DenyRule | undefined;
    for (let denyIndex = 0; denyIndex < internal.denies.length; denyIndex += 1) {
      const candidate = internal.denies[denyIndex];
      // An unreadable deny rule is an internal failure; the catch above denies.
      if (candidate === undefined) throw new TypeError("A deny rule could not be read.");
      if (denyRuleMatches(candidate, approver, permission, properties)) {
        denyRule = candidate;
        break;
      }
    }
    if (denyRule !== undefined) {
      reject("approver_denied_by_rule", denyRule.id);
      continue;
    }
    const eligibility = rule.eligibleApprovers;
    if (eligibility.kind === "roles") {
      const approverRoles = eligibility.roles;
      let eligible = false;
      for (let roleIndex = 0; roleIndex < approver.roles.length && !eligible; roleIndex += 1) {
        const assignment = approver.roles[roleIndex];
        eligible =
          assignment !== undefined &&
          contains(approverRoles, assignment.role) &&
          scopeCovers(assignment.scope, properties).ok;
      }
      if (!eligible) {
        reject("approver_role_missing");
        continue;
      }
    } else if (eligibility.kind === "permission") {
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
    } else {
      // No other kind passes the schema. Fail closed if one ever does.
      reject("approver_role_missing");
      continue;
    }
    if (sod.exclusiveRequestAndApproveRoles) {
      let conflict: string | undefined;
      for (let roleIndex = 0; roleIndex < approver.roles.length; roleIndex += 1) {
        const assignment = approver.roles[roleIndex];
        if (assignment !== undefined && setHas(requestingRoles, assignment.role)) {
          conflict = assignment.role;
          break;
        }
      }
      if (conflict !== undefined) {
        reject("sod_role_conflict", conflict);
        continue;
      }
    }
    if (sod.requesterNeverApprovesSameType) {
      let requestedBefore = false;
      for (let priorIndex = 0; priorIndex < history.length && !requestedBefore; priorIndex += 1) {
        const prior = history[priorIndex];
        requestedBefore =
          prior !== undefined &&
          prior.principalId === approver.id &&
          prior.permission === permission;
      }
      if (requestedBefore) {
        reject("sod_prior_request");
        continue;
      }
    }
    if (rule.requireProof) {
      const rejection = await awaitable(
        checkProof(approval, approver.id, digestValue, verifiers, rule.proofTypes),
      );
      if (rejection !== null) {
        reject(rejection.reason, rejection.detail);
        continue;
      }
    }
    append(counted, approver.id);
  }

  const rest = { ...ruleBase, counted, rejected };
  if (counted.length >= rule.approvers) return result("allow", "approved", rest);
  return result("pending", "approvals_pending", rest);
}

/** The detail of a proof that is not counted because a promise hook changed. */
const hooksChanged =
  "a then on a built-in prototype, or a replaced Promise.prototype.then, " +
  "Promise.prototype.constructor or Promise[Symbol.species]";

/** The detail of a proof whose result is a thenable but not a native promise. */
const foreignThenable = "verifier returned a thenable that is not a native promise";

async function checkProof(
  approval: Approval,
  approverId: string,
  digestValue: string,
  verifiers: ReadonlyMap<string, BoundVerifier>,
  proofTypes: readonly string[] | undefined,
): Promise<ProofRejection | null> {
  const proof = approval.proof;
  if (proof === undefined) return proofRejection("proof_missing");
  if (proofTypes !== undefined && !contains(proofTypes, proof.type)) {
    return proofRejection("proof_type_not_allowed", proof.type);
  }
  if (proof.approverId !== approverId || proof.requestDigest !== digestValue) {
    return proofRejection("proof_mismatch");
  }
  const verifier = mapGet(verifiers, proof.type);
  if (verifier === undefined) return proofRejection("proof_verifier_missing", proof.type);
  // A then on Object.prototype, Array.prototype or Function.prototype, or a replaced
  // Promise.prototype.then, could choose the result of an async verifier inside its own promise, before permitkit reads it. Fail closed,
  // before the call and again after the result settles.
  if (!promiseHooksIntact()) return proofRejection("proof_invalid", hooksChanged);
  try {
    // Not `await` on the result: it would read `then` and `constructor`, which caller code can
    // replace after load and so choose the verification.
    const settled = await settledValue(
      verifier.verify(proof, expectation(approverId, digestValue)),
    );
    if (!promiseHooksIntact()) return proofRejection("proof_invalid", hooksChanged);
    // The captured then threw for a promise or thenable: a getter on its constructor or species
    // may have changed the value, so it never counts.
    if (settled.refused === "promise") return proofRejection("proof_invalid", hooksChanged);
    if (settled.refused === "thenable") return proofRejection("proof_invalid", foreignThenable);
    const verification = settled.value;
    // Count only the exact success shape. Anything else, also a truthy string, is a rejection.
    // Own properties only: an inherited `valid` or echo must never count.
    if (ownValue(verification, "valid") !== true) {
      const reason = ownValue(verification, "reason");
      if (typeof reason === "string") return proofRejection("proof_invalid", reason);
      return proofRejection(
        "proof_invalid",
        hasThen(verification) ? foreignThenable : "verifier did not confirm",
      );
    }
    if (
      ownValue(verification, "approverId") !== approverId ||
      ownValue(verification, "requestDigest") !== digestValue
    ) {
      return proofRejection("proof_invalid", "verifier echo does not match");
    }
    return null;
  } catch {
    // The verifier threw, or its result or error object threw when read. Never count it.
    return proofRejection("proof_invalid", "verifier failed");
  }
}

/**
 * What the verifier gets as `expected`: frozen and without a prototype. A read of an inherited
 * key, for example `toJSON` in JSON.stringify(expected), then runs no getter that caller code
 * set on Object.prototype.
 */
function expectation(approverId: string, digestValue: string): VerifierExpectation {
  const value = bareObject<{ approverId: string; requestDigest: string }>();
  value.approverId = approverId;
  value.requestDigest = digestValue;
  return freeze(value);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null;
}

function failOptions(message: string): never {
  throw new PermitkitError("options_invalid", message);
}

interface VerifierExpectation {
  readonly approverId: string;
  readonly requestDigest: string;
}

/** A verifier as permitkit stores it: type and verify read once, result not trusted. */
interface BoundVerifier {
  readonly type: string;
  verify(proof: ApprovalProof, expected: VerifierExpectation): unknown;
}

interface ProofRejection {
  readonly reason: ApprovalRejectionCode;
  readonly detail?: string;
}

/**
 * A rejection without a prototype. checkProof is async: a plain object would inherit a
 * polluted Object.prototype.then and be resolved as a thenable, which could turn a rejection
 * into null, and null means "counted".
 */
function proofRejection(reason: ApprovalRejectionCode, detail?: string): ProofRejection {
  const value = bareObject<{ reason: ApprovalRejectionCode; detail?: string }>();
  value.reason = reason;
  if (detail !== undefined) value.detail = detail;
  return value;
}

/**
 * Validates the options once. Bad options are a programming error, so they throw a coded error.
 * Two verifiers for one type are rejected, because the second would silently replace the first.
 */
function verifierMap(options: unknown): ReadonlyMap<string, BoundVerifier> {
  if (!isRecord(options)) return failOptions("The options must be an object.");
  const keys = objectKeys(options);
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    if (key !== "verifiers") return failOptions(`Unknown option: ${key ?? ""}.`);
  }
  const list: unknown = hasOwn(options, "verifiers") ? options["verifiers"] : undefined;
  const map = newMap<string, BoundVerifier>();
  if (list === undefined) return map;
  if (!isArray(list)) return failOptions("options.verifiers must be an array.");
  // By index, not for-of: a for-of reads the array iterator, which caller code can replace.
  for (let index = 0; index < list.length; index += 1) {
    const item: unknown = list[index];
    // Read type and verify once, from own properties, and keep the values read.
    const type = ownValue(item, "type");
    const verify = ownValue(item, "verify");
    if (typeof type !== "string" || typeof verify !== "function") {
      return failOptions("Each verifier needs an own string type and an own verify function.");
    }
    if (mapGet(map, type) !== undefined) return failOptions(`Two verifiers have the type ${type}.`);
    const bound = (proof: ApprovalProof, expected: VerifierExpectation): unknown =>
      apply(verify, item, [proof, expected]);
    mapSet(map, type, freeze({ type, verify: bound }));
  }
  return map;
}

function ownValue(value: unknown, key: string): unknown {
  if (!isRecord(value) || !hasOwn(value, key)) return undefined;
  return value[key];
}

/**
 * A copy of the decision without a prototype. An inherited `then` on Object.prototype must not
 * turn the result into a thenable, which would keep the returned promise pending forever.
 */
function decisionOf(fields: ApprovalDecision): ApprovalDecision {
  const decision = bareObject<ApprovalDecision>();
  const keys = objectKeys(fields);
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    if (key !== undefined) defineData(decision, key, field(fields, key));
  }
  return decision;
}
