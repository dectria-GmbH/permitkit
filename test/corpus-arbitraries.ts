// Generators for the verdict corpora in test/zod-verdicts.test.ts: policy documents, approval
// inputs, approvals, proofs and decision records. Request generators are in request-arbitraries.ts.
// The recorded Zod verdicts belong to the inputs that these generators give for a fixed seed, so a
// change here changes the corpus: test/zod-verdicts.test.ts then fails on the input digest.
import * as fc from "fast-check";

import { maxApprovalWindowSeconds } from "../src/time.js";
import {
  identifierArb,
  latestRequestInstant,
  limitsArb,
  optionalField,
  permissionArb,
  scopeArb,
  textArb,
  timestampArb,
} from "./differential.js";
import { idArb, requestArb, subjectArb, timestamp } from "./request-arbitraries.js";

// Policy documents.

const permissionsArb = fc.array(permissionArb, { minLength: 1, maxLength: 3 });
const descriptionArb = optionalField(
  "description",
  fc.oneof(
    { weight: 8, arbitrary: textArb(12) },
    { weight: 1, arbitrary: fc.constant("d".repeat(1000)) },
  ),
);

const grantArb = fc.record({
  id: identifierArb,
  permissions: permissionsArb,
  scope: scopeArb,
  limits: limitsArb,
});

const roleArb = fc
  .tuple(descriptionArb, fc.array(grantArb, { maxLength: 3 }))
  .map(([description, grants]) => ({ ...description, grants }));

const denyArb = fc
  .tuple(
    identifierArb,
    descriptionArb,
    permissionsArb,
    optionalField("roles", fc.array(identifierArb, { minLength: 1, maxLength: 2 })),
    optionalField("subjectTypes", fc.subarray(["human", "service", "agent"], { minLength: 1 })),
    scopeArb,
  )
  .map(([id, description, permissions, roles, subjectTypes, scope]) => ({
    id,
    ...description,
    permissions,
    ...roles,
    ...subjectTypes,
    scope,
  }));

const whenArb = fc.oneof(
  fc.constant({ kind: "always" }),
  fc.record({
    kind: fc.constant("threshold"),
    properties: fc.dictionary(
      identifierArb,
      fc.record({
        gte: fc.oneof(fc.integer(), fc.double({ noNaN: true, noDefaultInfinity: true })),
      }),
      { minKeys: 1, maxKeys: 2 },
    ),
  }),
);

const eligibleArb = fc.oneof(
  fc.constant({ kind: "permission" }),
  fc.record({
    kind: fc.constant("roles"),
    roles: fc.array(identifierArb, { minLength: 1, maxLength: 2 }),
  }),
);

const approvalRuleArb = fc
  .tuple(
    identifierArb,
    descriptionArb,
    permissionsArb,
    whenArb,
    fc.integer({ min: 1, max: 10 }),
    eligibleArb,
    fc.oneof(
      fc.constantFrom(60, maxApprovalWindowSeconds),
      fc.integer({ min: 60, max: maxApprovalWindowSeconds }),
    ),
    fc.boolean(),
    optionalField(
      "proofTypes",
      fc.array(fc.oneof(textArb(8, 1), fc.constant("p".repeat(64))), {
        minLength: 1,
        maxLength: 2,
      }),
    ),
  )
  .map(
    ([
      id,
      description,
      permissions,
      when,
      approvers,
      eligibleApprovers,
      expiresInSeconds,
      requireProof,
      proofTypes,
    ]) => ({
      id,
      ...description,
      permissions,
      when,
      approvers,
      eligibleApprovers,
      expiresInSeconds,
      requireProof,
      ...proofTypes,
    }),
  );

export const policyArb = fc.record({
  schema: fc.constant(2),
  version: fc.oneof(textArb(8, 1), fc.constant("v".repeat(128))),
  roles: fc.dictionary(identifierArb, roleArb, { maxKeys: 3 }),
  denies: fc.array(denyArb, { maxLength: 2 }),
  approvalRules: fc.array(approvalRuleArb, { maxLength: 2 }),
  separationOfDuties: fc.record({
    requesterNeverApprovesSameType: fc.boolean(),
    exclusiveRequestAndApproveRoles: fc.boolean(),
  }),
});

// Approval inputs, approvals and proofs.

const digestArb = fc.oneof(
  { weight: 8, arbitrary: fc.stringMatching(/^[0-9a-f]{64}$/) },
  { weight: 1, arbitrary: fc.constant("0".repeat(64)) },
);

const payloadArb = fc.oneof(
  fc.constant(null),
  fc.boolean(),
  fc.integer(),
  textArb(8),
  fc.record({ ok: fc.boolean(), signature: textArb(8) }),
  fc.array(fc.oneof(fc.integer(), textArb(4)), { maxLength: 3 }),
);

export const proofArb = fc
  .tuple(
    fc.oneof(textArb(8, 1), fc.constant("p".repeat(64))),
    idArb,
    digestArb,
    optionalField("payload", payloadArb),
  )
  .map(([type, approverId, requestDigest, payload]) => ({
    type,
    approverId,
    requestDigest,
    ...payload,
  }));

export const approvalArb = fc
  .tuple(subjectArb, timestamp, digestArb, optionalField("proof", proofArb))
  .map(([approver, approvedAt, requestDigest, proof]) => ({
    approver,
    approvedAt,
    requestDigest,
    ...proof,
  }));

const priorRequestArb = fc.record({
  principalId: fc.oneof(textArb(6, 1), idArb),
  permission: fc.oneof(permissionArb, textArb(6, 1)),
});

export const approvalInputArb = fc
  .tuple(
    requestArb,
    fc.array(approvalArb, { maxLength: 3 }),
    timestampArb(latestRequestInstant),
    optionalField("priorRequests", fc.array(priorRequestArb, { maxLength: 3 })),
  )
  .map(([request, approvals, now, priorRequests]) => ({
    request,
    approvals,
    now,
    ...priorRequests,
  }));

// Decision records.

export const recordArb = fc
  .tuple(
    fc.oneof(
      { weight: 8, arbitrary: fc.constant("permitkit.decision/2") },
      { weight: 1, arbitrary: textArb(4) },
    ),
    fc.record({
      version: textArb(6),
      digest: fc.oneof(fc.stringMatching(/^[0-9a-f]{64}$/), textArb(4)),
    }),
    optionalField("request", fc.oneof(requestArb, fc.constant(null))),
    fc.option(fc.stringMatching(/^[0-9a-f]{64}$/), { nil: null }),
    fc.array(
      fc.record({
        type: fc.constantFrom("human", "service", "agent"),
        id: idArb,
        grantId: fc.option(idArb, { nil: null }),
      }),
      { maxLength: 3 },
    ),
    fc.constantFrom("allow", "deny", "approval_required"),
    fc.constantFrom("granted", "no_grant", "approval_required", "invalid_request"),
    optionalField(
      "rule",
      fc.oneof(fc.constant(null), fc.record({ kind: fc.constant("grant"), role: idArb })),
    ),
    optionalField(
      "approval",
      fc.oneof(fc.constant(null), fc.record({ ruleId: idArb, approvers: fc.integer() })),
    ),
  )
  .map(([schema, policy, request, requestDigest, actorChain, outcome, reason, rule, approval]) => ({
    schema,
    policy,
    ...request,
    requestDigest,
    actorChain,
    outcome,
    reason,
    ...rule,
    ...approval,
  }));
