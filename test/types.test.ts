// The exported types are hand-written. These assertions keep each one equal to the type that the
// earlier Zod schema gave, so the validators and the types cannot drift apart. `pnpm typecheck`
// checks them; the test body itself does nothing at run time.
import { describe, expectTypeOf, it } from "vitest";
import type { z } from "zod";

import type {
  AccessRequest,
  Actor,
  Approval,
  ApprovalInput,
  ApprovalProof,
  AgentGrant,
  AgentGrantEntry,
  ApprovalRule,
  DenyRule,
  EligibleApprovers,
  GrantRule,
  Limits,
  PolicyDocument,
  PolicyInput,
  RoleAssignment,
  Scalar,
  Scope,
  Subject,
  When,
} from "../src/index.js";
import type {
  accessRequestSchema,
  agentGrantEntrySchema,
  approvalInputSchema,
  approvalProofSchema,
  approvalSchema,
  agentGrantSchema,
  approvalRuleSchema,
  denySchema,
  eligibleApproversSchema,
  grantSchema,
  limitsSchema,
  policySchema,
  roleAssignmentSchema,
  scalarSchema,
  scopeSchema,
  subjectSchema,
  whenSchema,
  ZodActor,
} from "../src/zod-schemas.js";

describe("exported types", () => {
  it("equal the types of the earlier Zod schemas", () => {
    expectTypeOf<PolicyInput>().toEqualTypeOf<z.input<typeof policySchema>>();
    expectTypeOf<PolicyDocument>().toEqualTypeOf<z.output<typeof policySchema>>();
    expectTypeOf<Scope>().toEqualTypeOf<z.output<typeof scopeSchema>>();
    expectTypeOf<Limits>().toEqualTypeOf<z.output<typeof limitsSchema>>();
    expectTypeOf<When>().toEqualTypeOf<z.output<typeof whenSchema>>();
    expectTypeOf<EligibleApprovers>().toEqualTypeOf<z.output<typeof eligibleApproversSchema>>();
    expectTypeOf<GrantRule>().toEqualTypeOf<z.output<typeof grantSchema>>();
    expectTypeOf<DenyRule>().toEqualTypeOf<z.output<typeof denySchema>>();
    expectTypeOf<ApprovalRule>().toEqualTypeOf<z.output<typeof approvalRuleSchema>>();
    expectTypeOf<AccessRequest>().toEqualTypeOf<z.output<typeof accessRequestSchema>>();
    expectTypeOf<AccessRequest>().toEqualTypeOf<z.input<typeof accessRequestSchema>>();
    expectTypeOf<Actor>().toEqualTypeOf<ZodActor>();
    expectTypeOf<AgentGrant>().toEqualTypeOf<z.output<typeof agentGrantSchema>>();
    expectTypeOf<AgentGrantEntry>().toEqualTypeOf<z.output<typeof agentGrantEntrySchema>>();
    expectTypeOf<RoleAssignment>().toEqualTypeOf<z.output<typeof roleAssignmentSchema>>();
    expectTypeOf<Scalar>().toEqualTypeOf<z.output<typeof scalarSchema>>();
    expectTypeOf<Subject>().toEqualTypeOf<z.output<typeof subjectSchema>>();
    expectTypeOf<ApprovalProof>().toEqualTypeOf<z.output<typeof approvalProofSchema>>();
    expectTypeOf<Approval>().toEqualTypeOf<z.output<typeof approvalSchema>>();
    expectTypeOf<ApprovalInput>().toEqualTypeOf<z.input<typeof approvalInputSchema>>();
  });
});
