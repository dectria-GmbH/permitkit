/**
 * The Zod 3 schemas that permitkit used before its hand-written validators. Only the
 * differential tests import this module. The schemas here are the reference that those tests
 * compare the hand-written validators with. Do not change them to match a validator.
 */

import { z } from "zod";

// Private copies, so that the reference shares no code with the hand-written validators.
// policySchemaVersion is from src/policy.ts and maxActorDepth from src/request.ts; the other
// constants and the timestamp checks are from src/time.ts. All are verbatim as of e258cf0.

/** The policy document format that this release reads. */
const policySchemaVersion = 2;

/** Maximum nesting of `act`. RFC 8693 chains in practice are short. */
const maxActorDepth = 4;

/**
 * ISO 8601 date-time with seconds, at most millisecond precision and an explicit offset in
 * the range of the ECMAScript date-time format. Wider forms (offsets above 23:59, offsets
 * without a colon, more fraction digits) parse differently or not at all across engines, so
 * they are rejected.
 */
const isoInstant =
  /^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])T([01]\d|2[0-3]):[0-5]\d:[0-5]\d(\.\d{1,3})?(Z|[+-]([01]\d|2[0-3]):[0-5]\d)$/;

/** The longest approval window that a policy can set, in seconds (31 days). */
const maxApprovalWindowSeconds = 31 * 24 * 3600;

/**
 * The earliest and latest accepted instants. Inside this range, the UTC form of every timestamp
 * has a four-digit year, so a normalized time (`toISOString()`) is again a valid timestamp.
 * An offset can move a local time across a bound: `0000-01-01T00:30:00+01:00` is in year -1.
 */
const earliestInstant = Date.parse("0000-01-01T00:00:00.000Z");
const latestInstant = Date.parse("9999-12-31T23:59:59.999Z");

/**
 * The latest accepted request time. The end of the longest approval window after it is still
 * inside the accepted range, so `approval.expiresAt` is always a valid timestamp.
 */
const latestRequestInstant = latestInstant - maxApprovalWindowSeconds * 1000;

const timestampMessage =
  "Use an ISO 8601 date-time with an offset, for example 2026-01-15T10:00:00Z.";

/** A timestamp between 0000-01-01T00:00:00Z and 9999-12-31T23:59:59.999Z. */
export const timestampSchema = z
  .string()
  .regex(isoInstant, timestampMessage)
  .refine(isCalendarInstant, "The date-time does not exist.")
  .refine(
    (value) => inRange(value, latestInstant),
    "The date-time must be between 0000-01-01T00:00:00Z and 9999-12-31T23:59:59.999Z.",
  );

/**
 * A request or evaluation time. It ends 31 days before the latest timestamp, so the end of an
 * approval window that starts at it can still be written as a timestamp.
 */
export const requestTimeSchema = timestampSchema.refine(
  (value) => inRange(value, latestRequestInstant),
  "A request time must be at most 9999-11-30T23:59:59.999Z.",
);

function inRange(value: string, latest: number): boolean {
  const time = Date.parse(value);
  // Written so that an unreadable time fails the check.
  return time >= earliestInstant && time <= latest;
}

/**
 * Rejects days that the month does not have. V8 reads 2026-02-30 as 2 March, other engines
 * return NaN, so the day is checked here instead of trusting Date.parse.
 */
function isCalendarInstant(value: string): boolean {
  const year = Number(value.slice(0, 4));
  const month = Number(value.slice(5, 7));
  const day = Number(value.slice(8, 10));
  // setUTCFullYear, because Date.UTC maps the years 0 to 99 to 1900 to 1999.
  const end = new Date(0);
  end.setUTCFullYear(year, month, 0);
  const daysInMonth = end.getUTCDate();
  return day <= daysInMonth && Number.isFinite(Date.parse(value));
}

const identifier = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9][A-Za-z0-9_.:-]*$/, "Use letters, digits, and _ . : - only.");
const permissionName = z
  .string()
  .regex(/^[a-z][a-z0-9_-]*:[a-z][a-z0-9_-]*$/, "Use the form <resource>:<action>.");

/**
 * A discriminated union on `kind` whose error names the accepted shapes. A missing, null, empty
 * or misspelt value is refused; no shape is ever read as the wide case by default.
 */
function explicit<
  Options extends [
    z.ZodDiscriminatedUnionOption<"kind">,
    ...z.ZodDiscriminatedUnionOption<"kind">[],
  ],
>(what: string, shapes: string, options: Options) {
  const message = `State the ${what} explicitly: ${shapes}. A missing, null, empty or unknown ${what} is refused.`;
  return z.discriminatedUnion("kind", options, {
    errorMap: (issue, context) =>
      issue.code === z.ZodIssueCode.invalid_type || issue.code === "invalid_union_discriminator"
        ? { message }
        : { message: context.defaultError },
  });
}

const scopeValue = z
  .string()
  .min(1)
  .refine((value) => value !== "*", '"*" is not a wildcard. Use { kind: "all" } for everywhere.');

/** Property name to the list of allowed string values. At least one property. */
const scopeValueLists = z
  .record(identifier, z.array(scopeValue).min(1).max(1000))
  .refine(
    (properties) => Object.keys(properties).length > 0,
    'A match scope needs at least one property. Use { kind: "all" } for everywhere.',
  );

/**
 * Where a grant, role assignment, agent grant entry or deny rule applies.
 * `{ kind: "all" }` is the only way to say "everywhere". `{ kind: "match", properties }` lists
 * the allowed string values per resource property.
 */
export const scopeSchema = explicit(
  "scope",
  '{ kind: "all" } or { kind: "match", properties: { <property>: [<values>] } }',
  [
    z.object({ kind: z.literal("all") }).strict(),
    z.object({ kind: z.literal("match"), properties: scopeValueLists }).strict(),
  ],
);

/**
 * An inclusive numeric range. Both bounds are required: a number, or `null` for "no bound on
 * this side". A lost bound is refused, never read as open. At least one bound is a number.
 */
const limitSchema = z
  .object({ min: z.number().finite().nullable(), max: z.number().finite().nullable() })
  .strict()
  .refine(
    (limit) => limit.min !== null || limit.max !== null,
    "Give at least one bound as a number. Both bounds null restrict nothing.",
  )
  .refine(
    (limit) => limit.min === null || limit.max === null || limit.min <= limit.max,
    "min must not be greater than max.",
  );

/**
 * Numeric limits of a grant or agent grant entry. `{ kind: "unlimited" }` is the only way to
 * say "no limit". `{ kind: "range", properties }` gives a range per numeric resource property.
 */
export const limitsSchema = explicit(
  "limits",
  '{ kind: "unlimited" } or { kind: "range", properties: { <property>: { min, max } } } with each bound a number or null',
  [
    z.object({ kind: z.literal("unlimited") }).strict(),
    z
      .object({
        kind: z.literal("range"),
        properties: z
          .record(identifier, limitSchema)
          .refine(
            (properties) => Object.keys(properties).length > 0,
            'A range needs at least one property. Use { kind: "unlimited" } for no limit.',
          ),
      })
      .strict(),
  ],
);

/**
 * When an approval rule applies. `{ kind: "always" }` applies to every covered request.
 * `{ kind: "threshold", properties }` applies if any listed property is at least `gte`, is
 * missing, or is not a finite number.
 */
export const whenSchema = explicit(
  "when condition",
  '{ kind: "always" } or { kind: "threshold", properties: { <property>: { gte } } }',
  [
    z.object({ kind: z.literal("always") }).strict(),
    z
      .object({
        kind: z.literal("threshold"),
        properties: z
          .record(identifier, z.object({ gte: z.number().finite() }).strict())
          .refine(
            (properties) => Object.keys(properties).length > 0,
            'A threshold needs at least one property. Use { kind: "always" } instead.',
          ),
      })
      .strict(),
  ],
);

/**
 * Who may approve. `{ kind: "roles", roles }`: a holder of one of these roles whose assignment
 * scope covers the resource. `{ kind: "permission" }`: a holder of the permission itself.
 */
export const eligibleApproversSchema = explicit(
  "approver eligibility",
  '{ kind: "roles", roles: [<role>] } or { kind: "permission" }',
  [
    z.object({ kind: z.literal("permission") }).strict(),
    z.object({ kind: z.literal("roles"), roles: z.array(identifier).min(1) }).strict(),
  ],
);

export const grantSchema = z
  .object({
    id: identifier,
    permissions: z.array(permissionName).min(1),
    scope: scopeSchema,
    limits: limitsSchema,
  })
  .strict();

export const roleSchema = z
  .object({
    description: z.string().max(1000).optional(),
    grants: z.array(grantSchema),
  })
  .strict();

// Literals, not z.enum: Zod 3 caches enum values on the instance through a lazy property.
export const subjectTypeSchema = z.union([
  z.literal("human"),
  z.literal("service"),
  z.literal("agent"),
]);

export const denySchema = z
  .object({
    id: identifier,
    description: z.string().max(1000).optional(),
    permissions: z.array(permissionName).min(1),
    /** The rule applies only to subjects that hold one of these roles. Absent: everyone. */
    roles: z.array(identifier).min(1).optional(),
    /** The rule applies only to these subject types. `agent` means an agent acts. Absent: all. */
    subjectTypes: z.array(subjectTypeSchema).min(1).optional(),
    /**
     * The resources the rule applies to. In a match scope, a property that is missing on the
     * resource or is not a string counts as inside, so leaving out a property never escapes it.
     */
    scope: scopeSchema,
  })
  .strict();

export const approvalRuleSchema = z
  .object({
    id: identifier,
    description: z.string().max(1000).optional(),
    permissions: z.array(permissionName).min(1),
    when: whenSchema,
    /** Number of distinct approvers besides the requester. */
    approvers: z.number().int().min(1).max(10),
    eligibleApprovers: eligibleApproversSchema,
    /** Approvals count only inside this window after the request time. */
    expiresInSeconds: z.number().int().min(60).max(maxApprovalWindowSeconds),
    /** Each approval must carry a proof that a registered verifier accepts. */
    requireProof: z.boolean(),
    /** The proof types that count. Required with requireProof, refused without it. */
    proofTypes: z.array(z.string().min(1).max(64)).min(1).optional(),
  })
  .strict();

export const separationOfDutiesSchema = z
  .object({
    /** Who requested an action of a type before may never approve an action of that type. */
    requesterNeverApprovesSameType: z.boolean(),
    /** Nobody may hold both a requesting and an approving role for the same permission. */
    exclusiveRequestAndApproveRoles: z.boolean(),
  })
  .strict();

export const policySchema = z
  .object({
    /** Format version of the policy document. */
    schema: z.literal(policySchemaVersion),
    /** Operator-chosen version label. Decisions and audit records carry it. */
    version: z.string().min(1).max(128),
    roles: z.record(identifier, roleSchema),
    // Required, also when empty: a lost list must not read as "no deny rules".
    denies: z.array(denySchema),
    approvalRules: z.array(approvalRuleSchema),
    separationOfDuties: separationOfDutiesSchema,
  })
  .strict();

const id = z.string().min(1).max(256);
const timestamp = timestampSchema;
export const scalarSchema = z.union([
  z.string().max(4096),
  z.number().finite(),
  z.boolean(),
  z.null(),
]);

export const roleAssignmentSchema = z
  .object({
    role: z.string().min(1).max(128),
    /** Where the role applies. `{ kind: "all" }` is the only way to say everywhere. */
    scope: scopeSchema,
  })
  .strict();

export const agentGrantEntrySchema = z
  .object({
    permissions: z.array(z.string().min(1)).min(1),
    /** Required: a missing scope is refused, never read as the principal's full scope. */
    scope: scopeSchema,
    /** Required: a missing limit is refused, never read as no limit. */
    limits: limitsSchema,
  })
  .strict();

/**
 * A grant that a principal gave to an agent. It can only narrow the principal's rights:
 * the effective right is the intersection of the principal's roles and this grant.
 */
export const agentGrantSchema = z
  .object({
    id,
    principalId: id,
    /** The type of the issuing principal. Ids of humans and services may overlap. */
    principalType: z.union([z.literal("human"), z.literal("service")]),
    /** The agent this grant is for. Only an actor with this id can use it. */
    agentId: id,
    entries: z.array(agentGrantEntrySchema).min(1),
    /** Start of validity, inclusive. Required; `null` means no start bound. */
    notBefore: timestamp.nullable(),
    expiresAt: timestamp,
    /** Revocation time, exclusive. Required; `null` means not revoked. */
    revokedAt: timestamp.nullable(),
  })
  .strict();

/** The earlier hand-written Actor type, kept as written, as the reference for the new one. */
export interface ZodActor {
  type: "agent";
  id: string;
  /** The grant this actor holds, or `null`. The current actor needs one. */
  grant: z.output<typeof agentGrantSchema> | null;
  /** Prior actor in the chain, RFC 8693 `act` shape, or `null`. Logged, not decided on. */
  act: ZodActor | null;
}

export const actorSchema: z.ZodType<ZodActor> = z.lazy(() =>
  z
    .object({
      type: z.literal("agent"),
      id,
      grant: agentGrantSchema.nullable(),
      act: actorSchema.nullable(),
    })
    .strict(),
);

export const subjectSchema = z
  .object({
    // Literals, not z.enum: Zod 3 caches enum values on the instance through a lazy property.
    type: z.union([z.literal("human"), z.literal("service")]),
    /** One identity per human. Roles are listed here, never split over accounts. */
    id,
    roles: z.array(roleAssignmentSchema).max(256),
    /**
     * The current actor if an agent acts on behalf of this principal, or `null` if the principal
     * acts directly. Required: a failed actor lookup must not read as "acts directly".
     */
    act: actorSchema.nullable(),
  })
  .strict();

export const accessRequestSchema = z
  .object({
    subject: subjectSchema,
    action: z.object({ name: z.string().min(1).max(128) }).strict(),
    resource: z
      .object({
        type: z.string().min(1).max(128),
        id: z.string().min(1).max(256).optional(),
        properties: z.record(z.string(), scalarSchema).optional(),
      })
      .strict(),
    context: z
      .object({
        /** Evaluation time. permitkit never reads the clock, so decisions are reproducible. */
        now: requestTimeSchema,
        /** If set, the decision denies unless the loaded policy has this version label. */
        policyVersion: z.string().min(1).max(128).optional(),
        /** If set, the decision denies unless the loaded policy has this digest. */
        policyDigest: z
          .string()
          .regex(/^[0-9a-f]{64}$/)
          .optional(),
      })
      .strict(),
  })
  .strict()
  .superRefine((request, ctx) => {
    let depth = 0;
    // Walk own properties only, so a polluted Object.prototype cannot add actors.
    for (let actor: unknown = ownAct(request.subject); actor !== null; actor = ownAct(actor)) {
      depth += 1;
      if (depth > maxActorDepth) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ["subject", "act"],
          message: `The actor chain is deeper than ${maxActorDepth}.`,
        });
        return;
      }
    }
  });

/** The own `act` value, or null if there is none or it is not an object. */
function ownAct(value: unknown): unknown {
  if (typeof value !== "object" || value === null || !Object.hasOwn(value, "act")) return null;
  const act: unknown = Reflect.get(value, "act");
  return typeof act === "object" ? act : null;
}

// The approval and record schemas, verbatim from src/approval.ts and src/audit.ts as of f04df14.
// maxApprovals is from src/bounds.ts.

/** The most approvals that one evaluateApprovals call reads. Twice the largest `approvers`. */
const maxApprovals = 20;

const hexDigest = z.string().regex(/^[0-9a-f]{64}$/, "Use a lowercase hex SHA-256 digest.");

export const approvalProofSchema = z
  .object({
    type: z.string().min(1).max(64),
    approverId: z.string().min(1).max(256),
    requestDigest: hexDigest,
    payload: z.unknown(),
  })
  .strict();

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

export const approvalInputSchema = z
  .object({
    /** The original request. Its context.now is the request time. */
    request: accessRequestSchema,
    approvals: z.array(z.unknown()).max(maxApprovals),
    /** Evaluation time. The requester's rights and the window are checked at this time. */
    now: requestTimeSchema,
    /**
     * Earlier requests by the approvers, as the consumer's records show them. Required if the
     * operator switched on requesterNeverApprovesSameType.
     */
    priorRequests: z
      .array(
        z
          .object({
            principalId: z.string().min(1),
            permission: z.string().min(1),
          })
          .strict(),
      )
      .optional(),
  })
  .strict();

export const recordShapeSchema = z
  .object({
    schema: z.literal("permitkit.decision/2"),
    policy: z.object({ version: z.string(), digest: z.string() }).strict(),
    request: z.unknown(),
    requestDigest: z.string().nullable(),
    actorChain: z.array(z.unknown()),
    outcome: z.string(),
    reason: z.string(),
    rule: z.unknown(),
    approval: z.unknown(),
  })
  .strict();
