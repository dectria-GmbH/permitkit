import { z } from "zod";

import { limitsSchema, scopeSchema } from "./policy.js";
import { requestTimeSchema, timestampSchema } from "./time.js";

const id = z.string().min(1).max(256);
const timestamp = timestampSchema;
const scalar = z.union([z.string().max(4096), z.number().finite(), z.boolean(), z.null()]);

/** Maximum nesting of `act`. RFC 8693 chains in practice are short. */
export const maxActorDepth = 4;

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

export interface Actor {
  type: "agent";
  id: string;
  /** The grant this actor holds, or `null`. The current actor needs one. */
  grant: AgentGrant | null;
  /** Prior actor in the chain, RFC 8693 `act` shape, or `null`. Logged, not decided on. */
  act: Actor | null;
}

export const actorSchema: z.ZodType<Actor> = z.lazy(() =>
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
        properties: z.record(z.string(), scalar).optional(),
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

export type RoleAssignment = z.output<typeof roleAssignmentSchema>;
export type AgentGrant = z.output<typeof agentGrantSchema>;
export type AgentGrantEntry = z.output<typeof agentGrantEntrySchema>;
export type Subject = z.output<typeof subjectSchema>;
export type AccessRequest = z.output<typeof accessRequestSchema>;
export type Scalar = z.output<typeof scalar>;

/** The own `act` value, or null if there is none or it is not an object. */
function ownAct(value: unknown): unknown {
  if (typeof value !== "object" || value === null || !Object.hasOwn(value, "act")) return null;
  const act: unknown = Reflect.get(value, "act");
  return typeof act === "object" ? act : null;
}
