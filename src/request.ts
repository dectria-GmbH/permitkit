import { z } from "zod";

import { limitsSchema, scopeSchema } from "./policy.js";
import { timestampSchema } from "./time.js";

const id = z.string().min(1).max(256);
const timestamp = timestampSchema;
const scalar = z.union([z.string().max(4096), z.number().finite(), z.boolean(), z.null()]);

/** Maximum nesting of `act`. RFC 8693 chains in practice are short. */
export const maxActorDepth = 4;

export const roleAssignmentSchema = z
  .object({
    role: z.string().min(1).max(128),
    /** Where the role applies. `{}` means everywhere. The field is required on purpose. */
    scope: scopeSchema,
  })
  .strict();

export const agentGrantEntrySchema = z
  .object({
    permissions: z.array(z.string().min(1)).min(1),
    scope: scopeSchema.optional(),
    limits: limitsSchema.optional(),
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
    /** The agent this grant is for. Only an actor with this id can use it. */
    agentId: id,
    entries: z.array(agentGrantEntrySchema).min(1),
    notBefore: timestamp.optional(),
    expiresAt: timestamp,
    revokedAt: timestamp.optional(),
  })
  .strict();

export interface Actor {
  type: "agent";
  id: string;
  grant?: AgentGrant | undefined;
  /** Prior actor in the chain, RFC 8693 `act` shape. Logged, not used for the decision. */
  act?: Actor | undefined;
}

export const actorSchema: z.ZodType<Actor> = z.lazy(() =>
  z
    .object({
      type: z.literal("agent"),
      id,
      grant: agentGrantSchema.optional(),
      act: actorSchema.optional(),
    })
    .strict(),
);

export const subjectSchema = z
  .object({
    type: z.enum(["human", "service"]),
    /** One identity per human. Roles are listed here, never split over accounts. */
    id,
    roles: z.array(roleAssignmentSchema).max(256),
    /** The current actor, if an agent acts on behalf of this principal. */
    act: actorSchema.optional(),
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
        now: timestamp,
        /** If set, the decision denies unless the loaded policy has this version. */
        policyVersion: z.string().min(1).max(128).optional(),
      })
      .strict(),
  })
  .strict()
  .superRefine((request, ctx) => {
    let depth = 0;
    for (let actor = request.subject.act; actor !== undefined; actor = actor.act) {
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
