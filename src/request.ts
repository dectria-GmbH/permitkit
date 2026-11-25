/**
 * The access request: its types and its validator. Every rule here has a named test in
 * `test/request-validator.test.ts` and is compared with the earlier Zod schema in
 * `test/request-differential.test.ts`.
 */

import { limits, scope, type Limits, type Scope } from "./policy-document.js";
import { requestTime, timestamp } from "./time.js";
import {
  at,
  bare,
  dictionary,
  fail,
  finiteNumber,
  invalid,
  isObject,
  knownKeys,
  list,
  nullable,
  oneOf,
  optional,
  required,
  text,
  type Check,
} from "./validate.js";

/** Maximum nesting of `act`. RFC 8693 chains in practice are short. */
export const maxActorDepth = 4;

export type RoleAssignment = {
  role: string;
  /** Where the role applies. `{ kind: "all" }` is the only way to say everywhere. */
  scope: Scope;
};

export type AgentGrantEntry = {
  permissions: string[];
  /** Required: a missing scope is refused, never read as the principal's full scope. */
  scope: Scope;
  /** Required: a missing limit is refused, never read as no limit. */
  limits: Limits;
};

/**
 * A grant that a principal gave to an agent. It can only narrow the principal's rights:
 * the effective right is the intersection of the principal's roles and this grant.
 */
export type AgentGrant = {
  id: string;
  principalId: string;
  /** The type of the issuing principal. Ids of humans and services may overlap. */
  principalType: "human" | "service";
  /** The agent this grant is for. Only an actor with this id can use it. */
  agentId: string;
  entries: AgentGrantEntry[];
  /** Start of validity, inclusive. Required; `null` means no start bound. */
  notBefore: string | null;
  expiresAt: string;
  /** Revocation time, exclusive. Required; `null` means not revoked. */
  revokedAt: string | null;
};

export interface Actor {
  type: "agent";
  id: string;
  /** The grant this actor holds, or `null`. The current actor needs one. */
  grant: AgentGrant | null;
  /** Prior actor in the chain, RFC 8693 `act` shape, or `null`. Logged, not decided on. */
  act: Actor | null;
}

export type Subject = {
  type: "human" | "service";
  /** One identity per human. Roles are listed here, never split over accounts. */
  id: string;
  roles: RoleAssignment[];
  /**
   * The current actor if an agent acts on behalf of this principal, or `null` if the principal
   * acts directly. Required: a failed actor lookup must not read as "acts directly".
   */
  act: Actor | null;
};

export type Scalar = string | number | boolean | null;

export type AccessRequest = {
  subject: Subject;
  action: { name: string };
  resource: {
    type: string;
    id?: string | undefined;
    properties?: Record<string, Scalar> | undefined;
  };
  context: {
    /** Evaluation time. permitkit never reads the clock, so decisions are reproducible. */
    now: string;
    /** If set, the decision denies unless the loaded policy has this version label. */
    policyVersion?: string | undefined;
    /** If set, the decision denies unless the loaded policy has this digest. */
    policyDigest?: string | undefined;
  };
};

const id = text({ min: 1, max: 256 });
const name = text({ min: 1, max: 128 });
const principalType = oneOf(["human", "service"]);

const scalarText = text({ max: 4096 });
const scalarNumber = finiteNumber({});

const scalar: Check<Scalar> = (value, path, issues) => {
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "string") return scalarText(value, path, issues);
  if (typeof value === "number") return scalarNumber(value, path, issues);
  return fail(issues, path, "Use a string, a finite number, true, false or null.");
};

const roleAssignment: Check<RoleAssignment> = (value, path, issues) => {
  if (!isObject(value)) return fail(issues, path, "Expected a role assignment object.");
  const role = required(value, "role", path, issues, name);
  const where = required(value, "scope", path, issues, scope);
  const known = knownKeys(value, ["role", "scope"], path, issues);
  return role === invalid || where === invalid || !known ? invalid : bare({ role, scope: where });
};

const grantPermissions = list(text({ min: 1 }), { min: 1 });

const agentGrantEntry: Check<AgentGrantEntry> = (value, path, issues) => {
  if (!isObject(value)) return fail(issues, path, "Expected an agent grant entry object.");
  const permissions = required(value, "permissions", path, issues, grantPermissions);
  const where = required(value, "scope", path, issues, scope);
  const bounds = required(value, "limits", path, issues, limits);
  const known = knownKeys(value, ["permissions", "scope", "limits"], path, issues);
  if (permissions === invalid || where === invalid || bounds === invalid || !known) return invalid;
  return bare({ permissions, scope: where, limits: bounds });
};

const agentGrantEntries = list(agentGrantEntry, { min: 1 });

const agentGrant: Check<AgentGrant> = (value, path, issues) => {
  if (!isObject(value)) return fail(issues, path, "Expected an agent grant object.");
  const grantId = required(value, "id", path, issues, id);
  const principalId = required(value, "principalId", path, issues, id);
  const type = required(value, "principalType", path, issues, principalType);
  const agentId = required(value, "agentId", path, issues, id);
  const entries = required(value, "entries", path, issues, agentGrantEntries);
  const notBefore = required(value, "notBefore", path, issues, nullable(timestamp));
  const expiresAt = required(value, "expiresAt", path, issues, timestamp);
  const revokedAt = required(value, "revokedAt", path, issues, nullable(timestamp));
  const known = knownKeys(
    value,
    [
      "id",
      "principalId",
      "principalType",
      "agentId",
      "entries",
      "notBefore",
      "expiresAt",
      "revokedAt",
    ],
    path,
    issues,
  );
  if (
    grantId === invalid ||
    principalId === invalid ||
    type === invalid ||
    agentId === invalid ||
    entries === invalid ||
    notBefore === invalid ||
    expiresAt === invalid ||
    revokedAt === invalid ||
    !known
  ) {
    return invalid;
  }
  return bare({
    id: grantId,
    principalId,
    principalType: type,
    agentId,
    entries,
    notBefore,
    expiresAt,
    revokedAt,
  });
};

const agentType = oneOf(["agent"]);

/**
 * An actor and its prior actors. The chain is checked as deep as the input goes (the size guard
 * bounds the depth); the depth limit runs on the whole request afterwards, as before.
 */
const actor: Check<Actor> = (value, path, issues) => {
  if (!isObject(value)) return fail(issues, path, "Expected an actor object.");
  const type = required(value, "type", path, issues, agentType);
  const actorId = required(value, "id", path, issues, id);
  const grant = required(value, "grant", path, issues, nullable(agentGrant));
  const prior = required(value, "act", path, issues, nullable(actor));
  const known = knownKeys(value, ["type", "id", "grant", "act"], path, issues);
  if (type === invalid || actorId === invalid || grant === invalid || prior === invalid || !known) {
    return invalid;
  }
  return bare({ type, id: actorId, grant, act: prior });
};

const roleAssignments = list(roleAssignment, { max: 256 });

const subject: Check<Subject> = (value, path, issues) => {
  if (!isObject(value)) return fail(issues, path, "Expected a subject object.");
  const type = required(value, "type", path, issues, principalType);
  const subjectId = required(value, "id", path, issues, id);
  const roles = required(value, "roles", path, issues, roleAssignments);
  const act = required(value, "act", path, issues, nullable(actor));
  const known = knownKeys(value, ["type", "id", "roles", "act"], path, issues);
  if (type === invalid || subjectId === invalid || roles === invalid || act === invalid || !known) {
    return invalid;
  }
  return bare({ type, id: subjectId, roles, act });
};

const action: Check<AccessRequest["action"]> = (value, path, issues) => {
  if (!isObject(value)) return fail(issues, path, "Expected an action object.");
  const actionName = required(value, "name", path, issues, name);
  const known = knownKeys(value, ["name"], path, issues);
  return actionName === invalid || !known ? invalid : bare({ name: actionName });
};

/** A `__proto__` key is checked and then left out, as before. See the input rules in README. */
const properties = dictionary(scalar, { dropProtoKey: true });

const resource: Check<AccessRequest["resource"]> = (value, path, issues) => {
  if (!isObject(value)) return fail(issues, path, "Expected a resource object.");
  const type = required(value, "type", path, issues, name);
  const resourceId = optional(value, "id", path, issues, id);
  const props = optional(value, "properties", path, issues, properties);
  const known = knownKeys(value, ["type", "id", "properties"], path, issues);
  if (type === invalid || resourceId.value === invalid || props.value === invalid || !known) {
    return invalid;
  }
  return bare({
    type,
    ...(resourceId.present ? { id: resourceId.value } : {}),
    ...(props.present ? { properties: props.value } : {}),
  });
};

const digestPin = text({
  pattern: /^[0-9a-f]{64}$/,
  patternMessage: "Use a lowercase hex SHA-256 digest.",
});

const context: Check<AccessRequest["context"]> = (value, path, issues) => {
  if (!isObject(value)) return fail(issues, path, "Expected a context object.");
  const now = required(value, "now", path, issues, requestTime);
  const version = optional(value, "policyVersion", path, issues, name);
  const pin = optional(value, "policyDigest", path, issues, digestPin);
  const known = knownKeys(value, ["now", "policyVersion", "policyDigest"], path, issues);
  if (now === invalid || version.value === invalid || pin.value === invalid || !known) {
    return invalid;
  }
  return bare({
    now,
    ...(version.present ? { policyVersion: version.value } : {}),
    ...(pin.present ? { policyDigest: pin.value } : {}),
  });
};

/** The number of actors in the chain of a validated subject. */
function actorDepth(request: AccessRequest): number {
  let depth = 0;
  for (let item = request.subject.act; item !== null; item = item.act) depth += 1;
  return depth;
}

/**
 * Validates an access request as the size guard copied it. The actor depth limit runs last, and
 * only on an otherwise valid request.
 */
export const accessRequest: Check<AccessRequest> = (value, path, issues) => {
  if (!isObject(value)) return fail(issues, path, "Expected a request object.");
  const who = required(value, "subject", path, issues, subject);
  const what = required(value, "action", path, issues, action);
  const on = required(value, "resource", path, issues, resource);
  const when = required(value, "context", path, issues, context);
  const known = knownKeys(value, ["subject", "action", "resource", "context"], path, issues);
  if (who === invalid || what === invalid || on === invalid || when === invalid || !known) {
    return invalid;
  }
  const request = bare({ subject: who, action: what, resource: on, context: when });
  if (actorDepth(request) > maxActorDepth) {
    return fail(
      issues,
      at(at(path, "subject"), "act"),
      `The actor chain is deeper than ${maxActorDepth}.`,
    );
  }
  return request;
};
