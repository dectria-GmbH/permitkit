// Generators for access requests, shared by the request and approval differential tests.
import * as fc from "fast-check";

import {
  identifierArb,
  latestInstant,
  latestRequestInstant,
  limitsArb,
  optionalField,
  permissionArb,
  scopeArb,
  textArb,
  timestampArb,
  withKey,
} from "./differential.js";

export const idArb = fc.oneof(
  { weight: 10, arbitrary: textArb(8, 1) },
  { weight: 1, arbitrary: fc.constant("i".repeat(256)) },
);
export const nameArb = fc.oneof(
  { weight: 10, arbitrary: textArb(8, 1) },
  { weight: 1, arbitrary: fc.constant("n".repeat(128)) },
);
export const timestamp = timestampArb(latestInstant);

const grantArb = fc.record({
  id: idArb,
  principalId: fc.constantFrom("u", "s"),
  principalType: fc.constantFrom("human", "service"),
  agentId: idArb,
  entries: fc.array(
    fc.record({
      permissions: fc.array(fc.oneof(permissionArb, textArb(6, 1)), { minLength: 1, maxLength: 3 }),
      scope: scopeArb,
      limits: limitsArb,
    }),
    { minLength: 1, maxLength: 2 },
  ),
  notBefore: fc.option(timestamp, { nil: null }),
  expiresAt: timestamp,
  revokedAt: fc.option(timestamp, { nil: null }),
});

/** Actor chains from 0 to 6 actors, so depth 4 (accepted) and 5 (refused) both occur. */
const actArb = fc
  .array(fc.record({ id: idArb, grant: fc.option(grantArb, { nil: null }) }), { maxLength: 6 })
  .map((actors) => {
    let act: unknown = null;
    for (let index = actors.length - 1; index >= 0; index -= 1) {
      const actor = actors[index];
      if (actor !== undefined) act = { type: "agent", id: actor.id, grant: actor.grant, act };
    }
    return act;
  });

const roleAssignmentArb = fc.record({ role: nameArb, scope: scopeArb });
const rolesArb = fc.oneof(
  { weight: 12, arbitrary: fc.array(roleAssignmentArb, { maxLength: 3 }) },
  {
    weight: 1,
    arbitrary: roleAssignmentArb.map((item) => Array.from({ length: 256 }, () => item)),
  },
);

const scalarArb = fc.oneof(
  textArb(8),
  fc.constant("s".repeat(4096)),
  fc.integer(),
  fc.double({ noNaN: true, noDefaultInfinity: true }),
  fc.boolean(),
  fc.constant(null),
);
const propertiesArb = fc
  .tuple(
    fc.dictionary(fc.oneof(identifierArb, textArb(4)), scalarArb, { maxKeys: 4 }),
    fc.option(scalarArb, { nil: undefined }),
  )
  .map(([properties, proto]) =>
    proto === undefined ? properties : withKey({ ...properties }, "__proto__", proto),
  );

/** Subjects of both types, with 0 to 6 actors. */
export const subjectArb = fc.record({
  type: fc.constantFrom("human", "service"),
  id: idArb,
  roles: rolesArb,
  act: actArb,
});

export const requestArb = fc
  .record({
    subject: subjectArb,
    action: fc.record({ name: nameArb }),
    resourceType: nameArb,
    resourceId: optionalField("id", idArb),
    resourceProperties: optionalField("properties", propertiesArb),
    now: timestampArb(latestRequestInstant),
    version: optionalField("policyVersion", nameArb),
    pin: optionalField("policyDigest", fc.stringMatching(/^[0-9a-f]{64}$/)),
  })
  .map((parts) => ({
    subject: parts.subject,
    action: parts.action,
    resource: { type: parts.resourceType, ...parts.resourceId, ...parts.resourceProperties },
    context: { now: parts.now, ...parts.version, ...parts.pin },
  }));
