# permitkit

Authorization toolkit for TypeScript: roles, scopes, limits, deny rules, dual approval and
delegated agent access. Every decision is a pure function of the policy and the request, so you
can log it and re-evaluate it later against the same policy version.

Status: 0.1, in development, not published. The API can change before 1.0.

## Principles

- **Deny by default.** Without a grant that covers the request, the answer is `deny`.
- **Deterministic.** `decide(policy, request)` reads no clock, no environment, no database. The
  request carries `context.now`. Equal inputs give equal decisions.
- **Explainable.** Every decision has a stable reason code and names the rule that matched.
  `explain()` returns every evaluation step and a fix hint.
- **Auditable.** A decision carries the policy version, a policy digest and a request digest.
  `toDecisionRecord()` and `reevaluate()` replay a logged decision under the same policy.
- **Fixed catalogue, free policy.** Permissions live in code. Roles, scopes, limits, deny rules
  and approval rules are versioned data, validated with Zod.
- **One identity per human.** A subject is one identity with any number of role assignments.
  permitkit has no notion of a second account for the same person, so dual approval compares
  identity ids. Your identity layer must make sure that one person has one id.
- **Agents act on behalf of a principal, with narrower rights.** The effective right is the
  intersection of the principal's roles and the agent grant.
- **No framework in the core.** The only runtime dependency is Zod 3.

## Install

The package is not on a registry yet. Build it from source with Node 24 and pnpm:

```sh
pnpm install
pnpm build
```

## Quick start

```ts
import { compilePolicy, decide, defineCatalog } from "permitkit";

// 1. The permission catalogue lives in code.
const catalog = defineCatalog({
  ticket: {
    actions: ["read", "close", "refund"],
    scopes: ["queue"], // string properties that scopes can restrict
    limits: ["amount"], // numeric properties that limits and approval rules can test
  },
});

// 2. The policy is data. Store it, version it, review changes to it.
const policy = compilePolicy(catalog, {
  schema: 1,
  version: "2026-01-01.1",
  roles: {
    support: {
      grants: [
        { id: "support-work", permissions: ["ticket:read", "ticket:close"] },
        { id: "support-refund", permissions: ["ticket:refund"], limits: { amount: { max: 500 } } },
      ],
    },
  },
  denies: [{ id: "no-agent-refunds", permissions: ["ticket:refund"], subjectTypes: ["agent"] }],
  approvalRules: [
    {
      id: "refund-dual",
      permissions: ["ticket:refund"],
      when: { amount: { gte: 100 } },
      approvers: 2,
      expiresInSeconds: 86400,
    },
  ],
});

// 3. Decide.
const decision = decide(policy, {
  subject: {
    type: "human",
    id: "user-17",
    roles: [{ role: "support", scope: { queue: ["billing"] } }],
  },
  action: { name: "close" },
  resource: { type: "ticket", id: "t-4711", properties: { queue: "billing" } },
  context: { now: new Date().toISOString() },
});

decision.outcome; // "allow" | "deny" | "approval_required"
decision.reason; // stable code, for example "granted" or "scope_mismatch"
decision.rule; // { kind: "grant", role: "support", id: "support-work" }
```

## Concepts

### Catalogue

`defineCatalog()` declares resource types, their actions, and the property names that policies
may refer to. A permission name is `<resource>:<action>`. `compilePolicy()` rejects any policy
that names a permission, scope property or limit property that the catalogue does not declare.

### Policy

A policy document has `schema: 1`, a `version` label, `roles`, `denies`, `approvalRules` and
`separationOfDuties`. Unknown keys are rejected everywhere, so a typo fails validation instead of
being ignored. `compilePolicy()` returns a frozen policy with a digest over the catalogue and the
normalized document. Only compiled policies are accepted by `decide()`. A request can pin
`context.policyVersion` (a label) and `context.policyDigest` (the exact content); a mismatch
denies with `policy_version_mismatch`. Pin the digest when the label alone is not enough.

Matching rules:

| Element              | Rule                                                                                                                        |
| -------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| Grant scope          | Every listed property must be present on the resource as a string and be in the list.                                       |
| Assignment scope     | Same as grant scope. `scope: {}` is explicit and means everywhere.                                                          |
| Limit                | The property must be a finite number in the range `min` to `max` (both inclusive, either optional). Missing means exceeded. |
| Deny rule scope      | Matches unless the property is a string outside the list. Missing or non-string values count as inside.                     |
| Approval rule `when` | Applies if any listed property is missing, not a number, or at least `gte`.                                                 |
| Precedence           | Deny rules win over grants. Approval rules apply only after a grant covers the request.                                     |

### Subjects and agents

A subject is a `human` or `service` principal with role assignments. If an agent acts, the
request carries the agent as `subject.act`, in the RFC 8693 `act` shape; nested `act` values are
prior actors. They do not grant rights. If a prior actor carries a grant, that grant must come
from the same principal, or the request is denied with `agent_grant_principal_mismatch`. Prior
actors are part of the request digest and the
audit record, and their ids cannot approve the request. The current actor must hold a grant that
the principal issued (`principalId` and `principalType`) to this agent (`agentId`), that is
inside its validity window (`notBefore` inclusive, `expiresAt` and `revokedAt` exclusive), and
that covers the permission, scope and limits of the request. Deny rules with
`subjectTypes: ["agent"]` apply when an agent acts; rules with `["human"]` or `["service"]` match
the principal's type, also when an agent acts for it.

### Dual approval

If a grant covers the request and an approval rule applies, the outcome is `approval_required`
with the rule id, the number of approvers and the end of the approval window. Store the request
and its `requestDigest`, collect approvals, then call `evaluateApprovals()`:

- evaluated with the roles and grants you pass, the request is `approval_required` under the
  same rule at its request time, and the requester holds the permission at evaluation time. Both
  checks use the roles you pass, so they cannot see the roles the requester had back then. To
  bind to those, keep the decision record from the request time and compare it. If no approval
  rule applies at evaluation time, the result is `allow` with `approval_not_required`, the same
  as `decide()` at that time;
- each approver is a human principal acting directly, not through an agent;
- the requester never counts: neither the principal nor any agent id in its actor chain;
- each approver counts once;
- each approval names the request digest, which covers principal, each actor with the content
  of its grant, action, resource, request time and policy version, so an approval cannot move
  to another request or survive a policy change;
- approvals count only inside the window, both ends inclusive;
- with `approverRoles`, the approver must hold one of those roles with an assignment scope that
  covers the resource. Only the assignment scope counts, not the scope of the role's grants, so
  use dedicated approver roles with `grants: []`. Without `approverRoles`, the approver must hold
  the permission itself;
- a deny rule for the permission that matches the approver excludes the approval;
- with `requireProof`, each approval needs a proof that a registered verifier accepts; with
  `proofTypes`, only those proof types count, so an approver cannot pick a weaker registered
  verifier.

`evaluateApprovals()` checks the identity data you pass in; it cannot look it up. Before each
call, rebuild from your identity store, not from what a client or an earlier step submitted:

- `request.subject.roles` and the current agent grant, including `revokedAt`. Role assignments
  and `revokedAt` are not part of the request digest, so a stored request with stale roles or a
  stale revocation still matches its approvals;
- each `approver` subject (type and roles). An approval proof binds only the approver id and the
  request digest, so roles taken from the approval itself let approvers claim their own
  eligibility;
- each approver's session actor chain as `approver.act`, if an agent acted in that session. An
  identity store does not know this, but the session does. Without it, an agent that acts for
  both the requester and the approver can complete both sides. If your session layer cannot
  tell, set `requireProof` with a user-presence proof such as WebAuthn;
- each approver id from the authenticated session in which that person approved. Without
  `requireProof`, nothing else binds the id: code that lets the requester submit "an approval by
  someone else" lets one person satisfy the rule alone;
- each `approvedAt` from your server clock when the approval arrives. A proof does not cover the
  time, and the request digest is predictable, so a client-supplied time could place an approval
  inside the window after the fact.

`evaluateApprovals()` does not know whether a request already ran. Mark a request as executed
once, in the same transaction that executes it, keyed on the `requestDigest`, not on your own row
id. Two requests with the same content and the same request time share a digest, so give each
request a `resource.id` or a distinct request time.

### Approval proofs

An approval proof binds an approval to evidence of who approved, for example a WebAuthn assertion
whose challenge is the request digest. permitkit defines the interface and does not implement
WebAuthn:

```ts
const verifier: ApprovalProofVerifier = {
  type: "webauthn",
  async verify(proof, expected) {
    // Your WebAuthn library checks the signature against the approver's stored credentials.
    const credentials = await loadCredentials(expected.approverId);
    const assertion = await verifyAssertion(proof.payload, credentials, { timeoutMs: 5000 });
    if (!assertion.ok) return { valid: false, reason: assertion.error };
    // Return what the signature covers. Never copy the values from `expected`.
    return { valid: true, approverId: assertion.userId, requestDigest: assertion.challenge };
  },
};
await evaluateApprovals(policy, input, { verifiers: [verifier] });
```

`loadCredentials` and `verifyAssertion` stand for your own code. The proof `payload` must be
plain JSON (for example base64url strings), within the size bounds; binary objects such as a
`Uint8Array` make the whole input unusable. permitkit checks that the proof
names the approver and the digest before it calls the verifier, and compares the returned values
after. That comparison only protects you if the verifier returns the values from the verified
evidence: a verifier that echoes `expected` lets a valid assertion for one request pass for
another. permitkit waits for the verifier's promise, so give the verifier its own timeout.

### Separation of duties

The operator switches these settings in the policy:

- `requesterNeverApprovesSameType`: who requested an action of a type before may never approve an
  action of that type. Pass the history as `priorRequests`; without it, the result is a deny.
  An empty list means "no earlier requests", so pass the full history for the approvers.
- `exclusiveRequestAndApproveRoles`: nobody may hold both a role that grants the permission and an
  approver role for it. Requests and approvals from such subjects are refused.

### Audit and re-evaluation

```ts
const { decision, record } = decideAndRecord(policy, request); // record is plain JSON
reevaluate(policy, record); // "reproduced" | "diverged" | "policy_mismatch" | "not_replayable"
```

`decideAndRecord()` reads the request once, so the record holds exactly what was decided.
`toDecisionRecord(request, decision)` builds a record for an existing decision; pass it the same
plain data. `reevaluate()` refuses to run under a policy with another version or digest. Keep every policy
version that produced decisions. It checks consistency, not integrity: the digests are not keyed,
so whoever can write the log can write a consistent forged record. Sign or chain the audit log if
you need tamper evidence.

### AuthZEN

`evaluate(policy, request)` accepts an OpenID AuthZEN 1.0 access evaluation request and returns
`{ decision, context }`. It reads `subject.type`, `subject.id`, `subject.properties.roles`,
`subject.properties.act`, `action.name`, `resource.type`, `resource.id`, `resource.properties`,
`context.now`, `context.policy_version` and `context.policy_digest`. `action.properties` is
accepted and not used. Any other key gives `invalid_request`, so a misspelt actor or pin cannot
be ignored. AuthZEN defines no reason fields, so `context` uses permitkit's own
names: `outcome`, `reason_codes`, `rule`, `approval`, `policy_version`, `policy_digest`,
`request_digest`.

### Threat model

permitkit treats every input as possibly hostile data: wrong types, objects that are not plain
data (a `Map`, a `Date`, a class instance, non-enumerable or symbol keys, getters and setters),
proxies, array
holes, huge values, and data-valued pollution of `Object.prototype` from a bug elsewhere in the process.
Such input gives a deny, never an exception from a decision function. Proxies count as not plain
data, also reactive ones from UI state libraries: pass a plain copy. Code that runs in your
process with its own functions (a replaced `Array.prototype.map`, a function on
`Object.prototype.then`) is not covered. permitkit hardens the paths it knows about, but such
code can change the behaviour of any library in the process.

### Input rules

- A key set to `undefined` counts as absent, as in JSON. `limits: { amount: { max: undefined } }`
  is therefore an empty limit and fails validation, and `scope: undefined` on a grant means no
  scope restriction. Build policies from validated configuration, not from optional values.
- A service principal is its own identity. If a person triggers a service action, model the
  person as the principal and the service as the actor, or the person can approve their own
  request through the service.
- Every input is trusted data from your server, not from a client: `context.now` from your clock,
  `subject.roles` and agent grants (with `revokedAt`) from your identity store,
  `resource.properties` from your database. permitkit decides on what you pass; a backdated
  `now` or a client-supplied role decides wrongly.
- Limits are ranges. A limit with only `max` accepts any smaller value, also a negative one;
  add `min` where that matters.

- Ids, role names and scope values are compared as exact strings. permitkit does not change case,
  trim spaces or normalize Unicode. Normalize ids and scope values once, where they enter your
  system, or a deny rule for `vip` does not match `VIP`.
- Timestamps are ISO 8601 with seconds, at most three fraction digits and an offset
  (`Z` or `+hh:mm` up to 23:59). Other forms are rejected, because engines read them differently.
- Inputs pass a size guard before validation. Limits are in [docs/reference.md](docs/reference.md).

## Test kit

`permitkit/testing` has builders and assertions that work with any test runner:

```ts
import { accessRequest, assertDecision, human, permissionMatrix, role } from "permitkit/testing";

assertDecision(policy, accessRequest(human("u1", role("support")), "ticket:read"), {
  outcome: "allow",
});
```

`permissionMatrix()` decides a set of subjects against a set of cases and returns a sorted table.
Commit it as a snapshot, so that every policy change shows up as a reviewable diff.

## Reference

- Reason codes and error codes: [docs/reference.md](docs/reference.md)
- Enforcement inside the database (design note): [docs/database-enforcement.md](docs/database-enforcement.md)

## Planned entry points

`permitkit/nestjs` (guard), `permitkit/react` (hooks over server-provided decisions) and
`permitkit/kysely` (query helpers) are planned as separate entry points. The core stays free of
framework dependencies.

## Licence

MIT, see [LICENSE](LICENSE).
