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
// "Everywhere" and "no limit" are always written out: { kind: "all" }, { kind: "unlimited" }.
const policy = compilePolicy(catalog, {
  schema: 2,
  version: "2026-01-01.1",
  roles: {
    support: {
      grants: [
        {
          id: "support-work",
          permissions: ["ticket:read", "ticket:close"],
          scope: { kind: "all" },
          limits: { kind: "unlimited" },
        },
        {
          id: "support-refund",
          permissions: ["ticket:refund"],
          scope: { kind: "all" },
          limits: { kind: "range", properties: { amount: { min: null, max: 500 } } },
        },
      ],
    },
  },
  denies: [
    {
      id: "no-agent-refunds",
      permissions: ["ticket:refund"],
      subjectTypes: ["agent"],
      scope: { kind: "all" },
    },
  ],
  approvalRules: [
    {
      id: "refund-dual",
      permissions: ["ticket:refund"],
      when: { kind: "threshold", properties: { amount: { gte: 100 } } },
      approvers: 2,
      eligibleApprovers: { kind: "permission" },
      expiresInSeconds: 86400,
      requireProof: false,
    },
  ],
  separationOfDuties: {
    requesterNeverApprovesSameType: false,
    exclusiveRequestAndApproveRoles: false,
  },
});

// 3. Decide.
const decision = decide(policy, {
  subject: {
    type: "human",
    id: "user-17",
    roles: [{ role: "support", scope: { kind: "match", properties: { queue: ["billing"] } } }],
    act: null, // no agent acts; required, so a failed actor lookup cannot pass as "acts directly"
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

A policy document has `schema: 2`, a `version` label, `roles`, `denies`, `approvalRules` and
`separationOfDuties`, all required. Unknown keys are rejected everywhere, so a typo fails
validation instead of being ignored. A document with another `schema` value, such as a schema 1
document from an earlier release, fails with `policy_schema_unsupported`; permitkit does not
migrate old documents. `compilePolicy()` returns a frozen policy with a digest over the catalogue and the
normalized document. Only compiled policies are accepted by `decide()`. A request can pin
`context.policyVersion` (a label) and `context.policyDigest` (the exact content); a mismatch
denies with `policy_version_mismatch`. Pin the digest when the label alone is not enough.

Shapes:

| Field                            | Accepted values                                                                                                             |
| -------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `scope`                          | `{ kind: "all" }` or `{ kind: "match", properties: { queue: ["billing"] } }`                                                |
| `limits`                         | `{ kind: "unlimited" }` or `{ kind: "range", properties: { amount: { min: 0, max: 500 } } }`; each bound a number or `null` |
| `when` (approval rule)           | `{ kind: "always" }` or `{ kind: "threshold", properties: { amount: { gte: 100 } } }`                                       |
| `eligibleApprovers`              | `{ kind: "roles", roles: ["approver"] }` or `{ kind: "permission" }`                                                        |
| `requireProof`, `proofTypes`     | `requireProof: true` with `proofTypes: ["webauthn"]`, or `requireProof: false` without `proofTypes`                         |
| `notBefore`, `revokedAt` (grant) | A timestamp, or `null` for "no start bound" and "not revoked"                                                               |
| `act` (subject, actor)           | An actor, or `null` for "no agent acts"                                                                                     |

Matching rules:

| Element              | Rule                                                                                                                                                          |
| -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Grant scope          | `all` covers every resource. `match`: every listed property must be present on the resource as a string and be in the list.                                   |
| Assignment scope     | Same as grant scope.                                                                                                                                          |
| Agent grant scope    | Same as grant scope.                                                                                                                                          |
| Limits               | `unlimited` holds always. `range`: the property must be a finite number from `min` to `max` (both inclusive; `null` is an open side). Missing means exceeded. |
| Deny rule scope      | `all` matches every resource. `match`: matches unless the property is a string outside the list. Missing or non-string values count as inside.                |
| Approval rule `when` | `always` applies always. `threshold`: applies if any listed property is missing, not a number, or at least `gte`.                                             |
| Precedence           | Deny rules win over grants. Approval rules apply only after a grant covers the request.                                                                       |

Several properties in one match scope combine with AND: a deny rule with
`{ kind: "match", properties: { queue: ["vip"], project: ["alpha"] } }` matches only resources in
both. The conditions of one deny rule (`roles`,
`subjectTypes`, `scope`) also combine with AND: `roles: ["contractor"]` with
`subjectTypes: ["agent"]` denies only agents acting for contractors. Use separate deny rules for
OR. The properties of a `threshold` combine with OR, so more conditions mean more approvals.

### Subjects and agents

A subject is a `human` or `service` principal with role assignments. If an agent acts, the
request carries the agent as `subject.act`, in the RFC 8693 `act` shape; nested `act` values are
prior actors. `act` is required on the subject and on every actor: `null` ends the chain. They do not grant rights. If a prior actor carries a grant, that grant must come
from the same principal, name that prior actor as its agent, and be inside its validity window
and not revoked; otherwise the request is denied (`agent_grant_principal_mismatch`,
`agent_grant_expired`, `agent_grant_revoked` or `agent_grant_not_yet_valid`). A prior grant's
coverage is not checked, because it grants nothing. Prior actors are part of the request digest
and the
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
- with `eligibleApprovers: { kind: "roles", roles }`, the approver must hold one of those roles
  with an assignment scope that covers the resource. Only the assignment scope counts, not the
  scope of the role's grants, so use dedicated approver roles with `grants: []`. With
  `{ kind: "permission" }`, the approver must hold the permission itself;
- a deny rule for the permission that matches the approver excludes the approval;
- with `requireProof: true`, each approval needs a proof that a registered verifier accepts, and
  only the listed `proofTypes` count, so an approver cannot pick a weaker registered verifier.
  `requireProof: true` without `proofTypes`, and `proofTypes` without `requireProof`, are policy
  errors.

`evaluateApprovals()` checks the identity data you pass in; it cannot look it up. The stored
request's `subject.id`, `subject.type` and actor chain must come from the requester's
authenticated session at request time; a spoofed principal would turn the real requester into
an eligible approver. Before each call, rebuild from your identity store, not from what a client
or an earlier step submitted:

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
  An empty list means "no earlier requests", so pass the full history for the approvers. Each
  entry must name a permission of the current catalogue, or the result is `invalid_input`, so
  filter out permissions that a later release removed.
- `exclusiveRequestAndApproveRoles`: nobody may hold both a role that grants the permission and an
  approver role for it. Requests and approvals from such subjects are refused. Every approval
  rule then needs `eligibleApprovers: { kind: "roles", ... }`.

Both flags are required, also when `false`.

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
`subject.properties.act` (required, `null` if no agent acts), `action.name`, `resource.type`, `resource.id`, `resource.properties`,
`context.now`, `context.policy_version` and `context.policy_digest`. `action.properties` is
accepted and not used. Any other key gives `invalid_request`, so a misspelt actor or pin cannot
be ignored. AuthZEN defines no reason fields, so `context` uses permitkit's own
names: `outcome`, `reason_codes`, `rule`, `approval`, `policy_version`, `policy_digest`,
`request_digest`.

### Threat model

permitkit treats every input as possibly hostile data: wrong types, objects that are not plain
data (a `Map`, a `Date`, a class instance, non-enumerable or symbol keys, getters and setters),
proxies, array
holes, huge values, and data-valued pollution of `Object.prototype` from a bug elsewhere in the
process. Data-valued pollution of `Array.prototype` also gives a deny, but is tested less.
Such input gives a deny, never an exception from a decision function. One gap remains: a
built-in or class instance that keeps its data in `#private` fields or engine slots that
permitkit cannot identify (for example a `URL`, a `WeakRef` or an `Intl` object), with its
prototype set to `Object.prototype` by caller code, copies as `{}`. A `{}` is refused as a scope,
limit or condition and narrows as `resource.properties`, so it cannot widen access. Pass plain
copies, also of reactive objects from UI state libraries.

How permitkit identifies objects that are not plain data depends on the runtime. It picks one of
two ways when it loads:

- **Node** (and other runtimes whose `process.getBuiltinModule("node:util")` returns a working
  `util.types`, such as Deno). permitkit uses `util.types`. A proxy is refused. Every built-in
  that `util.types` identifies by its engine slots is refused, also with a swapped prototype: a
  `Map`, `Set`, `WeakMap`, `WeakSet`, `Date`, `RegExp`, `Promise`, buffer, typed array,
  `DataView`, boxed primitive, error, generator, `Map` or `Set` iterator, module namespace and
  `arguments` object.
- **Other runtimes** (no `process`, for example Cloudflare Workers without `nodejs_compat`).
  permitkit calls built-in methods that fail for an object without the slot and run no caller
  code. A `Map`, `Set`, `WeakMap`, `WeakSet`, `Date`, `RegExp`, buffer, typed array, `DataView`
  and boxed primitive are refused, also with a swapped prototype. An error is refused this way
  only where the runtime has `Error.isError`. Elsewhere an error is refused only by its hidden
  own keys (`stack`, `message`), and an error without own keys copies as `{}`.
  The checks for typed arrays, `DataView`s and errors never fail with an exception, so they run
  on every object. The other checks fail with an exception for every plain object, which costs
  time, so they run only on objects without own keys or with a non-enumerable own `length` (a
  boxed string, an `arguments` object; JSON cannot produce such a key). So a `Map`, `Set`,
  `WeakMap`, `WeakSet`, `Date`, `ArrayBuffer`, `SharedArrayBuffer` or boxed number, boolean,
  symbol or bigint with a swapped prototype and own keys added by hand copies as those own keys
  instead of being refused. JSON input cannot produce such an object. The copy
  holds only the object's own data, so the result is the same as for a plain object with those
  keys. The Node path still refuses it. Typed arrays, `DataView`s, boxed strings and errors
  (where `Error.isError` exists) are refused also with own keys. An `arguments` object of a
  sloppy-mode function with `length`, `callee` and `Symbol.iterator` deleted copies as its index
  data, for example `{"0": 1}`; Node refuses it. A `Promise`, generator or iterator has no check
  without side effects: with a swapped prototype it copies as `{}`, like the gap above, and with
  own keys added by hand it copies as those keys.
  A JavaScript program cannot tell a proxy from its target, so a proxy is not refused. The size
  guard copies it like any object: own data properties only, and the proxy's traps run. Each
  copy reads it once, and validation and the decision use that copy, so the proxy cannot show
  one value to validation and another to the decision. A proxy that hides its keys copies as
  `{}`, which cannot widen access. `evaluateApprovals` reads its input more than once, though:
  it counts the approvals and checks the request size on separate reads before it copies the
  whole input. A proxy can show a small input to those early checks and a larger one to the
  copy. The copy still enforces the approval input bounds and the decision uses it, so this
  costs only work up to those bounds, never access.
  A proxy also defeats the size bound's cost control. The guard lists the keys of an object
  before it refuses one that is too large, and a proxy with no traps around a large typed array
  (or another object with many keys) is listed key by key. For example,
  `new Proxy(Object.setPrototypeOf(new Uint8Array(1e7), Object.prototype), {})` costs about 7.9 s
  of CPU and 2.1 GB before the guard returns `too_large`; Node refuses it at once. Only a caller
  that builds such an object in its own process can cause this. JSON input cannot.

The test suite checks the portable path in two ways: a text scan of `src` and `dist` for plain
uses of Node globals and modules, and a run of the built package in a V8 context without
`process`, `Buffer` or `require`. Neither is a proof. A text scan cannot see a name that code
builds at run time, and the run covers only the code paths it calls.

The SHA-256 for digests is part of permitkit, so digests are the same in every runtime. It and
`canonicalJson` capture every built-in they use when they load, so a built-in that caller code
replaces later (`JSON.stringify`, `Array.prototype.toSorted`) does not change a digest. The size
guard does not capture its built-ins. Code that runs in your
process with its own functions (a replaced `Array.prototype.map`, a function on
`Object.prototype.then`) is not covered. permitkit hardens the paths it knows about, but such
code can change the behaviour of any library in the process.

### Input rules

- A key set to `undefined` counts as absent only in an optional field, for example
  `resource.id` or `description`. In a required field, and as a value inside a scope, limit or
  threshold record, it is refused. So a match scope with `project: undefined` or a range with
  `max: undefined` fails validation instead of losing a condition. See
  [Design choices](#design-choices) for what absence means per field, and for the content of
  lists and records that permitkit cannot check.
- Agent grants usually come from database rows. Map every column on purpose: a nullable
  `revoked_at` column maps to `revokedAt: row.revoked_at ?? null`, never to a missing key.
- Zod drops a `__proto__` key in `resource.properties`. It cannot be a scope or limit name, but
  two requests that differ only in it share a request digest.
- A service principal is its own identity. If a person triggers a service action, model the
  person as the principal and the service as the actor, or the person can approve their own
  request through the service.
- Every input is trusted data from your server, not from a client: `context.now` from your clock,
  `subject.roles` and agent grants (with `revokedAt`) from your identity store,
  `resource.properties` from your database. permitkit decides on what you pass; a backdated
  `now` or a client-supplied role decides wrongly.
- Limits are ranges. Each bound is required: a number, or `null` for an open side. A range with
  `min: null` accepts any smaller value, also a negative one; give `min` where that matters.

- Ids, role names and scope values are compared as exact strings. permitkit does not change case,
  trim spaces or normalize Unicode. Normalize ids and scope values once, where they enter your
  system, or a deny rule for `vip` does not match `VIP`.
- Timestamps are ISO 8601 with seconds, at most three fraction digits and an offset
  (`Z` or `+hh:mm` up to 23:59). Other forms are rejected, because engines read them differently.
- Inputs pass a size guard before validation. Limits are in [docs/reference.md](docs/reference.md).

## Design choices

### Everywhere is a value, never a default

A scope, limit, approval condition or approver constraint that is lost on its way into
permitkit must not grant more. A non-plain object copied as `{}`, an unmapped database column or
a default that a schema fills in all look like "nothing was said". So permitkit has no default
for any of them: the wide case is a value of its own, `{ kind: "all" }`, `{ kind: "unlimited" }`,
`{ kind: "always" }` or `{ kind: "permission" }`. It cannot come from data loss:

- the marker is an exact string in a discriminated union, not a truthy flag;
- losing `kind` or `properties`, emptying the object, or passing `null` gives a shape that the
  schema refuses, both in `compilePolicy` (`policy_invalid`) and in a decision
  (`invalid_request`);
- `{ kind: "all" }` with extra keys is refused, so a match scope that lost its `kind` and gained
  nothing cannot turn into it;
- `"*"` is not a wildcard; it is refused as a scope value;
- the condition engine reads only an own `kind`, and treats an unknown kind as "covers nothing"
  (grants, assignments, agent grants, limits) or "applies" (deny scopes, approval conditions).

What absence means after this rule:

| Field                                                             | Absent, empty, `null` or malformed                                                                                          |
| ----------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| Grant, assignment, agent grant `scope`                            | Refused                                                                                                                     |
| Grant and agent grant `limits`                                    | Refused                                                                                                                     |
| A key set to `undefined` inside a match scope, range or threshold | Refused, never a dropped condition                                                                                          |
| A range bound `min` or `max`                                      | Refused (`null` is the explicit open side)                                                                                  |
| Deny rule `scope`                                                 | Refused                                                                                                                     |
| Approval rule `when`                                              | Refused                                                                                                                     |
| Approval rule `eligibleApprovers`                                 | Refused                                                                                                                     |
| `requireProof`; `proofTypes` when `requireProof` is true          | Refused                                                                                                                     |
| `denies`, `approvalRules`, `separationOfDuties` and its flags     | Missing: refused. An empty list means no rules, as written                                                                  |
| `subject.act`, actor `act`, actor `grant`                         | Refused (`null` is the explicit "none")                                                                                     |
| Agent grant `notBefore`, `revokedAt`                              | Refused (`null` is the explicit "not set")                                                                                  |
| A property inside a match scope, on the resource                  | Narrows: the grant does not match                                                                                           |
| A property inside a deny match scope, on the resource             | Narrows: counts as inside, the deny rule matches                                                                            |
| A property in a `range` limit, on the resource                    | Narrows: the limit counts as exceeded                                                                                       |
| A property in a `threshold`, on the resource                      | Narrows: the approval rule applies                                                                                          |
| `resource.properties`                                             | Narrows: as if every property were missing                                                                                  |
| Deny rule `roles`, `subjectTypes`                                 | Narrows: the deny rule applies to everyone                                                                                  |
| `priorRequests` with `requesterNeverApprovesSameType`             | Missing: narrows (`sod_history_missing`). `[]` means no earlier requests. An unknown permission in it: `invalid_input`      |
| An approval `proof` with `requireProof`                           | Narrows: `proof_missing`                                                                                                    |
| Prior actor `grant: null`                                         | Explicit "no grant": prior actors grant nothing, so no grant checks run for that actor. A present prior grant must be valid |
| `context.policyVersion`, `context.policyDigest`                   | No pin: the loaded policy decides, which still grants only what it says                                                     |
| `resource.id`, `description`                                      | No effect on the decision                                                                                                   |

What permitkit cannot check is the content of a list or an open record. It refuses a required
field that is missing, `undefined` or `null` (where `null` is not the documented "none"), and an
empty scope, range or threshold. An empty list is accepted and means "none, as written":
`denies: []`, `approvalRules: []`, `subject.roles: []`, `grants: []`, `priorRequests: []`.
permitkit cannot know that an item is missing from a list that is still well-formed. Each of
these looks the same as data that was never written, and each widens access when it is lost on
its way:

- a property key left out of a grant, assignment or agent grant match scope, a range or a
  threshold (for example `{ queue: [...] }` built from a row whose `project` column was not
  read). In a deny rule's match scope a lost key makes the rule broader instead;
- a deny rule left out of `denies`, an approval rule left out of `approvalRules`, one item left
  out of a deny rule's `permissions`, `roles`, `subjectTypes` or scope values, and one item left
  out of an approval rule's `permissions`;
- a role assignment left out of `subject.roles` or `approver.roles`, when a deny rule or
  `exclusiveRequestAndApproveRoles` keys on that role;
- an actor left out of the `act` chain: its id is then not excluded from approving;
- an entry left out of `priorRequests`, or the whole history passed as `[]`.

A role name that the policy does not define grants nothing and is skipped, so a misspelt role
also escapes a deny rule that names the correct one. permitkit does not refuse unknown role
names, because a consumer may assign a role before the policy that defines it is rolled out.
Build these lists from complete data, normalize role names where they enter your system, and
review policy changes as diffs.

### Own rule engine

Rule matching is permitkit's own small engine in one module, `src/engine/conditions.ts`. No
third-party rule engine is used. Reason: the rule set is small and fixed (scopes, ranges,
thresholds), and fully covered by tests and adversarial review. A general engine would add a
policy language, a dependency and behaviour that this library would have to re-test without
gaining a rule it needs.

## Test kit

`permitkit/testing` has builders and assertions that work with any test runner:

```ts
import {
  accessRequest,
  assertDecision,
  everywhere,
  human,
  permissionMatrix,
  role,
} from "permitkit/testing";

assertDecision(policy, accessRequest(human("u1", role("support", everywhere)), "ticket:read"), {
  outcome: "allow",
});
```

The builders never default a scope or a limit: `role()` needs `everywhere` or `within(...)`, and
agent grant entries need `unlimited` or `range(...)`. Their time defaults are for tests only:
`viaAgent()` grants run until 2099 and set `notBefore` and `revokedAt` to `null` unless given, so
never build production grants with it.

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
