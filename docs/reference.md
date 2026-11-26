# Reference

A code never changes its meaning once released. New codes can appear in a minor release. Treat
an unknown decision reason as a deny. The exported objects `reasonCodes`, `reasonHints`,
`approvalRejectionCodes` and `approvalReasonCodes` hold a short text for each of these codes at run time.

## Decision reasons (`decide`, `explain`, `evaluate`)

| Code                             | Outcome             | Meaning                                                                                                 |
| -------------------------------- | ------------------- | ------------------------------------------------------------------------------------------------------- |
| `granted`                        | `allow`             | A grant of one of the subject's roles covers the request.                                               |
| `approval_required`              | `approval_required` | A grant covers the request, and a dual-approval rule applies to it.                                     |
| `invalid_request`                | `deny`              | The request does not match the schema or exceeds the size bounds, for example a missing or empty scope. |
| `policy_version_mismatch`        | `deny`              | The request pins a policy version or digest that is not the loaded policy.                              |
| `unknown_permission`             | `deny`              | The permission is not in the catalogue.                                                                 |
| `no_grant`                       | `deny`              | No grant of the subject's roles includes the permission.                                                |
| `scope_mismatch`                 | `deny`              | A grant includes the permission, but a scope does not cover the resource.                               |
| `limit_exceeded`                 | `deny`              | A grant includes the permission, but a limit does not cover the resource.                               |
| `denied_by_rule`                 | `deny`              | A deny rule matches. Deny rules win over grants.                                                        |
| `agent_grant_missing`            | `deny`              | An agent acts without a grant.                                                                          |
| `agent_grant_principal_mismatch` | `deny`              | An agent grant in the chain belongs to another principal, or a prior actor's grant names another agent. |
| `agent_grant_actor_mismatch`     | `deny`              | The agent grant was issued to another agent id.                                                         |
| `agent_grant_not_yet_valid`      | `deny`              | The agent grant starts after the request time.                                                          |
| `agent_grant_expired`            | `deny`              | The agent grant expired at or before the request time.                                                  |
| `agent_grant_revoked`            | `deny`              | The agent grant was revoked at or before the request time.                                              |
| `agent_grant_insufficient`       | `deny`              | The agent grant does not cover the request.                                                             |
| `sod_role_conflict`              | `deny`              | The subject holds both a requesting and an approving role (if configured).                              |

The order of checks is: input shape, pinned policy version, catalogue, agent grant validity,
deny rules, grants of the principal, agent grant coverage, separation of duties, approval rule.
The first failing check gives the reason. If the library fails internally (for example a bug in
permitkit, or a built-in that was changed before permitkit loaded), the result is a deny with
`invalid_request`, also for a request that would be valid. A built-in that caller code replaces
after permitkit loads changes no decision (see the README threat model).

## Approval results (`evaluateApprovals`)

How to await the result safely: see "Promises in `evaluateApprovals`" in the README threat model.

| Code                             | Outcome   | Meaning                                                                       |
| -------------------------------- | --------- | ----------------------------------------------------------------------------- |
| `approved`                       | `allow`   | Enough distinct, eligible approvals exist.                                    |
| `approvals_pending`              | `pending` | Fewer eligible approvals exist than the rule requires.                        |
| `approval_window_expired`        | `deny`    | The approval window closed before the evaluation time.                        |
| `approval_not_required`          | `allow`   | No approval rule applies to the request.                                      |
| `requester_denied`               | `deny`    | The requester no longer holds the permission. See `requesterDecision`.        |
| `not_approvable_at_request_time` | `deny`    | At its request time, the request was not `approval_required` under this rule. |
| `sod_history_missing`            | `deny`    | The prior-request check is on, but the input has no `priorRequests`.          |
| `too_many_approvals`             | `deny`    | The input holds more than 20 approvals. Checked before the input is read.     |
| `input_too_large`                | `deny`    | The request or the whole input exceeds the size bounds below.                 |
| `invalid_input`                  | `deny`    | The input does not match the schema, is not plain data, or is inconsistent.   |

## Approval rejections (`ApprovalDecision.rejected`)

An entry can have a `detail` string. It can hold text from the input (a proof type) or the
`reason` that a verifier returned, so escape it before you render it.

| Code                       | Meaning                                                               |
| -------------------------- | --------------------------------------------------------------------- |
| `approval_invalid`         | The approval does not match the approval schema.                      |
| `approver_not_human`       | Only a human principal can approve.                                   |
| `approver_is_delegated`    | An approval given through an agent does not count.                    |
| `requester_cannot_approve` | The requesting principal, or an agent in its chain, cannot approve.   |
| `duplicate_approver`       | This approver was already counted.                                    |
| `digest_mismatch`          | The approval names another request digest.                            |
| `approved_before_request`  | The approval time is before the request time.                         |
| `approved_after_expiry`    | The approval time is after the approval window closed.                |
| `approved_in_future`       | The approval time is after the evaluation time.                       |
| `approver_role_missing`    | The approver holds none of the approver roles for this resource.      |
| `approver_denied_by_rule`  | A deny rule for the permission matches the approver.                  |
| `approver_not_permitted`   | The approver does not hold the permission (rules without roles).      |
| `sod_role_conflict`        | The approver also holds a requesting role (if configured).            |
| `sod_prior_request`        | The approver requested an action of this type before (if configured). |
| `proof_missing`            | The rule requires a proof and the approval has none.                  |
| `proof_type_not_allowed`   | The rule's `proofTypes` do not include the proof's type.              |
| `proof_mismatch`           | The proof names another approver or another request digest.           |
| `proof_verifier_missing`   | No verifier is registered for the proof type.                         |
| `proof_invalid`            | The verifier rejected the proof, threw, or echoed other values.       |

`proof_invalid` also covers two cases that the verifier does not decide. `detail` names them:
`a then on a built-in prototype, or a replaced Promise.prototype.then, Promise.prototype.constructor
or Promise[Symbol.species]` (checked before and after each verifier call, and set if the captured
`then` throws for the verifier's promise), and
`verifier returned a thenable that is not a native promise`. The first check reads every
ECMAScript built-in prototype that permitkit captured at load, for example Object.prototype,
Error.prototype, Map.prototype and the typed array, iterator and Intl prototypes, so a lasting
`then` there is caught. It also compares the prototype of each of them with the one at load, so
an object with a `then` put into their prototype chain is caught. Host objects are not checked:
DOMException, Buffer, Response, Request, Headers, URL, Blob, EventTarget, AbortSignal, Event,
CryptoKey, streams and WebAssembly objects. Never return one, for example a caught DOMException.
The check does not see a `then` on the prototype of a class of caller code, or a
`then` that is removed again before the verifier result settles: return the result as an object
without a prototype. The capture happens at load, so permitkit must load before untrusted code;
code that runs first can replace a constructor, and permitkit then captures the prototype of the
replacement. A captured prototype that becomes frozen later gains no `then`, and an own or
inherited `then` on it is still caught. A global replaced after load, for example
`globalThis.Error = X`, makes objects with `X.prototype`, which permitkit never captured: this
is the limit of a class of caller code, with the same remedy. The second
covers a verifier that returns a thenable that is not a native promise, for example a query
builder of an ORM: such a result never counts. Make `verify` an `async` function that awaits
the builder. In an async `verify`, `return await` a library promise and never return it
directly. `return await` removes the extra `then` read at return. Every `await` inside
`verify`, this one too, still reads `Promise.prototype.constructor`. A hook that is set and
removed in that window is not seen, the same limit as a self-removing `then`.

## Errors

permitkit throws only for programming and configuration errors. Decisions never throw for bad
requests, including throwing getters and revoked proxies; they deny. `decide`, `explain` and
`evaluate` throw only `policy_unknown`. Any other failure inside them, for example from a
built-in that was changed before permitkit loaded, gives a deny with reason `invalid_request`,
`rule: null` and `requestDigest: null`. `catalog_invalid` is also
thrown when `compilePolicy` gets a catalogue that `defineCatalog` did not create.
`canonicalJson` and `digest` throw `not_canonical`, never a raw error: for objects whose prototype
is not `Object.prototype`, `null` or `Array.prototype`, built-ins that the runtime's checks identify
by their internal slots (on Node a `Map` or `Date`, also with a swapped prototype; fewer kinds in
other runtimes, see below), symbol or non-enumerable keys, getters and setters (which are not run),
array holes and named array properties, revoked proxies, and input too deep to walk. On Node, every
proxy is refused too. In a runtime without `process` (for example Cloudflare Workers without
`nodejs_compat`), a proxy cannot be detected: it serializes as the data it reports, and its traps
run. There, a built-in whose kind only a check that throws could identify serializes as its own keys
when its prototype is set to `Object.prototype` or `null`, and as `{}` if it has none: a `Map`,
`Set`, `WeakMap`, `WeakSet`, `Date`, `Promise`, `ArrayBuffer`, `SharedArrayBuffer`, boxed number,
boolean, symbol or bigint, generator, and `Map` or `Set` iterator. Node refuses all of them. JSON
input cannot produce such an object (decided 2026-11-24, see the README threat model). Typed arrays,
`DataView`s and errors (where `Error.isError` exists) are still refused there, also with own keys. A
boxed string, an `arguments` object and any other object with a non-enumerable own `length` are
refused too. An object that keeps its data in `#private` fields or in slots that permitkit cannot
identify (a `URL`, a `WeakRef`, an `Intl` object, an array or string iterator), with its prototype
set to `Object.prototype`, serializes as `{}` in every runtime. The threat model in the README lists
the checks per runtime. Pass plain JSON data.

| Code                        | Thrown by                                                                                              | Meaning                                                                    |
| --------------------------- | ------------------------------------------------------------------------------------------------------ | -------------------------------------------------------------------------- |
| `catalog_invalid`           | `defineCatalog`                                                                                        | The catalogue definition is not valid. See `issues`.                       |
| `policy_invalid`            | `compilePolicy`                                                                                        | The policy document is not valid. See `issues`.                            |
| `policy_schema_unsupported` | `compilePolicy`                                                                                        | The document has another `schema` value than 2. No automatic migration.    |
| `policy_unknown`            | `decide`, `explain`, `evaluate`, `evaluateApprovals`, `reevaluate`, `decideAndRecord`, `requestDigest` | The policy did not come from `compilePolicy`.                              |
| `request_invalid`           | `requestDigest`                                                                                        | The request does not match the schema.                                     |
| `options_invalid`           | `evaluateApprovals`                                                                                    | The options are not `{ verifiers: [...] }`, or two verifiers share a type. |
| `not_canonical`             | `canonicalJson`, `digest`                                                                              | The value has no exact JSON form, or is not plain data.                    |

Each `PermitkitError` has `code`, `hint` and, for validation errors, `issues` with `path`,
`message` and `hint`. The codes are stable. The wording of issue messages is not part of the API
and can change in any release, so match on `code`, and on the reason code of a decision.

`PermitkitError.is(value)` returns `true` for every instance that the `PermitkitError`
constructor of this copy of permitkit built: the errors that permitkit throws, errors that you
create with `new PermitkitError(...)`, and instances of subclasses. It returns `false` for an
error from another copy of the package (a second install or another bundle), for an object made
with `Object.create(PermitkitError.prototype)`, for object literals, `null` and primitives. It
never throws. It checks a private field, so it runs no caller code: no Proxy trap and no getter,
and it does not read the prototype chain.
`instanceof` reads the prototype and runs the `getPrototypeOf` trap of a thrown Proxy, which can
throw inside your `catch` block. Use `PermitkitError.is(error)` in a `catch` block that can see
errors from code you do not control, and wherever a check must not throw:

```ts
try {
  policy = compilePolicy(catalog, document);
} catch (error) {
  if (!PermitkitError.is(error)) throw error;
  log(error.code, error.issues);
}
```

The private field also makes the `PermitkitError` type nominal. An object literal with `code`,
`hint` and `issues` no longer satisfies the type; create errors with `new PermitkitError(...)`.
`name` stays a writable `string`, so a subclass can set its own name.

## Size bounds

Before validation, every input is copied through a size guard (`src/bounds.ts`). Input
that is not plain data (objects other than plain objects and arrays, hidden keys, holes; see the
threat model in the README for the one gap) is
unusable as a whole and gives a deny. Getters and setters count as not plain data; the guard reads
data properties only, so no caller code runs during the copy. On Node, a proxy is also unusable. In
a runtime without `process`, a proxy cannot be detected: the guard copies it like a plain object,
its traps run during that read, and validation runs on the copy. `evaluateApprovals` reads a proxy
input more than once there (the early approval count and request check, then the full copy), so
the early checks can see a smaller input than the copy. The full copy still enforces the approval
input bounds, so this costs work up to those bounds, never access. A proxy around a large typed
array (or another object with many keys) is also listed key by key before the size bound refuses
it: about 7.9 s of CPU and 2.1 GB for a 1e7-element array behind a proxy with no traps, where Node
refuses it at once. Only a caller that builds such an object in its own process can cause this;
JSON input cannot. There, a `Map`, `Set`, `Date` or other built-in of a kind that only a check
that throws could identify, with a swapped prototype, also copies as its own keys, and as `{}` if
it has none; Node refuses it (see the README threat model). An error is identified there only
where the runtime has `Error.isError`. A swapped typed array or boxed string is refused before
its keys are read, on both paths, so its size costs nothing.
The guard stays in front of every validator. Every input (requests, policy documents, approval
inputs and stored decision records) uses permitkit's own validators, which check every item of a
list, also of a list longer than its limit; the guard bounds that work.
Requests: depth 24, 20,000 values, 1,000 items per array or object, 4,096
characters per string. Audit records: 300,000 values, and the request inside meets the request
bounds. Policies: depth 24, 500,000 values, 10,000 items, 4,096 characters.

`evaluateApprovals` checks its options, then bounds its cost before it reads the input, in this order:

1. At most 20 approvals (`too_many_approvals`). The count is read from the array length, without
   reading any approval. The largest rule needs 10 approvers.
2. The request meets the request bounds (`input_too_large`).
3. The whole input: 100,000 values, depth 24, 1,000 items per array, 4,096 characters per string
   (`input_too_large`).

The work after that is linear in the number of approvals: at most one decision per approval, and
at most one verifier call per approval.

## Timestamps

Every timestamp must lie between `0000-01-01T00:00:00Z` and `9999-12-31T23:59:59.999Z` as an
instant, after its offset is applied. Inside this range the UTC form has a four-digit year, so a
normalized time is again a valid timestamp. A request time (`context.now`, and `now` of
`evaluateApprovals`) must be at most `9999-11-30T23:59:59.999Z`, 31 days before the end, so that
`approval.expiresAt` after the longest approval window is still a valid timestamp.

## Digests

The request digest has the format tag `permitkit.request/2`. It covers the agent grant entries,
including their `scope` and `limits` in the schema 2 shape, so digests from the earlier format do
not match. Audit records have the format tag `permitkit.decision/2`; a record with another tag is
`not_replayable`.

## Plain-data path (`plainDataRuntime`)

`plainDataRuntime` is `"node"` or `"portable"`: the way permitkit tells plain data from objects
that only look plain, chosen once when the package loads (see the threat model in the README).
`"node"` means `process.getBuiltinModule("node:util")` gave a working `util.types`: proxies are
refused, and so is every built-in that `util.types` identifies by its engine slots, also with a
swapped prototype. `"portable"` means the package found no such `util.types` and uses the
checks that work without it, which do not detect a proxy. permitkit switches to the portable path
without an error or a log line. If your service needs the Node checks, assert the value at boot:

```ts
import { plainDataRuntime } from "permitkit";

if (plainDataRuntime !== "node") throw new Error("permitkit runs without node:util checks");
```
