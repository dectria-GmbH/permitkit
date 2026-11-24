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
The first failing check gives the reason. If the library fails internally (for example under
polluted built-in prototypes), the result is a deny with `invalid_request`, also for a request
that would be valid.

## Approval results (`evaluateApprovals`)

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

## Errors

permitkit throws only for programming and configuration errors. Decisions never throw for bad
requests, including throwing getters and revoked proxies; they deny. `catalog_invalid` is also
thrown when `compilePolicy` gets a catalogue that `defineCatalog` did not create.
`canonicalJson` and `digest` throw `not_canonical`, never a raw error: for objects whose
prototype is not `Object.prototype`, `null` or `Array.prototype`, built-ins identified by their
internal slots (a `Map` or `Date`, also with a swapped prototype), symbol or non-enumerable keys,
getters and setters (which are not run), array holes and named array properties, revoked
proxies, and input too deep to walk. On Node, every proxy is refused too. In a runtime without
`process` (for example Cloudflare Workers without `nodejs_compat`), a proxy cannot be detected:
it serializes as the data it reports, and its traps run. There, a `Promise`, generator or
iterator with its prototype set to `Object.prototype` serializes as `{}`; Node refuses them. A
built-in with a swapped prototype and own keys (a `Map` or `Date` with keys added by hand, or a
typed array, whose elements are own keys) serializes as those own keys there; Node refuses it.
JSON input cannot produce such an object. An
object that keeps its data in `#private` fields or in slots that permitkit cannot identify (a
`URL`, a `WeakRef`, an `Intl` object), with its prototype set to `Object.prototype`, serializes
as `{}` in every runtime. The threat model in the README lists the checks per runtime. Pass plain
JSON data.

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
`message` and `hint`.

## Size bounds

Before schema validation, every input is copied through a size guard (`src/bounds.ts`). Input
that is not plain data (objects other than plain objects and arrays, hidden keys, holes; see the
threat model in the README for the one gap) is
unusable as a whole and gives a deny. Getters and setters count as not plain data; the guard reads
data properties only, so no caller code runs during the copy. On Node, a proxy is also unusable. In
a runtime without `process`, a proxy cannot be detected: the guard copies it like a plain object,
its traps run during that read, and validation runs on the copy. `evaluateApprovals` reads a proxy
input more than once there (the early approval count and request check, then the full copy), so
the early checks can see a smaller input than the copy. The full copy still enforces the approval
input bounds, so this costs work up to those bounds, never access. There, a built-in with a
swapped prototype and own keys also copies as those own keys; Node refuses it (see the README
threat model). An error is identified there only where the runtime has `Error.isError`.
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
`not_replayable`. The
guard exists because Zod 3 validates every item of an oversized array and keeps one issue per
failing item (GHSA-mrhx-c7xc-m3w5, no fix in Zod 3).
