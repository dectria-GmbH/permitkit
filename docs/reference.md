# Reference

A code never changes its meaning once released. New codes can appear in a minor release. Treat
an unknown decision reason as a deny. The exported objects `reasonCodes`, `reasonHints`,
`approvalRejectionCodes` and `approvalReasonCodes` hold the same texts at run time.

## Decision reasons (`decide`, `explain`, `evaluate`)

| Code                             | Outcome             | Meaning                                                                    |
| -------------------------------- | ------------------- | -------------------------------------------------------------------------- |
| `granted`                        | `allow`             | A grant of one of the subject's roles covers the request.                  |
| `approval_required`              | `approval_required` | A grant covers the request, and a dual-approval rule applies to it.        |
| `invalid_request`                | `deny`              | The request does not match the schema or exceeds the size bounds.          |
| `policy_version_mismatch`        | `deny`              | The request pins a policy version that is not the loaded policy.           |
| `unknown_permission`             | `deny`              | The permission is not in the catalogue.                                    |
| `no_grant`                       | `deny`              | No grant of the subject's roles includes the permission.                   |
| `scope_mismatch`                 | `deny`              | A grant includes the permission, but a scope does not cover the resource.  |
| `limit_exceeded`                 | `deny`              | A grant includes the permission, but a limit does not cover the resource.  |
| `denied_by_rule`                 | `deny`              | A deny rule matches. Deny rules win over grants.                           |
| `agent_grant_missing`            | `deny`              | An agent acts without a grant.                                             |
| `agent_grant_principal_mismatch` | `deny`              | The agent grant belongs to another principal.                              |
| `agent_grant_not_yet_valid`      | `deny`              | The agent grant starts after the request time.                             |
| `agent_grant_expired`            | `deny`              | The agent grant expired at or before the request time.                     |
| `agent_grant_revoked`            | `deny`              | The agent grant was revoked at or before the request time.                 |
| `agent_grant_insufficient`       | `deny`              | The agent grant does not cover the request.                                |
| `sod_role_conflict`              | `deny`              | The subject holds both a requesting and an approving role (if configured). |

The order of checks is: input shape, pinned policy version, catalogue, agent grant validity,
deny rules, grants of the principal, agent grant coverage, separation of duties, approval rule.
The first failing check gives the reason.

## Approval results (`evaluateApprovals`)

| Code                      | Outcome   | Meaning                                                                      |
| ------------------------- | --------- | ---------------------------------------------------------------------------- |
| `approved`                | `allow`   | Enough distinct, eligible approvals exist.                                   |
| `approvals_pending`       | `pending` | Fewer eligible approvals exist than the rule requires.                       |
| `approval_window_expired` | `deny`    | The approval window closed before the evaluation time.                       |
| `approval_not_required`   | `allow`   | No approval rule applies to the request.                                     |
| `requester_denied`        | `deny`    | The requester no longer holds the permission. See `requesterDecision`.       |
| `sod_history_missing`     | `deny`    | The prior-request check is on, but the input has no `priorRequests`.         |
| `invalid_input`           | `deny`    | The input does not match the schema, exceeds the bounds, or is inconsistent. |

## Approval rejections (`ApprovalDecision.rejected`)

| Code                       | Meaning                                                               |
| -------------------------- | --------------------------------------------------------------------- |
| `approval_invalid`         | The approval does not match the approval schema.                      |
| `approver_not_human`       | Only a human principal can approve.                                   |
| `approver_is_delegated`    | An approval given through an agent does not count.                    |
| `requester_cannot_approve` | The principal who requested the action cannot approve it.             |
| `duplicate_approver`       | This approver was already counted.                                    |
| `digest_mismatch`          | The approval names another request digest.                            |
| `approved_before_request`  | The approval time is before the request time.                         |
| `approved_after_expiry`    | The approval time is after the approval window closed.                |
| `approved_in_future`       | The approval time is after the evaluation time.                       |
| `approver_role_missing`    | The approver holds none of the approver roles for this resource.      |
| `approver_not_permitted`   | The approver does not hold the permission (rules without roles).      |
| `sod_role_conflict`        | The approver also holds a requesting role (if configured).            |
| `sod_prior_request`        | The approver requested an action of this type before (if configured). |
| `proof_missing`            | The rule requires a proof and the approval has none.                  |
| `proof_mismatch`           | The proof names another approver or another request digest.           |
| `proof_verifier_missing`   | No verifier is registered for the proof type.                         |
| `proof_invalid`            | The verifier rejected the proof, threw, or echoed other values.       |

## Errors

permitkit throws only for programming and configuration errors. Decisions never throw for bad
requests; they deny.

| Code              | Thrown by                                | Meaning                                              |
| ----------------- | ---------------------------------------- | ---------------------------------------------------- |
| `catalog_invalid` | `defineCatalog`                          | The catalogue definition is not valid. See `issues`. |
| `policy_invalid`  | `compilePolicy`                          | The policy document is not valid. See `issues`.      |
| `policy_unknown`  | `decide`, `explain`, `evaluateApprovals` | The policy did not come from `compilePolicy`.        |
| `not_canonical`   | `canonicalJson`, `digest`                | The value has no exact JSON form.                    |

Each `PermitkitError` has `code`, `hint` and, for validation errors, `issues` with `path`,
`message` and `hint`.

## Size bounds

Before schema validation, every input is copied through a size guard (`src/bounds.ts`).
Requests and approval inputs: depth 24, 20,000 values, 1,000 items per array or object, 4,096
characters per string. Policies: depth 24, 500,000 values, 10,000 items, 4,096 characters. The
guard exists because Zod 3 validates every item of an oversized array and keeps one issue per
failing item (GHSA-mrhx-c7xc-m3w5, no fix in Zod 3).
