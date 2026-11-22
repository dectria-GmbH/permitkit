# Enforcement inside the database

Status: design note. Nothing in this note is built.

## Problem

An application that uses permitkit decides in its own process. The database then stores what the
application writes. A common gap: the table for approvals accepts a requester id and an approver
id as plain arguments from the caller. Any code path with write access can then record an
approval by any two ids, also two ids for the same person, and no rule in the database stops it.

permitkit makes the decision deterministic and records it with a policy digest and a request
digest. The open question is what the database itself should check, so that an application bug
or a second code path cannot bypass the decision.

## Option A: the database checks the invariants of a recorded decision

The application evaluates with permitkit as now. The database enforces the invariants that do not
need the policy, through functions that are the only write path for the runtime role.

- Tables: `authz_request` (request digest, requester id, permission, resource, policy version,
  policy digest, required approver count, window end, executed at), `authz_approval` (request
  digest, approver id, approved at, proof reference).
- The runtime role has no `INSERT` or `UPDATE` grant on these tables. It calls
  `SECURITY DEFINER` functions: `authz_record_request(...)`, `authz_approve(request_digest)`,
  `authz_execute(request_digest)`.
- `authz_approve` takes the approver id from the transaction's authenticated context (for
  example `current_setting('app.principal_id')`, set by the authentication layer per
  transaction), never from an argument. It rejects the requester, every agent id in the
  requester's actor chain, a second approval by the same id, and an approval after the window
  end. It sets `approved_at` from the database clock.
- `authz_execute` runs in the transaction that performs the action. It checks the count of
  distinct approvers, the window, and that `executed_at` is null, then sets it. This gives single
  use, which permitkit cannot give.
- Constraints back this up: a unique index on (request digest, approver id), a check that the
  approver id differs from the requester id.

Gains: small SQL surface; no second policy engine; closes the "two caller-supplied ids" gap and
adds single use. The database also holds the digests, so an audit can join a logged decision to
its approvals.

Limits: the database trusts the application for roles, scopes, limits and agent grants. It cannot
verify an approval proof such as a WebAuthn assertion without an extension; it stores a reference
to the verification result. A fully compromised application process can still set the session
context.

## Option B: the database evaluates the policy

The policy document is loaded into tables per version, and a PL/pgSQL function
`authz_decide(principal, action, resource, now)` reimplements the decision. Triggers on the
protected tables call it before a write.

Gains: an application logic bug in the decision path cannot write a row that the policy does not
allow; the database reads role assignments from its own tables.

Limits: a second implementation of the same rules in another language. Every rule change needs
both engines and a parity test suite over shared vectors. Agent grants, scopes, limits, deny
rules, approval rules and separation of duties all need SQL versions. The principal identity
still comes from the application through the session context, so this option does not protect
against a compromised application either. The cost is much higher than option A.

## Recommendation

1. Build option A first: `SECURITY DEFINER` functions as the only write path, approver taken from
   the authenticated session, distinct and non-requester approvers, window and single use.
2. Keep the policy evaluation in permitkit only. Record its decision and request digest with each
   request row, so an audit can re-evaluate it with `reevaluate()`.
3. Revisit option B only if the threat model requires that a faulty application must not be able
   to authorize a write that the policy does not grant. Even then, prefer a separate authorization
   service with its own database role over a second engine in SQL.
4. If permitkit ships a helper for option A later, it should be a SQL migration template plus a
   small adapter, as a separate entry point, not part of the core.
