// evaluateApprovals with each built-in replaced after load, in the five ways of
// replacement-harness.ts. Approval inputs go through Zod 3, which calls built-ins when it runs, so
// a replacement may refuse an input there: the result then is a deny, or pending with fewer
// counted approvals. It must never widen: no deny or pending result becomes allow, and no
// approval is counted that the clean run did not count. The replacement stays in place while the
// promise settles, so the asynchronous part (proof checks) runs under it too. The test records
// while the replacement is active and compares after the restore.
import { describe, expect, it } from "vitest";

import {
  compilePolicy,
  evaluateApprovals,
  PermitkitError,
  requestDigest,
  type ApprovalProof,
  type ApprovalProofVerifier,
  type Subject,
} from "../src/index.js";
import { accessRequest, everywhere, human, role, viaAgent } from "../src/testing/index.js";
import { catalog, editablePolicyInput, policy } from "./fixtures.js";
import { install, modes, restore, targetsOf } from "./replacement-harness.js";

const stringify = JSON.stringify;
const isPermitkitError = (value: unknown): boolean => PermitkitError.is(value);

const requester = human("u-req", role("lead", everywhere));
const peerA = human("u-a", role("lead", everywhere));
const peerB = human("u-b", role("lead", everywhere));
const peerC = human("u-c", role("lead", everywhere));
const request = accessRequest(requester, "ticket:refund", {
  id: "t-1",
  properties: { amount: 250 },
});
const digest = requestDigest(policy, request);
const otherDigest = "0".repeat(64);
const later = "2026-01-15T10:30:00.000Z";
const approval = (approver: Subject, extra: Record<string, unknown> = {}) => ({
  approver,
  approvedAt: "2026-01-15T10:10:00.000Z",
  requestDigest: digest,
  ...extra,
});

const proofInput = editablePolicyInput();
proofInput.approvalRules = [
  { ...proofInput.approvalRules[0]!, requireProof: true, proofTypes: ["sig"] },
];
const proofPolicy = compilePolicy(catalog, proofInput);
const proofDigest = requestDigest(proofPolicy, request);
const verifier: ApprovalProofVerifier = {
  type: "sig",
  verify(proof: ApprovalProof, expected) {
    const payload = proof.payload as { ok?: boolean };
    return payload.ok === true
      ? { valid: true, approverId: expected.approverId, requestDigest: expected.requestDigest }
      : { valid: false, reason: "not signed" };
  },
};
const signed = (approver: Subject, ok: boolean) => ({
  approver,
  approvedAt: "2026-01-15T10:10:00.000Z",
  requestDigest: proofDigest,
  proof: { type: "sig", approverId: approver.id, requestDigest: proofDigest, payload: { ok } },
});
const agentPeer = viaAgent(peerA, "bot", {
  entries: [
    { permissions: ["ticket:refund"], scope: { kind: "all" }, limits: { kind: "unlimited" } },
  ],
});
const options = { verifiers: [verifier] };

const scenarios: [name: string, run: () => Promise<unknown>][] = [
  [
    "two peers",
    () =>
      evaluateApprovals(policy, {
        request,
        now: later,
        approvals: [approval(peerA), approval(peerB)],
      }),
  ],
  [
    "peer and requester",
    () =>
      evaluateApprovals(policy, {
        request,
        now: later,
        approvals: [approval(peerA), approval(requester)],
      }),
  ],
  [
    "one peer twice",
    () =>
      evaluateApprovals(policy, {
        request,
        now: later,
        approvals: [approval(peerA), approval(peerA)],
      }),
  ],
  [
    "other digest",
    () =>
      evaluateApprovals(policy, {
        request,
        now: later,
        approvals: [approval(peerA, { requestDigest: otherDigest }), approval(peerB)],
      }),
  ],
  [
    "agent approver",
    () =>
      evaluateApprovals(policy, {
        request,
        now: later,
        approvals: [approval(agentPeer), approval(peerB)],
      }),
  ],
  [
    "window closed",
    () =>
      evaluateApprovals(policy, {
        request,
        now: "2026-01-15T11:00:00.001Z",
        approvals: [approval(peerA), approval(peerB)],
      }),
  ],
  [
    "before the request",
    () =>
      evaluateApprovals(policy, {
        request,
        now: later,
        approvals: [approval(peerA, { approvedAt: "2026-01-15T09:00:00.000Z" }), approval(peerB)],
      }),
  ],
  [
    "approver without a role",
    () =>
      evaluateApprovals(policy, {
        request,
        now: later,
        approvals: [approval(human("x")), approval(peerB)],
      }),
  ],
  [
    "one proof fails",
    () =>
      evaluateApprovals(
        proofPolicy,
        { request, now: later, approvals: [signed(peerA, true), signed(peerB, false)] },
        options,
      ),
  ],
  [
    "both proofs hold",
    () =>
      evaluateApprovals(
        proofPolicy,
        { request, now: later, approvals: [signed(peerA, true), signed(peerB, true)] },
        options,
      ),
  ],
  [
    "proofs missing",
    () =>
      evaluateApprovals(
        proofPolicy,
        { request, now: later, approvals: [approval(peerA), approval(peerB)] },
        options,
      ),
  ],
  [
    "three peers",
    () =>
      evaluateApprovals(policy, {
        request,
        now: later,
        approvals: [approval(peerA), approval(peerB), approval(peerC)],
      }),
  ],
];

async function runAll(): Promise<string[]> {
  const out: string[] = [];
  for (let index = 0; index < scenarios.length; index += 1) {
    const run = (scenarios[index] as [string, () => Promise<unknown>])[1];
    try {
      out[index] = stringify(await run());
    } catch (error) {
      out[index] = isPermitkitError(error) ? "threw" : "raw";
    }
  }
  return out;
}

interface Summary {
  outcome?: string;
  counted?: string[];
}

function summaryOf(text: string): Summary {
  try {
    return JSON.parse(text) as Summary;
  } catch {
    return {};
  }
}

describe("evaluateApprovals with replaced built-ins", { timeout: 600_000 }, () => {
  it("never widens an approval result", async () => {
    const clean = await runAll();
    expect(clean.map((text) => summaryOf(text).outcome)).toEqual([
      "allow",
      "pending",
      "pending",
      "pending",
      "pending",
      "deny",
      "pending",
      "pending",
      "pending",
      "allow",
      "pending",
      "allow",
    ]);
    const targets = targetsOf();
    const wrong: string[] = [];
    let same = 0;
    let narrowed = 0;
    for (const mode of modes) {
      for (const target of targets) {
        install(target, mode);
        let polluted: string[] = [];
        try {
          polluted = await runAll();
        } finally {
          restore(target);
        }
        for (let index = 0; index < clean.length; index += 1) {
          const before = clean[index] ?? "";
          const after = polluted[index] ?? "missing";
          if (after === before) {
            same += 1;
            continue;
          }
          const was = summaryOf(before);
          const now = summaryOf(after);
          const fewer =
            now.outcome === "pending" &&
            was.outcome !== "deny" &&
            (now.counted ?? []).every((id) => (was.counted ?? []).includes(id));
          if (now.outcome === "deny" || fewer) {
            narrowed += 1;
            continue;
          }
          const name = (scenarios[index] as [string, unknown])[0];
          wrong.push(
            `${mode} ${target.label} ${name}: ${String(was.outcome)} -> ${after.slice(0, 80)}`,
          );
        }
      }
    }
    // Printed for the record.
    process.stdout.write(
      `approvals: ${targets.length} built-ins x ${modes.length} modes x ${scenarios.length} ` +
        `inputs; same ${same}, narrowed ${narrowed}, wrong ${wrong.length}\n`,
    );
    expect(wrong.slice(0, 20)).toEqual([]);
  });
});
