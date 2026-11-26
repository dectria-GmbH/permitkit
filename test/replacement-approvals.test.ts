// evaluateApprovals and reevaluate with each built-in replaced after load, in the five ways of
// replacement-harness.ts. A result must never widen: no deny or pending result becomes allow, no
// approval is counted that the clean run did not count, and a diverged record never reevaluates
// as reproduced. The hand-written validators call no built-in at call time, so in practice every
// result is the clean one; the test prints the counts. The replacement stays in place while the
// promise settles, so the asynchronous part (proof checks, asynchronous verifiers) runs under it
// too. The test records while the replacement is active and compares after the restore.
import { describe, expect, it } from "vitest";

import {
  compilePolicy,
  decide,
  decideAndRecord,
  evaluateApprovals,
  reevaluate,
  toDecisionRecord,
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
// Plain object results on purpose: the harness also replaces Object.assign and Object.create,
// and this verifier must not call a replaced built-in. A real verifier returns its result
// without a prototype (README, "Approval proofs").
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
const asyncVerifier: ApprovalProofVerifier = {
  type: "sig",
  verify: (proof, expected) => Promise.resolve(verifier.verify(proof, expected)),
};
const asyncOptions = { verifiers: [asyncVerifier] };

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
    "one async proof fails",
    () =>
      evaluateApprovals(
        proofPolicy,
        { request, now: later, approvals: [signed(peerA, true), signed(peerB, false)] },
        asyncOptions,
      ),
  ],
  [
    "both async proofs hold",
    () =>
      evaluateApprovals(
        proofPolicy,
        { request, now: later, approvals: [signed(peerA, true), signed(peerB, true)] },
        asyncOptions,
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

// Records: one that reproduces, one forged to diverge, one for another policy.
const viewerRequest = accessRequest(human("u-v", role("viewer", everywhere)), "ticket:refund", {
  id: "t-1",
  properties: { amount: 250 },
});
const reproducible = decideAndRecord(policy, request).record;
const forged = { ...toDecisionRecord(request, decide(policy, request)), request: viewerRequest };
const foreign = decideAndRecord(proofPolicy, request).record;
const records: [name: string, record: typeof reproducible][] = [
  ["reproduced", reproducible],
  ["forged", forged],
  ["other policy", foreign],
];

function replayAll(): string[] {
  const out: string[] = [];
  for (let index = 0; index < records.length; index += 1) {
    const stored = (records[index] as [string, typeof reproducible])[1];
    try {
      out[index] = stringify(reevaluate(policy, stored));
    } catch (error) {
      out[index] = isPermitkitError(error) ? "threw" : "raw";
    }
  }
  return out;
}

function statusOf(text: string): string {
  try {
    return String((JSON.parse(text) as { status?: unknown }).status);
  } catch {
    return text;
  }
}

describe("reevaluate with replaced built-ins", { timeout: 600_000 }, () => {
  it("never reevaluates a diverged record as reproduced", () => {
    const clean = replayAll();
    expect(clean.map(statusOf)).toEqual(["reproduced", "diverged", "policy_mismatch"]);
    const targets = targetsOf();
    const wrong: string[] = [];
    let same = 0;
    let narrowed = 0;
    for (const mode of modes) {
      for (const target of targets) {
        install(target, mode);
        let polluted: string[] = [];
        try {
          polluted = replayAll();
        } finally {
          restore(target);
        }
        for (let index = 0; index < clean.length; index += 1) {
          const before = clean[index] ?? "";
          const after = polluted[index] ?? "missing";
          if (after === before) same += 1;
          else if (statusOf(after) === "not_replayable") narrowed += 1;
          else {
            const name = (records[index] as [string, unknown])[0];
            wrong.push(
              `${mode} ${target.label} ${name}: ${statusOf(before)} -> ${statusOf(after)}`,
            );
          }
        }
      }
    }
    // Printed for the record.
    process.stdout.write(
      `reevaluate: ${targets.length} built-ins x ${modes.length} modes x ${records.length} ` +
        `records; same ${same}, narrowed ${narrowed}, wrong ${wrong.length}\n`,
    );
    expect(wrong.slice(0, 20)).toEqual([]);
  });
});

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
      "pending",
      "allow",
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
