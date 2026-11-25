// Named cases for each rule of the approval validators. Each case runs through the hand-written
// validator and must give the expected verdict and first path, so a failure names the rule. The
// expected verdicts are those of the earlier Zod schema; test/zod-verdicts.test.ts compares
// seeded corpora with its recorded verdicts.
import { describe, expect, it } from "vitest";

import { approval, approvalInput } from "../src/approval-input.js";
import { dropAt, expectedOf, runCase, setAt, withKey, type CorpusCase } from "./differential.js";

const digest = "0123456789abcdef".repeat(4);

const subject = (id: string, act: unknown = null) => ({
  type: "human",
  id,
  roles: [{ role: "lead", scope: { kind: "all" } }],
  act,
});

const agent = { type: "agent", id: "bot", grant: null, act: null };

const proof = () => ({ type: "sig", approverId: "u-a", requestDigest: digest, payload: { ok: 1 } });

const approvalBase = (): Record<string, unknown> => ({
  approver: subject("u-a"),
  approvedAt: "2026-01-15T10:10:00Z",
  requestDigest: digest,
  proof: proof(),
});

const inputBase = (): Record<string, unknown> => ({
  request: {
    subject: subject("u-req"),
    action: { name: "refund" },
    resource: { type: "ticket", id: "t" },
    context: { now: "2026-01-15T10:00:00Z" },
  },
  approvals: [approvalBase(), { junk: 1 }],
  now: "2026-01-15T10:30:00Z",
  priorRequests: [{ principalId: "u-a", permission: "ticket:refund" }],
});

/** A chain of `depth` actors without grants. */
const chain = (depth: number): unknown => {
  let act: unknown = null;
  for (let level = depth; level >= 1; level -= 1) {
    act = { type: "agent", id: `a${level}`, grant: null, act };
  }
  return act;
};

const approvalCases: CorpusCase[] = [
  { name: "a valid approval", edit: () => {}, expected: "accept" },
  { name: "no proof", edit: (d) => dropAt(d, ["proof"]), expected: "accept" },
  {
    name: "proof set to undefined",
    edit: (d) => setAt(d, ["proof"], undefined),
    expected: "accept",
  },
  { name: "proof null", edit: (d) => setAt(d, ["proof"], null), expected: ["proof"] },
  { name: "unknown key", edit: (d) => setAt(d, ["extra"], 1), expected: [] },
  { name: "__proto__ key", edit: (d) => setAt(d, ["__proto__"], 1), expected: [] },
  { name: "no approver", edit: (d) => dropAt(d, ["approver"]), expected: ["approver"] },
  {
    name: "approver of an unknown type",
    edit: (d) => setAt(d, ["approver", "type"], "robot"),
    expected: ["approver", "type"],
  },
  {
    name: "service approver",
    edit: (d) => setAt(d, ["approver", "type"], "service"),
    expected: "accept",
  },
  {
    name: "delegated approver",
    edit: (d) => setAt(d, ["approver", "act"], agent),
    expected: "accept",
  },
  {
    name: "approver with five actors, no depth limit outside a request",
    edit: (d) => setAt(d, ["approver", "act"], chain(5)),
    expected: "accept",
  },
  {
    name: "approver without act",
    edit: (d) => dropAt(d, ["approver", "act"]),
    expected: ["approver", "act"],
  },
  {
    name: "approver with 257 roles",
    edit: (d) =>
      setAt(
        d,
        ["approver", "roles"],
        Array.from({ length: 257 }, () => ({ role: "lead", scope: { kind: "all" } })),
      ),
    expected: ["approver", "roles"],
  },
  { name: "approvedAt missing", edit: (d) => dropAt(d, ["approvedAt"]), expected: ["approvedAt"] },
  {
    name: "approvedAt without offset",
    edit: (d) => setAt(d, ["approvedAt"], "2026-01-15T10:10:00"),
    expected: ["approvedAt"],
  },
  {
    name: "approvedAt on 30 February",
    edit: (d) => setAt(d, ["approvedAt"], "2026-02-30T10:10:00Z"),
    expected: ["approvedAt"],
  },
  {
    name: "approvedAt at the last timestamp, after the last request time",
    edit: (d) => setAt(d, ["approvedAt"], "9999-12-31T23:59:59.999Z"),
    expected: "accept",
  },
  {
    name: "digest in upper case",
    edit: (d) => setAt(d, ["requestDigest"], digest.toUpperCase()),
    expected: ["requestDigest"],
  },
  {
    name: "digest of 65 characters",
    edit: (d) => setAt(d, ["requestDigest"], `${digest}0`),
    expected: ["requestDigest"],
  },
  {
    name: "proof without payload",
    edit: (d) => dropAt(d, ["proof", "payload"]),
    expected: "accept",
  },
  {
    name: "proof payload set to undefined",
    edit: (d) => setAt(d, ["proof", "payload"], undefined),
    expected: "accept",
  },
  {
    name: "proof payload null",
    edit: (d) => setAt(d, ["proof", "payload"], null),
    expected: "accept",
  },
  {
    name: "proof payload with a __proto__ key",
    edit: (d) => setAt(d, ["proof", "payload"], withKey({}, "__proto__", { ok: true })),
    expected: "accept",
  },
  {
    name: "proof with an unknown key",
    edit: (d) => setAt(d, ["proof", "extra"], 1),
    expected: ["proof"],
  },
  {
    name: "proof type empty",
    edit: (d) => setAt(d, ["proof", "type"], ""),
    expected: ["proof", "type"],
  },
  {
    name: "proof type of 64 characters",
    edit: (d) => setAt(d, ["proof", "type"], "t".repeat(64)),
    expected: "accept",
  },
  {
    name: "proof type of 65 characters",
    edit: (d) => setAt(d, ["proof", "type"], "t".repeat(65)),
    expected: ["proof", "type"],
  },
  {
    name: "proof approver id of 256 characters",
    edit: (d) => setAt(d, ["proof", "approverId"], "a".repeat(256)),
    expected: "accept",
  },
  {
    name: "proof approver id of 257 characters",
    edit: (d) => setAt(d, ["proof", "approverId"], "a".repeat(257)),
    expected: ["proof", "approverId"],
  },
  {
    name: "proof approver id missing",
    edit: (d) => dropAt(d, ["proof", "approverId"]),
    expected: ["proof", "approverId"],
  },
  {
    name: "proof digest in upper case",
    edit: (d) => setAt(d, ["proof", "requestDigest"], digest.toUpperCase()),
    expected: ["proof", "requestDigest"],
  },
  { name: "an array", edit: (d) => setAt(d, ["approver"], []), expected: ["approver"] },
];

const inputCases: CorpusCase[] = [
  { name: "a valid input", edit: () => {}, expected: "accept" },
  { name: "no priorRequests", edit: (d) => dropAt(d, ["priorRequests"]), expected: "accept" },
  {
    name: "priorRequests set to undefined",
    edit: (d) => setAt(d, ["priorRequests"], undefined),
    expected: "accept",
  },
  {
    name: "priorRequests null",
    edit: (d) => setAt(d, ["priorRequests"], null),
    expected: ["priorRequests"],
  },
  { name: "empty priorRequests", edit: (d) => setAt(d, ["priorRequests"], []), expected: "accept" },
  {
    name: "a prior request with an empty permission",
    edit: (d) => setAt(d, ["priorRequests", 0, "permission"], ""),
    expected: ["priorRequests", 0, "permission"],
  },
  {
    name: "a prior request with an unknown permission",
    edit: (d) => setAt(d, ["priorRequests", 0, "permission"], "ticket:fly"),
    expected: "accept",
  },
  {
    name: "a prior request without principalId",
    edit: (d) => dropAt(d, ["priorRequests", 0, "principalId"]),
    expected: ["priorRequests", 0, "principalId"],
  },
  {
    name: "a prior request with an unknown key",
    edit: (d) => setAt(d, ["priorRequests", 0, "at"], "2026-01-15T10:00:00Z"),
    expected: ["priorRequests", 0],
  },
  {
    name: "a prior request that is a string",
    edit: (d) => setAt(d, ["priorRequests", 0], "u-a"),
    expected: ["priorRequests", 0],
  },
  {
    name: "1000 prior requests",
    edit: (d) =>
      setAt(
        d,
        ["priorRequests"],
        Array.from({ length: 1000 }, () => ({ principalId: "p", permission: "ticket:refund" })),
      ),
    expected: "accept",
  },
  { name: "unknown key", edit: (d) => setAt(d, ["extra"], 1), expected: [] },
  { name: "__proto__ key", edit: (d) => setAt(d, ["__proto__"], 1), expected: [] },
  { name: "no approvals", edit: (d) => dropAt(d, ["approvals"]), expected: ["approvals"] },
  { name: "empty approvals", edit: (d) => setAt(d, ["approvals"], []), expected: "accept" },
  {
    name: "approvals that are not approvals, checked later one by one",
    edit: (d) => setAt(d, ["approvals"], [null, 1, "x", [], {}]),
    expected: "accept",
  },
  {
    name: "20 approvals",
    edit: (d) => setAt(d, ["approvals"], Array.from({ length: 20 }, approvalBase)),
    expected: "accept",
  },
  {
    name: "21 approvals",
    edit: (d) => setAt(d, ["approvals"], Array.from({ length: 21 }, approvalBase)),
    expected: ["approvals"],
  },
  {
    name: "approvals as an object",
    edit: (d) => setAt(d, ["approvals"], { 0: approvalBase() }),
    expected: ["approvals"],
  },
  { name: "no now", edit: (d) => dropAt(d, ["now"]), expected: ["now"] },
  {
    name: "now after the last request time",
    edit: (d) => setAt(d, ["now"], "9999-12-31T23:59:59.999Z"),
    expected: ["now"],
  },
  {
    name: "now before the request time, refused later and not here",
    edit: (d) => setAt(d, ["now"], "2026-01-15T09:00:00Z"),
    expected: "accept",
  },
  { name: "no request", edit: (d) => dropAt(d, ["request"]), expected: ["request"] },
  {
    name: "request with an unknown key",
    edit: (d) => setAt(d, ["request", "extra"], 1),
    expected: ["request"],
  },
  {
    name: "request with five actors",
    edit: (d) => setAt(d, ["request", "subject", "act"], chain(5)),
    expected: ["request", "subject", "act"],
  },
  {
    name: "request with four actors",
    edit: (d) => setAt(d, ["request", "subject", "act"], chain(4)),
    expected: "accept",
  },
  {
    name: "request time on 30 February",
    edit: (d) => setAt(d, ["request", "context", "now"], "2026-02-30T10:00:00Z"),
    expected: ["request", "context", "now"],
  },
  {
    name: "first issue in the request, before a bad now",
    edit: (d) => {
      setAt(d, ["request", "action", "name"], "");
      setAt(d, ["now"], 5);
    },
    expected: ["request", "action", "name"],
  },
  { name: "an array", edit: (d) => setAt(d, ["request"], []), expected: ["request"] },
];

describe("approval validator rules", () => {
  it.each(approvalCases.map((item) => [item.name, item] as const))("%s", (_name, item) => {
    expect(runCase(approval, approvalBase, item)).toBe(expectedOf(item));
  });

  it("keeps the payload key exactly if the input has it, as before", () => {
    const withPayload = approval(approvalBase(), null, []);
    const without = approvalBase();
    dropAt(without, ["proof", "payload"]);
    const withoutPayload = approval(without, null, []);
    const undefinedPayload = approvalBase();
    setAt(undefinedPayload, ["proof", "payload"], undefined);
    const keptUndefined = approval(undefinedPayload, null, []);
    expect(typeof withPayload === "object" && Object.keys(withPayload.proof ?? {})).toEqual([
      "type",
      "approverId",
      "requestDigest",
      "payload",
    ]);
    expect(
      typeof withoutPayload === "object" && Object.hasOwn(withoutPayload.proof ?? {}, "payload"),
    ).toBe(false);
    expect(
      typeof keptUndefined === "object" && Object.hasOwn(keptUndefined.proof ?? {}, "payload"),
    ).toBe(true);
  });

  it("returns objects without a prototype", () => {
    const result = approval(approvalBase(), null, []);
    if (typeof result !== "object") throw new Error("refused");
    expect(Object.getPrototypeOf(result)).toBeNull();
    expect(Object.getPrototypeOf(result.approver)).toBeNull();
    expect(Object.getPrototypeOf(result.proof)).toBeNull();
    expect(Object.getPrototypeOf(result.proof?.payload)).toBeNull();
  });
});

describe("approval input validator rules", () => {
  it.each(inputCases.map((item) => [item.name, item] as const))("%s", (_name, item) => {
    expect(runCase(approvalInput, inputBase, item)).toBe(expectedOf(item));
  });
});
