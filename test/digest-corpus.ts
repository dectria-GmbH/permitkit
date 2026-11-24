import { digest, requestDigest, type AccessRequest } from "../src/index.js";
import {
  accessRequest,
  everywhere,
  human,
  role,
  unlimited,
  viaAgent,
} from "../src/testing/index.js";
import { catalog, policy } from "./fixtures.js";

/**
 * Fixed inputs for the digest tests. The expected hex values in sha256.test.ts were produced
 * from these inputs by the node:crypto implementation on origin/main e258cf0.
 */

const lead = human("u-lead", role("lead", everywhere));

function withProperties(properties: Record<string, string>): AccessRequest {
  return accessRequest(lead, "ticket:read", { properties });
}

function agentChain(): AccessRequest {
  const subject = viaAgent(lead, "bot-executor", {
    entries: [{ permissions: ["ticket:read"], scope: everywhere, limits: unlimited }],
    notBefore: "2026-01-01T00:00:00.000Z",
  });
  const current = subject.act;
  if (current === null) throw new Error("viaAgent returned no actor");
  // Two actors: the executor acts for a planner agent that has no grant of its own.
  const chained = {
    ...subject,
    act: { ...current, act: { type: "agent" as const, id: "bot-planner", grant: null, act: null } },
  };
  return accessRequest(chained, "ticket:read");
}

/** A 4,096-code-unit string with one, two, three and four byte UTF-8 characters. */
const longText = "aé€😀".repeat(1024).slice(0, 4096);

export const digestCorpus: readonly (readonly [string, () => string])[] = [
  ["catalogue digest", () => catalog.digest],
  ["policy digest", () => policy.digest],
  ["request, direct", () => requestDigest(policy, accessRequest(lead, "ticket:read"))],
  ["request, agent chain", () => requestDigest(policy, agentChain())],
  [
    "request, non-ASCII",
    () => requestDigest(policy, withProperties({ queue: "Grüße aus Graz, café, Ωmega, ü" })),
  ],
  [
    "request, astral characters",
    () => requestDigest(policy, withProperties({ queue: "😀 𝔘𝔫𝔦𝔠𝔬𝔡𝔢 🇦🇹" })),
  ],
  ["request, 4,096-char string", () => requestDigest(policy, withProperties({ queue: longText }))],
  [
    "request, lone surrogate",
    () => requestDigest(policy, withProperties({ queue: "a\ud800b", project: "\udc00" })),
  ],
  ["value, empty string", () => digest("")],
  ["value, lone surrogates", () => digest(["\ud800", "\udfff", "x\ud83dy"])],
  ["value, nested keys", () => digest({ z: [1, -0, 0.1, 1e21], a: { é: null, b: true } })],
];
