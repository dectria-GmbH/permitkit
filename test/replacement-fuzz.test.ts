// Replacement of built-in functions after permitkit loads. Each case replaces one method,
// static, getter, constructor or iterator method with a function that returns a wrong value
// (true, false, undefined, an empty array or an empty iterator) or throws. It then runs decide,
// explain, evaluate, requestDigest and compilePolicy on a fixed corpus, restores the built-in, and
// compares with the results without the replacement. A result may turn into a deny or a refusal.
// It must never widen: no deny becomes approval_required or allow, no approval_required becomes
// allow, a decision that is not a deny is the same decision, and a digest is the same digest.
// The replacement can break the test framework, so each case only records while it is active
// and compares after the restore. Every function the harness calls while a built-in is replaced
// was captured before.
import { describe, expect, it } from "vitest";

import {
  compilePolicy,
  decide,
  evaluate,
  explain,
  PermitkitError,
  requestDigest,
  type AccessRequest,
  type AuthZenRequest,
  type CompiledPolicy,
} from "../src/index.js";
import {
  asAuthZen,
  replacementCatalog,
  replacementPolicies,
  replacementPolicyInputs,
  replacementRequests,
} from "./replacement-corpus.js";
import { install, modes, restore, targetsOf } from "./replacement-harness.js";

const isPermitkitError = (value: unknown): boolean => PermitkitError.is(value);
const stringify = JSON.stringify;

/** Requests per policy. PERMITKIT_REPLACEMENT_REQUESTS raises it for a longer run. */
const requestCount = Number(process.env["PERMITKIT_REPLACEMENT_REQUESTS"] ?? "24");

/**
 * By default each built-in runs in one mode: the modes take turns along the target list, so every
 * owner with five or more built-ins sees every mode, and every owner sees at least one.
 * call-time-spy.test.ts shows that no built-in runs at call time at all, so the sample only has to
 * show that a replacement reaches nothing. PERMITKIT_REPLACEMENT_ALL_MODES=1 runs every built-in
 * in every mode.
 */
const allModes = process.env["PERMITKIT_REPLACEMENT_ALL_MODES"] === "1";
const requests: AccessRequest[] = replacementRequests(requestCount);
const authzenRequests: AuthZenRequest[] = requests.map(asAuthZen);

const threw = Symbol("threw");
const rawThrow = Symbol("raw throw");

function attempt(run: () => unknown): unknown {
  try {
    return run();
  } catch (error) {
    return isPermitkitError(error) ? threw : rawThrow;
  }
}

/** One slot per call: [policy][request][decide, explain, evaluate, requestDigest]. */
const callsPerRequest = 4;

function runCorpus(policies: readonly CompiledPolicy[], into: unknown[]): void {
  let slot = 0;
  for (let policyIndex = 0; policyIndex < policies.length; policyIndex += 1) {
    const policy = policies[policyIndex] as CompiledPolicy;
    for (let index = 0; index < requests.length; index += 1) {
      const request = requests[index];
      const authzen = authzenRequests[index] as AuthZenRequest;
      into[slot] = attempt(() => decide(policy, request));
      into[slot + 1] = attempt(() => explain(policy, request));
      into[slot + 2] = attempt(() => evaluate(policy, authzen));
      into[slot + 3] = attempt(() => requestDigest(policy, request));
      slot += callsPerRequest;
    }
  }
}

function compileAll(into: unknown[]): void {
  for (let index = 0; index < replacementPolicyInputs.length; index += 1) {
    const input = replacementPolicyInputs[index];
    into[index] = attempt(() => compilePolicy(replacementCatalog, input));
  }
}

const rank: Record<string, number> = { deny: 0, approval_required: 1, allow: 2 };

interface Tally {
  same: number;
  narrowed: number;
  wrong: string[];
}

function outcomeOf(value: unknown): string | undefined {
  if (typeof value !== "object" || value === null) return undefined;
  const decision: unknown = "decision" in value ? value.decision : value;
  if (typeof decision === "object" && decision !== null && "outcome" in decision) {
    return String(decision.outcome);
  }
  if ("context" in value) {
    return String((value as { context: { outcome: unknown } }).context.outcome);
  }
  return undefined;
}

/** Classifies one polluted result against the clean one. */
function compare(label: string, polluted: unknown, clean: unknown, kind: number, tally: Tally) {
  if (polluted === rawThrow) {
    tally.wrong.push(`${label}: raw throw`);
    return;
  }
  if (kind === 3) {
    // requestDigest: the same digest, or the documented throw.
    if (polluted === clean) tally.same += 1;
    else if (polluted === threw) tally.narrowed += 1;
    else tally.wrong.push(`${label}: digest ${String(polluted)} vs ${String(clean)}`);
    return;
  }
  if (polluted === threw) {
    tally.wrong.push(`${label}: threw`);
    return;
  }
  const pollutedText = stringify(polluted);
  if (pollutedText === stringify(clean)) {
    tally.same += 1;
    return;
  }
  const pollutedOutcome = outcomeOf(polluted);
  const cleanOutcome = outcomeOf(clean);
  if (pollutedOutcome === "deny") {
    tally.narrowed += 1;
    return;
  }
  const pollutedRank = rank[pollutedOutcome ?? ""] ?? 9;
  const cleanRank = rank[cleanOutcome ?? ""] ?? 0;
  const how = pollutedRank > cleanRank ? "widened" : "changed";
  tally.wrong.push(`${label}: ${how} ${String(cleanOutcome)} -> ${String(pollutedOutcome)}`);
}

const clean: unknown[] = [];
runCorpus(replacementPolicies, clean);
const cleanDigests = replacementPolicies.map((policy) => policy.digest);

const callNames = ["decide", "explain", "evaluate", "requestDigest"];

describe("replaced built-ins after load", { timeout: 600_000 }, () => {
  const targets = targetsOf();

  it("finds the built-ins to replace", () => {
    expect(targets.length).toBeGreaterThan(300);
    // The modes take turns along the list, so an owner with n built-ins sees min(n, 5) modes.
    const seen = new Map<object, { count: number; modes: Set<number> }>();
    targets.forEach((target, index) => {
      const entry = seen.get(target.owner) ?? { count: 0, modes: new Set<number>() };
      entry.count += 1;
      modes.forEach((_, modeIndex) => {
        if (inSample(index, modeIndex)) entry.modes.add(modeIndex);
      });
      seen.set(target.owner, entry);
    });
    for (const entry of seen.values()) {
      expect(entry.modes.size).toBeGreaterThanOrEqual(Math.min(entry.count, modes.length));
    }
    const labels = targets.map((target) => target.label);
    for (const expected of [
      "Array.prototype.some",
      "Array.prototype.includes",
      "Array.prototype.Symbol(Symbol.iterator)",
      "%ArrayIteratorPrototype%.next",
      "Set.prototype.has",
      "Map.prototype.get",
      "Object.keys",
      "Object.hasOwn",
      "RegExp.prototype.exec",
      "Date.parse",
      "globalThis.Set",
    ]) {
      expect(labels).toContain(expected);
    }
    // The clean corpus reaches each outcome.
    const outcomes = new Set(
      clean.filter((_, slot) => slot % callsPerRequest === 0).map(outcomeOf),
    );
    expect(
      [...outcomes].toSorted((left, right) => String(left).localeCompare(String(right))),
    ).toEqual(["allow", "approval_required", "deny"]);
  });

  it.each(modes.map((mode, modeIndex) => [mode, modeIndex] as const))(
    "no result widens with each built-in replaced, mode %s",
    (mode, modeIndex) => {
      const tally: Tally = { same: 0, narrowed: 0, wrong: [] };
      const compileTally: Tally = { same: 0, narrowed: 0, wrong: [] };
      const polluted: unknown[] = [];
      const compiled: unknown[] = [];
      const afterCompile: unknown[] = [];
      let replaced = 0;
      for (let targetIndex = 0; targetIndex < targets.length; targetIndex += 1) {
        if (!inSample(targetIndex, modeIndex)) continue;
        const target = targets[targetIndex] as (typeof targets)[number];
        polluted.length = 0;
        compiled.length = 0;
        replaced += 1;
        install(target, mode);
        try {
          runCorpus(replacementPolicies, polluted);
          compileAll(compiled);
        } finally {
          restore(target);
        }
        for (let slot = 0; slot < clean.length; slot += 1) {
          const kind = slot % callsPerRequest;
          compare(
            `${target.label} ${callNames[kind] ?? ""} #${slot}`,
            polluted[slot],
            clean[slot],
            kind,
            tally,
          );
        }
        // A policy compiled under the replacement is the clean policy, or a refusal.
        const usable: CompiledPolicy[] = [];
        for (let index = 0; index < compiled.length; index += 1) {
          const result = compiled[index];
          if (result === threw) compileTally.narrowed += 1;
          else if (result === rawThrow)
            compileTally.wrong.push(`${target.label}: compile raw throw`);
          else {
            const policy = result as CompiledPolicy;
            if (policy.digest === cleanDigests[index]) compileTally.same += 1;
            else compileTally.wrong.push(`${target.label}: compiled digest differs`);
            usable.push(policy);
          }
        }
        // Its lookup tables were built under the replacement. Decide with them, unpolluted.
        if (usable.length === compiled.length) {
          afterCompile.length = 0;
          runCorpus(usable, afterCompile);
          for (let slot = 0; slot < clean.length; slot += 1) {
            const kind = slot % callsPerRequest;
            compare(
              `${target.label} compiled-under ${callNames[kind] ?? ""} #${slot}`,
              afterCompile[slot],
              clean[slot],
              kind,
              compileTally,
            );
          }
        }
      }
      // Printed for the record: identical, narrowed to a deny or refusal, and wrong.
      const wrongTargets = new Set(
        [...tally.wrong, ...compileTally.wrong].map((line) => line.split(" ")[0] ?? ""),
      );
      process.stdout.write(
        `replacement mode ${mode}: built-ins with a wrong result: ${[...wrongTargets].join(", ") || "none"}\n`,
      );
      process.stdout.write(
        `replacement mode ${mode}: ${replaced} of ${targets.length} built-ins, ${requests.length} requests x ` +
          `${replacementPolicies.length} policies; calls same ${tally.same}, narrowed ` +
          `${tally.narrowed}, wrong ${tally.wrong.length}; compile same ${compileTally.same}, ` +
          `narrowed ${compileTally.narrowed}, wrong ${compileTally.wrong.length}\n`,
      );
      expect(tally.wrong.slice(0, 20)).toEqual([]);
      expect(compileTally.wrong.slice(0, 20)).toEqual([]);
    },
  );
});

/** True if the target at this index runs in the mode at this index. */
function inSample(targetIndex: number, modeIndex: number): boolean {
  return allModes || targetIndex % modes.length === modeIndex;
}
