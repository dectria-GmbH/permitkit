// No built-in runs at call time. This test wraps every configurable method and getter of the
// built-in owners in replacement-harness.ts, and every global constructor, with a function that
// records the call and then calls the original. It also records writes that reach
// Array.prototype or Object.prototype at a low index. It then runs decide, explain, evaluate,
// requestDigest, parseRequest, canonicalJson, compilePolicy, reevaluate, toDecisionRecord,
// decideAndRecord and evaluateApprovals on valid and invalid input and expects no record. A call recorded here is a call that a replacement after load could answer
// with any value, so this proves for every built-in what replacement-fuzz.test.ts samples.
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import {
  approvalCases,
  callTimeCorpus,
  runApprovalCallTimeCorpus,
  runCallTimeCorpus,
  type CallName,
} from "./call-time-corpus.js";
import { approvalReasonCodes, approvalRejectionCodes } from "../src/index.js";
import { globalNames, targetsOf } from "./replacement-harness.js";

/** Every approval decision reason, and the two error codes that evaluateApprovals throws. */
const expectedReasons = [...Object.keys(approvalReasonCodes), "options_invalid", "policy_unknown"];
const approvalRejectionCodesList = Object.keys(approvalRejectionCodes);

const apply = Reflect.apply;
const construct = Reflect.construct;
const define = Object.defineProperty;
const deleteKey = Reflect.deleteProperty;
const hasOwn = Object.hasOwn;
const toText = String;
const create = Object.create;
const bareDescriptor = (): PropertyDescriptor => create(null) as PropertyDescriptor;

interface Spy {
  active: CallName | "";
  readonly calls: Record<string, number>;
  /**
   * Count only calls with a frame of permitkit's src on the stack. While an asynchronous call
   * is active, the test runner's own microtasks run too; they have no such frame.
   */
  readonly sourceOnly?: boolean;
}

const ErrorType = Error;
const includesMethod: unknown = Object.getOwnPropertyDescriptor(
  String.prototype,
  "includes",
)?.value;
const includes = (text: string, part: string): boolean =>
  apply(includesMethod as (search: string) => boolean, text, [part]);
const sourceDirectory = fileURLToPath(new URL("../src/", import.meta.url));

function hit(spy: Spy, label: string): void {
  if (spy.active === "") return;
  const entry = `${spy.active} ${label}`;
  const was = spy.active;
  // Nothing below may record itself.
  spy.active = "";
  const counted = spy.sourceOnly !== true || includes(new ErrorType().stack ?? "", sourceDirectory);
  if (counted) spy.calls[entry] = (spy.calls[entry] ?? 0) + 1;
  spy.active = was;
}

/** A wrapper that records the call, then calls or constructs the original. */
function recording(spy: Spy, label: string, original: (...args: unknown[]) => unknown) {
  return function wrapped(this: unknown, ...args: unknown[]): unknown {
    hit(spy, label);
    if (new.target !== undefined) return construct(original, args, new.target);
    return apply(original, this, args);
  };
}

interface Saved {
  readonly owner: object;
  readonly key: PropertyKey;
  readonly saved: PropertyDescriptor | undefined;
}

function install(spy: Spy, saved: Saved[]): void {
  for (const target of targetsOf()) {
    saved.push({ owner: target.owner, key: target.key, saved: target.saved });
    const descriptor = bareDescriptor();
    descriptor.configurable = true;
    descriptor.enumerable = target.saved.enumerable ?? false;
    if (target.owner === globalThis) {
      // A global binding: a getter that records the read and returns the original value.
      const value: unknown = target.saved.value;
      const label = `read ${target.label}`;
      descriptor.get = () => {
        hit(spy, label);
        return value;
      };
    } else if (typeof target.saved.get === "function") {
      // The accessors are called through apply with their receiver, never unbound.
      // oxlint-disable-next-line typescript/unbound-method
      const { get: getter, set: setter } = target.saved;
      descriptor.get = recording(spy, `get ${target.label}`, getter);
      if (setter !== undefined) descriptor.set = setter;
    } else {
      const original = target.saved.value as (...args: unknown[]) => unknown;
      descriptor.value = recording(spy, target.label, original);
      descriptor.writable = target.saved.writable ?? true;
    }
    define(target.owner, target.key, descriptor);
  }
  // Writes that walk to a prototype at an index: an inherited setter could catch them.
  for (const [label, owner] of [
    ["Array.prototype", Array.prototype],
    ["Object.prototype", Object.prototype],
  ] as const) {
    for (let index = 0; index < 10; index += 1) {
      const key = toText(index);
      if (hasOwn(owner, key)) continue;
      const accessor = bareDescriptor();
      accessor.configurable = true;
      accessor.enumerable = false;
      accessor.get = () => undefined;
      accessor.set = function set(this: object, value: unknown) {
        hit(spy, `write ${label}[${key}]`);
        const data = bareDescriptor();
        data.value = value;
        data.writable = true;
        data.enumerable = true;
        data.configurable = true;
        define(this, key, data);
      };
      saved.push({ owner, key, saved: undefined });
      define(owner, key, accessor);
    }
  }
}

function uninstall(saved: Saved[]): void {
  for (let index = saved.length - 1; index >= 0; index -= 1) {
    const entry = saved[index] as Saved;
    deleteKey(entry.owner, entry.key);
    if (entry.saved !== undefined) define(entry.owner, entry.key, entry.saved);
  }
}

/** Installs the spies, runs the body with the spy, removes them, and returns the calls. */
function recordCalls(body: (spy: Spy) => void): Record<string, number> {
  const spy: Spy = { active: "", calls: Object.create(null) as Record<string, number> };
  const saved: Saved[] = [];
  try {
    install(spy, saved);
    body(spy);
  } finally {
    spy.active = "";
    uninstall(saved);
  }
  return spy.calls;
}

/** The same for a body that awaits. The spies stay in place until its promise settles. */
async function recordCallsAsync(body: (spy: Spy) => Promise<unknown>) {
  const spy: Spy = {
    active: "",
    calls: Object.create(null) as Record<string, number>,
    sourceOnly: true,
  };
  const saved: Saved[] = [];
  try {
    install(spy, saved);
    await body(spy);
  } finally {
    spy.active = "";
    uninstall(saved);
  }
  return spy.calls;
}

const corpus = callTimeCorpus(24);
const targetCount = targetsOf().length;

describe("no built-in runs at call time", () => {
  it("the spy records a built-in call, a global read and an index write (control)", () => {
    const calls = recordCalls((spy) => {
      spy.active = "decide";
      const list = [2, 1];
      list.toSorted((left, right) => left - right);
      void globalThis.Set;
      const empty: unknown[] = [];
      empty[0] = 1;
      spy.active = "";
    });
    expect(calls).toEqual({
      "decide Array.prototype.toSorted": 1,
      "decide read globalThis.Set": 1,
      "decide write Array.prototype[0]": 1,
    });
  });

  it("records no call in the synchronous calls", () => {
    expect(targetCount).toBeGreaterThan(300);
    expect(globalNames.length).toBeGreaterThan(10);
    const calls = recordCalls((spy) => {
      runCallTimeCorpus(
        corpus,
        (name) => {
          spy.active = name;
        },
        () => {
          spy.active = "";
        },
      );
    });
    expect(calls).toEqual({});
  });

  it("records no call in evaluateApprovals, also around verifier calls", async () => {
    let paused: CallName | "" = "";
    let spyRef: Spy | undefined;
    const hooks = {
      pause: () => {
        if (spyRef === undefined) return;
        paused = spyRef.active;
        spyRef.active = "";
      },
      resume: () => {
        if (spyRef !== undefined) spyRef.active = paused;
      },
    };
    const cases = approvalCases(hooks);
    let results: unknown[] = [];
    const calls = await recordCallsAsync(async (spy) => {
      spyRef = spy;
      results = await runApprovalCallTimeCorpus(
        cases,
        (name) => {
          spy.active = name;
        },
        () => {
          spy.active = "";
        },
      );
    });
    expect(calls).toEqual({});
    // Control: the cases reach every decision reason and every rejection reason.
    const reasons = new Set<string>();
    const rejections = new Set<string>();
    for (const result of results) {
      const decision = result as {
        reason?: unknown;
        code?: unknown;
        rejected?: { reason: string }[];
      };
      reasons.add(String(decision.reason ?? decision.code));
      for (const rejection of decision.rejected ?? []) rejections.add(rejection.reason);
    }
    expect([...reasons].toSorted()).toEqual([...expectedReasons].toSorted());
    expect([...rejections].toSorted()).toEqual([...approvalRejectionCodesList].toSorted());
  });
});
