/**
 * Condition matching. This module is the only place that interprets scopes, limits and
 * thresholds, so a different rule engine can replace it without a change to the public API.
 * Every lookup uses own properties only, so names such as `constructor` cannot match
 * inherited values.
 */

import type { Scalar } from "../request.js";

export type Properties = Readonly<Record<string, Scalar>> | undefined;
type ScopeLike = Readonly<Record<string, readonly string[]>> | undefined;
type LimitsLike =
  | Readonly<
      Record<string, { readonly min?: number | undefined; readonly max?: number | undefined }>
    >
  | undefined;
type ThresholdLike = Readonly<Record<string, { readonly gte: number }>> | undefined;

export type ScopeResult =
  | { ok: true }
  | { ok: false; property: string; allowed: readonly string[]; actual: Scalar | undefined };

export type LimitResult =
  | { ok: true }
  | {
      ok: false;
      property: string;
      min: number | null;
      max: number | null;
      actual: Scalar | undefined;
    };

export function ownValue(properties: Properties, name: string): Scalar | undefined {
  if (properties === undefined || !Object.hasOwn(properties, name)) return undefined;
  return properties[name];
}

/**
 * A grant scope covers a resource if every restricted property is present on the resource as a
 * string and is one of the allowed values. A missing property does not match.
 */
export function scopeCovers(scope: ScopeLike, properties: Properties): ScopeResult {
  if (scope === undefined) return { ok: true };
  for (const name of Object.keys(scope)) {
    const allowed = scope[name] ?? [];
    const actual = ownValue(properties, name);
    if (typeof actual !== "string" || !allowed.includes(actual)) {
      return { ok: false, property: name, allowed, actual };
    }
  }
  return { ok: true };
}

/**
 * A deny scope touches a resource unless a restricted property is present and outside the
 * listed values. A missing or non-string property counts as inside, so leaving out a property
 * never escapes a deny rule.
 */
export function scopeTouches(scope: ScopeLike, properties: Properties): boolean {
  if (scope === undefined) return true;
  for (const name of Object.keys(scope)) {
    const allowed = scope[name] ?? [];
    const actual = ownValue(properties, name);
    if (typeof actual === "string" && !allowed.includes(actual)) return false;
  }
  return true;
}

/** Limits hold if every limited property is a finite number inside its inclusive range. */
export function limitsHold(limits: LimitsLike, properties: Properties): LimitResult {
  if (limits === undefined) return { ok: true };
  for (const name of Object.keys(limits)) {
    const limit = limits[name];
    if (limit === undefined) continue;
    const actual = ownValue(properties, name);
    const min = limit.min ?? null;
    const max = limit.max ?? null;
    const inside =
      typeof actual === "number" &&
      Number.isFinite(actual) &&
      (min === null || actual >= min) &&
      (max === null || actual <= max);
    if (!inside) {
      return { ok: false, property: name, min, max, actual };
    }
  }
  return { ok: true };
}

/**
 * A threshold applies if any listed property is missing, not a finite number, or at least its
 * `gte` value. Absent thresholds always apply. This errs toward more approvals.
 */
export function thresholdApplies(threshold: ThresholdLike, properties: Properties): boolean {
  if (threshold === undefined) return true;
  const names = Object.keys(threshold);
  if (names.length === 0) return true;
  return names.some((name) => {
    const condition = threshold[name];
    if (condition === undefined) return true;
    const actual = ownValue(properties, name);
    return typeof actual !== "number" || !Number.isFinite(actual) || actual >= condition.gte;
  });
}
