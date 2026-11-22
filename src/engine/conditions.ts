/**
 * Condition matching. This module is the only place that interprets scopes, limits and
 * thresholds. It is permitkit's own small engine; no third-party rule engine is used.
 * Every lookup uses own properties only, so names such as `constructor` cannot match
 * inherited values. Every function fails toward less access for a value whose `kind` it does
 * not know, so a schema gap cannot turn into a wide match.
 */

import type { Scalar } from "../request.js";

export type Properties = Readonly<Record<string, Scalar>> | undefined;

type ScopeLike =
  | { readonly kind: "all" }
  | { readonly kind: "match"; readonly properties: Readonly<Record<string, readonly string[]>> };
type LimitsLike =
  | { readonly kind: "unlimited" }
  | {
      readonly kind: "range";
      readonly properties: Readonly<
        Record<string, { readonly min: number | null; readonly max: number | null }>
      >;
    };
type WhenLike =
  | { readonly kind: "always" }
  | {
      readonly kind: "threshold";
      readonly properties: Readonly<Record<string, { readonly gte: number }>>;
    };

export type ScopeResult =
  | { ok: true }
  | { ok: false; property: string | null; allowed: readonly string[]; actual: Scalar | undefined };

export type LimitResult =
  | { ok: true }
  | {
      ok: false;
      property: string | null;
      min: number | null;
      max: number | null;
      actual: Scalar | undefined;
    };

export function ownValue(properties: Properties, name: string): Scalar | undefined {
  if (properties === undefined || !Object.hasOwn(properties, name)) return undefined;
  return properties[name];
}

const unknownScope: ScopeResult = { ok: false, property: null, allowed: [], actual: undefined };

/**
 * A scope covers a resource if it is `all`, or if it is `match` and every listed property is
 * present on the resource as a string and is one of the allowed values. A missing property
 * does not match. Any other value covers nothing.
 */
export function scopeCovers(scope: ScopeLike, properties: Properties): ScopeResult {
  const kind = ownKind(scope);
  if (kind === "all") return { ok: true };
  if (kind !== "match" || scope.kind !== "match") return unknownScope;
  const listed = scope.properties;
  const names = Object.keys(listed);
  if (names.length === 0) return unknownScope;
  for (const name of names) {
    const allowed = listed[name] ?? [];
    const actual = ownValue(properties, name);
    if (typeof actual !== "string" || !allowed.includes(actual)) {
      return { ok: false, property: name, allowed, actual };
    }
  }
  return { ok: true };
}

/**
 * A deny scope touches a resource if it is `all`, or if it is `match` and no listed property
 * is present as a string outside its listed values. A missing or non-string property counts as
 * inside, so leaving out a property never escapes a deny rule. Any other value touches every
 * resource, so a broken deny scope denies more, never less.
 */
export function scopeTouches(scope: ScopeLike, properties: Properties): boolean {
  if (ownKind(scope) !== "match" || scope.kind !== "match") return true;
  const listed = scope.properties;
  for (const name of Object.keys(listed)) {
    const allowed = listed[name] ?? [];
    const actual = ownValue(properties, name);
    if (typeof actual === "string" && !allowed.includes(actual)) return false;
  }
  return true;
}

const unknownLimits: LimitResult = {
  ok: false,
  property: null,
  min: null,
  max: null,
  actual: undefined,
};

/**
 * Limits hold if they are `unlimited`, or if they are `range` and every listed property is a
 * finite number inside its inclusive range. A missing property exceeds the limit. Any other
 * value holds for nothing.
 */
export function limitsHold(limits: LimitsLike, properties: Properties): LimitResult {
  const kind = ownKind(limits);
  if (kind === "unlimited") return { ok: true };
  if (kind !== "range" || limits.kind !== "range") return unknownLimits;
  const listed = limits.properties;
  const names = Object.keys(listed);
  if (names.length === 0) return unknownLimits;
  for (const name of names) {
    const limit = listed[name];
    if (limit === undefined) return unknownLimits;
    const actual = ownValue(properties, name);
    const min: unknown = limit.min;
    const max: unknown = limit.max;
    // Each bound is a number or null, and one of them is a number. Anything else holds for
    // nothing, so a lost bound never reads as open.
    const minOk = min === null || typeof min === "number";
    const maxOk = max === null || typeof max === "number";
    if (!minOk || !maxOk || (min === null && max === null)) return unknownLimits;
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
 * A `when` condition applies if it is `always`, or if it is `threshold` and any listed
 * property is missing, not a finite number, or at least its `gte` value. Any other value
 * applies. This errs toward more approvals.
 */
export function whenApplies(when: WhenLike, properties: Properties): boolean {
  if (ownKind(when) !== "threshold" || when.kind !== "threshold") return true;
  const listed = when.properties;
  const names = Object.keys(listed);
  if (names.length === 0) return true;
  return names.some((name) => {
    const condition = listed[name];
    if (condition === undefined) return true;
    const actual = ownValue(properties, name);
    return typeof actual !== "number" || !Number.isFinite(actual) || actual >= condition.gte;
  });
}

/** The own `kind` of a value, or undefined. Never an inherited one. */
export function ownKind(value: { readonly kind: string }): unknown {
  if (typeof value !== "object" || value === null || !Object.hasOwn(value, "kind")) {
    return undefined;
  }
  const kind: unknown = Reflect.get(value, "kind");
  return kind;
}
