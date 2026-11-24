import { isProxy, slotsAfterKeys, slotsBeforeKeys } from "./plain.js";

/**
 * Size guard that runs before schema validation. Zod 3 parses every item of an array even when
 * the array is longer than its `max()`, and keeps one issue per failing item, so a huge input
 * can exhaust memory before validation fails. The guard stops early, reads every property
 * exactly once, and returns a plain copy. Validation then runs on that copy, so getters and
 * proxies on the caller's object cannot return one value to the guard and another later.
 */

export interface InputBounds {
  readonly maxDepth: number;
  readonly maxNodes: number;
  readonly maxArrayLength: number;
  readonly maxStringLength: number;
}

/** Bounds for requests and approval inputs. */
export const requestBounds: InputBounds = Object.freeze({
  maxDepth: 24,
  maxNodes: 20_000,
  maxArrayLength: 1_000,
  maxStringLength: 4_096,
});

/**
 * Bounds for audit records, which wrap a request. The request inside is checked again with
 * requestBounds, so a request at the limit can still be replayed.
 */
export const wrapperBounds: InputBounds = Object.freeze({
  maxDepth: 24,
  maxNodes: 300_000,
  maxArrayLength: 1_000,
  maxStringLength: 4_096,
});

/** The most approvals that one evaluateApprovals call reads. Twice the largest `approvers`. */
export const maxApprovals = 20;

/**
 * Bounds for approval inputs: the request (which must also meet requestBounds), up to
 * maxApprovals approvals and the prior-request history.
 */
export const approvalInputBounds: InputBounds = Object.freeze({
  maxDepth: 24,
  maxNodes: 100_000,
  maxArrayLength: 1_000,
  maxStringLength: 4_096,
});

/** Bounds for policy documents, which are larger but come from the operator. */
export const policyBounds: InputBounds = Object.freeze({
  maxDepth: 24,
  maxNodes: 500_000,
  maxArrayLength: 10_000,
  maxStringLength: 4_096,
});

/** Marks input that exceeds the bounds, cannot be read, or is not plain data. */
const unusable = Symbol("unusable");

/**
 * Deep copy of validated data into objects without a prototype. permitkit reads optional
 * fields with plain property access; on a null-prototype object an absent field is undefined,
 * so a polluted Object.prototype cannot supply a value.
 */
export function detach<T>(value: T): T {
  if (typeof value !== "object" || value === null) return value;
  // The copy has the same structure as the input, so the type parameter still holds.
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion
  if (Array.isArray(value)) return value.map((item: unknown) => detach(item)) as T;
  const result: Record<string, unknown> = Object.create(null);
  // Keys plus index access, no [key, value] destructuring: closing a destructured iterator reads
  // `return` through the prototype chain, which a polluted Object.prototype supplies.
  for (const key of Object.keys(value)) {
    const item: unknown = Reflect.get(value, key);
    Object.defineProperty(result, key, {
      value: detach(item),
      enumerable: true,
      writable: true,
      configurable: true,
    });
  }
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion
  return result as T;
}

/**
 * A plain copy of the value, or `undefined` if the value exceeds the bounds, cannot be read, or
 * holds anything but plain objects, arrays and primitives. Arrays and objects
 * become plain arrays and objects with own enumerable string keys. Other values stay as they are,
 * so the schema still rejects functions, symbols and similar values.
 */
export function boundedSnapshot(value: unknown, bounds: InputBounds): unknown {
  const result = snapshotOf(value, bounds);
  return result.ok ? result.value : undefined;
}

export type SnapshotResult =
  | { readonly ok: true; readonly value: unknown }
  | { readonly ok: false; readonly reason: "too_large" | "not_plain" };

/** Like boundedSnapshot, but says whether the input was too large or not plain data. */
export function snapshotOf(value: unknown, bounds: InputBounds): SnapshotResult {
  const state = { nodes: 0, tooLarge: false };
  try {
    const copy = clone(value, 0, bounds, state);
    if (copy !== unusable) return { ok: true, value: copy };
    return { ok: false, reason: state.tooLarge ? "too_large" : "not_plain" };
  } catch {
    // A throwing getter or a revoked proxy: treat the input as unusable.
    return { ok: false, reason: "not_plain" };
  }
}

/**
 * The length of an own data property that holds a plain array, read without running caller
 * code and without copying. Undefined for anything else; the full snapshot then decides.
 */
export function ownArrayLength(value: unknown, key: string): number | undefined {
  if (typeof value !== "object" || value === null || isProxy(value)) return undefined;
  const item = dataValue(value, key);
  if (!Array.isArray(item) || isProxy(item)) return undefined;
  const length: unknown = dataValue(item, "length");
  return typeof length === "number" ? length : undefined;
}

/** An own data property, read without running caller code. Undefined for anything else. */
export function ownDataValue(value: unknown, key: string): unknown {
  if (typeof value !== "object" || value === null || isProxy(value)) return undefined;
  const item = dataValue(value, key);
  return item === unusable ? undefined : item;
}

function clone(
  value: unknown,
  depth: number,
  bounds: InputBounds,
  state: { nodes: number; tooLarge: boolean },
): unknown {
  state.nodes += 1;
  if (state.nodes > bounds.maxNodes || depth > bounds.maxDepth) {
    state.tooLarge = true;
    return unusable;
  }
  if (typeof value === "string") {
    if (value.length <= bounds.maxStringLength) return value;
    state.tooLarge = true;
    return unusable;
  }
  // Functions, symbols and bigints are not JSON data. Unusable, so nothing else can reach them.
  if (typeof value === "function" || typeof value === "symbol" || typeof value === "bigint") {
    return unusable;
  }
  if (typeof value !== "object" || value === null) return value;
  // A proxy can describe itself as any plain object, for example one without keys, which as a
  // scope would read as "everywhere". Proxies are unusable; pass plain data. Only Node can
  // detect a proxy. Elsewhere it is copied like a plain object: each property is read once and
  // validation runs on the copy, so a proxy that hides its keys copies as `{}`.
  if (isProxy(value)) return unusable;
  // Only plain data is copied. A Map, a Date, a class instance or hidden keys (non-enumerable or
  // symbol) would lose data in the copy, and a lost scope reads as "everywhere". Such input is
  // unusable as a whole.
  const prototype: unknown = Object.getPrototypeOf(value);
  if (Array.isArray(value)) {
    if (prototype !== Array.prototype) return unusable;
    const length: number = value.length;
    if (length > bounds.maxArrayLength) {
      state.tooLarge = true;
      return unusable;
    }
    // Own keys of a plain array are its indices plus "length". Fewer means holes, more means
    // named or symbol properties.
    if (Reflect.ownKeys(value).length !== length + 1) return unusable;
    const items: unknown[] = [];
    for (let index = 0; index < length; index += 1) {
      // A hole or an accessor is not plain data. Data properties only, so no caller code runs.
      const property = dataValue(value, String(index));
      if (property === unusable) return unusable;
      const item = clone(property, depth + 1, bounds, state);
      if (item === unusable) return unusable;
      items.push(item);
    }
    return items;
  }
  if (prototype !== Object.prototype && prototype !== null) return unusable;
  // A Map or Date with a swapped prototype has no own keys and would copy as `{}`. The check
  // runs before any key is listed: a swapped typed array or boxed string can have millions.
  if (slotsBeforeKeys(value)) return unusable;
  const keys = Object.keys(value);
  if (keys.length > bounds.maxArrayLength) {
    state.tooLarge = true;
    return unusable;
  }
  const ownKeys = Reflect.ownKeys(value);
  // The portable path runs its throwing checks only on objects without own keys (see plain.ts).
  if (slotsAfterKeys(value, ownKeys.length > 0)) return unusable;
  if (ownKeys.length !== keys.length) return unusable;
  // A null prototype: a missing key reads as undefined even if Object.prototype was polluted.
  const result: Record<string, unknown> = Object.create(null);
  for (const key of keys) {
    if (key.length > bounds.maxStringLength) {
      state.tooLarge = true;
      return unusable;
    }
    const property = dataValue(value, key);
    if (property === unusable) return unusable;
    // A key set to undefined stays an own key with the value undefined. Dropping it would remove
    // one condition from an AND-combined record (a match scope, a range, a threshold), and the
    // rest of the record would match more widely. The schema refuses undefined in every record
    // value and every required field; only optional fields read it as absent.
    const item = property === undefined ? undefined : clone(property, depth + 1, bounds, state);
    if (item === unusable) return unusable;
    // defineProperty keeps a key named __proto__ as data instead of changing the prototype.
    Object.defineProperty(result, key, {
      value: item,
      enumerable: true,
      writable: true,
      configurable: true,
    });
  }
  // Nothing can change the object during the copy, because only data properties were read.
  // Check the prototype again anyway, as a guard against future changes to this function.
  if (Object.getPrototypeOf(value) !== prototype) return unusable;
  return result;
}

/**
 * The value of an own data property. Accessors (getters, setters) and missing properties are
 * unusable: a getter is caller code that can change the object, for example delete a later key so
 * that an inherited value is read in its place.
 */
function dataValue(value: object, key: string): unknown {
  const descriptor = Reflect.getOwnPropertyDescriptor(value, key);
  // Object.hasOwn, not `in`: a descriptor is a plain object, and `in` would also find a polluted
  // Object.prototype.value on an accessor descriptor.
  if (descriptor === undefined || !Object.hasOwn(descriptor, "value")) return unusable;
  const item: unknown = descriptor.value;
  return item;
}
