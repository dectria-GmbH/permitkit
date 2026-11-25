/**
 * Building blocks for the hand-written validators of requests and policy documents.
 *
 * The validators run on the output of the size guard (`src/bounds.ts`): plain arrays, objects
 * without a prototype, strings, numbers, booleans, null and undefined. They follow the Zod 3
 * schemas that they replace, rule for rule:
 *
 * - An object is anything of type "object" that is not null and not an array.
 * - Fields are checked in their declared order, then unknown keys. Issues come in that order,
 *   so the first issue names the same path as before.
 * - A required field that is missing or set to undefined is refused. An optional field reads
 *   undefined as absent; a key set to undefined stays in the output with the value undefined.
 * - A refinement (a rule over a whole value) runs only if the value had no other issue.
 *
 * Only own properties are read, by index or key, never through an iterator, so a polluted
 * Object.prototype or Array.prototype cannot supply a field or an item. The rules of each
 * checker are copied into an object without a prototype when the checker is made, so an
 * absent rule such as `min` or `key` reads as undefined and never runs an inherited getter.
 * Every built-in is called through a copy captured at load (see intrinsics.ts).
 */

import {
  append,
  bareObject,
  contains,
  defineData,
  field,
  hasOwn,
  isArray,
  isFiniteNumber,
  isInteger,
  isNaNNumber,
  jsonText,
  matches,
  objectKeys,
  toText,
} from "./intrinsics.js";

/** A path into the input, built only when an issue needs it. */
export type Path = { readonly parent: Path; readonly key: string | number } | null;

export interface Issue {
  readonly path: (string | number)[];
  readonly message: string;
}

/** Marks a value that failed validation. Its issues are in the issue list. */
export const invalid: unique symbol = Symbol("invalid");
export type Checked<T> = T | typeof invalid;

/** Validates one value. Returns `invalid` exactly when it added at least one issue. */
export type Check<T> = (value: unknown, path: Path, issues: Issue[]) => Checked<T>;

export function at(path: Path, key: string | number): Path {
  return { parent: path, key };
}

export function pathOf(path: Path): (string | number)[] {
  // The chain runs from the leaf to the root. Reversed by index, without unshift.
  const leafFirst: (string | number)[] = [];
  for (let node = path; node !== null; node = node.parent) append(leafFirst, node.key);
  const keys: (string | number)[] = [];
  for (let index = leafFirst.length - 1; index >= 0; index -= 1) {
    const key = leafFirst[index];
    if (key !== undefined) append(keys, key);
  }
  return keys;
}

/** Joins items with a separator. A loop, not Array.prototype.join, which pollution can replace. */
export function joined(items: readonly (string | number)[], separator: string): string {
  let result = "";
  for (let index = 0; index < items.length; index += 1) {
    result += `${index === 0 ? "" : separator}${toText(items[index])}`;
  }
  return result;
}

/** Adds an issue and returns `invalid`. */
export function fail(issues: Issue[], path: Path, message: string): typeof invalid {
  append(issues, { path: pathOf(path), message });
  return invalid;
}

/** A plain object, an object without a prototype, or any other non-array object. */
export function isObject(value: unknown): value is object {
  return typeof value === "object" && value !== null && !isArray(value);
}

/** The own value of a key, or undefined. Never an inherited value. */
export function own(value: object, key: string): unknown {
  if (!hasOwn(value, key)) return undefined;
  return field(value, key);
}

/** A copy of the object in an object without a prototype, so absent keys read as undefined. */
export function bare<T extends object>(value: T): T {
  const result = bareObject();
  const keys = objectKeys(value);
  for (let index = 0; index < keys.length; index += 1) {
    const key = keys[index];
    if (key === undefined) continue;
    defineData(result, key, field(value, key));
  }
  // The copy has exactly the keys and values of the input.
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion
  return result as T;
}

/** Adds one issue for keys outside the list. Returns false if there were any. */
export function knownKeys(
  value: object,
  keys: readonly string[],
  path: Path,
  issues: Issue[],
): boolean {
  const present = objectKeys(value);
  const unknown: string[] = [];
  for (let index = 0; index < present.length; index += 1) {
    const key = present[index];
    if (key !== undefined && !contains(keys, key)) append(unknown, jsonText(key));
  }
  if (unknown.length === 0) return true;
  fail(issues, path, `Unknown key(s): ${joined(unknown, ", ")}.`);
  return false;
}

/** Checks a required field. A missing key and a key set to undefined are both refused. */
export function required<T>(
  value: object,
  key: string,
  path: Path,
  issues: Issue[],
  check: Check<T>,
): Checked<T> {
  return check(own(value, key), at(path, key), issues);
}

/**
 * Checks an optional field. Undefined, absent or not, counts as absent. `present` is true if the
 * key exists, so the output keeps a key set to undefined, as the input had it.
 */
export function optional<T>(
  value: object,
  key: string,
  path: Path,
  issues: Issue[],
  check: Check<T>,
): { readonly present: boolean; readonly value: Checked<T | undefined> } {
  const item = own(value, key);
  const present = hasOwn(value, key);
  if (item === undefined) return { present, value: undefined };
  return { present, value: check(item, at(path, key), issues) };
}

export interface StringRules {
  readonly min?: number;
  readonly max?: number;
  readonly pattern?: RegExp;
  readonly patternMessage?: string;
}

/** A string. Lengths count UTF-16 code units, as `String.prototype.length` does. */
export function text(options: StringRules): Check<string> {
  const rules = bare(options);
  return (value, path, issues) => {
    if (typeof value !== "string") return fail(issues, path, "Expected a string.");
    const before = issues.length;
    if (rules.min !== undefined && value.length < rules.min) {
      fail(issues, path, `Use at least ${rules.min} character(s).`);
    }
    if (rules.max !== undefined && value.length > rules.max) {
      fail(issues, path, `Use at most ${rules.max} character(s).`);
    }
    if (rules.pattern !== undefined && !matches(rules.pattern, value)) {
      fail(issues, path, rules.patternMessage ?? "The text has the wrong format.");
    }
    return issues.length === before ? value : invalid;
  };
}

export interface NumberRules {
  readonly integer?: boolean;
  readonly min?: number;
  readonly max?: number;
}

/** A finite number (NaN and infinities are refused), optionally an integer within bounds. */
export function finiteNumber(options: NumberRules): Check<number> {
  const rules = bare(options);
  return (value, path, issues) => {
    if (typeof value !== "number" || isNaNNumber(value)) {
      return fail(issues, path, "Expected a number.");
    }
    const before = issues.length;
    if (rules.integer === true && !isInteger(value)) {
      fail(issues, path, "Expected an integer.");
    }
    if (rules.min !== undefined && value < rules.min) {
      fail(issues, path, `Use a number of at least ${rules.min}.`);
    }
    if (rules.max !== undefined && value > rules.max) {
      fail(issues, path, `Use a number of at most ${rules.max}.`);
    }
    if (!isFiniteNumber(value)) fail(issues, path, "The number must be finite.");
    return issues.length === before ? value : invalid;
  };
}

export const bool: Check<boolean> = (value, path, issues) =>
  typeof value === "boolean" ? value : fail(issues, path, "Expected true or false.");

/** One of the listed strings, compared exactly. */
export function oneOf<const T extends string>(values: readonly T[]): Check<T> {
  return (value, path, issues) => {
    for (let index = 0; index < values.length; index += 1) {
      const option = values[index];
      if (option !== undefined && value === option) return option;
    }
    return fail(issues, path, `Use one of: ${joined(values, ", ")}.`);
  };
}

/** The value, or null. */
export function nullable<T>(check: Check<T>): Check<T | null> {
  return (value, path, issues) => (value === null ? null : check(value, path, issues));
}

export interface ArrayRules {
  readonly min?: number;
  readonly max?: number;
}

/**
 * An array whose items pass `item`. Length issues come first, then item issues; every item is
 * checked, as before. Items are read by index, not through the array iterator.
 */
export function list<T>(item: Check<T>, options: ArrayRules = {}): Check<T[]> {
  const rules = bare(options);
  return (value, path, issues) => {
    if (!isArray(value)) return fail(issues, path, "Expected a list.");
    const before = issues.length;
    const length: number = value.length;
    if (rules.min !== undefined && length < rules.min) {
      fail(issues, path, `List at least ${rules.min} item(s).`);
    }
    if (rules.max !== undefined && length > rules.max) {
      fail(issues, path, `List at most ${rules.max} item(s).`);
    }
    const result: T[] = [];
    for (let index = 0; index < length; index += 1) {
      const checked = item(own(value, toText(index)), at(path, index), issues);
      if (checked !== invalid) append(result, checked);
    }
    return issues.length === before ? result : invalid;
  };
}

export interface RecordRules {
  /** Rules for each key. Without them, every string key is accepted. */
  readonly key?: Check<string>;
  /** Accept a `__proto__` key, check its value, and leave it out of the output. */
  readonly dropProtoKey?: boolean;
  /** If set, an empty record is refused with this message. */
  readonly nonEmpty?: string;
}

/**
 * An object used as a map from key to value. For each key in own-key order, the key is checked,
 * then the value. The output is an object without a prototype.
 */
export function dictionary<T>(item: Check<T>, options: RecordRules = {}): Check<Record<string, T>> {
  const rules = bare(options);
  return (value, path, issues) => {
    if (!isObject(value)) return fail(issues, path, "Expected an object.");
    const before = issues.length;
    const result = bareObject<Record<string, T>>();
    const keys = objectKeys(value);
    for (let index = 0; index < keys.length; index += 1) {
      const key = keys[index];
      if (key === undefined) continue;
      const keyPath = at(path, key);
      if (rules.key !== undefined) rules.key(key, keyPath, issues);
      const checked = item(own(value, key), keyPath, issues);
      if (checked === invalid || (key === "__proto__" && rules.dropProtoKey === true)) continue;
      defineData(result, key, checked);
    }
    if (issues.length !== before) return invalid;
    if (rules.nonEmpty !== undefined && objectKeys(result).length === 0) {
      return fail(issues, path, rules.nonEmpty);
    }
    return result;
  };
}
