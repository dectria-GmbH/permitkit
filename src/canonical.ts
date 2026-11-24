import { PermitkitError } from "./errors.js";
import { hasInternalSlots, isProxy } from "./plain.js";
import { sha256Hex } from "./sha256.js";

/**
 * Serializes a JSON value with sorted object keys and no insignificant whitespace.
 * The same value always gives the same string, so a digest over it is stable across
 * processes and releases. Values that JSON cannot represent exactly are rejected with
 * `not_canonical`: non-plain objects (class instances, a Map or Date, proxies on Node), symbol or
 * non-enumerable keys, getters and setters, array holes and named array properties. Nothing is
 * dropped silently, except a key set to `undefined`, which counts as absent as in JSON.
 * No caller code runs: only data properties are read. In a runtime without node:util a proxy
 * cannot be detected: it is read like a plain object, and its traps run.
 */
export function canonicalJson(value: unknown): string {
  try {
    return serialize(value, new Set());
  } catch (error) {
    if (error instanceof PermitkitError) throw error;
    // For example a stack overflow on very deep input. Never a raw error.
    throw new PermitkitError("not_canonical", "The value could not be read as plain JSON data.");
  }
}

/**
 * Orders strings by UTF-16 code units. Unlike localeCompare, the result does not depend on the
 * runtime's locale data, so sorted output is the same on every machine.
 */
export function compareText(left: string, right: string): number {
  if (left < right) return -1;
  return left > right ? 1 : 0;
}

/** Lowercase hex SHA-256 over the canonical JSON form of a value. */
export function digest(value: unknown): string {
  return sha256Hex(canonicalJson(value));
}

function notCanonical(message: string): never {
  throw new PermitkitError("not_canonical", message);
}

function serialize(value: unknown, seen: Set<object>): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "string":
      return JSON.stringify(value);
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) return notCanonical("Non-finite numbers have no JSON form.");
      return JSON.stringify(value);
    case "object":
      return serializeObject(value, seen);
    case "bigint":
    case "function":
    case "symbol":
    case "undefined":
      return notCanonical(`Values of type ${typeof value} have no JSON form.`);
  }
  return notCanonical("Unknown value type.");
}

/** The value of an own data property. Accessors and missing properties are refused. */
function dataProperty(object: object, key: string): unknown {
  const descriptor = Reflect.getOwnPropertyDescriptor(object, key);
  if (descriptor === undefined || !Object.hasOwn(descriptor, "value")) {
    return notCanonical("Getters, setters and array holes have no JSON form.");
  }
  const item: unknown = descriptor.value;
  return item;
}

function serializeObject(object: object, seen: Set<object>): string {
  // A proxy can report any shape and run code on every read. Only Node can detect one; see
  // plain.ts for the other runtimes.
  if (isProxy(object)) return notCanonical("Proxies have no canonical JSON form.");
  if (seen.has(object)) return notCanonical("Cyclic values have no JSON form.");
  seen.add(object);
  try {
    const prototype: unknown = Object.getPrototypeOf(object);
    if (Array.isArray(object)) {
      if (prototype !== Array.prototype) {
        return notCanonical("Only plain arrays have a canonical JSON form.");
      }
      const length: unknown = dataProperty(object, "length");
      // A plain array only: holes or named properties would be lost or printed as non-JSON.
      if (typeof length !== "number" || Reflect.ownKeys(object).length !== length + 1) {
        return notCanonical("Arrays with holes or extra keys have no JSON form.");
      }
      const items: string[] = [];
      for (let index = 0; index < length; index += 1) {
        items.push(serialize(dataProperty(object, String(index)), seen));
      }
      return `[${items.join(",")}]`;
    }
    if (prototype !== Object.prototype && prototype !== null) {
      return notCanonical("Only plain objects have a canonical JSON form.");
    }
    if (hasInternalSlots(object)) {
      return notCanonical("Built-in objects such as a Map or Date have no canonical JSON form.");
    }
    const keys = Object.keys(object);
    // Symbol and non-enumerable keys would be dropped from the output.
    if (Reflect.ownKeys(object).length !== keys.length) {
      return notCanonical("Symbol and non-enumerable keys have no JSON form.");
    }
    // Keys plus index access, no [key, value] destructuring (see detach in bounds.ts).
    const members: string[] = [];
    for (const key of keys.toSorted(compareText)) {
      const item = dataProperty(object, key);
      if (item !== undefined) members.push(`${JSON.stringify(key)}:${serialize(item, seen)}`);
    }
    return `{${members.join(",")}}`;
  } finally {
    seen.delete(object);
  }
}
