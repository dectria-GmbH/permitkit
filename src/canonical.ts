import { createHash } from "node:crypto";

import { PermitkitError } from "./errors.js";

/**
 * Serializes a JSON value with sorted object keys and no insignificant whitespace.
 * The same value always gives the same string, so a digest over it is stable across
 * processes and releases. Values that JSON cannot represent exactly are rejected.
 */
export function canonicalJson(value: unknown): string {
  return serialize(value, new Set());
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
  return createHash("sha256").update(canonicalJson(value), "utf8").digest("hex");
}

function serialize(value: unknown, seen: Set<object>): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "string":
      return JSON.stringify(value);
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!Number.isFinite(value)) {
        throw new PermitkitError("not_canonical", "Non-finite numbers have no JSON form.");
      }
      return JSON.stringify(value);
    case "object":
      return serializeObject(value, seen);
    case "bigint":
    case "function":
    case "symbol":
    case "undefined":
      throw new PermitkitError(
        "not_canonical",
        `Values of type ${typeof value} have no JSON form.`,
      );
  }
  throw new PermitkitError("not_canonical", "Unknown value type.");
}

function serializeObject(object: object, seen: Set<object>): string {
  if (seen.has(object)) {
    throw new PermitkitError("not_canonical", "Cyclic values have no JSON form.");
  }
  seen.add(object);
  try {
    if (Array.isArray(object)) {
      return `[${object.map((item: unknown) => serialize(item, seen)).join(",")}]`;
    }
    const prototype: unknown = Object.getPrototypeOf(object);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new PermitkitError("not_canonical", "Only plain objects have a canonical JSON form.");
    }
    // Keys plus index access, no [key, value] destructuring (see detach in bounds.ts).
    const members: string[] = [];
    for (const key of Object.keys(object).toSorted(compareText)) {
      const item: unknown = Reflect.get(object, key);
      if (item !== undefined) members.push(`${JSON.stringify(key)}:${serialize(item, seen)}`);
    }
    return `{${members.join(",")}}`;
  } finally {
    seen.delete(object);
  }
}
