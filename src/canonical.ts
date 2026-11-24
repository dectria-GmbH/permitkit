import { PermitkitError } from "./errors.js";
import { hasInternalSlots, isProxy } from "./plain.js";
import { sha256Hex } from "./sha256.js";

// Every built-in that a call reads is captured when the module loads. Caller code that replaces
// one later (a patched Array.prototype.toSorted that drops keys, a replaced JSON.stringify) would
// otherwise change the canonical form, and with it every digest that an approval binds to. The
// per-call code uses no array methods, iterators or for-of: strings are built by concatenation.
const apply = Reflect.apply;
const stringify = JSON.stringify;
const objectKeys = Object.keys;
const ownKeysOf = Reflect.ownKeys;
const ownDescriptor = Reflect.getOwnPropertyDescriptor;
const prototypeOf = Object.getPrototypeOf;
const hasOwn = Object.hasOwn;
const isArray = Array.isArray;
const isFiniteNumber = Number.isFinite;
const objectPrototype: unknown = Object.prototype;
const arrayPrototype: unknown = Array.prototype;
// Called with apply on a fresh array, never unbound.
// oxlint-disable-next-line typescript/unbound-method
const toSorted = Array.prototype.toSorted;
const SetConstructor = Set;
// oxlint-disable-next-line typescript/unbound-method
const setHas = Set.prototype.has;
// oxlint-disable-next-line typescript/unbound-method
const setAdd = Set.prototype.add;
// oxlint-disable-next-line typescript/unbound-method
const setDelete = Set.prototype.delete;

/**
 * Serializes a JSON value with sorted object keys and no insignificant whitespace.
 * The same value always gives the same string, so a digest over it is stable across
 * processes and releases. Values that JSON cannot represent exactly are rejected with
 * `not_canonical`: non-plain objects (class instances, a Map or Date, proxies on Node), symbol or
 * non-enumerable keys, getters and setters, array holes and named array properties. Nothing is
 * dropped silently, except a key set to `undefined`, which counts as absent as in JSON.
 * No caller code runs: only data properties are read. In a runtime without node:util a proxy
 * cannot be detected: it is read like a plain object, and its traps run. There, a built-in such as
 * a Map or Date with a swapped prototype serializes as its own keys (see plain.ts).
 */
export function canonicalJson(value: unknown): string {
  try {
    return serialize(value, new SetConstructor<object>());
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

/** JSON text of a string or a finite number, through the captured JSON.stringify. */
function jsonOf(value: string | number): string {
  const text: unknown = apply(stringify, undefined, [value]);
  if (typeof text !== "string") return notCanonical("The value has no JSON form.");
  return text;
}

function serialize(value: unknown, seen: Set<object>): string {
  if (value === null) return "null";
  switch (typeof value) {
    case "string":
      return jsonOf(value);
    case "boolean":
      return value ? "true" : "false";
    case "number":
      if (!isFiniteNumber(value)) return notCanonical("Non-finite numbers have no JSON form.");
      return jsonOf(value);
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
  const descriptor = ownDescriptor(object, key);
  if (descriptor === undefined || !hasOwn(descriptor, "value")) {
    return notCanonical("Getters, setters and array holes have no JSON form.");
  }
  const item: unknown = descriptor.value;
  return item;
}

function serializeObject(object: object, seen: Set<object>): string {
  // A proxy can report any shape and run code on every read. Only Node can detect one; see
  // plain.ts for the other runtimes.
  if (isProxy(object)) return notCanonical("Proxies have no canonical JSON form.");
  if (apply(setHas, seen, [object])) {
    return notCanonical("Cyclic values have no JSON form.");
  }
  apply(setAdd, seen, [object]);
  try {
    const prototype: unknown = prototypeOf(object);
    if (isArray(object)) {
      if (prototype !== arrayPrototype) {
        return notCanonical("Only plain arrays have a canonical JSON form.");
      }
      const length: unknown = dataProperty(object, "length");
      // A plain array only: holes or named properties would be lost or printed as non-JSON.
      if (typeof length !== "number" || ownKeysOf(object).length !== length + 1) {
        return notCanonical("Arrays with holes or extra keys have no JSON form.");
      }
      let items = "";
      for (let index = 0; index < length; index += 1) {
        const item = serialize(dataProperty(object, `${index}`), seen);
        items = index === 0 ? item : `${items},${item}`;
      }
      return `[${items}]`;
    }
    if (prototype !== objectPrototype && prototype !== null) {
      return notCanonical("Only plain objects have a canonical JSON form.");
    }
    // Before any key is listed: a swapped typed array or boxed string can have millions. The
    // portable path identifies fewer kinds (see plain.ts).
    if (hasInternalSlots(object)) {
      return notCanonical("Built-in objects such as a Map or Date have no canonical JSON form.");
    }
    const keys = objectKeys(object);
    const ownKeys = ownKeysOf(object);
    // Symbol and non-enumerable keys would be dropped from the output.
    if (ownKeys.length !== keys.length) {
      return notCanonical("Symbol and non-enumerable keys have no JSON form.");
    }
    // Keys plus index access, no [key, value] destructuring (see detach in bounds.ts).
    const sorted: unknown = apply(toSorted, keys, [compareText]);
    if (!isArray(sorted) || sorted.length !== keys.length) {
      return notCanonical("The keys could not be sorted.");
    }
    let members = "";
    for (let index = 0; index < sorted.length; index += 1) {
      const key: unknown = sorted[index];
      if (typeof key !== "string") return notCanonical("The keys could not be sorted.");
      const item = dataProperty(object, key);
      if (item === undefined) continue;
      const member = `${jsonOf(key)}:${serialize(item, seen)}`;
      members = members === "" ? member : `${members},${member}`;
    }
    return `{${members}}`;
  } finally {
    apply(setDelete, seen, [object]);
  }
}
