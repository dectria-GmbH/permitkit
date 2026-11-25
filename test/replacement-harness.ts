// Shared by the tests that replace built-ins after permitkit loads: the list of built-ins to
// replace, the five ways to replace them, and install and restore. Every function that the
// harness calls while a built-in is replaced was captured when this module loaded.

const define = Object.defineProperty;
const describeOwn = Object.getOwnPropertyDescriptor;
const ownKeysOf = Reflect.ownKeys;
const deleteKey = Reflect.deleteProperty;
const ErrorType = Error;

const iteratorPrototypeOf = (value: Iterable<unknown>): object =>
  Object.getPrototypeOf(value[Symbol.iterator]()) as object;
const arrayIterator = iteratorPrototypeOf([]);

const owners: [name: string, owner: object][] = [
  ["Array.prototype", Array.prototype],
  ["Array", Array],
  ["%ArrayIteratorPrototype%", arrayIterator],
  ["%IteratorPrototype%", Object.getPrototypeOf(arrayIterator) as object],
  ["Object", Object],
  ["Object.prototype", Object.prototype],
  ["Reflect", Reflect],
  ["Function.prototype", Function.prototype],
  ["Set.prototype", Set.prototype],
  ["%SetIteratorPrototype%", iteratorPrototypeOf(new Set())],
  ["Map.prototype", Map.prototype],
  ["%MapIteratorPrototype%", iteratorPrototypeOf(new Map())],
  ["WeakMap.prototype", WeakMap.prototype],
  ["WeakSet.prototype", WeakSet.prototype],
  ["String.prototype", String.prototype],
  ["String", String],
  ["%StringIteratorPrototype%", iteratorPrototypeOf("")],
  ["RegExp.prototype", RegExp.prototype],
  ["RegExp", RegExp],
  ["Date.prototype", Date.prototype],
  ["Date", Date],
  ["Number.prototype", Number.prototype],
  ["Number", Number],
  ["JSON", JSON],
  ["Math", Math],
  ["Error", Error],
  ["Error.prototype", Error.prototype],
  ["%TypedArray%.prototype", Object.getPrototypeOf(Uint8Array.prototype) as object],
  ["%TypedArray%", Object.getPrototypeOf(Uint8Array) as object],
  ["Uint8Array", Uint8Array],
  ["Int32Array", Int32Array],
  ["ArrayBuffer", ArrayBuffer],
  ["ArrayBuffer.prototype", ArrayBuffer.prototype],
  ["TextEncoder.prototype", TextEncoder.prototype],
];

/** Global bindings that a call could read at call time. */
export const globalNames: readonly string[] = [
  "Array",
  "ArrayBuffer",
  "Boolean",
  "Date",
  "Error",
  "Int32Array",
  "JSON",
  "Map",
  "Math",
  "Number",
  "Object",
  "Proxy",
  "Reflect",
  "RegExp",
  "Set",
  "String",
  "Symbol",
  "TextEncoder",
  "TypeError",
  "Uint8Array",
  "WeakMap",
  "WeakSet",
];

export interface Target {
  readonly label: string;
  readonly owner: object;
  readonly key: PropertyKey;
  readonly saved: PropertyDescriptor;
}

export function targetsOf(): Target[] {
  const found: Target[] = [];
  for (const [name, owner] of owners) {
    for (const key of ownKeysOf(owner)) {
      const saved = describeOwn(owner, key);
      if (saved === undefined || saved.configurable !== true) continue;
      const isMethod = typeof saved.value === "function";
      const isGetter = typeof saved.get === "function";
      if (!isMethod && !isGetter) continue;
      found.push({ label: `${name}.${String(key)}`, owner, key, saved });
    }
  }
  for (const name of globalNames) {
    const saved = describeOwn(globalThis, name);
    if (saved === undefined || saved.configurable !== true) continue;
    found.push({ label: `globalThis.${name}`, owner: globalThis, key: name, saved });
  }
  return found;
}

export const modes = ["true", "false", "undefined", "throws", "empty"] as const;
export type Mode = (typeof modes)[number];

function emptyIterator(): object {
  const iterator = {
    next: () => ({ done: true, value: undefined }),
    [Symbol.iterator]: () => iterator,
  };
  return iterator;
}

/** A function (constructible, so `new` on a replaced constructor also runs it). */
function replacementFor(mode: Mode, key: PropertyKey): () => unknown {
  // oxlint-disable-next-line typescript/switch-exhaustiveness-check
  switch (mode) {
    case "true":
      return function replaced() {
        return true;
      };
    case "false":
      return function replaced() {
        return false;
      };
    case "undefined":
      return function replaced() {
        return undefined;
      };
    case "throws":
      return function replaced() {
        throw new ErrorType("replaced built-in");
      };
    default:
      if (key === Symbol.iterator) return emptyIterator;
      if (key === "next") {
        return function replaced() {
          return { done: true, value: undefined };
        };
      }
      return function replaced() {
        return [];
      };
  }
}

export function install(target: Target, mode: Mode): void {
  const replacement = replacementFor(mode, target.key);
  if (typeof target.saved.get === "function") {
    define(target.owner, target.key, { get: replacement, configurable: true });
  } else {
    define(target.owner, target.key, {
      value: replacement,
      writable: true,
      enumerable: target.saved.enumerable ?? false,
      configurable: true,
    });
  }
}

export function restore(target: Target): void {
  deleteKey(target.owner, target.key);
  define(target.owner, target.key, target.saved);
}
