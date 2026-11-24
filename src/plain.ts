/**
 * Checks that tell plain data from objects that only look plain: proxies, and built-ins that
 * keep their data in internal slots (a Map, Set, Date, buffer, typed array, boxed primitive and
 * similar). Such a built-in has no own keys, so with its prototype swapped to Object.prototype it
 * would pass a prototype check and copy as `{}`.
 *
 * There are two paths, chosen once at module load:
 * - Node: `process.getBuiltinModule("node:util")` gives `util.types`, which identifies proxies
 *   and every slot kind below. This is not an `import`, so bundlers for Workers do not try to
 *   resolve it.
 * - Portable (no usable `process`, for example Cloudflare workerd without `nodejs_compat`):
 *   ArrayBuffer.isView and Error.isError (where it exists) on every object; both answer without
 *   throwing. An object other than an array with a non-enumerable own `length` (a boxed string,
 *   an arguments object, or one made by hand) is refused too. JSON input cannot produce a
 *   non-enumerable key, so plain data never meets this rule.
 *   Decided 2026-11-24: there are no brand checks that throw for a wrong receiver. A throw costs
 *   microseconds, and every plain object without own keys paid one per check: decide() with
 *   19,000 `{}` took about 1.8 s of CPU here against 13 ms on Node (measured in Node 24, see the
 *   README threat model). So a built-in whose kind only such a
 *   check identifies (a Map, Set, WeakMap, WeakSet, Date, Promise, ArrayBuffer, boxed number,
 *   boolean, symbol or bigint, and others) copies as its own keys when its prototype is
 *   swapped, and as `{}` if it has none. Node refuses all of them. A proxy cannot be detected in
 *   JavaScript; it is read like a plain object.
 *
 * Every built-in function is captured at module load, so later pollution or replacement of a
 * prototype method cannot change a check.
 */

type Check = (value: object) => boolean;

export interface PlainDataChecks {
  readonly runtime: "node" | "portable";
  /** True for a proxy. Always false on the portable path, where a proxy cannot be detected. */
  readonly isProxy: Check;
  /**
   * True for a built-in object that keeps its data in internal slots, in O(1). Callers run it
   * before they list the object's keys: a typed array or a boxed string can have millions.
   */
  readonly hasInternalSlots: Check;
}

const apply = Reflect.apply;
const getOwnPropertyDescriptor = Reflect.getOwnPropertyDescriptor;
const isArray = Array.isArray;
const freeze = Object.freeze;

/** The `util.types` checks that identify an object with internal slots, in today's order. */
const nodeSlotCheckNames = [
  "isMap",
  "isSet",
  "isWeakMap",
  "isWeakSet",
  "isDate",
  "isRegExp",
  "isPromise",
  "isAnyArrayBuffer",
  "isArrayBufferView",
  "isBoxedPrimitive",
  "isNativeError",
  "isGeneratorObject",
  "isMapIterator",
  "isSetIterator",
  "isModuleNamespaceObject",
  "isArgumentsObject",
  "isExternal",
] as const;

/** The only check that may be missing: Deno's util.types has no isExternal. */
const optionalNodeCheck = "isExternal";

/**
 * The Node checks, read from `host.getBuiltinModule("node:util")`, or undefined if the host
 * does not provide a working `util.types`. The host is untrusted: it may be absent, a polyfill,
 * or polluted, and any read may throw.
 */
export function nodeChecks(host: unknown): PlainDataChecks | undefined {
  try {
    if ((typeof host !== "object" && typeof host !== "function") || host === null) {
      return undefined;
    }
    const load: unknown = Reflect.get(host, "getBuiltinModule");
    if (typeof load !== "function") return undefined;
    const util: unknown = apply(load, host, ["node:util"]);
    if (typeof util !== "object" || util === null) return undefined;
    const types: unknown = Reflect.get(util, "types");
    if (typeof types !== "object" || types === null) return undefined;
    const proxyCheck: unknown = Reflect.get(types, "isProxy");
    if (typeof proxyCheck !== "function") return undefined;
    const slotChecks: unknown[] = [];
    for (const name of nodeSlotCheckNames) {
      const check: unknown = Reflect.get(types, name);
      // An External is a native handle that JavaScript code cannot create or receive from
      // permitkit's callers, so a util.types without isExternal (Deno) still takes this path.
      if (check === undefined && name === optionalNodeCheck) continue;
      if (typeof check !== "function") return undefined;
      slotChecks.push(check);
    }
    const call = (check: unknown, value: object): boolean =>
      typeof check === "function" && apply(check, undefined, [value]) === true;
    // A stub (a polyfill that answers false to everything) would turn every check off.
    if (!call(proxyCheck, new Proxy({}, {})) || call(proxyCheck, {})) return undefined;
    if (!call(slotChecks[0], new Map()) || call(slotChecks[0], {})) return undefined;
    const count = slotChecks.length;
    const slots = (value: object): boolean => {
      for (let index = 0; index < count; index += 1) {
        if (call(slotChecks[index], value)) return true;
      }
      return false;
    };
    return freeze({
      runtime: "node",
      isProxy: (value: object) => call(proxyCheck, value),
      hasInternalSlots: slots,
    });
  } catch {
    return undefined;
  }
}

// Both answer without throwing and run no caller code. Error.isError is ES2026.
const isView: unknown = getOwnPropertyDescriptor(ArrayBuffer, "isView")?.value;
const isError: unknown = getOwnPropertyDescriptor(Error, "isError")?.value;

/**
 * The two checks that never throw, then the `length` rule. A non-enumerable own `length` marks
 * the built-ins whose keys are indices (a boxed string, an `arguments` object), so a boxed
 * string with millions of characters is refused before its keys are listed. An array is
 * excluded: its `length` is non-enumerable too, and the callers check arrays on their own path.
 * The size guard and canonicalJson refuse every non-enumerable key anyway, so for an object that
 * is not a proxy the rule refuses nothing that they would accept; it only refuses earlier. A
 * proxy can report a non-enumerable `length` here and no own keys later. Such a proxy copied as
 * `{}` before this rule and is refused now, which only narrows.
 *
 * It does not throw. A proxy can revoke itself in its getOwnPropertyDescriptor trap, and then
 * Array.isArray throws; such a value is refused.
 */
function portableHasInternalSlots(value: object): boolean {
  if (typeof isView === "function" && apply(isView, undefined, [value]) === true) return true;
  if (typeof isError === "function" && apply(isError, undefined, [value]) === true) return true;
  let length: PropertyDescriptor | undefined;
  try {
    // On a proxy this runs its getOwnPropertyDescriptor trap once, in O(1).
    length = getOwnPropertyDescriptor(value, "length");
  } catch {
    // A revoked proxy. The caller fails on its next read of the value and refuses it.
    return false;
  }
  // A data or an accessor property. The descriptor is a new object from the engine.
  if (length === undefined || length.enumerable !== false) return false;
  try {
    return !isArray(value);
  } catch {
    // A proxy that revoked itself in the trap above. It is not plain data.
    return true;
  }
}

/** The checks for runtimes without `node:util`. Proxies cannot be detected. */
export const portableChecks: PlainDataChecks = freeze({
  runtime: "portable",
  isProxy: () => false,
  hasInternalSlots: portableHasInternalSlots,
});

function hostProcess(): unknown {
  try {
    return Reflect.get(globalThis, "process");
  } catch {
    return undefined;
  }
}

const active: PlainDataChecks = nodeChecks(hostProcess()) ?? portableChecks;

/** The path chosen at module load. Tests read it to confirm which path they cover. */
export const plainDataRuntime = active.runtime;

/** True for a proxy on Node. Always false on the portable path. */
export function isProxy(value: object): boolean {
  return active.isProxy(value);
}

/**
 * True for a built-in object that keeps its data in internal slots. Call it before listing the
 * object's keys. On Node this is all of `util.types`; see the file comment for the portable path.
 */
export function hasInternalSlots(value: object): boolean {
  return active.hasInternalSlots(value);
}
