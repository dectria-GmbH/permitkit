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
 *   ArrayBuffer.isView and Error.isError (where it exists) on every object, then brand checks
 *   through built-in getters and methods that throw for a wrong receiver and run no caller code.
 *   The throwing checks run only on objects without own keys or with an own `length`, because a
 *   throw costs microseconds and every plain object would throw in each check. A Map, Set, Date or other
 *   built-in of a throwing kind with a swapped prototype and own keys added by hand therefore
 *   copies as those own keys. JSON input cannot produce such an object. A proxy cannot be
 *   detected in JavaScript; it is read like a plain object.
 *
 * Every built-in function is captured at module load, so later pollution or replacement of a
 * prototype method cannot change a check.
 */

type Check = (value: object) => boolean;

/**
 * True for a built-in object that keeps its data in internal slots. `hasOwnKeys` says whether
 * `Reflect.ownKeys(value)` is not empty; the caller computes it once and passes it on.
 */
type SlotCheck = (value: object, hasOwnKeys: boolean) => boolean;

export interface PlainDataChecks {
  readonly runtime: "node" | "portable";
  /** True for a proxy. Always false on the portable path, where a proxy cannot be detected. */
  readonly isProxy: Check;
  /**
   * The part of the slot check that runs before the caller reads the object's keys, in O(1).
   * A typed array or a boxed string can have millions of own keys, so it must be refused before
   * they are listed. The Node path runs all of util.types here.
   */
  readonly slotsBeforeKeys: Check;
  /**
   * The part that runs after the caller has listed the own keys. The Node path answers false:
   * it decided before. The portable path runs its throwing checks only if `hasOwnKeys` is false.
   */
  readonly slotsAfterKeys: SlotCheck;
  /** Both parts together, for callers that do not list keys themselves. */
  readonly hasInternalSlots: SlotCheck;
}

const apply = Reflect.apply;
const getOwnPropertyDescriptor = Reflect.getOwnPropertyDescriptor;
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
      slotsBeforeKeys: slots,
      slotsAfterKeys: () => false,
      hasInternalSlots: (value: object, _hasOwnKeys: boolean) => slots(value),
    });
  } catch {
    return undefined;
  }
}

/** A brand check: the built-in function and the arguments to call it with. */
type BrandCheck = readonly [fn: unknown, args: readonly unknown[]];

function getterOf(constructor: unknown, key: string): BrandCheck | undefined {
  if (typeof constructor !== "function") return undefined;
  const prototype: unknown = Reflect.get(constructor, "prototype");
  if (typeof prototype !== "object" || prototype === null) return undefined;
  const descriptor = getOwnPropertyDescriptor(prototype, key);
  return typeof descriptor?.get === "function" ? [descriptor.get, []] : undefined;
}

function methodOf(constructor: unknown, key: string, args: readonly unknown[] = []) {
  if (typeof constructor !== "function") return undefined;
  const prototype: unknown = Reflect.get(constructor, "prototype");
  if (typeof prototype !== "object" || prototype === null) return undefined;
  const descriptor = getOwnPropertyDescriptor(prototype, key);
  const method: unknown = descriptor?.value;
  return typeof method === "function" ? ([method, args] as const) : undefined;
}

/**
 * Each of these throws a TypeError for a receiver without the slot and runs no caller code: the
 * slot check comes first, before any property read. Promise `then` and iterator `next` would
 * also identify their kinds, but they have side effects, so those kinds are not checked.
 */
const brandChecks: readonly BrandCheck[] = [
  getterOf(Map, "size"),
  getterOf(Set, "size"),
  methodOf(WeakMap, "has", [undefined]),
  methodOf(WeakSet, "has", [undefined]),
  methodOf(Date, "getTime"),
  getterOf(RegExp, "source"),
  getterOf(ArrayBuffer, "byteLength"),
  getterOf(Reflect.get(globalThis, "SharedArrayBuffer"), "byteLength"),
  methodOf(Number, "valueOf"),
  methodOf(String, "valueOf"),
  methodOf(Boolean, "valueOf"),
  methodOf(Symbol, "valueOf"),
  methodOf(BigInt, "valueOf"),
].filter((check) => check !== undefined);

// RegExp.prototype.source returns "(?:)" for RegExp.prototype itself, which has no slots.
const regExpPrototype: unknown = RegExp.prototype;
// Both answer without throwing and run no caller code. Error.isError is ES2026.
const isView: unknown = getOwnPropertyDescriptor(ArrayBuffer, "isView")?.value;
const isError: unknown = getOwnPropertyDescriptor(Error, "isError")?.value;
const brandCount = brandChecks.length;

/**
 * Before the keys are listed: the two checks that never throw, on every object. An own `length`
 * marks the keyed built-ins whose keys are indices (a boxed string, an `arguments` object); for
 * those the throwing checks run too, so that a boxed string with millions of characters is
 * refused before its keys are listed. A plain object with a `length` key only pays the checks.
 */
function portableBeforeKeys(value: object): boolean {
  if (typeof isView === "function" && apply(isView, undefined, [value]) === true) return true;
  if (typeof isError === "function" && apply(isError, undefined, [value]) === true) return true;
  let length: PropertyDescriptor | undefined;
  try {
    length = getOwnPropertyDescriptor(value, "length");
  } catch {
    // A revoked proxy. The caller fails on its next read of the value and refuses it.
    return false;
  }
  return length !== undefined && throwingBrandChecks(value);
}

/**
 * After the keys are listed. Decided 2026-11-24: the throwing checks run only on objects without
 * own keys. See the file comment.
 */
function portableAfterKeys(value: object, hasOwnKeys: boolean): boolean {
  return !hasOwnKeys && throwingBrandChecks(value);
}

function throwingBrandChecks(value: object): boolean {
  for (let index = 0; index < brandCount; index += 1) {
    const check = brandChecks[index];
    if (check === undefined || typeof check[0] !== "function") continue;
    try {
      apply(check[0], value, check[1]);
      if (value !== regExpPrototype) return true;
    } catch {
      // A wrong receiver: the value does not have this slot.
    }
  }
  return false;
}

/** The checks for runtimes without `node:util`. Proxies cannot be detected. */
export const portableChecks: PlainDataChecks = freeze({
  runtime: "portable",
  isProxy: () => false,
  slotsBeforeKeys: portableBeforeKeys,
  slotsAfterKeys: portableAfterKeys,
  hasInternalSlots: (value: object, hasOwnKeys: boolean) =>
    portableBeforeKeys(value) || portableAfterKeys(value, hasOwnKeys),
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
 * The first part of the check for built-in objects that keep their data in internal slots.
 * Call it before listing the object's keys. On Node this is all of `util.types`.
 */
export function slotsBeforeKeys(value: object): boolean {
  return active.slotsBeforeKeys(value);
}

/**
 * The second part, after the caller listed the own keys. Pass whether `Reflect.ownKeys(value)`
 * is not empty. Always false on Node. On the portable path it runs the throwing brand checks
 * only for an object without own keys.
 */
export function slotsAfterKeys(value: object, hasOwnKeys: boolean): boolean {
  return active.slotsAfterKeys(value, hasOwnKeys);
}

/** Both parts. Pass whether `Reflect.ownKeys(value)` is not empty. */
export function hasInternalSlots(value: object, hasOwnKeys: boolean): boolean {
  return active.hasInternalSlots(value, hasOwnKeys);
}
