/**
 * Built-in functions captured when this module loads, before caller code can replace them.
 * Every call on the decision path (decide, explain, evaluate, requestDigest, compilePolicy, the
 * size guard and the validators) goes through these, so a later change to a prototype method,
 * a static, a getter, a constructor on `globalThis` or an iterator method changes no decision
 * and no digest. The path uses no iterators: no for-of, spread or destructuring of arrays, Sets
 * or Maps, and no Array.from. Arrays grow through `append`, which defines the item, so a setter
 * on Array.prototype cannot swallow it. Pollution or replacement that happens before permitkit
 * loads is not covered.
 */

export const apply = Reflect.apply;
export const hasOwn = Object.hasOwn;
export const objectKeys = Object.keys;
export const ownKeys = Reflect.ownKeys;
export const getOwnPropertyDescriptor = Reflect.getOwnPropertyDescriptor;
export const getPrototypeOf = Object.getPrototypeOf;
export const defineProperty = Object.defineProperty;
const defineOwn = Reflect.defineProperty;
export const freeze = Object.freeze;
export const isFrozen = Object.isFrozen;
export const isArray = Array.isArray;
export const isFiniteNumber = Number.isFinite;
export const isInteger = Number.isInteger;
export const isNaNNumber = Number.isNaN;
export const toNumber = Number;
export const toText = String;
export const parseDate = Date.parse;
export const jsonText = JSON.stringify;
export const objectPrototype: object = Object.prototype;
export const arrayPrototype: object = Array.prototype;
const functionPrototype: object = Function.prototype;
const promisePrototype: object = Promise.prototype;
const create = Object.create;
const DateConstructor = Date;
const SetConstructor = Set;
const MapConstructor = Map;
const PromiseConstructor = Promise;
// Unbound on purpose: each one is called through apply with its receiver.
/* oxlint-disable typescript/unbound-method */
const weakMapGetMethod = WeakMap.prototype.get;
const weakMapSetMethod = WeakMap.prototype.set;
const weakSetHasMethod = WeakSet.prototype.has;
const weakSetAddMethod = WeakSet.prototype.add;
const setHasMethod = Set.prototype.has;
const setAddMethod = Set.prototype.add;
const mapGetMethod = Map.prototype.get;
const mapSetMethod = Map.prototype.set;
const toSortedMethod = Array.prototype.toSorted;
const regExpExecMethod = RegExp.prototype.exec;
const sliceMethod = String.prototype.slice;
const indexOfMethod = String.prototype.indexOf;
const toISOStringMethod = Date.prototype.toISOString;
const promiseThenMethod = Promise.prototype.then;
// The key is captured, so a replaced Symbol cannot point the check at another key.
const speciesKey = Symbol.species;
const speciesDescriptor = getOwnPropertyDescriptor(Promise, speciesKey);
const setUTCFullYearMethod = Date.prototype.setUTCFullYear;
const getUTCDateMethod = Date.prototype.getUTCDate;
/* oxlint-enable typescript/unbound-method */

/** An object without a prototype, so an absent key reads as undefined under pollution. */
// The type parameter names the shape that the caller fills in.
// oxlint-disable-next-line typescript/no-unnecessary-type-parameters
export function bareObject<T extends object = Record<string, unknown>>(): T {
  // A fresh object without keys; the caller fills it to the declared shape.
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion
  return create(null) as T;
}

/**
 * The value of a key, by plain property access: no Reflect.get, which caller code can replace.
 * Runs a getter, so call it after a check that the key is an own data property, or on copies
 * that hold data properties only.
 */
export function field(value: object, key: string): unknown {
  // Any object can be read by key; the value is unknown.
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion
  return (value as Record<string, unknown>)[key];
}

/**
 * The descriptor that the slow paths of defineData and append pass to defineProperty, reused for
 * every call. defineProperty reads `get` and `set` through the prototype chain of a descriptor, so
 * an object literal would pick up a polluted Object.prototype.get. This one inherits from a
 * frozen object without keys or prototype, so nothing can add an inherited field. defineProperty
 * reads it before it runs any other code, and the targets are permitkit's own arrays and
 * objects, never a proxy, so one shared descriptor is safe.
 */
const shared: PropertyDescriptor = create(freeze(create(null)));
shared.writable = true;
shared.enumerable = true;
shared.configurable = true;

function defineSlow(target: object, key: PropertyKey, value: unknown): void {
  shared.value = value;
  try {
    defineProperty(target, key, shared);
  } finally {
    // The shared descriptor must not keep the value alive.
    shared.value = undefined;
  }
}

/**
 * Sets an own, enumerable, writable data property on a new object of permitkit's. On an object
 * without a prototype an assignment cannot reach a setter, and a key named __proto__ stays data,
 * so it assigns (defineProperty costs about ten times as much). Any other target goes through
 * defineProperty.
 */
export function defineData(target: object, key: PropertyKey, value: unknown): void {
  if (getPrototypeOf(target) === null) {
    // The target has no prototype, so this creates or overwrites an own data property.
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion
    (target as Record<PropertyKey, unknown>)[key] = value;
  } else {
    defineSlow(target, key, value);
  }
}

/**
 * Adds an item at the end of an array that permitkit created. Unlike push, no prototype method
 * runs. An assignment to a new index walks Array.prototype and Object.prototype, where a setter
 * or a read-only value could catch it, so the assignment runs only if neither has that index
 * and the chain is the normal one. Otherwise the item is defined, which no setter sees.
 */
export function append<T>(list: T[], item: T): void {
  const index = list.length;
  if (
    getPrototypeOf(arrayPrototype) === objectPrototype &&
    !hasOwn(arrayPrototype, index) &&
    !hasOwn(objectPrototype, index)
  ) {
    list[index] = item;
  } else {
    defineSlow(list, index, item);
  }
}

/** True if the list holds the item (===). Reads by index, not through includes. */
export function contains<T>(list: readonly T[], item: T): boolean {
  for (let index = 0; index < list.length; index += 1) {
    if (list[index] === item) return true;
  }
  return false;
}

/**
 * A copy of the list sorted with the comparison, through the captured toSorted. V8 writes the
 * item of a one-item list with an ordinary assignment, which an accessor or a read-only value
 * on Array.prototype[0] catches, so a list of fewer than two items is copied with append. Every
 * item of the result must be an own property: a hole would read through Array.prototype.
 */
export function sorted<T>(list: readonly T[], compare: (left: T, right: T) => number): T[] {
  if (list.length < 2) {
    const copy: T[] = [];
    for (let index = 0; index < list.length; index += 1) {
      // The index is below the length, so the item is an item of the list.
      // oxlint-disable-next-line typescript/no-unsafe-type-assertion
      append(copy, list[index] as T);
    }
    return copy;
  }
  const result: unknown = apply(toSortedMethod, list, [compare]);
  if (!isArray(result) || result.length !== list.length) {
    throw new TypeError("The list could not be sorted.");
  }
  for (let index = 0; index < result.length; index += 1) {
    if (!hasOwn(result, index)) throw new TypeError("The list could not be sorted.");
  }
  // toSorted returns the same items in a new array.
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion
  return result as T[];
}

/**
 * The value of an own data property, or undefined for an accessor or a missing key. Runs no
 * getter. On a Proxy it runs the getOwnPropertyDescriptor trap, so pass only checked objects.
 */
export function ownDataValue(value: object, key: PropertyKey): unknown {
  const descriptor = getOwnPropertyDescriptor(value, key);
  // hasOwn, not `in`: `in` would also find a polluted Object.prototype.value.
  return descriptor !== undefined && hasOwn(descriptor, "value") ? descriptor.value : undefined;
}

export function weakMapGet<K extends WeakKey, V>(map: WeakMap<K, V>, key: K): V | undefined {
  // The captured method returns the value type of the map it is called on.
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion
  return apply(weakMapGetMethod, map, [key]) as V | undefined;
}

export function weakMapSet<K extends WeakKey, V>(map: WeakMap<K, V>, key: K, value: V): void {
  apply(weakMapSetMethod, map, [key, value]);
}

export function weakSetHas<T extends WeakKey>(set: WeakSet<T>, value: T): boolean {
  return apply(weakSetHasMethod, set, [value]);
}

export function weakSetAdd<T extends WeakKey>(set: WeakSet<T>, value: T): void {
  apply(weakSetAddMethod, set, [value]);
}

/** A new, empty Set from the captured constructor. Fill it with setAdd. */
export function newSet<T>(): Set<T> {
  return new SetConstructor<T>();
}

export function setHas<T>(set: Set<T>, value: T): boolean {
  return apply(setHasMethod, set, [value]);
}

export function setAdd<T>(set: Set<T>, value: T): void {
  apply(setAddMethod, set, [value]);
}

/** A new, empty Map from the captured constructor. Fill it with mapSet. */
export function newMap<K, V>(): Map<K, V> {
  return new MapConstructor<K, V>();
}

export function mapGet<K, V>(map: ReadonlyMap<K, V>, key: K): V | undefined {
  // The captured method returns the value type of the map it is called on.
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion
  return apply(mapGetMethod, map, [key]) as V | undefined;
}

export function mapSet<K, V>(map: Map<K, V>, key: K, value: V): void {
  apply(mapSetMethod, map, [key, value]);
}

/**
 * True if the pattern matches the text. RegExp.prototype.test looks up `exec` on the pattern at
 * call time, so this calls the captured exec. Pass only patterns without the g or y flag.
 */
export function matches(pattern: RegExp, text: string): boolean {
  return apply(regExpExecMethod, pattern, [text]) !== null;
}

export function sliceText(text: string, start: number, end?: number): string {
  return apply(sliceMethod, text, [start, end]);
}

export function indexOfText(text: string, search: string): number {
  return apply(indexOfMethod, text, [search]);
}

/** The ISO 8601 UTC form of a time in milliseconds. Throws for a time outside the Date range. */
export function isoOf(time: number): string {
  return apply(toISOStringMethod, new DateConstructor(time), []);
}

/** The number of days in a month (1 to 12) of a year, for every year from 0 to 9999. */
export function daysInMonth(year: number, month: number): number {
  // setUTCFullYear, because Date.UTC maps the years 0 to 99 to 1900 to 1999.
  const end = new DateConstructor(0);
  apply(setUTCFullYearMethod, end, [year, month, 0]);
  return apply(getUTCDateMethod, end, []);
}

/** The promises that awaitable marked. guardedThen reads through `await` only on these. */
const marked = new WeakSet<object>();

/** Waits for a marked promise and hands on its value or reason. Never rejects. */
async function follow(
  source: Promise<unknown>,
  fulfilled: (value: unknown) => void,
  rejected: (reason: unknown) => void,
): Promise<void> {
  let value: unknown;
  try {
    // The source has an own constructor that is the captured Promise, so `await` reads no
    // `then`, no `constructor` through the prototype chain and no Symbol.species.
    value = await source;
  } catch (reason) {
    rejected(reason);
    return;
  }
  fulfilled(value);
}

/**
 * The own `then` of a marked promise. The native then builds its result through
 * Promise[Symbol.species], a getter that caller code can replace, and the promise it returns
 * would read Promise.prototype.constructor and then when awaited. This one returns a marked
 * promise from the captured constructor, so `await` on it, `.then` on it again, Promise.all and
 * Promise.race read the same own markers. It calls the callbacks in the same job as the native
 * then. On a promise that permitkit did not mark, it is the native then.
 */
function guardedThen(
  this: Promise<unknown>,
  onFulfilled?: unknown,
  onRejected?: unknown,
): Promise<unknown> {
  if (!weakSetHas(marked, this)) {
    // Not permitkit's promise: behave as the native then.
    // oxlint-disable-next-line typescript/no-unsafe-type-assertion
    return apply(promiseThenMethod, this, [onFulfilled, onRejected]) as Promise<unknown>;
  }
  const derived = new PromiseConstructor<unknown>((resolve, reject) => {
    const settle = (handler: unknown, input: unknown, passOn: (value: unknown) => void) => {
      if (typeof handler !== "function") {
        passOn(input);
        return;
      }
      try {
        resolve(apply(handler, undefined, [input]));
      } catch (error) {
        reject(error);
      }
    };
    void follow(
      this,
      (value) => {
        settle(onFulfilled, value, resolve);
      },
      (reason) => {
        settle(onRejected, reason, reject);
      },
    );
  });
  return awaitable(derived);
}
freeze(guardedThen);

/**
 * The promise, with an own `constructor` that is the captured Promise and an own `then` that is
 * guardedThen. `await` reads `constructor` on a native promise: if it is not %Promise%, the
 * promise is resolved through its `then`, and a replaced Promise.prototype.constructor and then
 * could choose the value. A caller that returns the promise from an async function, calls .then
 * on it or passes it to Promise.all or Promise.race reads `then`, and gets guardedThen.
 */
export function awaitable<T>(promise: Promise<T>): Promise<T> {
  const marker = bareObject<PropertyDescriptor>();
  marker.value = PromiseConstructor;
  const then = bareObject<PropertyDescriptor>();
  then.value = guardedThen;
  if (!defineOwn(promise, "constructor", marker) || !defineOwn(promise, "then", then)) {
    throw new TypeError("The promise could not be marked.");
  }
  weakSetAdd(marked, promise);
  return promise;
}

/** The own data property `prototype` of a constructor on globalThis, if the runtime has one. */
function optionalPrototype(name: string): unknown {
  const constructor = ownDataValue(globalThis, name);
  return typeof constructor === "function" ? ownDataValue(constructor, "prototype") : undefined;
}

function* generatorShape(): Generator<number> {
  yield 0;
}
async function* asyncGeneratorShape(): AsyncGenerator<number> {
  yield 0;
}

/**
 * Every built-in prototype other than Object.prototype, Array.prototype, Function.prototype and
 * Promise.prototype, captured at load. A verifier result that inherits from one of them, for
 * example an Error, is resolved through a `then` there. Promise.prototype has its own `then`
 * and is checked on its own. Prototypes that a runtime may lack are read from globalThis and
 * left out if missing.
 */
function capturedPrototypes(): readonly object[] {
  const arrayIterator: unknown = getPrototypeOf([].values());
  const iteratorPrototype: unknown = getPrototypeOf(arrayIterator);
  const generatorFunction: unknown = getPrototypeOf(generatorShape);
  const asyncGeneratorFunction: unknown = getPrototypeOf(asyncGeneratorShape);
  const generatorPrototype: unknown = getPrototypeOf(getPrototypeOf(generatorShape()));
  const asyncGeneratorPrototype: unknown = getPrototypeOf(getPrototypeOf(asyncGeneratorShape()));
  const helperMap: unknown =
    typeof iteratorPrototype === "object" && iteratorPrototype !== null
      ? ownDataValue(iteratorPrototype, "map")
      : undefined;
  const candidates: unknown[] = [
    Error.prototype,
    EvalError.prototype,
    RangeError.prototype,
    ReferenceError.prototype,
    SyntaxError.prototype,
    TypeError.prototype,
    URIError.prototype,
    optionalPrototype("AggregateError"),
    optionalPrototype("SuppressedError"),
    RegExp.prototype,
    Date.prototype,
    Map.prototype,
    Set.prototype,
    WeakMap.prototype,
    WeakSet.prototype,
    optionalPrototype("WeakRef"),
    optionalPrototype("FinalizationRegistry"),
    ArrayBuffer.prototype,
    optionalPrototype("SharedArrayBuffer"),
    DataView.prototype,
    getPrototypeOf(Int8Array.prototype),
    Int8Array.prototype,
    Uint8Array.prototype,
    Uint8ClampedArray.prototype,
    Int16Array.prototype,
    Uint16Array.prototype,
    Int32Array.prototype,
    Uint32Array.prototype,
    optionalPrototype("Float16Array"),
    Float32Array.prototype,
    Float64Array.prototype,
    BigInt64Array.prototype,
    BigUint64Array.prototype,
    Boolean.prototype,
    Number.prototype,
    String.prototype,
    Symbol.prototype,
    BigInt.prototype,
    optionalPrototype("DisposableStack"),
    optionalPrototype("AsyncDisposableStack"),
    iteratorPrototype,
    arrayIterator,
    getPrototypeOf(new Map().entries()),
    getPrototypeOf(new Set().values()),
    getPrototypeOf(""[Symbol.iterator]()),
    getPrototypeOf(/a/g[Symbol.matchAll]("")),
    typeof helperMap === "function"
      ? getPrototypeOf(apply(helperMap, [].values(), [(item: unknown) => item]))
      : undefined,
    generatorFunction,
    asyncGeneratorFunction,
    getPrototypeOf(async () => {}),
    generatorPrototype,
    asyncGeneratorPrototype,
    getPrototypeOf(asyncGeneratorPrototype),
  ];
  const found: object[] = [];
  for (let index = 0; index < candidates.length; index += 1) {
    const candidate = candidates[index];
    if (
      ((typeof candidate === "object" && candidate !== null) || typeof candidate === "function") &&
      candidate !== objectPrototype &&
      candidate !== arrayPrototype &&
      candidate !== functionPrototype &&
      candidate !== promisePrototype &&
      !contains(found, candidate)
    ) {
      append(found, candidate);
    }
  }
  return freeze(found);
}
const builtinPrototypes = capturedPrototypes();

/**
 * False if a `then` on a built-in prototype could turn a value into a thenable, or if
 * Promise.prototype.then, Promise.prototype.constructor or Promise[Symbol.species] is not the
 * one found at load. The built-in prototypes are Object.prototype, Array.prototype,
 * Function.prototype and every one in builtinPrototypes, all captured at load. A verifier that
 * is an async function resolves its own promise with its result, and that resolution reads
 * `then` through the prototype chain before permitkit sees the value. The captured then reads
 * `constructor` and Symbol.species of the verifier's promise, and a getter there runs with that
 * promise as `this`. Reads descriptors only, so no getter runs. A `then` on the prototype of a
 * class of caller code is not seen: the settled value does not show which chain was read.
 */
export function promiseHooksIntact(): boolean {
  if (hasOwn(objectPrototype, "then") || hasOwn(arrayPrototype, "then")) return false;
  if (hasOwn(functionPrototype, "then")) return false;
  if (builtinThen()) return false;
  const then = getOwnPropertyDescriptor(promisePrototype, "then");
  if (then === undefined || !hasOwn(then, "value") || then.value !== promiseThenMethod) {
    return false;
  }
  const constructor = getOwnPropertyDescriptor(promisePrototype, "constructor");
  if (
    constructor === undefined ||
    !hasOwn(constructor, "value") ||
    constructor.value !== PromiseConstructor
  ) {
    return false;
  }
  const species = getOwnPropertyDescriptor(PromiseConstructor, speciesKey);
  return (
    species !== undefined &&
    speciesDescriptor !== undefined &&
    hasOwn(species, "get") &&
    hasOwn(species, "set") &&
    species.get === speciesDescriptor.get &&
    species.set === speciesDescriptor.set
  );
}

/** True if a prototype in builtinPrototypes has an own `then`. */
function builtinThen(): boolean {
  for (let index = 0; index < builtinPrototypes.length; index += 1) {
    const prototype = builtinPrototypes[index];
    if (prototype !== undefined && hasOwn(prototype, "then")) return true;
  }
  return false;
}

/** True if the value or an object on its prototype chain has a `then`. Runs no getter. */
export function hasThen(value: unknown): boolean {
  if ((typeof value !== "object" || value === null) && typeof value !== "function") return false;
  let current: object | null = value;
  for (let depth = 0; current !== null && depth < 64; depth += 1) {
    if (hasOwn(current, "then")) return true;
    const next: unknown = getPrototypeOf(current);
    current = typeof next === "object" || typeof next === "function" ? next : null;
  }
  return false;
}

/**
 * True if Promise.prototype is on the value's prototype chain, or if an object on it has a
 * `then`. Runs no getter. A chain longer than 64 counts as true.
 */
function promiseLike(value: object): { readonly promise: boolean; readonly thenable: boolean } {
  let current: object | null = value;
  let thenable = false;
  for (let depth = 0; current !== null; depth += 1) {
    if (depth >= 64 || current === promisePrototype) return { promise: true, thenable: true };
    if (hasOwn(current, "then")) thenable = true;
    const next: unknown = getPrototypeOf(current);
    current = typeof next === "object" || typeof next === "function" ? next : null;
  }
  return { promise: false, thenable };
}

/** The result of settledValue. `refused` is set if the value must not count as a result. */
export interface Settled {
  readonly value: unknown;
  readonly refused?: "promise" | "thenable";
}

/**
 * The settled value of a native promise, or the value itself for anything else, in a box
 * without a prototype. `await` on a value reads `then` through the prototype chain, and on a
 * native promise it reads `constructor`: a polluted Object.prototype.then or a replaced
 * Promise.prototype.constructor and then could choose the value. Here a native promise is read
 * through the captured then, and every other value is taken as it is.
 *
 * The captured then reads `constructor` and Symbol.species of the promise, and a getter there
 * runs with the promise as `this`: it can give the promise own fields and then make then throw.
 * So the prototype chain is read before then runs. If then throws for a value that has
 * Promise.prototype or a `then` on its chain, the value is refused, never taken as it is.
 */
export function settledValue(value: unknown): Promise<Settled> {
  const promise = new PromiseConstructor<Settled>((resolve, reject) => {
    const box = (item: unknown) => {
      const result = bareObject<{ value: unknown }>();
      result.value = item;
      resolve(result);
    };
    if ((typeof value === "object" && value !== null) || typeof value === "function") {
      const shape = promiseLike(value);
      try {
        // Throws a TypeError at once if the value is not a native promise.
        // The promise that then returns settles with the value; nothing reads it.
        void apply(promiseThenMethod, value, [box, reject]);
        return;
      } catch {
        // Not a native promise, or its constructor or species failed.
      }
      if (shape.thenable) {
        const result = bareObject<{ value: unknown; refused: "promise" | "thenable" }>();
        result.value = undefined;
        result.refused = shape.promise ? "promise" : "thenable";
        resolve(result);
        return;
      }
    }
    box(value);
  });
  return awaitable(promise);
}
