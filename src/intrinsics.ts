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

/** A copy of the list sorted with the comparison, through the captured toSorted. */
export function sorted<T>(list: readonly T[], compare: (left: T, right: T) => number): T[] {
  const result: unknown = apply(toSortedMethod, list, [compare]);
  if (!isArray(result) || result.length !== list.length) {
    throw new TypeError("The list could not be sorted.");
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

/**
 * The promise, with an own `constructor` that is the captured Promise. `await` reads
 * `constructor` on a native promise: if it is not %Promise%, the promise is resolved through its
 * `then`, and replaced Promise.prototype.constructor and then methods could choose the value.
 */
export function awaitable<T>(promise: Promise<T>): Promise<T> {
  const descriptor = bareObject<PropertyDescriptor>();
  descriptor.value = PromiseConstructor;
  if (!defineOwn(promise, "constructor", descriptor)) {
    throw new TypeError("The promise could not be marked.");
  }
  return promise;
}
