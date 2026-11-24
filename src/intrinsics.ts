/**
 * Built-in methods captured when this module loads, before caller code can replace them. The
 * registries that tell a compiled policy or a catalogue from a forged one go through these, so
 * a data-valued WeakMap.prototype.get or WeakSet.prototype.has cannot make them throw.
 * Pollution that happens before permitkit loads is not covered.
 */

// Unbound on purpose: each one is called through apply with its receiver.
/* oxlint-disable typescript/unbound-method */
const apply = Reflect.apply;
const weakMapGet = WeakMap.prototype.get;
const weakMapSet = WeakMap.prototype.set;
const weakSetHas = WeakSet.prototype.has;
const weakSetAdd = WeakSet.prototype.add;
/* oxlint-enable typescript/unbound-method */

export function mapGet<K extends WeakKey, V>(map: WeakMap<K, V>, key: K): V | undefined {
  // The captured method returns the value type of the map it is called on.
  // oxlint-disable-next-line typescript/no-unsafe-type-assertion
  return apply(weakMapGet, map, [key]) as V | undefined;
}

export function mapSet<K extends WeakKey, V>(map: WeakMap<K, V>, key: K, value: V): void {
  apply(weakMapSet, map, [key, value]);
}

export function setHas<T extends WeakKey>(set: WeakSet<T>, value: T): boolean {
  return apply(weakSetHas, set, [value]);
}

export function setAdd<T extends WeakKey>(set: WeakSet<T>, value: T): void {
  apply(weakSetAdd, set, [value]);
}
