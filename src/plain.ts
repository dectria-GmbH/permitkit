import { types } from "node:util";

/**
 * True for built-in objects that keep their data in internal slots: a Map, Set, Date, buffer,
 * typed array, boxed primitive and similar. Such an object has no own keys, so with its
 * prototype swapped to Object.prototype it would pass a prototype check and copy as `{}`.
 */
export function hasInternalSlots(value: object): boolean {
  return (
    types.isMap(value) ||
    types.isSet(value) ||
    types.isWeakMap(value) ||
    types.isWeakSet(value) ||
    types.isDate(value) ||
    types.isRegExp(value) ||
    types.isPromise(value) ||
    types.isAnyArrayBuffer(value) ||
    types.isArrayBufferView(value) ||
    types.isBoxedPrimitive(value) ||
    types.isNativeError(value) ||
    types.isGeneratorObject(value) ||
    types.isMapIterator(value) ||
    types.isSetIterator(value) ||
    types.isModuleNamespaceObject(value) ||
    types.isArgumentsObject(value) ||
    types.isExternal(value)
  );
}
