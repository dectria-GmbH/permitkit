/**
 * Size guard that runs before schema validation. Zod 3 parses every item of an array even when
 * the array is longer than its `max()`, and keeps one issue per failing item, so a huge input
 * can exhaust memory before validation fails. The guard stops early, reads every property
 * exactly once, and returns a plain copy. Validation then runs on that copy, so getters and
 * proxies on the caller's object cannot return one value to the guard and another later.
 */

export interface InputBounds {
  readonly maxDepth: number;
  readonly maxNodes: number;
  readonly maxArrayLength: number;
  readonly maxStringLength: number;
}

/** Bounds for requests and approval inputs. */
export const requestBounds: InputBounds = Object.freeze({
  maxDepth: 24,
  maxNodes: 20_000,
  maxArrayLength: 1_000,
  maxStringLength: 4_096,
});

/** Bounds for policy documents, which are larger but come from the operator. */
export const policyBounds: InputBounds = Object.freeze({
  maxDepth: 24,
  maxNodes: 500_000,
  maxArrayLength: 10_000,
  maxStringLength: 4_096,
});

const tooLarge = Symbol("tooLarge");

/**
 * A plain copy of the value, or `undefined` if the value exceeds the bounds or cannot be read. Arrays and objects
 * become plain arrays and objects with own enumerable string keys. Other values stay as they are,
 * so the schema still rejects functions, symbols and similar values.
 */
export function boundedSnapshot(value: unknown, bounds: InputBounds): unknown {
  const state = { nodes: 0 };
  try {
    const copy = clone(value, 0, bounds, state);
    return copy === tooLarge ? undefined : copy;
  } catch {
    // A throwing getter or a revoked proxy: treat the input as unusable.
    return undefined;
  }
}

function clone(
  value: unknown,
  depth: number,
  bounds: InputBounds,
  state: { nodes: number },
): unknown {
  state.nodes += 1;
  if (state.nodes > bounds.maxNodes || depth > bounds.maxDepth) return tooLarge;
  if (typeof value === "string") return value.length > bounds.maxStringLength ? tooLarge : value;
  if (typeof value !== "object" || value === null) return value;
  if (Array.isArray(value)) {
    const length: number = value.length;
    if (length > bounds.maxArrayLength) return tooLarge;
    const items: unknown[] = [];
    for (let index = 0; index < length; index += 1) {
      const item = clone((value as unknown[])[index], depth + 1, bounds, state);
      if (item === tooLarge) return tooLarge;
      items.push(item);
    }
    return items;
  }
  const keys = Object.keys(value);
  if (keys.length > bounds.maxArrayLength) return tooLarge;
  const result: Record<string, unknown> = {};
  for (const key of keys) {
    if (key.length > bounds.maxStringLength) return tooLarge;
    const property: unknown = Reflect.get(value, key);
    const item = clone(property, depth + 1, bounds, state);
    if (item === tooLarge) return tooLarge;
    // defineProperty keeps a key named __proto__ as data instead of changing the prototype.
    Object.defineProperty(result, key, {
      value: item,
      enumerable: true,
      writable: true,
      configurable: true,
    });
  }
  return result;
}
