// A guard against the next missing intrinsic. permitkit captures the ECMAScript built-in
// prototypes at load (src/intrinsics.ts). This test lists every prototype that the runtime has,
// from a fixed list of ECMAScript constructor names (ECMA-262 and ECMA-402) plus the hidden
// intrinsics that only an expression reaches. It plants an own `then` on each one and expects
// promiseHooksIntact() to refuse. A prototype that permitkit did not capture fails here by name.
import { afterEach, describe, expect, it } from "vitest";

import { promiseHooksIntact } from "../src/intrinsics.js";

const define = Reflect.defineProperty;
const deleteKey = Reflect.deleteProperty;

// Constructors of ECMA-262 that have an own `prototype`. Promise is left out: its prototype has
// the own `then` that permitkit compares with the captured one, in a separate check. Host
// globals (URL, Buffer, DOMException, ...) are not ECMAScript and are not listed.
const ecmaScriptConstructors = [
  "Object",
  "Function",
  "Array",
  "String",
  "Boolean",
  "Number",
  "BigInt",
  "Symbol",
  "Date",
  "RegExp",
  "Error",
  "AggregateError",
  "EvalError",
  "RangeError",
  "ReferenceError",
  "SyntaxError",
  "TypeError",
  "URIError",
  "SuppressedError",
  "Map",
  "Set",
  "WeakMap",
  "WeakSet",
  "WeakRef",
  "FinalizationRegistry",
  "ArrayBuffer",
  "SharedArrayBuffer",
  "DataView",
  "Int8Array",
  "Uint8Array",
  "Uint8ClampedArray",
  "Int16Array",
  "Uint16Array",
  "Int32Array",
  "Uint32Array",
  "Float16Array",
  "Float32Array",
  "Float64Array",
  "BigInt64Array",
  "BigUint64Array",
  "Iterator",
  "DisposableStack",
  "AsyncDisposableStack",
];
// ECMA-402, as properties of Intl.
const intlConstructors = [
  "Collator",
  "DateTimeFormat",
  "DisplayNames",
  "DurationFormat",
  "ListFormat",
  "Locale",
  "NumberFormat",
  "PluralRules",
  "RelativeTimeFormat",
  "Segmenter",
];
// The Temporal proposal, as properties of Temporal. Node 24 has no Temporal, so nothing is
// listed from it there.
const temporalConstructors = [
  "Duration",
  "Instant",
  "PlainDate",
  "PlainDateTime",
  "PlainMonthDay",
  "PlainTime",
  "PlainYearMonth",
  "ZonedDateTime",
];

type Found = { readonly name: string; readonly prototype: object };

/** The own data property `prototype` of the constructor `name` on `owner`, if it is an object. */
function prototypeOf(owner: object | undefined, name: string): object | undefined {
  if (owner === undefined) return undefined;
  const constructor = Reflect.getOwnPropertyDescriptor(owner, name)?.value as unknown;
  if (typeof constructor !== "function") return undefined;
  const prototype = Reflect.getOwnPropertyDescriptor(constructor, "prototype")?.value as unknown;
  return typeof prototype === "object" && prototype !== null ? prototype : undefined;
}

/** A global object such as Intl, if the runtime has it. */
function globalObject(name: string): object | undefined {
  const value = Reflect.getOwnPropertyDescriptor(globalThis, name)?.value as unknown;
  return typeof value === "object" && value !== null ? value : undefined;
}

function* generatorShape(): Generator<number> {
  yield 0;
}
async function* asyncGeneratorShape(): AsyncGenerator<number> {
  yield 0;
}

function enumerate(): Found[] {
  const found: Found[] = [];
  const add = (name: string, prototype: unknown) => {
    if (typeof prototype === "object" && prototype !== null) found.push({ name, prototype });
    else if (typeof prototype === "function") found.push({ name, prototype });
  };
  for (const name of ecmaScriptConstructors)
    add(`${name}.prototype`, prototypeOf(globalThis, name));
  for (const name of intlConstructors)
    add(`Intl.${name}.prototype`, prototypeOf(globalObject("Intl"), name));
  for (const name of temporalConstructors) {
    add(`Temporal.${name}.prototype`, prototypeOf(globalObject("Temporal"), name));
  }

  // Hidden intrinsics, reached by an expression.
  const getPrototypeOf = Object.getPrototypeOf as (value: unknown) => object;
  const arrayIterator = getPrototypeOf([].values());
  const iteratorPrototype = getPrototypeOf(arrayIterator);
  const asyncGeneratorPrototype = getPrototypeOf(getPrototypeOf(asyncGeneratorShape()));
  add("%TypedArray%.prototype", getPrototypeOf(Uint8Array.prototype));
  add("%IteratorPrototype%", iteratorPrototype);
  add("%ArrayIteratorPrototype%", arrayIterator);
  add("%MapIteratorPrototype%", getPrototypeOf(new Map().entries()));
  add("%SetIteratorPrototype%", getPrototypeOf(new Set().values()));
  add("%StringIteratorPrototype%", getPrototypeOf(""[Symbol.iterator]()));
  add("%RegExpStringIteratorPrototype%", getPrototypeOf(/a/g[Symbol.matchAll]("")));
  add("%GeneratorFunction.prototype%", getPrototypeOf(generatorShape));
  add("%GeneratorPrototype%", getPrototypeOf(getPrototypeOf(generatorShape())));
  add("%AsyncGeneratorFunction.prototype%", getPrototypeOf(asyncGeneratorShape));
  add("%AsyncGeneratorPrototype%", asyncGeneratorPrototype);
  add(
    "%AsyncFunction.prototype%",
    getPrototypeOf(async () => {}),
  );
  add("%AsyncIteratorPrototype%", getPrototypeOf(asyncGeneratorPrototype));
  const helperMap = (iteratorPrototype as { map?: unknown }).map;
  if (typeof helperMap === "function") {
    add(
      "%IteratorHelperPrototype%",
      getPrototypeOf(Reflect.apply(helperMap, [].values(), [(item: unknown) => item])),
    );
  }
  const from = (globalThis as { Iterator?: { from?: unknown } }).Iterator?.from;
  if (typeof from === "function") {
    const source = Object.assign(Object.create(null) as object, { next: () => ({}) });
    add(
      "%WrapForValidIteratorPrototype%",
      getPrototypeOf(
        Reflect.apply(from, (globalThis as { Iterator?: unknown }).Iterator, [source]),
      ),
    );
  }
  // %AsyncFromSyncIteratorPrototype% belongs to an internal wrapper that no expression returns.
  return found;
}

const planted: object[] = [];
afterEach(() => {
  for (const prototype of planted) deleteKey(prototype, "then");
  planted.length = 0;
});

const found = enumerate();

describe("every ECMAScript prototype of the runtime is checked for a then", () => {
  it("finds the prototypes (control: the list is not empty)", () => {
    const names = found.map((entry) => entry.name);
    expect(names).toContain("Error.prototype");
    expect(names).toContain("%TypedArray%.prototype");
    expect(names).toContain("%IteratorHelperPrototype%");
    expect(names).toContain("Intl.NumberFormat.prototype");
    expect(found.length).toBeGreaterThan(50);
  });

  it("starts with no then on any of them", () => {
    expect(promiseHooksIntact()).toBe(true);
  });

  for (const { name, prototype } of found) {
    it(`${name}: an own then is refused`, () => {
      // oxlint-disable-next-line unicorn/no-thenable
      const set = define(prototype, "then", {
        value: () => {},
        writable: true,
        configurable: true,
      });
      expect(set).toBe(true);
      planted.push(prototype);
      expect(promiseHooksIntact()).toBe(false);
    });
  }
});

describe("limit: prototypes that permitkit does not capture", () => {
  // %SegmentsPrototype% and %SegmentIteratorPrototype% need `new Intl.Segmenter()` at load, which
  // costs about 10 to 20 ms. A then there is not seen. See README, "Approval proofs".
  it("%SegmentsPrototype% and %SegmentIteratorPrototype% are not checked", () => {
    const getPrototypeOf = Object.getPrototypeOf as (value: unknown) => object;
    const segments = new Intl.Segmenter().segment("a");
    const segmentIterator = segments[Symbol.iterator]();
    for (const prototype of [getPrototypeOf(segments), getPrototypeOf(segmentIterator)]) {
      // oxlint-disable-next-line unicorn/no-thenable
      define(prototype, "then", { value: () => {}, writable: true, configurable: true });
      planted.push(prototype);
      expect(promiseHooksIntact()).toBe(true);
      deleteKey(prototype, "then");
    }
  });
});
