import { beforeAll } from "vitest";

// Test-only switch for the "portable" vitest project. src/plain.ts picks its path once, when it
// loads. This file runs before each test file is imported, so hiding process.getBuiltinModule
// here makes src load as it would in a runtime without node:util. It is restored before the
// first test, so tests can still load node:util as a reference. Nothing in src can reach this.
const descriptor = Object.getOwnPropertyDescriptor(process, "getBuiltinModule");
if (descriptor === undefined) throw new Error("process.getBuiltinModule is missing");
Reflect.deleteProperty(process, "getBuiltinModule");

beforeAll(() => {
  Object.defineProperty(process, "getBuiltinModule", descriptor);
});
