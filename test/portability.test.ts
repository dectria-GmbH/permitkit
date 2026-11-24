import { readdirSync, readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { portabilityFindings } from "../scripts/portable-scan.mjs";

const sourceRoot = new URL("../src/", import.meta.url);

function sourceFiles(directory: URL): URL[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    if (entry.isDirectory()) return sourceFiles(new URL(`${entry.name}/`, directory));
    return entry.name.endsWith(".ts") ? [new URL(entry.name, directory)] : [];
  });
}

describe("portability", () => {
  it("finds Node specifiers and Node globals, but not words in comments or strings", () => {
    const sample = [
      'import { a } from "node:util";',
      "import type { B } from 'crypto';",
      'export * from "node:fs";',
      'import "node:process";',
      'const c = await import("node:path");',
      'const d = require("os");',
      'import { e } from "./e.js";',
      "const f = process.env;",
      "const g = Buffer.from(text);",
      "const h = typeof global;",
      "// process, Buffer and require in a comment",
      '/* process */ const i = "process Buffer require";',
      "const j = Reflect.get(globalThis, `process`);",
      "const k = object.process + globalThis.Buffer;",
    ].join("\n");
    expect(portabilityFindings(sample)).toEqual([
      "import: node:util",
      "import: crypto",
      "import: node:fs",
      "import: node:process",
      "import: node:path",
      "import: os",
      "global: require",
      "global: process",
      "global: Buffer",
      "global: global",
    ]);
  });

  it("finds nothing that needs Node anywhere under src", () => {
    const files = sourceFiles(sourceRoot);
    expect(files.length).toBeGreaterThan(10);
    const found = files.flatMap((file) =>
      portabilityFindings(readFileSync(file, "utf8")).map(
        (finding) => `${file.pathname.slice(sourceRoot.pathname.length)}: ${finding}`,
      ),
    );
    expect(found).toEqual([]);
  });
});
