import { readdirSync, readFileSync } from "node:fs";
import { builtinModules } from "node:module";

import { describe, expect, it } from "vitest";

const sourceRoot = new URL("../src/", import.meta.url);

function sourceFiles(directory: URL): URL[] {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    if (entry.isDirectory()) return sourceFiles(new URL(`${entry.name}/`, directory));
    return entry.name.endsWith(".ts") ? [new URL(entry.name, directory)] : [];
  });
}

/** Module specifiers in static imports and exports, dynamic import() and require(). */
function moduleSpecifiers(source: string): string[] {
  const patterns = [
    /\b(?:import|export)\s[^;]*?\bfrom\s*["']([^"']+)["']/g,
    /\bimport\s*["']([^"']+)["']/g,
    /\b(?:import|require)\s*\(\s*["'`]([^"'`]+)["'`]/g,
  ];
  return patterns.flatMap((pattern) =>
    [...source.matchAll(pattern)].map((match) => match[1] ?? ""),
  );
}

const builtins = new Set(builtinModules);

function isNodeBuiltin(specifier: string): boolean {
  return specifier.startsWith("node:") || builtins.has(specifier.split("/")[0] ?? "");
}

describe("portability", () => {
  it("finds the specifiers it looks for", () => {
    const sample = [
      'import { a } from "node:util";',
      "import type { B } from 'crypto';",
      'export * from "node:fs";',
      'import "node:process";',
      'const c = await import("node:path");',
      'const d = require("os");',
      'import { e } from "./e.js";',
    ].join("\n");
    expect(moduleSpecifiers(sample).filter(isNodeBuiltin)).toEqual([
      "node:util",
      "crypto",
      "node:fs",
      "node:process",
      "node:path",
      "os",
    ]);
  });

  it("imports no Node built-in module anywhere under src", () => {
    const files = sourceFiles(sourceRoot);
    expect(files.length).toBeGreaterThan(10);
    const found = files.flatMap((file) =>
      moduleSpecifiers(readFileSync(file, "utf8"))
        .filter(isNodeBuiltin)
        .map((specifier) => `${file.pathname.slice(sourceRoot.pathname.length)}: ${specifier}`),
    );
    expect(found).toEqual([]);
  });
});
