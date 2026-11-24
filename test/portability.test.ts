import { describe, expect, it } from "vitest";

import {
  allowlist,
  compareWithAllowlist,
  filesUnder,
  portabilityFindings,
} from "../scripts/portable-scan.mjs";

const root = new URL("../", import.meta.url);

describe("portability", () => {
  // From the review: each of these hid a Node dependency from the first scanner.
  const bypasses: Record<string, string> = {
    templateSubstitution: "const a = `${process.env.HOME}`;",
    templateBuffer: "const b = `x${Buffer.from('a').length}`;",
    regexQuote: "const q = /'/; const v = process.env.X; const r = /'/;",
    regexQuote2: 'const q = /"/.test(s); Buffer.alloc(1); const r = /"/;',
    regexSlashSlash: "const re = /\\/\\//; process.exit();",
    regexWithBacktick: "const re = /`/; require('fs'); const t = `x`;",
    dynamicSpecifier: "const m = 'node:' + 'fs'; await import(m);",
    dotted: "globalThis.process.exit();",
    newFunction: "new Function('return process')();",
    optionalChain: "globalThis?.process?.env;",
    importMetaResolve: "import.meta.resolve('node:fs');",
    bareModule: "import { createRequire } from 'module';",
    unicodeEscape: "const a = \\u0070rocess.env;",
    importWithComment: "import /* x */ ('node:fs');",
    importAttribute: "import fs from 'node:fs' with { type: 'json' };",
    exportFromMultiline: "export {\n  a,\n} from 'node:fs';",
    bareCrypto: "import { createHash } from 'crypto';",
  };

  it("finds every known bypass", () => {
    const missed = Object.entries(bypasses)
      .filter(([, source]) => portabilityFindings(source).length === 0)
      .map(([name]) => name);
    expect(missed).toEqual([]);
    // Not a match: names that only contain a Node global. Member access does match, so that
    // globalThis.process is found.
    expect(portabilityFindings("const a = processes + ArrayBuffer + requireProof;")).toEqual([]);
  });

  it("finds in src only the listed occurrences", () => {
    const files = filesUnder(root, "src/", ".ts");
    expect(files.length).toBeGreaterThan(10);
    expect(compareWithAllowlist(root, files, allowlist.src)).toEqual([]);
  });

  it("fails on a new occurrence and on a listed one that is gone", () => {
    const files = filesUnder(root, "src/", ".ts");
    const shorter = { ...allowlist.src, "src/catalog.ts": [] };
    expect(compareWithAllowlist(root, files, shorter)).toEqual([
      "unexpected src/catalog.ts: process | /** True only for objects that defineCatalog returned in this process. */",
    ]);
    const longer = { ...allowlist.src, "src/decide.ts": ["process | nothing"] };
    expect(compareWithAllowlist(root, files, longer)).toEqual([
      "missing src/decide.ts: process | nothing",
    ]);
  });
});
