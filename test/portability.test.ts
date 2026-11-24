import { describe, expect, it } from "vitest";

import {
  allowlist,
  compareWithAllowlist,
  filesUnder,
  portabilityFindings,
} from "../scripts/portable-scan.mjs";

const root = new URL("../", import.meta.url);

describe("portability tripwire (a text scan, not a proof)", () => {
  // From the reviews: each of these hid a plain Node use from an earlier scanner.
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
    importSplitOverLines: "const m = await import\n(name);",
    importSplitWithComment: "const m = await import /* a */\n  /* b */ (name);",
    importSplitWithLineComment: "const m = await import // c\n(name);",
    escapedColon: 'const m = "node\\:fs";',
    escapedLetter: 'const m = "no\\de:os";',
    escapedHex: 'const m = "node\\x3autil";',
    escapedGlobalLetter: 'globalThis["proc\\ess"];',
    escapedGlobalHex: 'globalThis["pro\\x63ess"];',
    escapedGlobalBraces: 'globalThis["pro\\u{63}ess"];',
    bareAfterComment: 'import fs from /* c */ "fs";',
    bareSideEffectAfterComment: 'import /* c */ "fs";',
    bareAfterLineComment: 'import fs from // c\n"fs";',
  };

  it("flags each plain-use bypass from the reviews", () => {
    const missed = Object.entries(bypasses)
      .filter(([, source]) => portabilityFindings(source).length === 0)
      .map(([name]) => name);
    expect(missed).toEqual([]);
    // Not a match: names that only contain a Node global. Member access does match, so that
    // globalThis.process is found.
    expect(portabilityFindings("const a = processes + ArrayBuffer + requireProof;")).toEqual([]);
  });

  it("does not see names built at run time, which is why it is only a tripwire", () => {
    // Both passed the scan and the vm smoke step in review. They stay out of src by review.
    expect(portabilityFindings('Reflect.get(globalThis, "pro" + "cess");')).toEqual([]);
    expect(portabilityFindings('host.getBuiltinModule("no" + "de:os");')).toEqual([]);
  });

  it("flags in src only the listed plain uses", () => {
    const files = filesUnder(root, "src/", ".ts");
    expect(files.length).toBeGreaterThan(10);
    expect(compareWithAllowlist(root, files, allowlist.src)).toEqual([]);
  });

  it("fails on a new plain use and on a listed one that is gone", () => {
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
