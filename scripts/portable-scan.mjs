// Finds what could stop a file from loading in a runtime without Node built-ins (Cloudflare
// workerd without nodejs_compat). The scan is raw: comments and strings are not stripped, so no
// syntax (a template literal, a regex with a quote, an import with a comment) can hide a match.
// Every match must be on the allowlist in portable-allowlist.json, with its exact line, as often
// as listed. A new match fails, and so does a listed one that is gone.
// Used by test/portability.test.ts on src and by scripts/smoke-vm.mjs on dist.
import { readdirSync, readFileSync } from "node:fs";
import { builtinModules } from "node:module";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const builtins = new Set(builtinModules);
const byCodeUnit = (left, right) => (left < right ? -1 : left > right ? 1 : 0);

/**
 * Node globals and module syntax as raw text. `\u` catches escapes in identifiers
 * (`\u0070rocess` is `process`), `Function(` and `eval` catch code built from strings, `import(` catches every
 * dynamic import, `node:` catches every Node specifier, also one built by concatenation.
 */
const rawPattern =
  /(?<![\w$])(?:process|Buffer|require|global|__dirname|__filename|eval)(?![\w$])|node:|\\u|(?<![\w$])Function\s*\(|(?<![\w$.])import\s*(?:\/\*[\s\S]*?\*\/\s*)*\(/g;

/** Static import and export specifiers, so that a bare `fs` or `crypto` is caught too. */
const specifierPattern = /\b(?:from|import)\s*["']([^"']+)["']/g;

/** Each match as "<match> | <trimmed line>". */
export function portabilityFindings(source) {
  const findings = [];
  const lines = source.split("\n");
  for (const line of lines) {
    const trimmed = line.trim();
    for (const match of line.matchAll(rawPattern)) findings.push(`${match[0]} | ${trimmed}`);
    for (const match of line.matchAll(specifierPattern)) {
      const specifier = match[1];
      if (!specifier.startsWith("node:") && builtins.has(specifier.split("/")[0])) {
        findings.push(`${specifier} | ${trimmed}`);
      }
    }
  }
  return findings;
}

/** All files under `directory` with the extension, as paths relative to `root`. */
export function filesUnder(root, directory, extension) {
  const base = new URL(directory, root);
  return readdirSync(base, { recursive: true, withFileTypes: true })
    .filter((entry) => entry.isFile() && entry.name.endsWith(extension))
    .map((entry) => relative(fileURLToPath(root), join(entry.parentPath, entry.name)))
    .toSorted(byCodeUnit);
}

/**
 * Compares the findings in each file with the allowlist. Returns one line per difference:
 * "unexpected <file>: <finding>" or "missing <file>: <finding>". Empty if all match.
 */
export function compareWithAllowlist(root, files, allowlist) {
  const differences = [];
  const listedFiles = new Set(Object.keys(allowlist));
  for (const file of files) {
    listedFiles.delete(file);
    const found = portabilityFindings(readFileSync(new URL(file, root), "utf8")).toSorted(
      byCodeUnit,
    );
    const allowed = [...(allowlist[file] ?? [])].toSorted(byCodeUnit);
    for (const finding of found) {
      const at = allowed.indexOf(finding);
      if (at === -1) differences.push(`unexpected ${file}: ${finding}`);
      else allowed.splice(at, 1);
    }
    for (const finding of allowed) differences.push(`missing ${file}: ${finding}`);
  }
  for (const file of listedFiles) differences.push(`missing file ${file}`);
  return differences;
}

export const allowlist = JSON.parse(
  readFileSync(new URL("portable-allowlist.json", import.meta.url), "utf8"),
);
