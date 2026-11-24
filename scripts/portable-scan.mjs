// A tripwire for plain uses of Node built-ins in code meant for a runtime without them (Cloudflare
// workerd without nodejs_compat). It is not a proof. Strings are not parsed, so a template
// literal or a regex with a quote cannot hide a plain use. The scan reads the raw text and three
// more views of it: with comments removed, with JS escape sequences decoded, and with both. A
// match in any view counts. Comment removal is naive and may cut inside a string, which is why the
// raw view stays. It works on whole file text, so a match may span lines. Every match must be on
// the allowlist in portable-allowlist.json, with its exact line, as often as listed. A new match
// fails, and so does a listed one that is gone.
// A text scan cannot see names that code computes at run time, for example
// Reflect.get(globalThis, "pro" + "cess") or getBuiltinModule("no" + "de:os"). The vm smoke step
// (scripts/smoke-vm.mjs) runs the built package without Node globals, but it covers only the
// code paths it calls. Review computed names in src by hand.
// Used by test/portability.test.ts on src and by scripts/smoke-vm.mjs on dist.
import { readdirSync, readFileSync } from "node:fs";
import { builtinModules } from "node:module";
import { join, relative } from "node:path";
import { fileURLToPath } from "node:url";

const builtins = new Set(builtinModules);
const byCodeUnit = (left, right) => (left < right ? -1 : left > right ? 1 : 0);

/**
 * Plain uses of Node globals and module syntax, as raw text. `\u` catches escapes in identifiers
 * (`\u0070rocess` is `process`). `Function(` and `eval` mark code built from strings, and
 * `import(` marks every dynamic import, also one split over lines; each needs a review. `node:`
 * catches a Node specifier written as one literal.
 */
const rawPattern =
  /(?<![\w$])(?:process|Buffer|require|global|__dirname|__filename|eval)(?![\w$])|node:|\\u|(?<![\w$])Function\s*\(|(?<![\w$.])import\s*(?:\/\*[\s\S]*?\*\/\s*)*\(/g;

/** Static import and export specifiers, so that a bare `fs` or `crypto` is caught too. */
const specifierPattern = /\b(?:from|import)\s*["']([^"']+)["']/g;

/** Removes `//` and block comments. A comment becomes one space; a line comment keeps its newline. */
function stripComments(source) {
  return source.replaceAll(/\/\*[\s\S]*?\*\/|\/\/[^\n]*/g, " ");
}

/**
 * Decodes `\xHH`, `\uHHHH` and `\u{...}`. A backslash before any other character is dropped, as
 * in a string literal; a backslash before a line break removes both.
 */
function decodeEscapes(source) {
  return source.replaceAll(
    /\\(?:x([0-9a-fA-F]{2})|u\{([0-9a-fA-F]+)\}|u([0-9a-fA-F]{4})|(\r\n|[\s\S]))/g,
    (whole, hex, braces, unicode, other) => {
      const code = hex ?? braces ?? unicode;
      if (code === undefined) return /^[\n\r\u2028\u2029]/.test(other) ? "" : other;
      const point = Number.parseInt(code, 16);
      return point > 0x10ffff ? whole : String.fromCodePoint(point);
    },
  );
}

/** The trimmed text of the line where `index` lies. */
function lineAt(source, index) {
  const start = source.lastIndexOf("\n", index - 1) + 1;
  const end = source.indexOf("\n", index);
  return source.slice(start, end === -1 ? source.length : end).trim();
}

/** Each match as "<match> | <trimmed line where it starts>", over the whole file text. */
function findingsIn(source) {
  const findings = [];
  for (const match of source.matchAll(rawPattern)) {
    findings.push(`${match[0].replaceAll(/\s+/g, " ")} | ${lineAt(source, match.index)}`);
  }
  for (const match of source.matchAll(specifierPattern)) {
    const specifier = match[1];
    if (!specifier.startsWith("node:") && builtins.has(specifier.split("/")[0])) {
      findings.push(`${specifier} | ${lineAt(source, match.index)}`);
    }
  }
  return findings;
}

/** The match part of a finding. */
const keyOf = (finding) => finding.slice(0, finding.indexOf(" | "));

/**
 * Findings in the raw text, plus those that only show up in a view with comments removed or
 * escapes decoded. A finding that the raw view already has is not listed twice.
 */
export function portabilityFindings(source) {
  const findings = findingsIn(source);
  const seen = new Map();
  for (const finding of findings) seen.set(keyOf(finding), (seen.get(keyOf(finding)) ?? 0) + 1);
  const views = [
    stripComments(source),
    decodeEscapes(source),
    decodeEscapes(stripComments(source)),
  ];
  for (const view of views) {
    const counts = new Map();
    for (const finding of findingsIn(view)) {
      const key = keyOf(finding);
      const count = (counts.get(key) ?? 0) + 1;
      counts.set(key, count);
      if (count > (seen.get(key) ?? 0)) {
        findings.push(finding);
        seen.set(key, count);
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
