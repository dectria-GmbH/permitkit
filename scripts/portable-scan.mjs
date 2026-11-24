// Finds what would stop a file from loading in a runtime without Node built-ins (Cloudflare
// workerd without nodejs_compat): Node module specifiers, and the Node globals process, Buffer,
// require, global, __dirname and __filename used as identifiers.
// Used by test/portability.test.ts on src and by scripts/smoke-vm.mjs on dist.
import { builtinModules } from "node:module";

const builtins = new Set(builtinModules);
const nodeGlobals = /(?<![.\w$])(process|Buffer|require|global|__dirname|__filename)(?![\w$])/g;

/** Module specifiers in static imports and exports, dynamic import() and require(). */
export function moduleSpecifiers(source) {
  const patterns = [
    /\b(?:import|export)\s[^;]*?\bfrom\s*["']([^"']+)["']/g,
    /\bimport\s*["']([^"']+)["']/g,
    /\b(?:import|require)\s*\(\s*["'`]([^"'`]+)["'`]/g,
  ];
  return patterns.flatMap((pattern) => [...source.matchAll(pattern)].map((match) => match[1]));
}

export function isNodeBuiltin(specifier) {
  return specifier.startsWith("node:") || builtins.has(specifier.split("/")[0]);
}

/**
 * The source with comments and the contents of string and template literals blanked out, so
 * that a word in a comment or a string is not read as an identifier.
 */
export function codeOnly(source) {
  let result = "";
  let index = 0;
  while (index < source.length) {
    const char = source[index];
    const next = source[index + 1];
    if (char === "/" && next === "/") {
      while (index < source.length && source[index] !== "\n") index += 1;
    } else if (char === "/" && next === "*") {
      const end = source.indexOf("*/", index + 2);
      index = end === -1 ? source.length : end + 2;
      result += " ";
    } else if (char === '"' || char === "'" || char === "`") {
      index += 1;
      while (index < source.length && source[index] !== char) {
        index += source[index] === "\\" ? 2 : 1;
      }
      index += 1;
      result += `${char}${char}`;
    } else {
      result += char;
      index += 1;
    }
  }
  return result;
}

/** Each finding as "<kind>: <name>". Empty if the file can load without Node built-ins. */
export function portabilityFindings(source) {
  const specifiers = moduleSpecifiers(source)
    .filter(isNodeBuiltin)
    .map((specifier) => `import: ${specifier}`);
  const identifiers = [...codeOnly(source).matchAll(nodeGlobals)].map(
    (match) => `global: ${match[1]}`,
  );
  return [...specifiers, ...identifiers];
}
