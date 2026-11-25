// Lists the files that `npm pack` would put in the tarball and fails if a target in the exports
// map is missing, if a source map points at a file outside the tarball, or if a path that
// consumers must not get is present. Run it after `pnpm build`.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = fileURLToPath(new URL("..", import.meta.url));
const packageJson = JSON.parse(readFileSync(path.join(root, "package.json"), "utf8"));
// The npm next to the running Node, because npm is not always on PATH (for example when a shell
// loads it lazily). The release workflow publishes with npm, so the check uses npm, not pnpm.
const sibling = path.join(path.dirname(process.execPath), "npm");
const npm = existsSync(sibling) ? sibling : "npm";
const [result] = JSON.parse(
  execFileSync(npm, ["pack", "--dry-run", "--json", "--ignore-scripts"], {
    cwd: root,
    encoding: "utf8",
  }),
);
const files = new Set(result.files.map((file) => file.path));

function targets(value) {
  if (typeof value === "string") return [value];
  return Object.values(value).flatMap(targets);
}
for (const target of targets(packageJson.exports)) {
  const file = path.posix.normalize(target);
  assert.ok(files.has(file), `exports target ${target} is not in the tarball`);
}

for (const file of files) {
  if (!file.endsWith(".map")) continue;
  const map = JSON.parse(readFileSync(path.join(root, file), "utf8"));
  for (const source of map.sources) {
    const resolved = path.posix.join(path.posix.dirname(file), map.sourceRoot ?? "", source);
    assert.ok(files.has(resolved), `${file} points at ${resolved}, which is not in the tarball`);
  }
}

const refused = [
  /(^|\/)\.npmrc$/,
  /(^|\/)\.env/,
  /(^|\/)\.dev\.vars$/,
  /^\.github\//,
  /^test\//,
  /^scripts\//,
  /^docs\/releasing\.md$/,
  /\.test\.[cm]?[jt]s$/,
];
for (const file of files) {
  const rule = refused.find((pattern) => pattern.test(file));
  assert.equal(rule, undefined, `${file} must not be in the tarball (rule ${rule})`);
}

console.log(`pack ok: ${files.size} files, every export target and source map resolves`);
