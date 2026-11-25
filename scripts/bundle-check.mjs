// Bundles an entry that imports every export of the built package root and fails if the bundle
// holds any module outside dist: permitkit has no runtime dependency, and a Worker must not ship
// one by accident. It also fails if package.json lists a runtime dependency, or if the bundle
// holds Zod code. A control bundle that imports a dependency shows that the module check can
// fail. Rolldown comes through vitest's vite; permitkit has no direct bundler dependency.
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = createRequire(import.meta.url);
const vite = createRequire(root.resolve("vitest/package.json")).resolve("vite/package.json");
const { rolldown } = await import(pathToFileURL(createRequire(vite).resolve("rolldown")).href);

const packageRoot = fileURLToPath(new URL("../dist/index.js", import.meta.url));
const distDirectory = fileURLToPath(new URL("../dist/", import.meta.url));
const zodCode = /\b(ZodError|ZodType|ZodObject|ZodString)\b/;

async function bundle(entry) {
  const build = await rolldown({
    input: "entry",
    platform: "node",
    external: [/^node:/],
    logLevel: "silent",
    plugins: [
      {
        name: "entry",
        resolveId: (id) => (id === "entry" ? id : null),
        load: (id) => (id === "entry" ? entry : null),
      },
    ],
  });
  const { output } = await build.generate({ format: "esm", minify: true });
  await build.close();
  const chunks = output.filter((item) => item.type === "chunk");
  const code = chunks.map((chunk) => chunk.code).join("\n");
  const modules = chunks.flatMap((chunk) => chunk.moduleIds);
  return { code, modules, bytes: Buffer.byteLength(code) };
}

const outsideDist = (modules) =>
  modules.filter((id) => id !== "entry" && !id.startsWith(distDirectory));

const manifest = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
assert.deepEqual(manifest.dependencies ?? {}, {}, "package.json lists runtime dependencies");

const exported = Object.keys(await import(pathToFileURL(packageRoot).href));
assert.ok(exported.includes("decide") && exported.includes("evaluateApprovals"), "no exports");
const all = await bundle(
  `export { ${exported.join(", ")} } from ${JSON.stringify(packageRoot)};\n`,
);
assert.ok(all.modules.length > 10, "the bundle lists too few modules");
assert.deepEqual(outsideDist(all.modules), [], "the bundle includes modules outside dist");
assert.ok(!zodCode.test(all.code), "the bundle contains Zod code");

// Controls: the module check sees a dependency, and the Zod marker matches Zod code.
const dependency = JSON.stringify(root.resolve("fast-check"));
const control = await bundle(`export { assert } from ${dependency};\n`);
assert.ok(outsideDist(control.modules).length > 0, "control: a dependency is not found");
assert.ok(zodCode.test("class ZodObject {}"), "control: the Zod marker matches nothing");

console.log(
  `bundle ok: all ${exported.length} exports ${all.bytes} bytes, ${all.modules.length} modules`,
);
