// Bundles an entry that imports only defineCatalog, compilePolicy and decide from the built
// package root, and fails if the bundle holds Zod. A Worker that only decides must not ship it.
// As a control, a second entry that also imports evaluateApprovals must hold Zod, so the check
// can fail. Rolldown comes through vitest's vite; permitkit has no direct bundler dependency.
import assert from "node:assert/strict";
import { createRequire } from "node:module";
import { fileURLToPath, pathToFileURL } from "node:url";

const root = createRequire(import.meta.url);
const vite = createRequire(root.resolve("vitest/package.json")).resolve("vite/package.json");
const { rolldown } = await import(pathToFileURL(createRequire(vite).resolve("rolldown")).href);

const packageRoot = fileURLToPath(new URL("../dist/index.js", import.meta.url));
const zodCode = /\b(ZodError|ZodType|ZodObject|ZodString)\b/;

async function bundle(names) {
  const entry = `export { ${names.join(", ")} } from ${JSON.stringify(packageRoot)};\n`;
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

const isZodModule = (id) => /[\\/]zod[\\/]|zod-schemas/.test(id);

const core = await bundle(["defineCatalog", "compilePolicy", "decide"]);
assert.ok(core.modules.length > 0, "the core bundle lists no modules");
assert.deepEqual(core.modules.filter(isZodModule), [], "the core bundle includes Zod modules");
assert.ok(!zodCode.test(core.code), "the core bundle contains Zod code");

const control = await bundle(["defineCatalog", "compilePolicy", "decide", "evaluateApprovals"]);
assert.ok(control.modules.some(isZodModule), "control: evaluateApprovals no longer pulls in Zod");
assert.ok(zodCode.test(control.code), "control: the Zod marker does not match Zod code");

console.log(
  `bundle ok: decide without Zod ${core.bytes} bytes, with evaluateApprovals ${control.bytes} bytes`,
);
