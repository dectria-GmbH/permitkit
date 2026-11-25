// Bundles an entry that imports every export of the built package root except the known Zod
// users, and fails if the bundle holds Zod. A Worker that only decides must not ship it. A new
// export is gated without a change here. Each known Zod user, bundled alone, must still hold
// Zod, so the check can fail and the list cannot keep a name that no longer needs Zod.
// Rolldown comes through vitest's vite; permitkit has no direct bundler dependency.
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

// The exports that still use Zod, until the approval and audit validators replace it.
const zodUsers = ["decideAndRecord", "reevaluate", "toDecisionRecord"];
const exported = Object.keys(await import(pathToFileURL(packageRoot).href));
for (const name of zodUsers) assert.ok(exported.includes(name), `${name} is no longer exported`);
const coreNames = exported.filter((name) => !zodUsers.includes(name));
assert.ok(coreNames.includes("decide") && coreNames.includes("compilePolicy"), "no core exports");

const core = await bundle(coreNames);
assert.ok(core.modules.length > 0, "the core bundle lists no modules");
assert.deepEqual(core.modules.filter(isZodModule), [], "the core bundle includes Zod modules");
assert.ok(!zodCode.test(core.code), "the core bundle contains Zod code");

for (const name of zodUsers) {
  const alone = await bundle([name]);
  assert.ok(
    alone.modules.some(isZodModule),
    `${name} no longer pulls in Zod: remove it from zodUsers`,
  );
  assert.ok(zodCode.test(alone.code), `control: the Zod marker does not match the code of ${name}`);
}
const control = await bundle(exported);

console.log(
  `bundle ok: ${coreNames.length} exports without Zod ${core.bytes} bytes, all ${exported.length} exports ${control.bytes} bytes`,
);
