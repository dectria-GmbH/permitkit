// Loads the built package in a fresh V8 context without process, Buffer or require, as in
// Cloudflare workerd without nodejs_compat, and runs decisions and digests there.
// Run with: node --experimental-vm-modules scripts/smoke-vm.mjs
// Fails with a non-zero exit code if dist needs Node, or if a result differs from Node.
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import vm from "node:vm";

import { allowlist, compareWithAllowlist, filesUnder } from "./portable-scan.mjs";

const root = new URL("../", import.meta.url);
const dist = new URL("dist/", root);

// 1. Every Node global or specifier in dist is a listed one (portable-allowlist.json).
const files = filesUnder(root, "dist/", ".js");
assert.ok(files.length > 10, "dist has too few files; run the build first");
assert.deepEqual(
  compareWithAllowlist(root, files, allowlist.dist),
  [],
  "dist needs Node built-ins",
);

// 2. Load dist in a context that holds no Node object. workerd provides TextEncoder; this one is
// written in plain JavaScript and evaluated inside the context, because Node's TextEncoder
// reaches Node's process through its constructor.
const encoderSource = `globalThis.TextEncoder = class TextEncoder {
  get encoding() { return "utf-8"; }
  encode(input = "") {
    const text = \`\${input}\`;
    const bytes = [];
    for (let index = 0; index < text.length; index += 1) {
      let code = text.charCodeAt(index);
      if (code >= 0xd800 && code <= 0xdbff && index + 1 < text.length) {
        const low = text.charCodeAt(index + 1);
        if (low >= 0xdc00 && low <= 0xdfff) {
          code = 0x10000 + ((code - 0xd800) << 10) + (low - 0xdc00);
          index += 1;
        } else {
          code = 0xfffd;
        }
      } else if (code >= 0xd800 && code <= 0xdfff) {
        code = 0xfffd;
      }
      if (code < 0x80) bytes.push(code);
      else if (code < 0x800) bytes.push(0xc0 | (code >> 6), 0x80 | (code & 63));
      else if (code < 0x10000) {
        bytes.push(0xe0 | (code >> 12), 0x80 | ((code >> 6) & 63), 0x80 | (code & 63));
      } else {
        bytes.push(0xf0 | (code >> 18), 0x80 | ((code >> 12) & 63));
        bytes.push(0x80 | ((code >> 6) & 63), 0x80 | (code & 63));
      }
    }
    return new Uint8Array(bytes);
  }
};`;
const context = vm.createContext({});
vm.runInContext(encoderSource, context);
for (const name of ["process", "Buffer", "require", "global"]) {
  assert.equal(vm.runInContext(`typeof ${name}`, context), "undefined", `${name} in the context`);
}
assert.equal(
  vm.runInContext("TextEncoder.constructor('return typeof process')()", context),
  "undefined",
  "the context reaches Node's process",
);
// The encoder in the context gives the same bytes as Node's, also for lone surrogates.
for (const text of ["", "abc", "Grüße", "😀 𝔘", "a\ud800b", "\udc00", "x\ud83d"]) {
  const inside = vm.runInContext(
    `Array.from(new TextEncoder().encode(${JSON.stringify(text)}))`,
    context,
  );
  assert.deepEqual(
    [...inside],
    [...new TextEncoder().encode(text)],
    `encoding of ${JSON.stringify(text)}`,
  );
}
const modules = new Map();
function resolve(specifier, parent) {
  if (specifier.startsWith(".")) return new URL(specifier, parent).href;
  throw new Error(`cannot resolve ${specifier} from ${parent}`);
}
function load(url) {
  let module = modules.get(url);
  if (module === undefined) {
    const source = readFileSync(fileURLToPath(url), "utf8");
    module = new vm.SourceTextModule(source, { identifier: url, context });
    modules.set(url, module);
  }
  return module;
}
async function namespaceOf(path) {
  const module = load(new URL(path, dist).href);
  // A module that another entry imported is linked and evaluated already.
  if (module.status === "unlinked") {
    await module.link(async (specifier, referrer) => load(resolve(specifier, referrer.identifier)));
  }
  if (module.status !== "evaluated") await module.evaluate();
  return module.namespace;
}
const core = await namespaceOf("index.js");
const testing = await namespaceOf("testing/index.js");
const plain = await namespaceOf("plain.js");
assert.equal(plain.plainDataRuntime, "portable");
assert.equal(core.plainDataRuntime, "portable", "the package root reports the portable path");

// 3. Decisions and digests in the context match the same calls in Node.
const host = await import(new URL("index.js", dist).href);
const hostTesting = await import(new URL("testing/index.js", dist).href);
// Inputs built inside the context, so they are its plain objects, not Node's.
const inContext = (value) => vm.runInContext("JSON.parse", context)(JSON.stringify(value));
const catalogDefinition = { ticket: { actions: ["read"], scopes: ["queue"] } };
const policyInput = {
  schema: 2,
  version: "vm",
  roles: {
    reader: {
      grants: [
        {
          id: "g",
          permissions: ["ticket:read"],
          scope: { kind: "match", properties: { queue: ["a"] } },
          limits: { kind: "unlimited" },
        },
      ],
    },
  },
  denies: [],
  approvalRules: [],
  separationOfDuties: {
    requesterNeverApprovesSameType: false,
    exclusiveRequestAndApproveRoles: false,
  },
};
function run(api, apiTesting, wrap) {
  const catalog = api.defineCatalog(wrap(catalogDefinition));
  const policy = api.compilePolicy(catalog, wrap(policyInput));
  const subject = apiTesting.human("u", apiTesting.role("reader", apiTesting.everywhere));
  const request = (queue) =>
    apiTesting.accessRequest(subject, "ticket:read", wrap({ properties: { queue } }));
  const value = wrap({ text: "Grüße 😀 \ud800", list: [1, 2.5, null] });
  return {
    allowed: api.decide(policy, request("a")).outcome,
    denied: api.decide(policy, request("b")).reason,
    catalogDigest: catalog.digest,
    policyDigest: policy.digest,
    requestDigest: api.requestDigest(policy, request("a")),
    digest: api.digest(value),
    sha256OfCanonical: createHash("sha256").update(api.canonicalJson(value)).digest("hex"),
  };
}
const inVm = run(core, testing, inContext);
const inNode = run(host, hostTesting, (value) => structuredClone(value));
assert.equal(inVm.allowed, "allow");
assert.equal(inVm.denied, "scope_mismatch");
assert.equal(inVm.digest, inVm.sha256OfCanonical, "digest differs from node:crypto");
assert.deepEqual(inVm, inNode, "results in the context differ from Node");
console.log("smoke ok: dist loads and decides without process, Buffer or require");
