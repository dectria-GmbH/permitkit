// Imports the built package through its own exports map and runs one decision.
// Fails with a non-zero exit code if an entry point is missing or behaves wrongly.
import assert from "node:assert/strict";

const core = await import("permitkit");
const testing = await import("permitkit/testing");

const catalog = core.defineCatalog({ ticket: { actions: ["read"] } });
const policy = core.compilePolicy(catalog, {
  schema: 1,
  version: "smoke",
  roles: { reader: { grants: [{ id: "g", permissions: ["ticket:read"] }] } },
});
const allowed = core.decide(
  policy,
  testing.accessRequest(testing.human("u", testing.role("reader")), "ticket:read"),
);
const denied = core.decide(policy, testing.accessRequest(testing.human("u"), "ticket:read"));
assert.equal(allowed.outcome, "allow");
assert.equal(denied.outcome, "deny");
assert.equal(denied.reason, "no_grant");
console.log("smoke ok: permitkit and permitkit/testing load from dist");
