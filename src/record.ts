/**
 * The shape of a stored decision record, as reevaluate reads it. It replaces the Zod 3 schema
 * of the earlier version rule for rule and runs on the plain-data copy that the size guard
 * made. The request inside is validated later, by parseRequest. Every rule here has a named
 * test in `test/record-validator.test.ts`.
 */

import { bareObject, defineData, hasOwn } from "./intrinsics.js";
import {
  bare,
  fail,
  invalid,
  isObject,
  knownKeys,
  list,
  nullable,
  oneOf,
  own,
  required,
  text,
  type Check,
} from "./validate.js";

/** A record as reevaluate reads it. Absent unknown fields stay absent; they read as undefined. */
export interface StoredRecord {
  readonly schema: "permitkit.decision/2";
  readonly policy: { readonly version: string; readonly digest: string };
  readonly request?: unknown;
  readonly requestDigest: string | null;
  readonly actorChain: readonly unknown[];
  readonly outcome: string;
  readonly reason: string;
  readonly rule?: unknown;
  readonly approval?: unknown;
}

const anyText = text({});
const recordSchema = oneOf(["permitkit.decision/2"]);

const storedPolicy: Check<StoredRecord["policy"]> = (value, path, issues) => {
  if (!isObject(value)) return fail(issues, path, "Expected a policy reference object.");
  const version = required(value, "version", path, issues, anyText);
  const digest = required(value, "digest", path, issues, anyText);
  const known = knownKeys(value, ["version", "digest"], path, issues);
  return version === invalid || digest === invalid || !known ? invalid : bare({ version, digest });
};

/** The key and its value if the object has the key, else nothing. */
function ownEntry(value: object, key: string): Record<string, unknown> {
  const entry = bareObject();
  if (hasOwn(value, key)) defineData(entry, key, own(value, key));
  return entry;
}

/** Any value. */
const anything: Check<unknown> = (value) => value;

const actorChain = list(anything);
const requestDigest = nullable(anyText);

const recordKeys = [
  "schema",
  "policy",
  "request",
  "requestDigest",
  "actorChain",
  "outcome",
  "reason",
  "rule",
  "approval",
];

/**
 * A stored record. `request`, `rule` and `approval` may hold any plain data or be absent; an
 * absent one reads as undefined.
 */
export const storedRecord: Check<StoredRecord> = (value, path, issues) => {
  if (!isObject(value)) return fail(issues, path, "Expected a decision record object.");
  const schema = required(value, "schema", path, issues, recordSchema);
  const policy = required(value, "policy", path, issues, storedPolicy);
  const digest = required(value, "requestDigest", path, issues, requestDigest);
  const chain = required(value, "actorChain", path, issues, actorChain);
  const outcome = required(value, "outcome", path, issues, anyText);
  const reason = required(value, "reason", path, issues, anyText);
  const known = knownKeys(value, recordKeys, path, issues);
  if (
    schema === invalid ||
    policy === invalid ||
    digest === invalid ||
    chain === invalid ||
    outcome === invalid ||
    reason === invalid ||
    !known
  ) {
    return invalid;
  }
  // A key of type unknown is in the output exactly if the input has it, as before.
  return bare({
    schema,
    policy,
    ...ownEntry(value, "request"),
    requestDigest: digest,
    actorChain: chain,
    outcome,
    reason,
    ...ownEntry(value, "rule"),
    ...ownEntry(value, "approval"),
  });
};
