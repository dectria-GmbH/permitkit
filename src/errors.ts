/** Stable codes for errors that permitkit throws. Decisions never throw; they deny. */
export type ErrorCode =
  | "catalog_invalid"
  | "policy_invalid"
  | "policy_schema_unsupported"
  | "not_canonical"
  | "policy_unknown"
  | "request_invalid"
  | "options_invalid";

export interface PolicyIssue {
  /** Path into the policy document, for example `roles.editor.grants.0.scope.queue`. */
  path: string;
  message: string;
  hint: string;
}

const errorHints: Record<ErrorCode, string> = {
  catalog_invalid: "Fix the catalogue definition in code. Names must match /^[a-z][a-z0-9_-]*$/.",
  policy_invalid: "Fix the policy document. Each issue names its path and a hint.",
  policy_schema_unsupported:
    "Rewrite the policy document in the current schema. permitkit does not migrate old documents.",
  not_canonical:
    "Pass only JSON values: plain objects, arrays, strings, finite numbers, booleans, null.",
  options_invalid: "Pass options as { verifiers: [...] } with one verifier per proof type.",
  request_invalid: "Validate the request with parseRequest(), or read explain() issues.",
  policy_unknown:
    "Pass a policy that compilePolicy returned in this process. Do not build policy objects by hand.",
};

export class PermitkitError extends Error {
  // A class field, so the name is defined on the instance. An assignment would throw if
  // Error.prototype.name were made read-only or a getter.
  override name: string = "PermitkitError";
  readonly code: ErrorCode;
  readonly hint: string;
  readonly issues: readonly PolicyIssue[];
  /** Set only by this constructor. `#brand in value` runs no Proxy trap, unlike instanceof. */
  // Read by `#brand in value` in is(); the rule does not see that use.
  // oxlint-disable-next-line eslint/no-unused-private-class-members
  readonly #brand = true;

  /**
   * True if the value is a PermitkitError from this module. Safe for any value: unlike
   * instanceof, it runs no Proxy trap and reads no prototype.
   */
  static is(value: unknown): value is PermitkitError {
    return typeof value === "object" && value !== null && #brand in value;
  }

  constructor(code: ErrorCode, message: string, issues: readonly PolicyIssue[] = []) {
    super(message);
    this.code = code;
    this.hint = errorHints[code];
    this.issues = issues;
  }
}
