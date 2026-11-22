/** Stable codes for errors that permitkit throws. Decisions never throw; they deny. */
export type ErrorCode = "catalog_invalid" | "policy_invalid" | "not_canonical" | "policy_unknown";

export interface PolicyIssue {
  /** Path into the policy document, for example `roles.editor.grants.0.scope.queue`. */
  path: string;
  message: string;
  hint: string;
}

const errorHints: Record<ErrorCode, string> = {
  catalog_invalid: "Fix the catalogue definition in code. Names must match /^[a-z][a-z0-9_-]*$/.",
  policy_invalid: "Fix the policy document. Each issue names its path and a hint.",
  not_canonical:
    "Pass only JSON values: plain objects, arrays, strings, finite numbers, booleans, null.",
  policy_unknown:
    "Pass a policy that compilePolicy returned in this process. Do not build policy objects by hand.",
};

export class PermitkitError extends Error {
  readonly code: ErrorCode;
  readonly hint: string;
  readonly issues: readonly PolicyIssue[];

  constructor(code: ErrorCode, message: string, issues: readonly PolicyIssue[] = []) {
    super(message);
    this.name = "PermitkitError";
    this.code = code;
    this.hint = errorHints[code];
    this.issues = issues;
  }
}
