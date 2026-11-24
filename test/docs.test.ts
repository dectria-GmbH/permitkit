import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import {
  approvalReasonCodes,
  approvalRejectionCodes,
  PermitkitError,
  reasonCodes,
} from "../src/index.js";

const reference = readFileSync(new URL("../docs/reference.md", import.meta.url), "utf8");

describe("reference documentation", () => {
  it("lists every reason, approval and rejection code", () => {
    const codes = [
      ...Object.keys(reasonCodes),
      ...Object.keys(approvalReasonCodes),
      ...Object.keys(approvalRejectionCodes),
    ];
    const missing = codes.filter((code) => !reference.includes(`| \`${code}\``));
    expect(missing).toEqual([]);
  });

  it("documents every static method of PermitkitError", () => {
    const methods = Object.getOwnPropertyNames(PermitkitError).filter(
      (name) => typeof Reflect.get(PermitkitError, name) === "function",
    );
    expect(methods).toContain("is");
    const missing = methods.filter((name) => !reference.includes(`PermitkitError.${name}(`));
    expect(missing).toEqual([]);
  });
});
