import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { approvalReasonCodes, approvalRejectionCodes, reasonCodes } from "../src/index.js";

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
});
