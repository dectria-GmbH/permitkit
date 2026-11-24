import { inject } from "vitest";

declare module "vitest" {
  export interface ProvidedContext {
    /** The plain-data path this vitest project forces: see vitest.config.ts. */
    plainDataRuntime: "node" | "portable";
  }
}

/** The plain-data path the current vitest project runs on. */
export const expectedRuntime = inject("plainDataRuntime");
