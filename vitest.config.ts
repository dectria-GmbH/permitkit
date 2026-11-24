import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["test/**/*.test.ts"],
    environment: "node",
    projects: [
      { extends: true, test: { name: "node", provide: { plainDataRuntime: "node" } } },
      {
        // The whole suite again, with src/plain.ts on the path for runtimes without node:util.
        extends: true,
        test: {
          name: "portable",
          setupFiles: ["test/setup/portable-runtime.ts"],
          provide: { plainDataRuntime: "portable" },
        },
      },
    ],
  },
});
