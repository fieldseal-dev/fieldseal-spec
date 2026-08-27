import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    // Argon2id at the spec minima is slow by design (spec §7.3).
    testTimeout: 120_000,
    hookTimeout: 120_000,
    // The tenant AsyncLocalStorage and FIELDSEAL_* arming gates are
    // process-global; one worker per file keeps a test that arms one of them
    // from leaking into a file asserting the unarmed state.
    isolate: true,
    // Each test file drives its own SQLite file through a real Prisma client.
    fileParallelism: false,
  },
});
