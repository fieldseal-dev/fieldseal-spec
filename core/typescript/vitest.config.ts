import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["tests/**/*.test.ts"],
    // The vector harness and the 2^31-byte length-bound test are not quick.
    testTimeout: 120_000,
    hookTimeout: 120_000,
    // Key material and arming gates are process-global environment state;
    // keep one worker per file so a test arming FIELDSEAL_TEST_MODE cannot
    // leak into a file that asserts the unarmed state.
    isolate: true,
  },
});
