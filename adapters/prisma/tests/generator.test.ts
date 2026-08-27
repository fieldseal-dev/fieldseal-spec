/**
 * The generator, end to end through a real `prisma generate`.
 *
 * `emit.ts` is unit-tested in `declarations.test.ts`; what this covers is the
 * part that cannot be unit-tested -- that Prisma actually spawns the generator,
 * completes the RPC handshake, and hands it a DMMF carrying the `///`
 * documentation. That handshake is the only route by which declarations reach
 * this adapter at all (see `prisma-private-api.test.ts` for why), so it is
 * worth one slow test.
 */

import { execFileSync } from "node:child_process";
import { chmodSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

const pkgRoot = resolve(fileURLToPath(import.meta.url), "..", "..");
const binJs = join(pkgRoot, "dist", "generator", "bin.js");

/**
 * Prisma spawns a generator `provider` as an executable, with no shell. So a
 * bare `node foo.js` is not a command, and a `.js` file is not executable on
 * Windows. Real generators are reached through `node_modules/.bin`, which npm
 * populates from their `bin` field -- but a package does not get its own bin
 * linked into its own tree, so the test writes the equivalent shim itself.
 */
function writeShim(dir: string): string {
  if (process.platform === "win32") {
    const cmd = join(dir, "fieldseal-gen.cmd");
    writeFileSync(cmd, `@echo off\r\nnode "${binJs}" %*\r\n`, "utf8");
    return cmd;
  }
  const sh = join(dir, "fieldseal-gen");
  writeFileSync(sh, `#!/bin/sh\nexec node "${binJs}" "$@"\n`, "utf8");
  chmodSync(sh, 0o755);
  return sh;
}

const SCHEMA = (provider: string) => `
generator fieldseal {
  provider   = "${provider.replace(/\\/g, "\\\\")}"
  output     = "./out"
  importPath = "@fieldseal/prisma"
}

datasource db {
  provider = "sqlite"
}

/// @fieldseal(table_uuid: "018f3c2e-0000-7000-8000-0000000000aa")
model Patient {
  id        String  @id @default(uuid())
  /// @fieldseal(encrypted, column_uuid: "018f3c2e-0000-7000-8000-000000000001")
  email     Bytes
  /// @fieldseal(index: "email", idf: "hmac-sha512",
  ///            normalize: "nfc-casefold-v1", truncate_bits: 15,
  ///            projected_population: 100000)
  emailBidx Bytes?
  plainName String
}
`;

function runGenerate(dir: string): string {
  const config = join(dir, "prisma.config.ts");
  writeFileSync(
    config,
    `import { defineConfig } from "prisma/config";\n` +
      `export default defineConfig({ schema: "schema.prisma" });\n`,
    "utf8",
  );
  return execFileSync(
    process.execPath,
    [join(pkgRoot, "node_modules", "prisma", "build", "index.js"), "generate"],
    { cwd: dir, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
  );
}

describe("prisma generate", () => {
  it("spawns the generator and emits a field map from the /// declarations", () => {
    const dir = mkdtempSync(join(pkgRoot, ".tmp-gen-"));
    const shim = writeShim(dir);
    writeFileSync(join(dir, "schema.prisma"), SCHEMA(shim), "utf8");

    runGenerate(dir);

    const emitted = readFileSync(join(dir, "out", "fieldseal-map.ts"), "utf8");
    expect(emitted).toContain('import type { FieldMap } from "@fieldseal/prisma"');
    expect(emitted).toContain('"model": "Patient"');
    expect(emitted).toContain('"tableUuid": "018f3c2e-0000-7000-8000-0000000000aa"');
    expect(emitted).toContain('"columnUuid": "018f3c2e-0000-7000-8000-000000000001"');
    // The multi-line declaration survived the round trip through Prisma's
    // parser, the RPC, and the annotation grammar.
    expect(emitted).toContain('"truncateBits": 15');
    expect(emitted).toContain('"projectedPopulation": 100000');
    expect(emitted).toContain('"normalize": "nfc-casefold-v1"');
    // Defaults filled in.
    expect(emitted).toContain('"indexId": "exact"');
    expect(emitted).toContain('"onUnindexable": "refuse"');
    expect(emitted).toContain('"valueType": "string"');
  });

  it("fails the generate on a malformed declaration, rather than skipping it", () => {
    // The whole point of moving declaration checking to generate time: a
    // column that cannot be declared correctly must not produce a client that
    // silently treats it as plaintext.
    const dir = mkdtempSync(join(pkgRoot, ".tmp-gen-bad-"));
    const shim = writeShim(dir);
    writeFileSync(
      join(dir, "schema.prisma"),
      SCHEMA(shim).replace("018f3c2e-0000-7000-8000-000000000001", "not-a-uuid"),
      "utf8",
    );

    let failed = false;
    let output = "";
    try {
      runGenerate(dir);
    } catch (e) {
      failed = true;
      const err = e as { stdout?: string; stderr?: string; message: string };
      output = `${err.stdout ?? ""}${err.stderr ?? ""}${err.message}`;
    }
    expect(failed).toBe(true);
    expect(output).toMatch(/must be a UUID|Patient\.email/);
  });
});
