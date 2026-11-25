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

import { spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from "node:fs";
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
  /// @fieldseal(index: "email", suite_id: "0xFF01", idf: "hmac-sha512",
  ///            normalize: "nfc-casefold-v1", truncate_bits: 15,
  ///            projected_population: 100000)
  emailBidx Bytes?
  plainName String
}
`;

function runGenerate(dir: string): string {
  const r = runGenerateFull(dir);
  if (!r.ok) throw new Error(`prisma generate failed\n${r.stdout}${r.stderr}`);
  return r.stdout;
}

/** Run `prisma generate`; never throws, returns stdout, stderr and success. */
function runGenerateFull(
  dir: string,
  schema = "schema.prisma",
): { stdout: string; stderr: string; ok: boolean } {
  const config = join(dir, "prisma.config.ts");
  writeFileSync(
    config,
    `import { defineConfig } from "prisma/config";\n` +
      `export default defineConfig({ schema: ${JSON.stringify(schema)} });\n`,
    "utf8",
  );
  const r = spawnSync(
    process.execPath,
    [join(pkgRoot, "node_modules", "prisma", "build", "index.js"), "generate"],
    {
      cwd: dir,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "pipe"],
      // Prisma relays a generator's stderr lines only through its debug log
      // (or in the error, on failure); this makes them visible to assertions.
      env: { ...process.env, DEBUG: "*" },
    },
  );
  return { stdout: r.stdout, stderr: r.stderr, ok: r.status === 0 };
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

  describe("the declaration lockfile (#317)", () => {
    function setup() {
      const dir = mkdtempSync(join(pkgRoot, ".tmp-gen-lock-"));
      const shim = writeShim(dir);
      return {
        dir,
        schema: (f: (s: string) => string = (x) => x) =>
          writeFileSync(join(dir, "schema.prisma"), f(SCHEMA(shim)), "utf8"),
        lock: join(dir, "fieldseal.lock.json"),
        map: join(dir, "out", "fieldseal-map.ts"),
      };
    }

    it("creates the lock on first generate and says so on stderr", () => {
      const t = setup();
      t.schema();
      const r = runGenerateFull(t.dir);
      expect(r.ok).toBe(true);
      expect(r.stdout + r.stderr).toMatch(/created .*fieldseal\.lock\.json.*Commit it/s);
      const text = readFileSync(t.lock, "utf8");
      expect(text.endsWith("\n")).toBe(true);
      // Physical names: no @map here, so the Prisma names.
      const lock = JSON.parse(text);
      expect(lock.tables.Patient.columns.emailBidx).toMatchObject({
        kind: "index", source: "email", indexId: "exact", suiteId: 0xff01,
      });
      // Regenerating an unchanged schema is byte-identical and silent about the lock.
      const again = runGenerateFull(t.dir);
      expect(again.ok).toBe(true);
      expect(readFileSync(t.lock, "utf8")).toBe(text);
      expect(again.stdout + again.stderr).not.toMatch(/created|was updated/);
    });

    it("refuses a changed index_id and leaves the map and the lock untouched", () => {
      const t = setup();
      t.schema();
      runGenerateFull(t.dir);
      const lockBefore = readFileSync(t.lock, "utf8");
      const mapBefore = readFileSync(t.map, "utf8");

      t.schema((s) => s.replace('suite_id: "0xFF01"', 'index_id: "other", suite_id: "0xFF01"'));
      const r = runGenerateFull(t.dir);
      expect(r.ok).toBe(false);
      const out = r.stdout + r.stderr;
      expect(out).toContain("Patient.emailBidx (Patient.emailBidx): index_id changed exact");
      expect(out).toContain('tables["Patient"].columns["emailBidx"]');
      expect(readFileSync(t.lock, "utf8")).toBe(lockBefore);
      expect(readFileSync(t.map, "utf8")).toBe(mapBefore);
    });

    it("lets a projected_population change through and leaves the lock unchanged", () => {
      const t = setup();
      t.schema();
      runGenerateFull(t.dir);
      const lockBefore = readFileSync(t.lock, "utf8");
      t.schema((s) => s.replace("projected_population: 100000", "projected_population: 900000"));
      expect(runGenerateFull(t.dir).ok).toBe(true);
      expect(readFileSync(t.lock, "utf8")).toBe(lockBefore);
      expect(readFileSync(t.map, "utf8")).toContain('"projectedPopulation": 900000');
    });

    it("accepts a change once the entry is deleted from the lock", () => {
      const t = setup();
      t.schema();
      runGenerateFull(t.dir);
      t.schema((s) => s.replace("truncate_bits: 15", "truncate_bits: 12"));
      expect(runGenerateFull(t.dir).ok).toBe(false);

      const lock = JSON.parse(readFileSync(t.lock, "utf8"));
      delete lock.tables.Patient.columns.emailBidx;
      writeFileSync(t.lock, `${JSON.stringify(lock, null, 2)}\n`, "utf8");
      const r = runGenerateFull(t.dir);
      expect(r.ok).toBe(true);
      expect(r.stdout + r.stderr).toContain("was updated");
      expect(JSON.parse(readFileSync(t.lock, "utf8")).tables.Patient.columns.emailBidx.truncateBits).toBe(12);
    });

    it("refuses a changed column_uuid", () => {
      const t = setup();
      t.schema();
      runGenerateFull(t.dir);
      t.schema((s) => s.replace("000000000001", "000000000009"));
      const r = runGenerateFull(t.dir);
      expect(r.ok).toBe(false);
      expect(r.stdout + r.stderr).toContain("column_uuid changed 018f3c2e-0000-7000-8000-000000000001");
    });

    it("fails on a malformed lock rather than treating it as missing", () => {
      const t = setup();
      t.schema();
      writeFileSync(t.lock, "{not json", "utf8");
      const r = runGenerateFull(t.dir);
      expect(r.ok).toBe(false);
      expect(r.stdout + r.stderr).toMatch(/lockfile .* is malformed/s);
      expect(readFileSync(t.lock, "utf8")).toBe("{not json");
      expect(existsSync(t.map)).toBe(false);
    });

    it("honours the `lockfile` generator option, relative to the schema", () => {
      const t = setup();
      t.schema((s) => s.replace("importPath", 'lockfile   = "locks/fs.json"\n  importPath'));
      expect(runGenerateFull(t.dir).ok).toBe(true);
      expect(existsSync(join(t.dir, "locks", "fs.json"))).toBe(true);
      expect(existsSync(t.lock)).toBe(false);
    });

    it("keys by the physical names from @@map and @map, so a Prisma rename keeps its entry", () => {
      const t = setup();
      const mapped = (s: string) =>
        s
          .replace("  plainName String", '  plainName String\n  @@map("patients")')
          .replace("  email     Bytes", '  email     Bytes @map("email_enc")')
          .replace("  emailBidx Bytes?", '  emailBidx Bytes? @map("email_bidx")');
      t.schema(mapped);
      expect(runGenerateFull(t.dir).ok).toBe(true);
      const lock = JSON.parse(readFileSync(t.lock, "utf8"));
      expect(Object.keys(lock.tables)).toEqual(["patients"]);
      expect(lock.tables.patients.columns.email_bidx.source).toBe("email_enc");

      const before = readFileSync(t.lock, "utf8");
      // Rename the Prisma names (model and fields), keeping the mappings.
      t.schema((s) =>
        mapped(s)
          .replace("model Patient", "model Person")
          .replace(/\bemailBidx\b/g, "mailIdx")
          .replace('index: "email"', 'index: "mail"')
          .replace(/\bemail\b(?= +Bytes @map)/, "mail"),
      );
      expect(runGenerateFull(t.dir).ok).toBe(true);
      expect(readFileSync(t.lock, "utf8")).toBe(before);
    });

    it("puts the lock inside a multi-file schema folder, which Prisma passes as the schema path", () => {
      const t = setup();
      const folder = join(t.dir, "schema");
      mkdirSync(folder);
      writeFileSync(join(folder, "main.prisma"), SCHEMA(writeShim(t.dir)).replace('"./out"', '"../out"'), "utf8");
      expect(runGenerateFull(t.dir, "schema").ok).toBe(true);
      const lock = JSON.parse(readFileSync(join(folder, "fieldseal.lock.json"), "utf8"));
      expect(lock.schema).toBe(".");
      expect(existsSync(t.lock)).toBe(false);
    });

    it("refuses a lock that belongs to another schema in the same folder", () => {
      const t = setup();
      t.schema();
      expect(runGenerateFull(t.dir).ok).toBe(true);
      const lockBefore = readFileSync(t.lock, "utf8");
      writeFileSync(join(t.dir, "other.prisma"), readFileSync(join(t.dir, "schema.prisma"), "utf8"), "utf8");
      const r = runGenerateFull(t.dir, "other.prisma");
      expect(r.ok).toBe(false);
      expect(r.stdout + r.stderr).toContain("belongs to the schema schema.prisma");
      expect(readFileSync(t.lock, "utf8")).toBe(lockBefore);
    });
  });
});
