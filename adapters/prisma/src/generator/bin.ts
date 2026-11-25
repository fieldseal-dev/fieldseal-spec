#!/usr/bin/env node
/**
 * The Prisma generator entry point.
 *
 * Declared in the schema as:
 *
 *     generator fieldseal {
 *       provider = "fieldseal-prisma-generator"
 *       output   = "../src/generated"
 *     }
 *
 * Prisma spawns this at `prisma generate` and hands it the full DMMF --
 * including the `///` documentation that carries every @fieldseal declaration,
 * and the relation graph the args-tree visitor walks. Both halves, from
 * Prisma's own parser, through the supported hook.
 *
 * Note: `@prisma/generator-helper` is CommonJS. The named ESM import fails
 * with "Named export 'generatorHandler' not found"; the default import is the
 * supported form.
 */

import { mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";

import helper from "@prisma/generator-helper";

import { buildFieldMap, type Datamodel, renderModule } from "./emit.ts";
import { buildLock, DEFAULT_LOCKFILE, reconcileLock } from "./lock.ts";

const DEFAULT_IMPORT = "@fieldseal/prisma";

// The package version, read rather than written down: src/generator/bin.ts and
// dist/generator/bin.js both sit two levels below package.json.
const VERSION = (
  JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf8")) as { version: string }
).version;

helper.generatorHandler({
  onManifest() {
    return {
      defaultOutput: "./fieldseal",
      prettyName: "fieldseal declarations",
      version: VERSION,
    };
  },

  async onGenerate(options) {
    const out = options.generator.output?.value;
    if (out === undefined || out === null || out === "") {
      throw new Error(
        'fieldseal: the generator block needs an `output = "..."`. It is where ' +
          "the field map is written, and the extension imports it from there.",
      );
    }

    // `config` values arrive as strings.
    const importPath =
      typeof options.generator.config["importPath"] === "string"
        ? options.generator.config["importPath"]
        : DEFAULT_IMPORT;

    const datamodel = options.dmmf.datamodel as unknown as Datamodel;
    const map = buildFieldMap(
      datamodel,
      `fieldseal-prisma-generator@${VERSION}`,
    );

    // The declaration lock (#317): compared before anything is written, so a
    // refused change leaves the field map and the lock exactly as they were.
    const lockName =
      typeof options.generator.config["lockfile"] === "string"
        ? options.generator.config["lockfile"]
        : DEFAULT_LOCKFILE;
    // A multi-file schema arrives as its folder: the lock goes inside it.
    const schemaDir = statSync(options.schemaPath).isDirectory()
      ? options.schemaPath
      : dirname(options.schemaPath);
    const lockPath = resolve(schemaDir, lockName);
    let existing: string | null = null;
    try {
      existing = readFileSync(lockPath, "utf8");
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code !== "ENOENT") throw e;
    }
    // Which schema the lock belongs to, so two schemas cannot share one.
    const schema = relative(dirname(lockPath), options.schemaPath).split(sep).join("/") || ".";
    const { lock, origins } = buildLock(datamodel, map, schema);
    const reconciled = reconcileLock(existing, lock, origins, lockPath);

    // The lock first: if it cannot be written (a read-only schema folder),
    // the field map is left as it was too.
    if (reconciled.text !== null) {
      mkdirSync(dirname(lockPath), { recursive: true });
      writeFileSync(lockPath, reconciled.text, "utf8");
    }
    const file = join(out, "fieldseal-map.ts");
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, renderModule(map, importPath), "utf8");

    const columns = map.models.reduce((n, m) => n + m.encrypted.length, 0);
    const indexes = map.models.reduce((n, m) => n + m.indexes.length, 0);
    // stderr: stdout is the generator RPC channel.
    process.stderr.write(
      `fieldseal: ${String(columns)} encrypted column(s), ${String(indexes)} ` +
        `blind index(es) across ${String(map.models.length)} model(s) -> ${file}\n`,
    );
    if (reconciled.outcome === "created") {
      process.stderr.write(
        `fieldseal: created ${lockPath}. It records what the stored values are ` +
          `written under, and later generates are refused if they change it. ` +
          `Commit it.\n`,
      );
    } else if (reconciled.outcome === "updated") {
      process.stderr.write(
        `fieldseal: ${lockPath} was updated (entries: ${reconciled.summary ?? "changed"}). Commit it: ` +
          `a column is guarded only once its entry is committed.\n`,
      );
    }
  },
});
