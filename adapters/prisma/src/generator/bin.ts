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

import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

import helper from "@prisma/generator-helper";

import { buildFieldMap, type Datamodel, renderModule } from "./emit.ts";

const DEFAULT_IMPORT = "@fieldseal/prisma";

helper.generatorHandler({
  onManifest() {
    return {
      defaultOutput: "./fieldseal",
      prettyName: "fieldseal declarations",
      version: "0.1.0-provisional",
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

    const map = buildFieldMap(
      options.dmmf.datamodel as unknown as Datamodel,
      "fieldseal-prisma-generator@0.1.0-provisional",
    );

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
  },
});
