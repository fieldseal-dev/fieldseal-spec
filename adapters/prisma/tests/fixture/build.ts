/**
 * Build the fixture's field map, and the Postgres view of its schema.
 *
 * This drives the *same* `buildFieldMap` / `renderModule` the generator calls,
 * over the same DMMF the generator receives -- `getDMMF` is the function
 * Prisma's own generator pipeline uses to populate `options.dmmf`. What it
 * skips is only the RPC plumbing in `src/generator/bin.ts`, which
 * `tests/generator.test.ts` covers end-to-end by actually running
 * `prisma generate`.
 *
 * It also derives `schema.postgres.prisma` from `schema.prisma`. A datasource's
 * `provider` must be a string literal -- Prisma will not read it from the
 * environment -- so running the suite against Postgres needs a second schema
 * file, and a second *committed* schema file is a drift hazard: the two would
 * be edited apart, and the leg that caught the difference would be the one
 * nobody ran. Deriving it here, from the one schema, and gitignoring the
 * result, means there is exactly one place a column is declared.
 *
 * Run before `prisma generate`, because the Postgres leg generates from the
 * file this writes.
 */

import { createRequire } from "node:module";
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { buildFieldMap, type Datamodel, renderModule } from "../../src/generator/emit.ts";

// @prisma/internals is CommonJS; the named ESM import fails.
const require_ = createRequire(import.meta.url);
const { getDMMF } = require_("@prisma/internals") as {
  getDMMF: (o: { datamodel: string }) => Promise<{ datamodel: Datamodel }>;
};

const here = dirname(fileURLToPath(import.meta.url));
const schema = join(here, "schema.prisma");
const outDir = join(here, "generated");

const { readFileSync } = await import("node:fs");
const dmmf = await getDMMF({ datamodel: readFileSync(schema, "utf8") });
const map = buildFieldMap(dmmf.datamodel, "fixture-builder");

mkdirSync(outDir, { recursive: true });
const file = join(outDir, "fieldseal-map.ts");
writeFileSync(file, renderModule(map, "../../../src/index.ts"), "utf8");
process.stderr.write(`fixture: wrote ${file}\n`);

// The Postgres view of the same schema: one line differs, and the header says
// so, so nobody edits this file thinking it is a source.
const source = readFileSync(schema, "utf8");
const pgSchema = source.replace(/provider = "sqlite"/, 'provider = "postgresql"');
if (pgSchema === source) {
  throw new Error(
    'fixture: schema.prisma no longer declares `provider = "sqlite"`, so the ' +
      "Postgres view cannot be derived from it. Fix the substitution in this " +
      "file rather than committing a second schema -- two schemas drift.",
  );
}
const pgFile = join(here, "schema.postgres.prisma");
writeFileSync(
  pgFile,
  "// GENERATED from schema.prisma by tests/fixture/build.ts. Do not edit.\n" +
    "// The only difference is the datasource provider; everything else is the\n" +
    "// same file, because two schemas would drift apart exactly where the\n" +
    "// second backend was supposed to catch something.\n" +
    pgSchema,
  "utf8",
);
process.stderr.write(`fixture: wrote ${pgFile}\n`);
