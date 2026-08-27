/**
 * Build the fixture's field map.
 *
 * This drives the *same* `buildFieldMap` / `renderModule` the generator calls,
 * over the same DMMF the generator receives -- `getDMMF` is the function
 * Prisma's own generator pipeline uses to populate `options.dmmf`. What it
 * skips is only the RPC plumbing in `src/generator/bin.ts`, which
 * `tests/generator.test.ts` covers end-to-end by actually running
 * `prisma generate`.
 *
 * Run by `npm run fixture` before the suite.
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
