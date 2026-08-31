import { defineConfig } from "prisma/config";

// Prisma 7 removed `url` from the schema's datasource block: connection
// configuration lives here, and the client takes a driver adapter. Every
// schema example in docs/13 and docs/04 §3 predates that change.
//
// **Two backends, one config.** A datasource's `provider` must be a string
// literal -- it cannot read an environment variable -- so the Postgres leg
// needs its own schema file. `tests/fixture/build.ts` derives it from
// `schema.prisma` by rewriting exactly that line, and it is gitignored, so the
// two cannot drift: there is one schema, and one generated view of it.
const postgres = process.env["FIELDSEAL_TEST_DB"] === "postgres";

export default defineConfig({
  schema: postgres ? "tests/fixture/schema.postgres.prisma" : "tests/fixture/schema.prisma",
  datasource: {
    url: postgres
      ? (process.env["DATABASE_URL"] ??
        "postgresql://postgres:postgres@localhost:5432/fieldseal_test")
      : "file:./tests/fixture/fixture.db",
  },
});
