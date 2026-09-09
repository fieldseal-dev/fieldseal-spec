import { defineConfig } from "prisma/config";

// Prisma 7 removed `url` from the schema's datasource block: connection
// configuration lives here, and the client takes a driver adapter.
//
// `prisma generate` is the only Prisma CLI command this demo runs. Django owns
// the DDL (`../django/directory/models.py` says why), so there is no
// `db push` and no `migrate` here, and the url below exists only so the CLI
// has a complete datasource to validate against.
export default defineConfig({
  schema: "schema.prisma",
  datasource: {
    url:
      process.env["DATABASE_URL"] ??
      "postgresql://postgres:postgres@localhost:5432/fieldseal_demo",
  },
});
