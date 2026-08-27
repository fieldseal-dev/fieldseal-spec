import { defineConfig } from "prisma/config";

// Prisma 7 removed `url` from the schema's datasource block: connection
// configuration lives here, and the client takes a driver adapter. Every
// schema example in docs/13 and docs/04 §3 predates that change.
export default defineConfig({
  schema: "tests/fixture/schema.prisma",
  datasource: { url: "file:./tests/fixture/fixture.db" },
});
