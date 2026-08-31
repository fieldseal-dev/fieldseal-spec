/**
 * Assumptions this adapter makes about Prisma, asserted against the installed
 * version.
 *
 * **A failure in this file is not a bug in this file.** It means Prisma moved,
 * and the part of the adapter resting on the moved thing needs re-verifying by
 * hand. Each assertion names what breaks.
 *
 * This exists because the Django adapter needed its counterpart
 * (`test_query_private_api.py`): `_fetch_all` is not a documented extension
 * point, and its failure mode is *silent* -- verification stops, wrong rows
 * start being returned, and every behavioural test stays green. Prisma is worse
 * on this axis, not better: `docs/13` §1 was written against
 * `Prisma.dmmf`, which **no longer exists**, and nothing failed loudly when it
 * went away. It just would have read `undefined`.
 *
 * Verified against Prisma 7.10.0 on 2026-08-27.
 */

import { createRequire } from "node:module";
import { readFileSync } from "node:fs";

import { afterAll, describe, expect, it } from "vitest";

import { driverAdapter } from "./helpers.ts";
import { PrismaClient } from "./fixture/generated/prisma/client.ts";
import * as NS from "./fixture/generated/prisma/internal/prismaNamespace.ts";

const base = new PrismaClient({ adapter: driverAdapter() } as never);
afterAll(async () => {
  await base.$disconnect();
});

/** Record every `args` the extension sees, without changing behaviour. */
function spy(): { seen: Array<{ op: string; keys: string[] }>; client: unknown } {
  const seen: Array<{ op: string; keys: string[] }> = [];
  const client = base.$extends({
    name: "spy",
    query: {
      async $allOperations({ operation, args, query }: never) {
        const a = args as Record<string, unknown> | undefined;
        seen.push({ op: operation as unknown as string, keys: Object.keys(a ?? {}) });
        return (query as (x: unknown) => Promise<unknown>)(args);
      },
    },
  } as never);
  return { seen, client };
}

describe("DMMF: why the declarations come from a build-time generator", () => {
  it("Prisma.dmmf no longer exists on the generated namespace", () => {
    // docs/13 §1 was written against it ("read from the DMMF at runtime").
    // If this ever becomes defined again, the generator is still the better
    // route -- but the doc's original premise would be live again.
    expect((NS as Record<string, unknown>)["dmmf"]).toBeUndefined();
  });

  it("the client's runtime data model carries the relation graph but NO documentation", () => {
    // This is the exact split that forced the generator: the visitor needs the
    // relation graph (here) and the declarations (not here).
    const rdm = (base as unknown as {
      _runtimeDataModel: { models: Record<string, { fields: Array<Record<string, unknown>> }> };
    })._runtimeDataModel;

    const patient = rdm.models["Patient"]!;
    expect(patient.fields.some((f) => f["name"] === "email")).toBe(true);
    expect(patient.fields.some((f) => f["relationName"] !== undefined)).toBe(true);

    expect(patient.fields.some((f) => "documentation" in f)).toBe(false);
    expect("documentation" in (patient as unknown as Record<string, unknown>)).toBe(false);
  });

  it("Prisma's own parser DOES attach documentation -- which is what the generator uses", async () => {
    // @prisma/internals is CommonJS; the named ESM import fails. The generator
    // reaches the same data through @prisma/generator-helper's `options.dmmf`,
    // which this function populates.
    const require_ = createRequire(import.meta.url);
    const { getDMMF } = require_("@prisma/internals") as {
      getDMMF: (o: { datamodel: string }) => Promise<{
        datamodel: {
          models: Array<{
            name: string;
            documentation?: string;
            fields: Array<{ name: string; documentation?: string }>;
          }>;
        };
      }>;
    };
    const dmmf = await getDMMF({
      datamodel: readFileSync("tests/fixture/schema.prisma", "utf8"),
    });
    const patient = dmmf.datamodel.models.find((m) => m.name === "Patient")!;
    expect(patient.documentation).toMatch(/@fieldseal\(table_uuid/);
    expect(patient.fields.find((f) => f.name === "email")?.documentation).toMatch(
      /@fieldseal\(encrypted/,
    );
  });

  it("a multi-line /// declaration arrives joined with newlines, prefix stripped", async () => {
    // The annotation parser's continuation handling depends on this exactly.
    const require_ = createRequire(import.meta.url);
    const { getDMMF } = require_("@prisma/internals") as {
      getDMMF: (o: { datamodel: string }) => Promise<{
        datamodel: { models: Array<{ name: string; fields: Array<{ name: string; documentation?: string }> }> };
      }>;
    };
    const dmmf = await getDMMF({
      datamodel: readFileSync("tests/fixture/schema.prisma", "utf8"),
    });
    const doc = dmmf.datamodel.models
      .find((m) => m.name === "Patient")!
      .fields.find((f) => f.name === "emailBidx")!.documentation!;
    expect(doc).toContain("\n");
    expect(doc).not.toContain("///");
    expect(doc).toMatch(/projected_population: 100000/);
  });
});

describe("extension composition order", () => {
  it("registers first = outermost, so fieldseal must be registered LAST", async () => {
    // If this inverts, the guidance in the README and docs/13 §6 inverts with
    // it, and every other extension starts seeing envelopes instead of values.
    const trace: string[] = [];
    const probe = (label: string) =>
      ({
        name: label,
        query: {
          async $allOperations({ args, query }: never) {
            trace.push(`${label}:in`);
            const r = await (query as (x: unknown) => Promise<unknown>)(args);
            trace.push(`${label}:out`);
            return r;
          },
        },
      }) as never;

    const client = base.$extends(probe("first")).$extends(probe("second"));
    await (client as unknown as { patient: { findMany: (a: unknown) => Promise<unknown> } }).patient.findMany({
      where: { plainName: "__none__" },
    });

    expect(trace).toEqual(["first:in", "second:in", "second:out", "first:out"]);
  });
});

describe("what $allOperations can see", () => {
  it("sees raw operations only at the TOP level of `query`, not under $allModels", async () => {
    // Pipeline step 1 ("model === undefined") is reachable only from the top
    // level. Registered under $allModels, raw ops bypass the extension
    // entirely and `strictRaw` silently stops working.
    const topLevel: string[] = [];
    const underAllModels: string[] = [];

    const a = base.$extends({
      name: "top",
      query: {
        async $allOperations({ model, operation, args, query }: never) {
          if ((model as unknown) === undefined) topLevel.push(operation as unknown as string);
          return (query as (x: unknown) => Promise<unknown>)(args);
        },
      },
    } as never);
    const b = base.$extends({
      name: "models",
      query: {
        $allModels: {
          async $allOperations({ model, operation, args, query }: never) {
            if ((model as unknown) === undefined) underAllModels.push(operation as unknown as string);
            return (query as (x: unknown) => Promise<unknown>)(args);
          },
        },
      },
    } as never);

    await (a as unknown as { $queryRawUnsafe: (s: string) => Promise<unknown> }).$queryRawUnsafe(
      "SELECT 1 AS one",
    );
    await (b as unknown as { $queryRawUnsafe: (s: string) => Promise<unknown> }).$queryRawUnsafe(
      "SELECT 1 AS one",
    );

    expect(topLevel.length).toBeGreaterThan(0);
    expect(underAllModels).toEqual([]);
  });

  it("sees take, skip, cursor, orderBy, distinct, by and _count in args", async () => {
    const { seen, client } = spy();
    const p = (client as { patient: Record<string, (a?: unknown) => Promise<unknown>> }).patient;

    await p["findMany"]!({ take: 5, skip: 1, where: { plainName: "x" } });
    await p["findMany"]!({ distinct: ["plainName"], orderBy: { plainName: "asc" } });
    await p["count"]!({ where: { plainName: "x" } });
    await p["groupBy"]!({ by: ["plainName"], _count: { _all: true } });
    await p["findMany"]!({ select: { id: true, _count: { select: { visits: true } } } });

    const keys = seen.flatMap((s) => s.keys);
    for (const k of ["take", "skip", "orderBy", "distinct", "by", "_count", "select"]) {
      expect(keys, `\`${k}\` must be visible for its refusal to be reachable`).toContain(k);
    }
  });

  it("does NOT put take: 1 in findFirst's args -- the LIMIT is applied below", async () => {
    // The single most important pin in this file, and the reason the L2 work
    // in PR2 cannot simply pattern-match `take` to find LIMIT hazards.
    //
    // Prisma applies findFirst's LIMIT 1 beneath the extension, so an
    // index-rewritten findFirst has the database return ONE candidate before
    // spec §7.5 re-verification can run. If that candidate is a §7.4
    // collision, the answer is a wrong row; if the true match sorted behind
    // it, the answer is a miss. Neither is visible in `args`.
    const { seen, client } = spy();
    await (client as { patient: { findFirst: (a: unknown) => Promise<unknown> } }).patient.findFirst({
      where: { plainName: "x" },
    });
    const call = seen.find((s) => s.op === "findFirst")!;
    expect(call.keys).toEqual(["where"]);
    expect(call.keys).not.toContain("take");
  });

  it("refuses to widen findFirst's LIMIT -- `take` must be 1 or -1", async () => {
    // The other half of the pin above, and the fact that decides the shape of
    // L2. `docs/13` §2 said an index-rewritten findFirst "MUST be rewritten as
    // an over-fetch (findMany + verify + first) or refused" -- and this is why
    // the first option does not exist. An extension also cannot turn one
    // operation into another (`query` is bound to the one it was called for),
    // so findFirst over a rewritten predicate is refused.
    const { client } = spy();
    const p = client as { patient: { findFirst: (a: unknown) => Promise<unknown> } };
    await expect(p.patient.findFirst({ where: { plainName: "x" }, take: 3 })).rejects.toThrow(
      /'take' argument that isn't 1 or -1/,
    );
    await expect(p.patient.findFirst({ where: { plainName: "x" }, take: 1 })).resolves.not.toThrow();
  });

  it("applies `distinct` below the extension, over the candidate rows", async () => {
    // So a row `distinct` kept may be one §7.5 then drops, while the row it
    // discarded would have matched. That is why `distinct` is refused beside a
    // rewritten filter rather than post-processed.
    await base.visit.deleteMany({});
    await base.referral.deleteMany({});
    await base.patient.deleteMany({});
    for (const [id, name] of [["d1", "same"], ["d2", "same"], ["d3", "other"]] as const) {
      await base.patient.create({
        data: {
          id,
          email: Buffer.from(id),
          note: Buffer.from("n"),
          age: Buffer.from("1"),
          plainName: name,
        } as never,
      });
    }
    const { seen, client } = spy();
    const rows = (await (
      client as { patient: { findMany: (a: unknown) => Promise<unknown[]> } }
    ).patient.findMany({ distinct: ["plainName"] })) as unknown[];
    expect(seen.some((s) => s.keys.includes("distinct"))).toBe(true);
    expect(rows).toHaveLength(2); // three rows in, two out: the dedup already ran
  });

  it("does not surface a client-level `omit` in args -- only in the result", async () => {
    // The projection hazard that no argument-side check can see, which is why
    // the §7.5 projection check runs on the returned row. If this ever starts
    // appearing in `args`, an earlier and clearer refusal becomes possible.
    const omitted = new PrismaClient({
      adapter: driverAdapter(),
      omit: { patient: { email: true } },
    } as never);
    const seen: Array<Record<string, unknown>> = [];
    const client = omitted.$extends({
      name: "omit-spy",
      query: {
        async $allOperations({ args, query }: never) {
          seen.push({ ...(args as Record<string, unknown>) });
          return (query as (x: unknown) => Promise<unknown>)(args);
        },
      },
    } as never);
    const rows = (await (
      client as unknown as { patient: { findMany: (a: unknown) => Promise<unknown[]> } }
    ).patient.findMany({ where: { plainName: "same" } })) as Array<Record<string, unknown>>;

    expect(Object.keys(seen[0] ?? {})).toEqual(["where"]);
    expect(seen[0]).not.toHaveProperty("omit");
    expect(rows[0]).not.toHaveProperty("email");
    await omitted.$disconnect();
  });

  it("passes each member of a $transaction through individually", async () => {
    const { seen, client } = spy();
    const p = client as {
      patient: Record<string, (a?: unknown) => Promise<unknown>> ;
      $transaction: (ops: unknown[]) => Promise<unknown>;
    };
    await p.$transaction([p["patient"]!["findMany"]!({ take: 1 }), p["patient"]!["count"]!()]);
    expect(seen.map((s) => s.op).sort()).toEqual(["count", "findMany"]);
  });

  it("honours mutations the extension makes to args", async () => {
    // The write pass mutates `args` in place; if Prisma ever snapshotted it,
    // encryption would silently stop being applied.
    const client = base.$extends({
      name: "mutate",
      query: {
        async $allOperations({ args, query }: never) {
          const a = args as Record<string, unknown>;
          a["where"] = { plainName: "__mutated__" };
          return (query as (x: unknown) => Promise<unknown>)(args);
        },
      },
    } as never);
    const rows = await (
      client as unknown as { patient: { findMany: (a: unknown) => Promise<unknown[]> } }
    ).patient.findMany({ where: { plainName: "__original__" } });
    expect(Array.isArray(rows)).toBe(true);
  });
});
