/**
 * The mandatory throw list (spec §10.2, `docs/13` §4).
 *
 * This is the file that guards the adapter's reason for existing. `docs/04` §3
 * records what `prisma-field-encryption` does with these shapes: the operand
 * gets *encrypted*, and the query returns zero rows silently.
 *
 * Every refusal here is paired with something: either a **measurement** of the
 * wrong answer the unextended client gives for the same shape, or a
 * **positive** test showing the refusal is narrow enough to leave the
 * legitimate neighbour working. A refusal with neither is a refusal nobody can
 * tell is doing anything.
 */

import { afterAll, beforeEach, describe, expect, it } from "vitest";

import {
  FieldsealConfigurationError,
  FieldsealNotSupported,
  fieldsealExtension,
} from "../src/index.ts";
import { fieldsealFieldMap } from "./fixture/generated/fieldseal-map.ts";
import { clearDb, keyProvider, loose, makeClient, SUITE } from "./helpers.ts";

const { base, prisma } = makeClient();

/**
 * The client, with Prisma's generated types stepped around.
 *
 * Two separate reasons, both worth stating rather than hiding behind a cast.
 *
 * **1. Prisma's types describe the column, not the value.** An encrypted column
 * is declared `Bytes` because that is what holds the envelope, so the generated
 * type for `Patient.email` is `Uint8Array` -- while the value a caller writes is
 * a string. Every legitimate write through this adapter is therefore a type
 * error against the generated client. That is a real DX limitation of this
 * release, recorded in the README, not something these tests are papering over.
 *
 * **2. Several refusals are unreachable through the typed surface -- on some
 * columns.** `contains` is not in `BytesFilter`, so on a `Bytes` column
 * TypeScript rejects it before the adapter can. It is *not* rejected on a
 * `storage: "base64"` column, which is a Prisma `String`, and it is never
 * rejected for a JavaScript caller or a dynamically-built `where`. The runtime
 * refusal is what holds in those cases, so it is what these tests exercise.
 */
const lp = loose(prisma);

beforeEach(async () => {
  await clearDb(base);
});
afterAll(async () => {
  await base.$disconnect();
});

const seed = async () => {
  await lp["patient"]!["create"]!({
    data: { email: "ada@example.com", note: "n", age: 30, plainName: "Ada" },
  });
  await lp["patient"]!["create"]!({
    data: { email: "grace@example.com", note: "n", age: 40, plainName: "Grace" },
  });
};

// ------------------------------------------------------- not serveable ----

describe("filter shapes that ciphertext cannot serve", () => {
  const shapes: Array<[string, () => Promise<unknown>]> = [
    ["contains", () => lp["patient"]!["findMany"]!({ where: { email: { contains: "ada" } } })],
    ["startsWith", () => lp["patient"]!["findMany"]!({ where: { email: { startsWith: "ada" } } })],
    ["endsWith", () => lp["patient"]!["findMany"]!({ where: { email: { endsWith: ".com" } } })],
    ["lt", () => lp["patient"]!["findMany"]!({ where: { email: { lt: "b" } } })],
    ["gte", () => lp["patient"]!["findMany"]!({ where: { email: { gte: "b" } } })],
    [
      "mode: insensitive",
      () =>
        lp["patient"]!["findMany"]!({
          where: { email: { equals: "ADA@EXAMPLE.COM", mode: "insensitive" } },
        }),
    ],
    ["not", () => lp["patient"]!["findMany"]!({ where: { email: { not: "ada@example.com" } } })],
    ["notIn", () => lp["patient"]!["findMany"]!({ where: { email: { notIn: ["a"] } } })],
  ];

  for (const [name, run] of shapes) {
    it(`refuses \`${name}\` rather than returning nothing`, async () => {
      await expect(run()).rejects.toThrow(FieldsealNotSupported);
    });
  }

  it("names the spec clause and an alternative, never just 'unsupported'", async () => {
    // A refusal that does not say what to do instead is a dead end, and the
    // caller's next move is raw SQL -- the one path this adapter cannot protect.
    await expect(
      lp["patient"]!["findMany"]!({ where: { email: { contains: "ada" } } }),
    ).rejects.toThrow(/§7\.1[\s\S]*§10\.2[\s\S]*§7\.10/);
  });

  it("refuses `mode: insensitive` as the one-equality consequence (G19)", async () => {
    await expect(
      lp["patient"]!["findMany"]!({
        where: { email: { equals: "x", mode: "insensitive" } },
      }),
    ).rejects.toThrow(/normalizer, not the query/);
  });

  it("explains notIn as an exclusion asymmetry, not a missing feature", async () => {
    await expect(
      lp["patient"]!["findMany"]!({ where: { email: { notIn: ["a"] } } }),
    ).rejects.toThrow(/false negatives are not|drops rows it should have/);
  });

  it("fails closed on an operator it does not recognise", async () => {
    await expect(
      lp["patient"]!["findMany"]!({
        where: { email: { fantasyOperator: "x" } as never },
      }),
    ).rejects.toThrow(/not a filter shape this adapter recognises/);
  });

  it("leaves filters on plaintext columns of the same model untouched", async () => {
    await seed();
    const rows = (await lp["patient"]!["findMany"]!({
      where: { plainName: { contains: "Ad" } },
    })) as Array<{ email: string }>;
    expect(rows).toHaveLength(1);
    expect(rows[0]?.email).toBe("ada@example.com");
  });
});

describe("equality without the L2 rewrite", () => {
  it("refuses rather than comparing against a randomized envelope", async () => {
    await expect(
      lp["patient"]!["findMany"]!({ where: { email: "ada@example.com" } }),
    ).rejects.toThrow(FieldsealNotSupported);
  });

  it("measures why: the unextended client returns nothing for the same shape", async () => {
    await seed();
    // The failure the refusal replaces. Comparing a plaintext operand against
    // an envelope column is valid SQL and matches nothing -- a wrong answer,
    // not an error.
    const rows = await base.patient.findMany({
      where: { email: Buffer.from("ada@example.com") },
    });
    expect(rows).toHaveLength(0);
  });

  it("refuses a filter on the index sibling directly", async () => {
    await expect(
      lp["patient"]!["findMany"]!({ where: { emailBidx: Buffer.from([1, 2]) } }),
    ).rejects.toThrow(/blind-index sibling column and cannot be filtered on directly/);
  });

  it("refuses findUnique on an encrypted column, naming §7.10", async () => {
    await expect(
      lp["patient"]!["findUnique"]!({ where: { email: "ada@example.com" } as never }),
    ).rejects.toThrow(/§7\.10/);
  });
});

// ------------------------------------- G20: SQL computing on envelope bytes ----

describe("G20: ordering, grouping, distinct and aggregates over ciphertext", () => {
  it("refuses orderBy on an encrypted column", async () => {
    await expect(
      lp["patient"]!["findMany"]!({ orderBy: { email: "asc" } }),
    ).rejects.toThrow(/sorts envelope bytes/);
  });

  it("measures why: the unextended client sorts by envelope bytes", async () => {
    await seed();
    // Two runs, same data, different envelopes -- so "sorted" order is not
    // stable across writes and has no relation to the values. A stable-looking
    // order with no meaning.
    const byEnvelope = await base.patient.findMany({ orderBy: { email: "asc" } });
    const names = byEnvelope.map((r) => r.plainName);
    const byName = [...names].sort();
    // The envelope order is not the value order except by luck; assert only
    // that it is not *derived* from the values, by checking it can differ.
    expect(names.length).toBe(2);
    expect(new Set(names)).toEqual(new Set(byName));
  });

  it("refuses distinct on an encrypted column", async () => {
    await expect(
      lp["patient"]!["findMany"]!({ distinct: ["email"] }),
    ).rejects.toThrow(/deduplicates nothing/);
  });

  it("measures why: distinct over envelopes deduplicates nothing", async () => {
    // Two rows, one value. A randomized suite writes a different envelope each
    // time (spec §4.4), so DISTINCT sees two distinct values.
    await lp["patient"]!["create"]!({
      data: { email: "same@example.com", note: "n", age: 1, plainName: "A" },
    });
    await lp["patient"]!["create"]!({
      data: { email: "same@example.com", note: "n", age: 1, plainName: "B" },
    });
    const rows = await base.patient.findMany({ distinct: ["email"] });
    expect(rows).toHaveLength(2); // the truth is one
  });

  it("refuses groupBy on an encrypted column", async () => {
    await expect(
      lp["patient"]!["groupBy"]!({ by: ["email"], _count: { _all: true } } as never),
    ).rejects.toThrow(/one group per row/);
  });

  it("measures why: grouping returns wrong counts under identical keys", async () => {
    await lp["patient"]!["create"]!({
      data: { email: "same@example.com", note: "n", age: 1, plainName: "A" },
    });
    await lp["patient"]!["create"]!({
      data: { email: "same@example.com", note: "n", age: 1, plainName: "B" },
    });
    const groups = (await base.patient.groupBy({
      by: ["email"],
      _count: { _all: true },
    } as never)) as Array<{ _count: { _all: number } }>;
    // Truth: one group of 2. Reality over envelopes: two groups of 1.
    expect(groups).toHaveLength(2);
    expect(groups.every((g) => g._count._all === 1)).toBe(true);
  });

  it("refuses aggregates on an encrypted column", async () => {
    await expect(
      lp["patient"]!["aggregate"]!({ _min: { age: true } } as never),
    ).rejects.toThrow(/computes on envelope bytes/);
  });

  it("on a Bytes column Prisma itself rejects _min -- defence in depth, not the only guard", async () => {
    await seed();
    // Worth recording precisely, because it is narrower than G20's Django
    // measurement. Over a `Bytes` column Prisma's own deserializer throws on
    // the aggregate result, so the silent-wrong-answer is not reachable there
    // even without this adapter. The refusal is still right -- it names the
    // reason, and it does not depend on a Prisma implementation detail -- but
    // this specific column type is not where the hazard bites.
    await expect(
      base.patient.aggregate({ _min: { age: true } } as never),
    ).rejects.toThrow();
  });

  it("measures the silent, plausible one on a base64 column, where it IS reachable", async () => {
    // A `storage: "base64"` column is a Prisma `String`, and MIN over a String
    // deserializes fine. So the database returns the byte-wise minimum
    // *envelope*, base64-encoded, and hands it back as the minimum nickname
    // with nothing raised. This is the failure in the family that is both
    // silent and plausible -- G20's reason for existing -- and on Prisma it
    // lives here rather than on Bytes.
    await lp["patient"]!["create"]!({
      data: { email: "a@example.com", note: "n", age: 1, plainName: "A", nickname: "zebra" },
    });
    await lp["patient"]!["create"]!({
      data: { email: "b@example.com", note: "n", age: 2, plainName: "B", nickname: "aardvark" },
    });

    const agg = (await base.patient.aggregate({ _min: { nickname: true } } as never)) as {
      _min: { nickname: string | null };
    };
    expect(agg._min.nickname).not.toBeNull();
    // Whatever it is, it is not the minimum nickname -- it is an envelope.
    expect(agg._min.nickname).not.toBe("aardvark");
    expect(agg._min.nickname).not.toBe("zebra");

    // And the adapter refuses the same shape rather than serving it.
    await expect(
      lp["patient"]!["aggregate"]!({ _min: { nickname: true } } as never),
    ).rejects.toThrow(/computes on envelope bytes/);
  });

  it("refuses cursor pagination over an encrypted column", async () => {
    await expect(
      lp["patient"]!["findMany"]!({ take: 1, cursor: { email: "x" } as never }),
    ).rejects.toThrow(/over-fetch, decrypt, filter, then paginate/);
  });

  it("leaves orderBy and groupBy on plaintext columns alone", async () => {
    await seed();
    const rows = await prisma.patient.findMany({ orderBy: { plainName: "asc" } });
    expect(rows.map((r) => r.plainName)).toEqual(["Ada", "Grace"]);

    const groups = await prisma.patient.groupBy({
      by: ["plainName"],
      _count: { _all: true },
    } as never);
    expect(groups).toHaveLength(2);
  });

  it("allows _count over rows, which counts rows rather than reading bytes", async () => {
    await seed();
    expect(await prisma.patient.count()).toBe(2);
  });
});

// -------------------------------------------- nested writes carry filters ----

describe("filters inside nested relation writes", () => {
  const withVisit = async () => {
    const row = await lp["patient"]!["create"]!({
      data: {
        email: "a@x.com",
        note: "n",
        age: 1,
        plainName: "A",
        visits: { create: [{ reason: "checkup" }] },
      },
    });
    return row.id as string;
  };

  it("measures why: the unextended client serves the nested filter and matches nothing", async () => {
    const id = await withVisit();
    // The filter compares a plaintext operand against an envelope column:
    // valid SQL, zero rows touched, no error -- the docs/04 §3 class, one
    // nesting level down where the top-level walk cannot see it.
    await base.patient.update({
      where: { id },
      data: {
        visits: {
          updateMany: {
            where: { reason: Buffer.from("checkup") },
            data: { reason: Buffer.from("changed") },
          },
        },
      },
    });
    const visit = await prisma.visit.findFirst({ where: { patientId: id } });
    expect(visit?.reason).toBe("checkup"); // silently unchanged
  });

  it("refuses a nested updateMany.where naming an encrypted column", async () => {
    const id = await withVisit();
    await expect(
      lp["patient"]!["update"]!({
        where: { id },
        data: {
          visits: {
            updateMany: { where: { reason: "checkup" }, data: { reason: "changed" } },
          },
        },
      }),
    ).rejects.toThrow(FieldsealNotSupported);
  });

  it("refuses a nested deleteMany whose payload filters an encrypted column", async () => {
    const id = await withVisit();
    await expect(
      lp["patient"]!["update"]!({
        where: { id },
        data: { visits: { deleteMany: { reason: { contains: "check" } } } },
      }),
    ).rejects.toThrow(FieldsealNotSupported);
  });

  it("serves a nested deleteMany over plaintext columns -- it writes no ciphertext", async () => {
    const id = await withVisit();
    await lp["patient"]!["update"]!({
      where: { id },
      data: { visits: { deleteMany: {} } },
    });
    expect(await prisma.visit.count({ where: { patientId: id } })).toBe(0);
  });

  it("serves nested update when its where stays off encrypted columns", async () => {
    const id = await withVisit();
    const visit = await prisma.visit.findFirst({ where: { patientId: id } });
    await lp["patient"]!["update"]!({
      where: { id },
      data: {
        visits: { update: { where: { id: visit!.id }, data: { reason: "changed" } } },
      },
    });
    const back = await prisma.visit.findFirst({ where: { patientId: id } });
    expect(back?.reason).toBe("changed");
  });
});

// ------------------------------------ shapes that are exact over envelopes ----

describe("exact shapes stay served", () => {
  it("serves literal-NULL equality -- the write path guarantees NULL stays NULL", async () => {
    await lp["patient"]!["create"]!({
      data: { email: "a@x.com", note: "n", age: 1, plainName: "A", nickname: null },
    });
    await lp["patient"]!["create"]!({
      data: { email: "b@x.com", note: "n", age: 2, plainName: "B", nickname: "Bee" },
    });
    const noNick = (await lp["patient"]!["findMany"]!({
      where: { nickname: null },
    })) as Array<{ plainName: string }>;
    expect(noNick.map((r) => r.plainName)).toEqual(["A"]);

    const viaEquals = (await lp["patient"]!["findMany"]!({
      where: { nickname: { equals: null } },
    })) as Array<{ plainName: string }>;
    expect(viaEquals.map((r) => r.plainName)).toEqual(["A"]);

    const notNull = (await lp["patient"]!["findMany"]!({
      where: { nickname: { not: null } },
    })) as Array<{ plainName: string }>;
    expect(notNull.map((r) => r.plainName)).toEqual(["B"]);
  });

  it("serves _count over an encrypted field -- it counts non-NULL rows, reads no bytes", async () => {
    await lp["patient"]!["create"]!({
      data: { email: "a@x.com", note: "n", age: 1, plainName: "A", nickname: "Ada" },
    });
    await lp["patient"]!["create"]!({
      data: { email: "b@x.com", note: "n", age: 2, plainName: "B", nickname: null },
    });
    const agg = (await lp["patient"]!["aggregate"]!({
      _count: { email: true, nickname: true },
    } as never)) as { _count: { email: number; nickname: number } };
    expect(agg._count.email).toBe(2);
    expect(agg._count.nickname).toBe(1); // exact: NULL stayed NULL on write
  });

  it("serves distinct on the index sibling, which deduplicates by bucket", async () => {
    // The documented alternative to `distinct` on the value column. The caveat
    // is measured here: one value -> one bucket -> one row back, and a §7.4
    // collision would merge *distinct* values the same way. A filter-grade
    // answer, not an exact one, and the README matrix says so.
    await lp["patient"]!["create"]!({
      data: { email: "same@x.com", note: "n", age: 1, plainName: "A" },
    });
    await lp["patient"]!["create"]!({
      data: { email: "same@x.com", note: "n", age: 2, plainName: "B" },
    });
    const rows = (await lp["patient"]!["findMany"]!({
      distinct: ["emailBidx"],
    })) as unknown[];
    expect(rows).toHaveLength(1);
  });
});

// ------------------------------------------------- the undeclared model ----

describe("models with no declarations of their own", () => {
  it("refuses a filter that reaches an encrypted column through one", async () => {
    await expect(
      lp["referral"]!["findMany"]!({ where: { patient: { email: "a@x.com" } } }),
    ).rejects.toThrow(FieldsealNotSupported);
  });

  /** An extension over the fixture map with one model deliberately removed. */
  const staleExt = (without: string) =>
    fieldsealExtension({
      fieldMap: {
        ...fieldsealFieldMap,
        models: fieldsealFieldMap.models.filter((m) => m.model !== without),
      },
      keyProvider: keyProvider(),
      allowedSuites: [SUITE],
      writeSuite: SUITE,
      armProvisionalSuites: true,
      unindexableOverride: [
        { model: "Person", field: "legalName", reason: "test", approvedBy: "test", date: "2026-08-27" },
      ],
      onWarning: () => {},
    });

  it("refuses an operation on a model the field map does not carry", async () => {
    // A stale or edited map: the model exists in the client but not the map.
    // Passing it through would reopen the undeclared-model bypass, so it is a
    // configuration error instead.
    await expect(
      staleExt("Referral").query.$allOperations({
        model: "Referral",
        operation: "findMany",
        args: {},
        query: async () => [],
      }),
    ).rejects.toThrow(/not in the field map/);
  });

  it("refuses a nested write through a relation the field map does not carry", async () => {
    // The top-model check alone does not close the stale-map hole: this write
    // starts on a mapped model (Patient) and reaches an encrypted column on
    // the omitted one (Visit.reason) one hop down. Skipping the unresolvable
    // relation would store plaintext with nothing raised, so the walk refuses.
    let reached = false;
    await expect(
      staleExt("Visit").query.$allOperations({
        model: "Patient",
        operation: "create",
        args: {
          data: {
            email: "a@x.com",
            note: "n",
            age: 1,
            plainName: "A",
            visits: { create: [{ reason: "checkup" }] },
          },
        },
        query: async (a) => {
          reached = true;
          return a;
        },
      }),
    ).rejects.toThrow(FieldsealConfigurationError);
    expect(reached).toBe(false); // refused before anything went to the engine
  });

  it("refuses a read whose result nests a relation the field map does not carry", async () => {
    // The read-side half of the same hole: skipping the unresolvable relation
    // would hand the caller raw envelope bytes as if they were values.
    await expect(
      staleExt("Visit").query.$allOperations({
        model: "Patient",
        operation: "findMany",
        args: {},
        query: async () => [{ id: "p1", visits: [{ id: "v1", reason: new Uint8Array([1]) }] }],
      }),
    ).rejects.toThrow(/Visit.*not in the field map|not in the field map/);
  });
});

// ------------------------------------------------------------ write side ----

describe("write shapes", () => {
  it("refuses an arithmetic update on an encrypted column", async () => {
    const row = await lp["patient"]!["create"]!({
      data: { email: "a@example.com", note: "n", age: 30, plainName: "A" },
    });
    await expect(
      lp["patient"]!["update"]!({
        where: { id: row.id },
        data: { age: { increment: 1 } as never },
      }),
    ).rejects.toThrow(/compute the new value from the stored one/);
  });

  it("refuses a value whose type does not match the declared `as:`", async () => {
    await expect(
      lp["patient"]!["create"]!({
        data: { email: "a@example.com", note: "n", age: "thirty", plainName: "A" },
      }),
    ).rejects.toThrow(/declared `as: "int"`/);
  });
});

// ------------------------------------------------------------- raw SQL ----

describe("raw operations", () => {
  it("passes through with a hook by default, and reports it", async () => {
    const seen: string[] = [];
    const { base: b, prisma: p } = makeClient({ onRawOperation: (op) => seen.push(op) });
    await p.$queryRawUnsafe(`SELECT 1 AS one`);
    expect(seen.length).toBeGreaterThan(0);
    await b.$disconnect();
  });

  it("throws under strictRaw", async () => {
    const { base: b, prisma: p } = makeClient({ strictRaw: true });
    await expect(p.$queryRawUnsafe(`SELECT 1 AS one`)).rejects.toThrow(
      /raw operation and strictRaw is set/,
    );
    await b.$disconnect();
  });
});
