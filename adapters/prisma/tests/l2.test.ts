/**
 * L2(b): the index rewrite and the spec §7.5 re-verification that makes it
 * correct.
 *
 * The two halves are tested against each other, because neither is worth
 * anything alone: the rewrite without re-verification returns §7.4 collision
 * rows as matches, and re-verification without the rewrite has nothing to
 * narrow. Every "measures why" test below runs the same query inside
 * `candidateScope()` -- which is exactly the rewrite with §7.5 switched off --
 * so the wrong answer is in the file beside the right one rather than described
 * in a comment.
 *
 * Collisions are **forged**, not waited for: the index is truncated to 15 bits
 * (spec §7.4's band for P = 100,000), so a natural collision is not
 * reproducible in a three-row fixture. Writing one row's index value onto
 * another through the *unextended* client presents the extension with exactly
 * what the database would present -- a bucket holding a row whose plaintext
 * differs.
 */

import { afterAll, beforeEach, describe, expect, it } from "vitest";

import { candidateScope, FieldsealNotSupported } from "../src/index.ts";
import { clearDb, loose, makeClient, rawColumn } from "./helpers.ts";

const { base, prisma } = makeClient();
const lp = loose(prisma);

beforeEach(async () => {
  await clearDb(base);
});
afterAll(async () => {
  await base.$disconnect();
});

const patient = (email: string, plainName: string) => ({
  email,
  note: "n",
  age: 1,
  plainName,
});

async function seed() {
  const ada = await lp["patient"]!["create"]!({ data: patient("ada@example.com", "1-ada") });
  const grace = await lp["patient"]!["create"]!({ data: patient("grace@example.com", "0-grace") });
  const alan = await lp["patient"]!["create"]!({ data: patient("alan@example.com", "2-alan") });
  return { ada: ada.id as string, grace: grace.id as string, alan: alan.id as string };
}

/**
 * Write `like`'s index value onto `onto`, through the unextended client.
 *
 * The base client bypasses the whole pipeline, which is the point: this is the
 * database's state, not something the adapter could have produced.
 */
async function forge(table: "Patient" | "Visit", column: string, onto: string, like: string) {
  const value = (await rawColumn(base, table, column, like)) as Uint8Array;
  await base.$executeRawUnsafe(
    `UPDATE "${table}" SET "${column}" = ? WHERE "id" = ?`,
    Buffer.from(value),
    onto,
  );
}

const names = (rows: unknown): string[] =>
  (rows as Array<{ plainName: string }>).map((r) => r.plainName).sort();

// --------------------------------------------------------- the rewrite ----

describe("the rewrite: equality and membership onto the sibling index", () => {
  it("finds the row by its plaintext value", async () => {
    await seed();
    const rows = await lp["patient"]!["findMany"]!({ where: { email: "ada@example.com" } });
    expect(names(rows)).toEqual(["1-ada"]);
    expect((rows as Array<{ email: string }>)[0]?.email).toBe("ada@example.com");
  });

  it("finds nothing for a value nobody holds", async () => {
    await seed();
    expect(
      await lp["patient"]!["findMany"]!({ where: { email: "nobody@example.com" } }),
    ).toHaveLength(0);
  });

  it("serves `equals` the same as the shorthand", async () => {
    await seed();
    const rows = await lp["patient"]!["findMany"]!({
      where: { email: { equals: "ada@example.com" } },
    });
    expect(names(rows)).toEqual(["1-ada"]);
  });

  it("rewrites `in` as spec §7.10 membership", async () => {
    await seed();
    const rows = await lp["patient"]!["findMany"]!({
      where: { email: { in: ["ada@example.com", "alan@example.com"] } },
    });
    expect(names(rows)).toEqual(["1-ada", "2-alan"]);
  });

  it("keeps `in: []` matching nothing, as SQL does", async () => {
    await seed();
    expect(await lp["patient"]!["findMany"]!({ where: { email: { in: [] } } })).toHaveLength(0);
  });

  it("drops a NULL target from `in`, because SQL IN never matches NULL", async () => {
    await seed();
    const rows = await lp["patient"]!["findMany"]!({
      where: { email: { in: [null, "ada@example.com"] } },
    });
    expect(names(rows)).toEqual(["1-ada"]);
  });

  it("the predicate that reaches the engine names the sibling, never the envelope column", async () => {
    await seed();
    // Registered *after* fieldseal, so it sits inside it and sees what the
    // extension produced. (Deployments must register fieldseal last, for the
    // opposite reason: everything else should see plaintext.)
    const seen: string[][] = [];
    const inner = (prisma as unknown as { $extends: (e: unknown) => unknown }).$extends({
      name: "inner-spy",
      query: {
        async $allOperations({ args, query }: never) {
          const where = (args as { where?: Record<string, unknown> }).where;
          seen.push(Object.keys(where ?? {}));
          return (query as (x: unknown) => Promise<unknown>)(args);
        },
      },
    }) as Record<string, Record<string, (a?: unknown) => Promise<unknown>>>;

    await inner["patient"]!["findMany"]!({ where: { email: "ada@example.com" } });
    expect(seen[0]).toEqual(["emailBidx"]);
    expect(seen[0]).not.toContain("email");
  });

  it("serves `AND` over an encrypted term", async () => {
    await seed();
    const rows = await lp["patient"]!["findMany"]!({
      where: { AND: [{ email: "ada@example.com" }, { plainName: "1-ada" }] },
    });
    expect(names(rows)).toEqual(["1-ada"]);
  });

  it("leaves the exact NULL forms on the envelope column beside the rewrite", async () => {
    // `{ equals: …, not: null }` is one filter with two parts: the equality is
    // rewritten onto the sibling, and IS NOT NULL stays on the envelope column,
    // where §10.2's NULL-preservation invariant makes it exact. Prisma only
    // accepts `not: null` on a nullable column, so this is `nickname`.
    await lp["patient"]!["create"]!({ data: { ...patient("a@x.com", "has"), nickname: "Ada" } });
    await lp["patient"]!["create"]!({ data: { ...patient("b@x.com", "none"), nickname: null } });
    const rows = await lp["patient"]!["findMany"]!({
      where: { nickname: { equals: "Ada", not: null } },
    });
    expect(names(rows)).toEqual(["has"]);
  });

  it("serves a bare `not: null` with no rewrite at all", async () => {
    await lp["patient"]!["create"]!({ data: { ...patient("a@x.com", "has"), nickname: "Ada" } });
    await lp["patient"]!["create"]!({ data: { ...patient("b@x.com", "none"), nickname: null } });
    const rows = await lp["patient"]!["findMany"]!({ where: { nickname: { not: null } } });
    expect(names(rows)).toEqual(["has"]);
  });

  it("serves an equality on a base64-stored column, whose index sibling is still raw bytes", async () => {
    // Spec §7.11: the index column is compared, not round-tripped, so it is
    // `Bytes` even where the value column is text.
    await lp["patient"]!["create"]!({ data: { ...patient("a@x.com", "has"), nickname: "Ada" } });
    const rows = await lp["patient"]!["findMany"]!({ where: { nickname: "Ada" } });
    expect(names(rows)).toEqual(["has"]);
  });
});

// ------------------------------------------------- the one equality (G19) ----

describe("equality is the index's own equality (spec §7.5, G19)", () => {
  it("a query for the lowercase value returns the row stored mixed-case", async () => {
    // The consequence spec §7.5 requires adapters to document: on a column
    // declaring `nfc-casefold-v1`, an equality lookup is equality *under that
    // normalizer*. The index already merged these; un-merging them here would
    // leave the caseless lookup the normalizer exists to enable unreachable.
    await lp["patient"]!["create"]!({ data: patient("Ada@Example.COM", "mixed") });
    const rows = await lp["patient"]!["findMany"]!({ where: { email: "ada@example.com" } });
    expect(names(rows)).toEqual(["mixed"]);
    expect((rows as Array<{ email: string }>)[0]?.email).toBe("Ada@Example.COM");
  });

  it("and the reverse, so verification did not quietly become byte equality", async () => {
    await lp["patient"]!["create"]!({ data: patient("ada@example.com", "lower") });
    const rows = await lp["patient"]!["findMany"]!({ where: { email: "ADA@EXAMPLE.COM" } });
    expect(names(rows)).toEqual(["lower"]);
  });
});

// ------------------------------------------- the §7.5 half: what shrinks ----

describe("re-verification drops the §7.4 collisions", () => {
  it("returns only the true match when the bucket holds another row", async () => {
    const ids = await seed();
    await forge("Patient", "emailBidx", ids.grace, ids.ada);

    const verified = await lp["patient"]!["findMany"]!({ where: { email: "ada@example.com" } });
    expect(names(verified)).toEqual(["1-ada"]);
  });

  it("measures why: the same query with §7.5 off returns the collision too", async () => {
    const ids = await seed();
    await forge("Patient", "emailBidx", ids.grace, ids.ada);

    const candidates = await candidateScope(() =>
      lp["patient"]!["findMany"]!({ where: { email: "ada@example.com" } }),
    );
    expect(names(candidates)).toEqual(["0-grace", "1-ada"]);
  });

  it("verifies each target of an `in`, not just the first", async () => {
    const ids = await seed();
    await forge("Patient", "emailBidx", ids.grace, ids.alan);
    const rows = await lp["patient"]!["findMany"]!({
      where: { email: { in: ["ada@example.com", "alan@example.com"] } },
    });
    expect(names(rows)).toEqual(["1-ada", "2-alan"]);
  });

  it("keeps the collision row findable by its own value", async () => {
    // Verification drops rows from *this* answer; it does not damage the row.
    const ids = await seed();
    await forge("Patient", "emailBidx", ids.grace, ids.ada);
    const rows = await lp["patient"]!["findMany"]!({ where: { email: "grace@example.com" } });
    // Grace's own index value was overwritten by the forge, so the bucket no
    // longer contains her -- which is what a forged collision *is*. The point
    // is that nothing was corrupted: the row still decrypts.
    expect(rows).toHaveLength(0);
    const all = await lp["patient"]!["findMany"]!({ where: { plainName: "0-grace" } });
    expect((all as Array<{ email: string }>)[0]?.email).toBe("grace@example.com");
  });
});

// ------------------------------- two operators on one field (conjunction) ----

describe("two rewritable operators on one field stay a conjunction", () => {
  // Prisma reads `{ equals: A, in: [...] }` as A AND membership, and the
  // rewrite compiles it that way. §7.5 must verify the same conjunction: one
  // obligation *per operator*, never a union of their targets -- a union would
  // verify the disjunction, and the case where that difference is observable
  // is exactly a §7.4 collision between the two operators' targets (below).

  it("serves the satisfiable conjunction", async () => {
    await seed();
    const rows = await lp["patient"]!["findMany"]!({
      where: { email: { equals: "ada@example.com", in: ["ada@example.com", "alan@example.com"] } },
    });
    expect(names(rows)).toEqual(["1-ada"]);
  });

  // `COLLIDER` was found by brute force over the fixture's fixed keys: its
  // 15-bit index value equals ada@example.com's (spec §7.4 mandates such pairs
  // to exist; the fixture's truncation makes one findable in ~2^15 tries).
  // The first test below re-derives both stored values and asserts they still
  // collide, so a key or schema change fails loudly here instead of quietly
  // turning the conjunction test into a vacuous empty-SQL-result test.
  const COLLIDER = "c26819@example.com";

  async function seedCollidingPair() {
    const ada = await lp["patient"]!["create"]!({ data: patient("ada@example.com", "1-ada") });
    const other = await lp["patient"]!["create"]!({ data: patient(COLLIDER, "0-collider") });
    const a = Buffer.from((await rawColumn(base, "Patient", "emailBidx", ada.id as string)) as Uint8Array);
    const b = Buffer.from((await rawColumn(base, "Patient", "emailBidx", other.id as string)) as Uint8Array);
    expect(a.equals(b), "fixture drift: COLLIDER no longer collides -- re-derive it").toBe(true);
  }

  it("a §7.4 collision between the two operators' targets cannot smuggle a row through", async () => {
    // email = ada AND email IN (collider): no value satisfies both, so the
    // verified answer is [] -- but because the two targets share one index
    // value, the rewritten SQL returns the whole bucket. An obligation that
    // unioned the targets would accept both rows as verified matches.
    await seedCollidingPair();
    const rows = await lp["patient"]!["findMany"]!({
      where: { email: { equals: "ada@example.com", in: [COLLIDER] } },
    });
    expect(rows).toHaveLength(0);
  });

  it("measures why: with §7.5 off the SQL admits the whole shared bucket", async () => {
    await seedCollidingPair();
    const candidates = await candidateScope(() =>
      lp["patient"]!["findMany"]!({
        where: { email: { equals: "ada@example.com", in: [COLLIDER] } },
      }),
    );
    expect(names(candidates)).toEqual(["0-collider", "1-ada"]);
  });
});

// ------------------------------------------ the bucket (docs/09 §7.2) ----

describe("bucketed unindexable values are separated by §7.5's raw-bytes fallback", () => {
  // U+0378 is unassigned in every published Unicode version, so the normalizer
  // refuses it and `Person.legalName` (on_unindexable: "bucket") stores the
  // column's reserved marker for both of these. SQL cannot tell them apart.
  const A = "X͸Y";
  const B = "Z͸W";

  it("returns only the queried value, though both share one index value", async () => {
    await lp["person"]!["create"]!({ data: { legalName: A } });
    await lp["person"]!["create"]!({ data: { legalName: B } });

    const rows = await lp["person"]!["findMany"]!({ where: { legalName: A } });
    expect((rows as Array<{ legalName: string }>).map((r) => r.legalName)).toEqual([A]);
  });

  it("measures why the fallback is load-bearing: the bucket holds both", async () => {
    await lp["person"]!["create"]!({ data: { legalName: A } });
    await lp["person"]!["create"]!({ data: { legalName: B } });

    const candidates = await candidateScope(() =>
      lp["person"]!["findMany"]!({ where: { legalName: A } }),
    );
    expect((candidates as Array<{ legalName: string }>).map((r) => r.legalName).sort()).toEqual(
      [A, B].sort(),
    );
  });
});

// ------------------------------------------------ the nested `where` site ----

describe("a relation `where` under include/select is the second verifiable site", () => {
  async function withVisits() {
    const row = await lp["patient"]!["create"]!({
      data: {
        ...patient("p@example.com", "P"),
        visits: { create: [{ reason: "checkup" }, { reason: "followup" }] },
      },
    });
    const visits = await base.visit.findMany({ where: { patientId: row.id as string } });
    const byReason = async (want: string) => {
      for (const v of visits) {
        // Read back through the extension so the comparison is against the
        // decrypted value; Prisma's generated type still says `Bytes`.
        const back = (await lp["visit"]!["findUnique"]!({ where: { id: v.id } })) as {
          reason?: string;
        };
        if (back.reason === want) return v.id;
      }
      throw new Error(`no visit with reason ${want}`);
    };
    return { patientId: row.id as string, checkup: await byReason("checkup"), followup: await byReason("followup") };
  }

  it("filters the nested rows and re-verifies them", async () => {
    const { followup, checkup } = await withVisits();
    await forge("Visit", "reasonBidx", followup, checkup);

    const rows = (await lp["patient"]!["findMany"]!({
      where: { plainName: "P" },
      include: { visits: { where: { reason: "checkup" } } },
    })) as unknown as Array<{ visits: Array<{ reason: string }> }>;

    expect(rows[0]!.visits.map((v) => v.reason)).toEqual(["checkup"]);
  });

  it("measures why: with §7.5 off the collision comes back nested too", async () => {
    const { followup, checkup } = await withVisits();
    await forge("Visit", "reasonBidx", followup, checkup);

    const rows = (await candidateScope(() =>
      lp["patient"]!["findMany"]!({
        where: { plainName: "P" },
        include: { visits: { where: { reason: "checkup" } } },
      }),
    )) as unknown as Array<{ visits: Array<{ reason: string }> }>;

    expect(rows[0]!.visits.map((v) => v.reason).sort()).toEqual(["checkup", "followup"]);
  });

  it("a `take` on the *parent* is fine: dropping child rows cannot change which parents matched", async () => {
    await withVisits();
    const rows = (await lp["patient"]!["findMany"]!({
      take: 1,
      include: { visits: { where: { reason: "checkup" } } },
    })) as unknown as Array<{ visits: unknown[] }>;
    expect(rows).toHaveLength(1);
    expect(rows[0]!.visits).toHaveLength(1);
  });

  it("verifies through a to-one hop in the path", async () => {
    const { followup, checkup } = await withVisits();
    await forge("Visit", "reasonBidx", followup, checkup);

    const rows = (await lp["visit"]!["findMany"]!({
      where: { id: checkup },
      include: { patient: { include: { visits: { where: { reason: "checkup" } } } } },
    })) as unknown as Array<{ patient: { visits: Array<{ reason: string }> } }>;

    expect(rows[0]!.patient.visits.map((v) => v.reason)).toEqual(["checkup"]);
  });

  it("still serves the nested filter under an operation that returns one row", async () => {
    // `findFirst`'s own LIMIT 1 is the hazard; a nested relation array under it
    // still materializes in full, so the nested obligation is dischargeable.
    await withVisits();
    const row = (await lp["patient"]!["findFirst"]!({
      where: { plainName: "P" },
      include: { visits: { where: { reason: "checkup" } } },
    })) as unknown as { visits: Array<{ reason: string }> };
    expect(row.visits.map((v) => v.reason)).toEqual(["checkup"]);
  });

  it("does not run findUnique's unique-input refusal against a nested include", async () => {
    // The nested walk used to inherit the operation name, so a nested `where`
    // on an encrypted column was reported as "findUnique requires a unique
    // column" -- the wrong refusal, and now the wrong answer as well, since
    // the nested site is serveable.
    const { patientId } = await withVisits();
    const row = (await lp["patient"]!["findUnique"]!({
      where: { id: patientId },
      include: { visits: { where: { reason: "checkup" } } },
    })) as unknown as { visits: Array<{ reason: string }> };
    expect(row.visits.map((v) => v.reason)).toEqual(["checkup"]);
  });
});

// ------------------------------------------------------- the projection ----

describe("§7.5 needs the column it is verifying against", () => {
  it("refuses a `select` that projects the encrypted column away", async () => {
    await seed();
    await expect(
      lp["patient"]!["findMany"]!({ where: { email: "ada@example.com" }, select: { id: true } }),
    ).rejects.toThrow(/there is nothing to compare/);
  });

  it("serves a `select` that keeps it", async () => {
    await seed();
    const rows = await lp["patient"]!["findMany"]!({
      where: { email: "ada@example.com" },
      select: { id: true, email: true },
    });
    expect(rows).toHaveLength(1);
  });

  it("refuses a query-level `omit` of the encrypted column", async () => {
    await seed();
    await expect(
      lp["patient"]!["findMany"]!({
        where: { email: "ada@example.com" },
        omit: { email: true },
      }),
    ).rejects.toThrow(FieldsealNotSupported);
  });

  it("refuses a *client-level* omit, which never appears in the arguments at all", async () => {
    // Measured against Prisma 7.10.0: with `new PrismaClient({ omit: { patient:
    // { email: true } } })` the operation arrives as a bare `{ where }` and the
    // row comes back without the key. This is the case the check on the result
    // exists for -- no argument-side check can see it.
    const { base: b2, prisma: p2 } = makeClient({}, { omit: { patient: { email: true } } });
    const l2 = loose(p2);
    await l2["patient"]!["create"]!({ data: patient("ada@example.com", "1-ada") });
    await expect(
      l2["patient"]!["findMany"]!({ where: { email: "ada@example.com" } }),
    ).rejects.toThrow(/client-level `omit: \{ patient/);
    await b2.$disconnect();
  });
});
