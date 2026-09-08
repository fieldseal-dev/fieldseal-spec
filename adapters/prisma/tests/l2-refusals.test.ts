/**
 * The LIMIT audit: everything the database answers before spec §7.5 can run.
 *
 * `docs/07` §7 records five classes of silent-wrong-answer path the Django L2
 * round found by asking one question -- *who applies a LIMIT before §7.5
 * runs?* -- and the plan for this adapter recorded that the question had never
 * been re-asked of Prisma. `docs/13` §2.0 is the measured answer; this file is
 * the audit as tests.
 *
 * Prisma's answer is narrower than Django's, because a Prisma extension cannot
 * turn one operation into another. Django could *serve* `count()`, `exists()`,
 * `get()` and `first()` by materializing the bucket itself. Here `query` is
 * bound to the operation it was called for, so an operation whose result is a
 * computed answer rather than rows cannot be verified at all -- it is refused,
 * and the message says what to run instead.
 *
 * Every refusal below is paired with a **measurement** wherever the wrong
 * answer can be produced, and it can be produced for almost all of them:
 * `candidateScope()` is precisely this rewrite with §7.5 switched off, so the
 * answer the refusal prevents is one line away and is asserted rather than
 * described.
 */

import { afterAll, beforeEach, describe, expect, it } from "vitest";

import { candidateScope, FieldsealNotSupported } from "../src/index.ts";
import { clearDb, loose, makeClient, rawColumn, setColumn } from "./helpers.ts";

const { base, prisma } = makeClient();
const lp = loose(prisma);

beforeEach(async () => {
  await clearDb(base);
});
afterAll(async () => {
  await base.$disconnect();
});

const ADA = "ada@example.com";

const patient = (email: string, plainName: string) => ({ email, note: "n", age: 1, plainName });

/**
 * Three rows, with `0-grace` forged into `1-ada`'s index bucket while holding a
 * different value -- exactly the state spec §7.4 says the bucket will reach on
 * its own at scale. `0-grace` sorts first, so any shape that lets the database
 * pick returns *her*.
 */
async function seedWithCollision() {
  const ada = await lp["patient"]!["create"]!({ data: patient(ADA, "1-ada") });
  const grace = await lp["patient"]!["create"]!({ data: patient("grace@example.com", "0-grace") });
  await lp["patient"]!["create"]!({ data: patient("alan@example.com", "2-alan") });
  const value = (await rawColumn(base, "Patient", "emailBidx", ada.id as string)) as Uint8Array;
  await setColumn(base, "Patient", "emailBidx", grace.id as string, Buffer.from(value));
  return { ada: ada.id as string, grace: grace.id as string };
}

// ------------------------------- operations whose answer is not a row set ----

describe("operations the database answers", () => {
  const shapes: Array<[string, () => Promise<unknown>]> = [
    ["findFirst", () => lp["patient"]!["findFirst"]!({ where: { email: ADA } })],
    ["findFirstOrThrow", () => lp["patient"]!["findFirstOrThrow"]!({ where: { email: ADA } })],
    ["count", () => lp["patient"]!["count"]!({ where: { email: ADA } })],
    [
      "aggregate",
      () => lp["patient"]!["aggregate"]!({ where: { email: ADA }, _count: { _all: true } }),
    ],
    [
      "groupBy",
      () =>
        lp["patient"]!["groupBy"]!({
          by: ["plainName"],
          where: { email: ADA },
          _count: { _all: true },
        }),
    ],
    [
      "updateMany",
      () => lp["patient"]!["updateMany"]!({ where: { email: ADA }, data: { plainName: "x" } }),
    ],
    ["deleteMany", () => lp["patient"]!["deleteMany"]!({ where: { email: ADA } })],
    [
      "update",
      () => lp["patient"]!["update"]!({ where: { id: "p", email: ADA }, data: { plainName: "x" } }),
    ],
    ["delete", () => lp["patient"]!["delete"]!({ where: { id: "p", email: ADA } })],
    [
      "upsert",
      () =>
        lp["patient"]!["upsert"]!({
          where: { id: "p", email: ADA },
          create: patient(ADA, "x"),
          update: { plainName: "x" },
        }),
    ],
  ];

  for (const [name, run] of shapes) {
    it(`refuses \`${name}\` filtered by an encrypted column`, async () => {
      await seedWithCollision();
      await expect(run()).rejects.toThrow(FieldsealNotSupported);
    });
  }

  it("names findFirst's invisible LIMIT, not a generic 'unsupported'", async () => {
    await expect(
      lp["patient"]!["findFirst"]!({ where: { email: ADA } }),
    ).rejects.toThrow(/LIMIT 1 below the extension[\s\S]*must be 1 or -1/);
  });

  it("measures why findFirst is refused: it returns the collision, not the match", async () => {
    await seedWithCollision();
    const wrong = (await candidateScope(() =>
      lp["patient"]!["findFirst"]!({ where: { email: ADA }, orderBy: { plainName: "asc" } }),
    )) as { plainName: string; email: string };
    // The database picked the first row of the §7.4 bucket. It decrypts
    // cleanly, it is a real row, and it is not the row asked for.
    expect(wrong.plainName).toBe("0-grace");
    expect(wrong.email).toBe("grace@example.com");
  });

  it("measures why count is refused: it counts the bucket", async () => {
    await seedWithCollision();
    const bucket = await candidateScope(() => lp["patient"]!["count"]!({ where: { email: ADA } }));
    const verified = await lp["patient"]!["findMany"]!({ where: { email: ADA } });
    expect(bucket).toBe(2);
    expect(verified).toHaveLength(1);
  });

  it("measures why deleteMany is refused: it deletes rows that do not match", async () => {
    await seedWithCollision();
    const { count } = (await candidateScope(() =>
      lp["patient"]!["deleteMany"]!({ where: { email: ADA } }),
    )) as { count: number };
    expect(count).toBe(2); // Grace held a different value. This is not recoverable.
  });

  it("points at findMany rather than leaving the caller at a dead end", async () => {
    await expect(lp["patient"]!["count"]!({ where: { email: ADA } })).rejects.toThrow(
      /findMany\(\{ where \}\)\)\.length/,
    );
  });
});

// ----------------------------- shapes applied to the candidate set in SQL ----

describe("take, skip, cursor and distinct beside a rewritten filter", () => {
  it("refuses `take`, naming spec §7.5's over-fetch pattern", async () => {
    await expect(
      lp["patient"]!["findMany"]!({ where: { email: ADA }, take: 10 }),
    ).rejects.toThrow(/over-fetch, decrypt, filter, then paginate/);
  });

  it("refuses `skip`", async () => {
    await expect(
      lp["patient"]!["findMany"]!({ where: { email: ADA }, skip: 1 }),
    ).rejects.toThrow(FieldsealNotSupported);
  });

  it("refuses `cursor` even on a plaintext column", async () => {
    await expect(
      lp["patient"]!["findMany"]!({ where: { email: ADA }, cursor: { id: "p" }, take: 1 }),
    ).rejects.toThrow(FieldsealNotSupported);
  });

  it("refuses `distinct` even on a plaintext column", async () => {
    await expect(
      lp["patient"]!["findMany"]!({ where: { email: ADA }, distinct: ["plainName"] }),
    ).rejects.toThrow(/dedup runs in the database/);
  });

  it("measures why `take` is refused: the page holds the collision and misses the match", async () => {
    await seedWithCollision();
    const page = (await candidateScope(() =>
      lp["patient"]!["findMany"]!({
        where: { email: ADA },
        orderBy: { plainName: "asc" },
        take: 1,
      }),
    )) as Array<{ plainName: string }>;
    expect(page.map((r) => r.plainName)).toEqual(["0-grace"]);
  });

  it("leaves take and skip alone when nothing was rewritten", async () => {
    await seedWithCollision();
    const rows = await lp["patient"]!["findMany"]!({
      where: { plainName: { startsWith: "0" } },
      take: 5,
    });
    expect(rows).toHaveLength(1);
  });

  it("refuses a `take` at the nested level that carries the obligation, naming it", async () => {
    await expect(
      lp["patient"]!["findMany"]!({
        include: { visits: { where: { reason: "checkup" }, take: 1 } },
      }),
    ).rejects.toThrow(/\(under `visits`\)/);
  });
});

// -------------------------------------------- unattributable combinations ----

describe("an encrypted term under OR or NOT", () => {
  it("refuses `OR`, because a returned row may be there for the other branch", async () => {
    await expect(
      lp["patient"]!["findMany"]!({
        where: { OR: [{ email: ADA }, { plainName: "2-alan" }] },
      }),
    ).rejects.toThrow(/may be there because the \*other\* branch matched/);
  });

  it("refuses `NOT`", async () => {
    await expect(
      lp["patient"]!["findMany"]!({ where: { NOT: [{ email: ADA }] } }),
    ).rejects.toThrow(FieldsealNotSupported);
  });

  it("refuses an encrypted term nested under OR inside AND", async () => {
    await expect(
      lp["patient"]!["findMany"]!({
        where: { AND: [{ OR: [{ email: ADA }, { plainName: "x" }] }] },
      }),
    ).rejects.toThrow(FieldsealNotSupported);
  });

  it("still serves OR over plaintext columns of a model that has encrypted ones", async () => {
    await seedWithCollision();
    const rows = await lp["patient"]!["findMany"]!({
      where: { OR: [{ plainName: "1-ada" }, { plainName: "2-alan" }] },
    });
    expect(rows).toHaveLength(2);
  });
});

// ----------------------------------------------------- relation filters ----

describe("a relation filter reaching an encrypted column", () => {
  const shapes: Array<[string, () => Promise<unknown>]> = [
    [
      "unwrapped to-one",
      () => lp["visit"]!["findMany"]!({ where: { patient: { email: ADA } } }),
    ],
    ["is", () => lp["visit"]!["findMany"]!({ where: { patient: { is: { email: ADA } } } })],
    ["some", () => lp["patient"]!["findMany"]!({ where: { visits: { some: { reason: "c" } } } })],
    ["every", () => lp["patient"]!["findMany"]!({ where: { visits: { every: { reason: "c" } } } })],
    ["none", () => lp["patient"]!["findMany"]!({ where: { visits: { none: { reason: "c" } } } })],
  ];

  for (const [name, run] of shapes) {
    it(`refuses the \`${name}\` form`, async () => {
      await expect(run()).rejects.toThrow(FieldsealNotSupported);
    });
  }

  it("explains it as a path the interception surface does not reach, with the join to run instead", async () => {
    // `docs/13` §2.1 listed some/every/none as *rewritten*. They cannot be:
    // the rewrite lands in a join or subquery and only the parent rows come
    // back, so §7.5 has nothing to verify. Spec §10.2 settles it directly.
    await expect(
      lp["visit"]!["findMany"]!({ where: { patient: { email: ADA } } }),
    ).rejects.toThrow(/join or subquery[\s\S]*select: \{ id: true, <col>: true \}/);
  });

  it("refuses a `_count` whose relation filter names an encrypted column", async () => {
    await expect(
      lp["patient"]!["findMany"]!({
        select: { id: true, _count: { select: { visits: { where: { reason: "c" } } } } },
      }),
    ).rejects.toThrow(/`_count` is computed by the database/);
  });

  it("refuses the filter a nested write carries", async () => {
    await expect(
      lp["patient"]!["update"]!({
        where: { id: "p" },
        data: { visits: { updateMany: { where: { reason: "c" }, data: { reason: "d" } } } },
      }),
    ).rejects.toThrow(/nested write acts on/);
  });
});

// ------------------------------------------------------- candidateScope ----

describe("candidateScope: what it hands over, and what it does not", () => {
  it("serves count, at bucket semantics", async () => {
    await seedWithCollision();
    expect(await candidateScope(() => lp["patient"]!["count"]!({ where: { email: ADA } }))).toBe(2);
  });

  it("serves a relation filter, at bucket semantics", async () => {
    const { ada, grace } = await seedWithCollision();
    // Through the extended client: a visit written past the pipeline would hold
    // raw plaintext and fail the read as NOT_CIPHERTEXT.
    await lp["visit"]!["create"]!({ data: { id: "v-ada", patientId: ada, reason: "x" } });
    await lp["visit"]!["create"]!({ data: { id: "v-grace", patientId: grace, reason: "x" } });
    const rows = (await candidateScope(() =>
      lp["visit"]!["findMany"]!({ where: { patient: { email: ADA } } }),
    )) as Array<{ id: string }>;
    expect(rows.map((r) => r.id).sort()).toEqual(["v-ada", "v-grace"]);
  });

  it("serves OR", async () => {
    await seedWithCollision();
    const rows = await candidateScope(() =>
      lp["patient"]!["findMany"]!({ where: { OR: [{ email: ADA }, { plainName: "2-alan" }] } }),
    );
    expect(rows).toHaveLength(3); // ada + the forged collision + alan
  });

  it("serves a projection that drops the encrypted column, since nothing verifies it", async () => {
    await seedWithCollision();
    const rows = await candidateScope(() =>
      lp["patient"]!["findMany"]!({ where: { email: ADA }, select: { id: true } }),
    );
    expect(rows).toHaveLength(2);
  });

  it("does NOT lift the G20 family -- ciphertext order has no semantics to accept", async () => {
    await expect(
      candidateScope(() => lp["patient"]!["findMany"]!({ orderBy: { email: "asc" } })),
    ).rejects.toThrow(/sorts envelope bytes/);
  });

  /**
   * G24 ([#100]), decided 2026-09-06: neither adapter's hatch lifts negation.
   *
   * This adapter already refused the two scalar operators, which is the half
   * the issue recorded. It lifted every *other* negated position -- `NOT`, and
   * the two relation wrappers that are negations -- and those are the cases
   * below that failed before the decision landed. `some`, `every`, `is` and
   * `OR` all widen the result when the bucket widens, so they stay lifted.
   */
  it("does NOT lift `notIn` or `not`", async () => {
    await expect(
      candidateScope(() => lp["patient"]!["findMany"]!({ where: { email: { notIn: [ADA] } } })),
    ).rejects.toThrow(/does not lift this/);
    await expect(
      candidateScope(() => lp["patient"]!["findMany"]!({ where: { email: { not: ADA } } })),
    ).rejects.toThrow(/does not lift this/);
  });

  const negated: Array<[string, () => Promise<unknown>]> = [
    ["NOT", () => lp["patient"]!["findMany"]!({ where: { NOT: { email: ADA } } })],
    [
      // The `OR` claims `combinator` first, so a visitor reading negation off
      // that slot walks straight past this one.
      "NOT nested under OR",
      () =>
        lp["patient"]!["findMany"]!({
          where: { OR: [{ NOT: { email: ADA } }, { plainName: "2-alan" }] },
        }),
    ],
    [
      "the relation filter `none`",
      () => lp["patient"]!["findMany"]!({ where: { visits: { none: { reason: "c" } } } }),
    ],
    [
      "the relation filter `isNot`",
      () => lp["visit"]!["findMany"]!({ where: { patient: { isNot: { email: ADA } } } }),
    ],
  ];

  for (const [name, run] of negated) {
    it(`does NOT lift ${name}`, async () => {
      await expect(candidateScope(run)).rejects.toThrow(/false negatives are not/);
    });
  }

  it("measures the answer the negation refusal prevents", async () => {
    // The SQL the extension used to compile inside the scope, run on the
    // unextended client -- the only way left to produce it. Grace holds
    // `grace@example.com`, so she belongs in `NOT (email = ada@example.com)`;
    // the forged bucket drops her, and nothing is raised.
    const { ada, grace } = await seedWithCollision();
    const bucket = (await rawColumn(base, "Patient", "emailBidx", ada)) as Uint8Array;
    const kept = await base.patient.findMany({
      where: { NOT: { emailBidx: Buffer.from(bucket) } },
      select: { id: true, plainName: true },
    });
    expect(kept.map((r) => r.id)).not.toContain(grace);
    expect(kept.map((r) => r.plainName)).toEqual(["2-alan"]);
  });

  it("still lifts the relation filters that widen rather than narrow", async () => {
    const { ada } = await seedWithCollision();
    await lp["visit"]!["create"]!({ data: { id: "v-ada", patientId: ada, reason: "x" } });
    for (const where of [
      { visits: { some: { reason: "x" } } },
      { visits: { every: { reason: "x" } } },
    ]) {
      await expect(
        candidateScope(() => lp["patient"]!["findMany"]!({ where })),
      ).resolves.toBeInstanceOf(Array);
    }
  });

  it("still serves `NOT` over an exact NULL, which touches no bucket", async () => {
    // §10.2's NULL-preservation invariant makes `IS NOT NULL` exact on the
    // envelope column: no index is read, so negation loses nothing and there
    // is no subtractive position to refuse.
    await lp["patient"]!["create"]!({ data: { ...patient(ADA, "1-ada"), nickname: "ada" } });
    const rows = await candidateScope(() =>
      lp["patient"]!["findMany"]!({ where: { NOT: { nickname: null } } }),
    );
    expect(rows).toHaveLength(1);
  });

  it("does NOT lift equality on a column with no declared index", async () => {
    await expect(
      candidateScope(() => lp["patient"]!["findMany"]!({ where: { note: "n" } })),
    ).rejects.toThrow(/needs a declared blind index/);
  });

  it("does NOT lift findUnique on an encrypted column -- that refusal is structural", async () => {
    await expect(
      candidateScope(() => lp["patient"]!["findUnique"]!({ where: { email: ADA } })),
    ).rejects.toThrow(/§7\.10/);
  });

  it("does NOT leak out of the callback", async () => {
    await seedWithCollision();
    await candidateScope(() => lp["patient"]!["count"]!({ where: { email: ADA } }));
    // The next operation verifies again: the scope is the callback, not a mode.
    await expect(lp["patient"]!["count"]!({ where: { email: ADA } })).rejects.toThrow(
      FieldsealNotSupported,
    );
  });

  it("covers a promise constructed OUTSIDE the scope but first awaited inside -- the boundary is dispatch", async () => {
    // A Prisma promise is lazy: construction dispatches nothing, so nothing is
    // analyzed or refused here even though no scope is open yet...
    await seedWithCollision();
    const constructedOutside = lp["patient"]!["count"]!({ where: { email: ADA } });
    // ...and awaiting it inside the scope dispatches it inside, where it is
    // served at bucket semantics. The scope covers whatever dispatches within
    // it, in both directions; the README says to construct inside the callback.
    expect(await candidateScope(() => constructedOutside)).toBe(2);
  });

  it("covers operations awaited concurrently inside the callback", async () => {
    await seedWithCollision();
    const [a, b] = (await candidateScope(() =>
      Promise.all([
        lp["patient"]!["count"]!({ where: { email: ADA } }),
        lp["patient"]!["findMany"]!({ where: { email: ADA }, take: 1 }),
      ]),
    )) as unknown as [number, unknown[]];
    expect(a).toBe(2);
    expect(b).toHaveLength(1);
  });
});

/**
 * The G24 review's item 5: three refusals justified themselves with §7.4
 * bucket mechanics on a column that has no bucket, and prescribed a remedy
 * refused on its own account.
 *
 * `NOT: { note: "x" }` said "the SQL excludes whole index buckets" for a
 * column with no declared index, and sent the caller to "fetch the matching
 * rows with the positive form", which raises "needs a declared blind index".
 * The `count` and `OR` refusals one clause over said the same kind of thing.
 *
 * The order of the checks is *not* the fix and is unchanged: `record()`'s
 * comment gives the reason, and reversing it sends a caller to run a schema
 * migration for a shape refused with the index too. The fact travels in the
 * message. G23 settled the principle: a refusal MUST NOT be justified by a
 * mechanism that is not operating.
 */
describe("a refusal does not invent a bucket the column does not have", () => {
  const NO_INDEX = /declares no blind index/;
  const BUCKET_CLAIM = /SQL excludes whole index buckets/;
  const FALLBACK = /filter after decryption in application code/;

  const unindexed: Array<[string, () => Promise<unknown>]> = [
    ["NOT", () => lp["patient"]!["findMany"]!({ where: { NOT: { note: "x" } } })],
    ["the scalar `not`", () => lp["patient"]!["findMany"]!({ where: { note: { not: "x" } } })],
    ["the scalar `notIn`", () => lp["patient"]!["findMany"]!({ where: { note: { notIn: ["x"] } } })],
    [
      // A negating relation wrapper, onto an *unindexed* column on the far
      // side: the site is subtractive and the column still has no bucket.
      "the relation filter `isNot`",
      () => lp["visit"]!["findMany"]!({ where: { patient: { isNot: { note: "x" } } } }),
    ],
    [
      "NOT under candidateScope",
      () => candidateScope(() => lp["patient"]!["findMany"]!({ where: { NOT: { note: "x" } } })),
    ],
  ];

  for (const [name, run] of unindexed) {
    it(`names the real reason under ${name}`, async () => {
      const err = await run().then(
        () => null,
        (e: unknown) => e as Error,
      );
      expect(err).toBeInstanceOf(FieldsealNotSupported);
      expect(err!.message).toMatch(NO_INDEX);
      expect(err!.message).not.toMatch(BUCKET_CLAIM);
      expect(err!.message).toMatch(FALLBACK);
    });
  }

  it("names the real reason for a database-answered operation", async () => {
    const err = await lp["patient"]!["count"]!({ where: { note: "x" } }).then(
      () => null,
      (e: unknown) => e as Error,
    );
    expect(err!.message).toMatch(NO_INDEX);
    // The two sentences that asserted this column's own bucket are gone. What
    // remains is the counterfactual -- refused with an index too -- which is a
    // statement about the indexed case, not about this column.
    expect(err!.message).not.toMatch(/COUNT over the index bucket/);
    expect(err!.message).not.toMatch(/the answer would be computed over/);
    expect(err!.message).toMatch(/not by rows this adapter can re-verify/);
  });

  it("names the real reason under OR", async () => {
    const err = await lp["patient"]!["findMany"]!({
      where: { OR: [{ note: "x" }, { plainName: "a" }] },
    }).then(
      () => null,
      (e: unknown) => e as Error,
    );
    expect(err!.message).toMatch(NO_INDEX);
    expect(err!.message).not.toMatch(/A returned row may be there/);
    expect(err!.message).toMatch(FALLBACK);
  });

  it("leaves the refusal that owns the remedy saying it", async () => {
    // The positive form is where "declare a blind index" is the right advice,
    // because declaring one makes *that* shape work.
    await expect(
      lp["patient"]!["findMany"]!({ where: { note: "x" } }),
    ).rejects.toThrow(/needs a declared blind index/);
  });

  const indexed: Array<[string, () => Promise<unknown>]> = [
    ["NOT", () => lp["patient"]!["findMany"]!({ where: { NOT: { email: ADA } } })],
    ["the scalar `not`", () => lp["patient"]!["findMany"]!({ where: { email: { not: ADA } } })],
    [
      "NOT under candidateScope",
      () => candidateScope(() => lp["patient"]!["findMany"]!({ where: { NOT: { email: ADA } } })),
    ],
  ];

  for (const [name, run] of indexed) {
    it(`keeps the bucket justification on an indexed column under ${name}`, async () => {
      const err = await run().then(
        () => null,
        (e: unknown) => e as Error,
      );
      expect(err!.message).toMatch(BUCKET_CLAIM);
      expect(err!.message).not.toMatch(NO_INDEX);
    });
  }

  it("keeps the bucket justification for `none` over an indexed column", async () => {
    // The mirror of the `isNot` case above: same subtractive relation family,
    // but `Visit.reason` has an index, so the claim is true and stays.
    await expect(
      lp["patient"]!["findMany"]!({ where: { visits: { none: { reason: "c" } } } }),
    ).rejects.toThrow(BUCKET_CLAIM);
  });

  it("keeps the candidate justification on an indexed column under OR", async () => {
    await expect(
      lp["patient"]!["findMany"]!({ where: { OR: [{ email: ADA }, { plainName: "a" }] } }),
    ).rejects.toThrow(/A returned row may be there/);
  });

  // ---- what the review round on this PR found the first cut got wrong ----

  const writes: Array<[string, () => Promise<unknown>]> = [
    [
      "updateMany",
      () => lp["patient"]!["updateMany"]!({ where: { note: "x" }, data: { plainName: "z" } }),
    ],
    ["deleteMany", () => lp["patient"]!["deleteMany"]!({ where: { note: "x" } })],
  ];

  for (const [name, run] of writes) {
    it(`keeps the operation's own fallback for ${name}`, async () => {
      // The first cut replaced `answered.fallback` with the read-side tail, so
      // the remedy a caller followed no longer performed the write at all --
      // the same defect class this describe block exists to remove, one layer
      // down. The operation-specific sentence is what names the shape to run.
      const err = await run().then(
        () => null,
        (e: unknown) => e as Error,
      );
      expect(err!.message).toMatch(NO_INDEX);
      expect(err!.message).toMatch(/act on their primary keys/);
      // And the clause that contradicted `why` two sentences earlier is gone:
      // a write does not "return an answer rather than the rows".
      expect(err!.message).not.toMatch(/returns an answer rather than the rows/);
      expect(err!.message).toMatch(/cannot go in the `where` at all/);
    });
  }

  it("keeps the relation-site fallback, which is a findMany that does return rows", async () => {
    const err = await lp["visit"]!["findMany"]!({
      where: { patient: { is: { note: "x" } } },
    }).then(
      () => null,
      (e: unknown) => e as Error,
    );
    expect(err!.message).toMatch(NO_INDEX);
    expect(err!.message).toMatch(/Query that model directly and join on the result/);
    expect(err!.message).not.toMatch(/returns an answer rather than the rows/);
  });

  it("keeps `notIn`'s own §7.10 reason, which holds with or without an index", async () => {
    // `extra` was dropped along with the bucket paragraph in the first cut.
    // It is the operator's reason, not the bucket's.
    await expect(
      lp["patient"]!["findMany"]!({ where: { note: { notIn: ["x"] } } }),
    ).rejects.toThrow(/no row for negated membership/);
  });

  it("still justifies a database-answered refusal by the bucket when there is one", async () => {
    // The `why` clauses were reworded (the bucket claim moved out of them and
    // into the paragraph below), so this pins that the *justification* an
    // indexed column gets is still the bucket one.
    const err = await lp["patient"]!["count"]!({ where: { email: ADA } }).then(
      () => null,
      (e: unknown) => e as Error,
    );
    expect(err!.message).toMatch(/Spec §7\.4 mandates that the index bucket/);
    expect(err!.message).not.toMatch(NO_INDEX);
    expect(err!.message).toMatch(/which counts verified rows/);
  });
});
