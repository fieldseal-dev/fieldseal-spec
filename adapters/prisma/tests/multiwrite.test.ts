/**
 * #250: one payload, every matched row.
 *
 * `updateMany` (and `updateManyAndReturn`) carries a single `data` payload for
 * every row its `where` matches. The extension sees that payload before the
 * engine sees the statement, so the value is encrypted **once** and the same
 * envelope -- same `msg_seed`, same nonce, same ciphertext -- is stored on all
 * of them. The bytes are not a nonce reuse (key, nonce, plaintext and context
 * are identical), but on a column with no blind index the matched rows become
 * visibly equal, which is what randomized encryption was bought to prevent.
 *
 * So the shape is refused by default (`src/visitor/write.ts`), and
 * `sharedEnvelopeScope()` is the explicit opt-in for a caller whose intent is
 * exactly "the same plaintext on every matched row". This file pins both
 * halves: the refusal (and that it writes nothing), and what the scope does and
 * does not lift.
 *
 * The refusal lives in the write walk, beside the `undefined`/`null` rules it
 * depends on, and the extension runs that walk once in check mode at its
 * refusal step -- so it is raised before any column is encrypted or any key
 * fetched. The cases below cover what is *not* refused too -- a payload
 * touching only plaintext, `null`, `createMany`, which carries one payload per
 * row, and a `where` that pins one row by a unique key.
 */

import { afterAll, beforeEach, describe, expect, it } from "vitest";

import type { FieldMap, ResolvedModel } from "../src/fieldmap.ts";
import { FieldsealNotSupported, sharedEnvelopeScope } from "../src/index.ts";
import { pinsOneRow } from "../src/visitor/write.ts";
import { fieldsealFieldMap } from "./fixture/generated/fieldseal-map.ts";
import { clearDb, loose, makeClient, rawColumn } from "./helpers.ts";

const { base, prisma } = makeClient();
const lp = loose(prisma);

beforeEach(async () => {
  await clearDb(base);
});
afterAll(async () => {
  await base.$disconnect();
});

const patient = (over: Record<string, unknown> = {}) => ({
  email: "ada@example.com",
  note: "a note",
  age: 36,
  plainName: "Ada",
  ...over,
});

const hex = (v: unknown): string =>
  v === null ? "NULL" : Buffer.from(v as Uint8Array).toString("hex");

/** Two rows with distinct `plainName`s, so a `where` can match both or one. */
async function seed(n = 2): Promise<string[]> {
  const ids: string[] = [];
  for (let i = 0; i < n; i++) {
    const row = await lp["patient"]!["create"]!({ data: patient({ plainName: `row-${i}` }) });
    ids.push(row.id as string);
  }
  return ids;
}

describe("the refusal", () => {
  it("refuses updateMany that would write an indexed encrypted column", async () => {
    const ids = await seed();
    const before = await Promise.all(ids.map((id) => rawColumn(base, "Patient", "email", id)));

    const err = await lp["patient"]!["updateMany"]!({
      where: { plainName: { startsWith: "row-" } },
      data: { email: "new@example.com" },
    }).then(
      () => null,
      (e: unknown) => e as Error,
    );

    expect(err).toBeInstanceOf(FieldsealNotSupported);
    // The shape, the column, the clause it breaks, and what to run instead are
    // all in the message: a refusal that names only one of them sends the
    // caller to search the docs.
    expect(err?.message).toMatch(/Patient\.email/);
    expect(err?.message).toMatch(/`updateMany` applies one payload to every row/);
    expect(err?.message).toMatch(/§3\.1 and §4\.4/);
    expect(err?.message).toMatch(/`update` with a unique `where`/);
    expect(err?.message).toMatch(/sharedEnvelopeScope\(\(\) => \.\.\.\)/);

    // Nothing was written: the refusal happens in the write pass, under the
    // journal, before the statement is dispatched.
    for (const [i, id] of ids.entries()) {
      expect(await rawColumn(base, "Patient", "email", id)).toEqual(before[i]);
    }
  });

  it("refuses updateMany on a column with no blind index", async () => {
    const ids = await seed();
    await expect(
      lp["patient"]!["updateMany"]!({
        where: { plainName: "row-0" },
        data: { note: "shared" },
      }),
    ).rejects.toThrow(/Patient\.note/);
    for (const id of ids) expect(await rawColumn(base, "Patient", "note", id)).not.toBeNull();
    const back = await lp["patient"]!["findUnique"]!({ where: { id: ids[0]! } });
    expect(back["note"]).toBe("a note");
  });

  it("refuses the `{ set }` form too -- the wrapper is not the question", async () => {
    await seed();
    await expect(
      lp["patient"]!["updateMany"]!({
        where: { plainName: "row-0" },
        data: { email: { set: "new@example.com" } },
      }),
    ).rejects.toThrow(/`updateMany` applies one payload/);
  });

  it("refuses updateManyAndReturn", async () => {
    await seed();
    await expect(
      lp["patient"]!["updateManyAndReturn"]!({
        where: { plainName: "row-0" },
        data: { note: "shared" },
      }),
    ).rejects.toThrow(/`updateManyAndReturn` applies one payload/);
  });

  it("refuses a nested updateMany, and names it rather than the operation above", async () => {
    const [id] = await seed();
    const err = await lp["patient"]!["update"]!({
      where: { id: id! },
      data: {
        visits: {
          // Not `{ id }`: a unique key pins one row and is served (below).
          updateMany: { where: { patientId: id! }, data: { reason: "changed" } },
        },
      },
    }).then(
      () => null,
      (e: unknown) => e as Error,
    );
    expect(err).toBeInstanceOf(FieldsealNotSupported);
    expect(err?.message).toMatch(/Visit\.reason/);
    expect(err?.message).toMatch(/the nested `updateMany` applies one payload/);
  });

  it("refuses inside an interactive transaction and writes nothing", async () => {
    const ids = await seed();
    const before = await rawColumn(base, "Patient", "email", ids[0]!);
    await expect(
      (
        prisma as unknown as {
          $transaction: (fn: (tx: unknown) => Promise<void>) => Promise<void>;
        }
      ).$transaction(async (tx) => {
        await (tx as typeof lp)["patient"]!["updateMany"]!({
          where: { plainName: "row-0" },
          data: { email: "new@example.com" },
        });
      }),
    ).rejects.toThrow(FieldsealNotSupported);
    expect(await rawColumn(base, "Patient", "email", ids[0]!)).toEqual(before);
  });
});

describe("what is not a shared envelope", () => {
  it("allows a payload that touches no encrypted column", async () => {
    await seed();
    const result = await lp["patient"]!["updateMany"]!({
      where: { plainName: { startsWith: "row-" } },
      data: { plainName: "renamed" },
    });
    expect(result["count"]).toBe(2);
    expect(await prisma.patient.findMany({ where: { plainName: "renamed" } })).toHaveLength(2);
  });

  it("allows null, which duplicates no envelope", async () => {
    const ids = await seed();
    const result = await lp["patient"]!["updateMany"]!({
      where: { plainName: { startsWith: "row-" } },
      data: { nickname: null },
    });
    expect(result["count"]).toBe(2);
    for (const id of ids) expect(await rawColumn(base, "Patient", "nickname", id)).toBeNull();
  });

  it("allows createMany, which gives every row its own payload", async () => {
    // The contrast that keeps the refusal narrow: same value into two rows, but
    // two payloads and therefore two draws.
    const result = await lp["patient"]!["createMany"]!({
      data: [patient({ id: "many-1" }), patient({ id: "many-2" })],
    });
    expect(result["count"]).toBe(2);
    const a = await rawColumn(base, "Patient", "note", "many-1");
    const b = await rawColumn(base, "Patient", "note", "many-2");
    expect(hex(a)).not.toBe(hex(b));
  });
});

describe("a `where` that pins a unique key: one row, so no shared envelope", () => {
  const pinning: Array<[string, (id: string) => Record<string, unknown>]> = [
    ["the shorthand", (id) => ({ id })],
    ["`equals`", (id) => ({ id: { equals: id } })],
    ["`AND`", (id) => ({ AND: [{ plainName: "row-0" }, { id }] })],
    ["a pin beside other terms", (id) => ({ id, plainName: { startsWith: "row-" } })],
  ];

  for (const [name, where] of pinning) {
    it(`serves updateMany pinned by ${name}, with a fresh envelope`, async () => {
      const [id, other] = await seed();
      const before = await rawColumn(base, "Patient", "email", id!);
      const otherBefore = await rawColumn(base, "Patient", "email", other!);
      const result = await lp["patient"]!["updateMany"]!({
        where: where(id!),
        data: { email: "ada@example.com" },
      });
      expect(result["count"]).toBe(1);
      expect(hex(await rawColumn(base, "Patient", "email", id!))).not.toBe(hex(before));
      const back = await lp["patient"]!["findUnique"]!({ where: { id: id! } });
      expect(back["email"]).toBe("ada@example.com");
      expect(await rawColumn(base, "Patient", "email", other!)).toEqual(otherBefore);
    });
  }

  it("serves updateManyAndReturn pinned by its primary key", async () => {
    const [id] = await seed();
    const rows = await lp["patient"]!["updateManyAndReturn"]!({
      where: { id: id! },
      data: { note: "only me" },
    });
    expect((rows as unknown as Array<{ note: string }>).map((r) => r.note)).toEqual(["only me"]);
  });

  it("serves a nested updateMany pinned by the target's primary key", async () => {
    const [id] = await seed();
    await lp["visit"]!["create"]!({ data: { id: "v-1", patientId: id!, reason: "checkup" } });
    await lp["patient"]!["update"]!({
      where: { id: id! },
      data: { visits: { updateMany: { where: { id: "v-1" }, data: { reason: "changed" } } } },
    });
    const visit = await lp["visit"]!["findUnique"]!({ where: { id: "v-1" } });
    expect(visit["reason"]).toBe("changed");
  });

  const notPinning: Array<[string, (a: string, b: string) => Record<string, unknown>]> = [
    ["`in`", (a, b) => ({ id: { in: [a, b] } })],
    ["`OR`", (a, b) => ({ OR: [{ id: a }, { id: b }] })],
    ["`NOT`", (a) => ({ NOT: { id: a } })],
    ["the scalar `not`", (a) => ({ id: { not: a } })],
    ["`mode: \"insensitive\"`", (a) => ({ id: { equals: a, mode: "insensitive" } })],
  ];

  for (const [name, where] of notPinning) {
    it(`still refuses a where that only looks pinned: ${name}`, async () => {
      const [a, b] = await seed();
      await expect(
        lp["patient"]!["updateMany"]!({ where: where(a!, b!), data: { note: "shared" } }),
      ).rejects.toThrow(/`updateMany` applies one payload/);
    });
  }

  it("still refuses on a map generated before unique keys were emitted", async () => {
    // The field is optional so an older map loads without a version bump; with
    // no keys to read, every updateMany is multi-row -- the refusal's side.
    const stale: FieldMap = {
      ...fieldsealFieldMap,
      models: fieldsealFieldMap.models.map(({ uniqueKeys: _, ...m }) => m),
    };
    const { base: staleBase, prisma: stalePrisma } = makeClient({ fieldMap: stale });
    try {
      const [id] = await seed();
      await expect(
        loose(stalePrisma)["patient"]!["updateMany"]!({ where: { id: id! }, data: { note: "x" } }),
      ).rejects.toThrow(/`updateMany` applies one payload/);
    } finally {
      await staleBase.$disconnect();
    }
  });

  it("needs every column of a compound key", () => {
    const model = { uniqueKeys: [["org", "email"]] } as unknown as ResolvedModel;
    expect(pinsOneRow(model, { org: "a", email: "b" })).toBe(true);
    expect(pinsOneRow(model, { org: "a", AND: { email: { equals: "b" } } })).toBe(true);
    expect(pinsOneRow(model, { org: "a" })).toBe(false);
    expect(pinsOneRow(model, { org: "a", email: null })).toBe(false);
    expect(pinsOneRow(model, { org: "a", OR: [{ email: "b" }] })).toBe(false);
    expect(pinsOneRow({ uniqueKeys: [] } as unknown as ResolvedModel, { org: "a" })).toBe(false);
  });
});

describe("sharedEnvelopeScope: what it lifts, and what it does not", () => {
  it("stores one envelope on every matched row, with the index derived for it", async () => {
    const ids = await seed();
    const result = await sharedEnvelopeScope(() =>
      lp["patient"]!["updateMany"]!({
        where: { plainName: { startsWith: "row-" } },
        data: { email: "new@example.com", nickname: "shared" },
      }),
    );
    expect(result["count"]).toBe(2);

    // The defect, made explicit: the bytes are identical across the rows. This
    // side of the scope is a deliberate acceptance, not an accident.
    const emails = await Promise.all(ids.map((id) => rawColumn(base, "Patient", "email", id)));
    const notes = await Promise.all(ids.map((id) => rawColumn(base, "Patient", "nickname", id)));
    expect(new Set(emails.map(hex)).size).toBe(1);
    expect(new Set(notes.map(hex)).size).toBe(1);

    // The scope changes nothing about the write pass: each declared index is
    // still derived from the plaintext, so equality still finds both rows.
    const found = await lp["patient"]!["findMany"]!({ where: { email: "new@example.com" } });
    expect((found as Array<{ id: string }>).map((r) => r.id).sort()).toEqual([...ids].sort());
    for (const id of ids) {
      const back = await lp["patient"]!["findUnique"]!({ where: { id } });
      expect(back["email"]).toBe("new@example.com");
    }
  });

  it("does not leak out of the callback", async () => {
    await seed();
    await sharedEnvelopeScope(() =>
      lp["patient"]!["updateMany"]!({ where: { plainName: "row-0" }, data: { note: "system" } }),
    );
    await expect(
      lp["patient"]!["updateMany"]!({ where: { plainName: "row-0" }, data: { note: "system" } }),
    ).rejects.toThrow(FieldsealNotSupported);
  });

  it("covers a statement constructed outside but first awaited inside -- the boundary is dispatch", async () => {
    await seed();
    const constructedOutside = lp["patient"]!["updateMany"]!({
      where: { plainName: "row-0" },
      data: { note: "system" },
    });
    expect(await sharedEnvelopeScope(() => constructedOutside)).toMatchObject({ count: 1 });
  });

  it("does NOT cover a statement constructed inside but awaited after the callback", async () => {
    // A Prisma promise is lazy, and `sharedEnvelopeScope` awaits the callback's
    // result *inside* the scope. A promise the callback does not return
    // dispatches after it closes. Construct and await inside; this is the same
    // measurement as `candidateScope` (`tests/l2-refusals.test.ts`).
    await seed();
    let escaped: Promise<Record<string, unknown>> | undefined;
    await sharedEnvelopeScope(() => {
      escaped = lp["patient"]!["updateMany"]!({
        where: { plainName: "row-0" },
        data: { note: "system" },
      });
    });
    await expect(escaped).rejects.toThrow(FieldsealNotSupported);
  });
});
