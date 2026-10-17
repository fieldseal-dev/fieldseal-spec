/**
 * Every top-level write path writes the blind index with the ciphertext.
 *
 * `tools/backfill/PROCEDURE.md` §6.3 rule 3: the statement that writes an
 * envelope writes the index for every index declared on the column, because an
 * envelope whose index is stale is a row no equality lookup finds. Django's
 * `bulk_update` did not (#240): it wrote the new envelope and left the sibling
 * holding the old value's index. `docs/13` §6 had verified this adapter's
 * `updateMany` for the ciphertext only, so this file asks the same question of
 * each path, one test per path and column, and asks it of the database:
 *
 *   (a) the stored sibling column, read through the unextended client, holds
 *       the new value's index and no longer the old one's;
 *   (b) an equality lookup for the new value finds the row, and one for the old
 *       value does not.
 *
 * (a) is there because a lookup says only that a row was missed, not which
 * column was wrong; (b) is there because it is what a caller sees.
 *
 * The expected index comes from a reference row written by `create`, whose
 * index `tests/l2.test.ts` pins; nothing here derives one. Both indexed columns
 * of the fixture are run: `email` is stored as raw bytes and `nickname` as
 * base64 text, and the sibling is raw bytes beside either (spec §7.11).
 *
 * The index is truncated to 15 bits, so two values can share one. OLD and NEW
 * do not under the fixture's fixed index key -- HMAC is deterministic, so that
 * is a property of this file rather than a probability -- and `seed` asserts it
 * instead of assuming it.
 */

import { afterAll, beforeEach, describe, expect, it } from "vitest";

import { clearDb, loose, makeClient, rawColumn, type LooseClient } from "./helpers.ts";

const { base, prisma } = makeClient();
const lp = loose(prisma);

beforeEach(async () => {
  await clearDb(base);
});
afterAll(async () => {
  await base.$disconnect();
});

const OLD = "old@example.com";
const NEW = "new@example.com";

const COLUMNS = [
  { field: "email", sibling: "emailBidx", storage: "Bytes" },
  { field: "nickname", sibling: "nicknameBidx", storage: "base64 String" },
] as const;
type Column = (typeof COLUMNS)[number];

/** A full Patient payload holding `value` in both indexed columns. */
const patient = (value: string, over: Record<string, unknown> = {}) => ({
  email: value,
  nickname: value,
  note: "n",
  age: 1,
  plainName: "p",
  ...over,
});

/** A stored index as hex; a NULL sibling is named rather than thrown on. */
const hex = (v: unknown): string =>
  v === null ? "NULL" : Buffer.from(v as Uint8Array).toString("hex");

async function storedIndex(col: Column, id: string): Promise<string> {
  return hex(await rawColumn(base, "Patient", col.sibling, id));
}

/** The index `create` stores for `value`, read raw from a row then removed. */
async function referenceIndex(col: Column, value: string): Promise<string> {
  const ref = await lp["patient"]!["create"]!({ data: patient(value) });
  const index = await storedIndex(col, ref.id as string);
  await base.patient.delete({ where: { id: ref.id as string } });
  return index;
}

async function seed(col: Column, n = 1) {
  const oldIndex = await referenceIndex(col, OLD);
  const newIndex = await referenceIndex(col, NEW);
  expect(oldIndex).not.toBe(newIndex);

  const ids: string[] = [];
  for (let i = 0; i < n; i++) {
    const row = await lp["patient"]!["create"]!({ data: patient(OLD, { plainName: "target" }) });
    ids.push(row.id as string);
    expect(await storedIndex(col, row.id as string)).toBe(oldIndex);
  }
  return { ids, id: ids[0]!, oldIndex, newIndex };
}

async function lookup(col: Column, value: string): Promise<string[]> {
  const rows = await lp["patient"]!["findMany"]!({ where: { [col.field]: value } });
  return (rows as unknown as Array<{ id: string }>).map((r) => r.id).sort();
}

/** (a) and (b), for every id in `ids`, plus the read that proves the envelope moved. */
async function expectIndexWritten(
  col: Column,
  ids: string[],
  index: { newIndex: string; oldIndex?: string },
): Promise<void> {
  for (const id of ids) {
    const stored = await storedIndex(col, id);
    expect(stored).toBe(index.newIndex);
    if (index.oldIndex !== undefined) expect(stored).not.toBe(index.oldIndex);

    const back = await lp["patient"]!["findUnique"]!({ where: { id } });
    expect(back[col.field]).toBe(NEW);
  }
  expect(await lookup(col, NEW)).toEqual([...ids].sort());
  expect(await lookup(col, OLD)).toEqual([]);
}

describe.each(COLUMNS)("the index sibling of $field ($storage)", (col) => {
  it("update writes it", async () => {
    const s = await seed(col);
    await lp["patient"]!["update"]!({ where: { id: s.id }, data: { [col.field]: NEW } });
    await expectIndexWritten(col, [s.id], s);
  });

  it("update with { set } writes it", async () => {
    const s = await seed(col);
    await lp["patient"]!["update"]!({
      where: { id: s.id },
      data: { [col.field]: { set: NEW } },
    });
    await expectIndexWritten(col, [s.id], s);
  });

  it("updateMany writes it", async () => {
    const s = await seed(col);
    const result = await lp["patient"]!["updateMany"]!({
      where: { id: s.id },
      data: { [col.field]: NEW },
    });
    expect(result["count"]).toBe(1);
    await expectIndexWritten(col, [s.id], s);
  });

  it("updateMany writes it on every row the statement matches", async () => {
    const s = await seed(col, 3);
    const result = await lp["patient"]!["updateMany"]!({
      where: { plainName: "target" },
      data: { [col.field]: NEW },
    });
    expect(result["count"]).toBe(3);
    await expectIndexWritten(col, s.ids, s);
  });

  it("updateManyAndReturn writes it", async () => {
    const s = await seed(col);
    await lp["patient"]!["updateManyAndReturn"]!({
      where: { id: s.id },
      data: { [col.field]: NEW },
    });
    await expectIndexWritten(col, [s.id], s);
  });

  it("upsert writes it on the update branch", async () => {
    const s = await seed(col);
    await lp["patient"]!["upsert"]!({
      where: { id: s.id },
      create: patient("unused@example.com"),
      update: { [col.field]: NEW },
    });
    await expectIndexWritten(col, [s.id], s);
  });

  it("upsert writes it on the create branch", async () => {
    const newIndex = await referenceIndex(col, NEW);
    const id = "upserted";
    await lp["patient"]!["upsert"]!({
      where: { id },
      create: patient(NEW, { id }),
      update: { [col.field]: "unused@example.com" },
    });
    await expectIndexWritten(col, [id], { newIndex });
  });

  it("createMany writes it on every row", async () => {
    const newIndex = await referenceIndex(col, NEW);
    const ids = ["many-1", "many-2"];
    const result = await lp["patient"]!["createMany"]!({
      data: ids.map((id) => patient(NEW, { id })),
    });
    expect(result["count"]).toBe(2);
    await expectIndexWritten(col, ids, { newIndex });
  });

  it("createManyAndReturn writes it on every row", async () => {
    const newIndex = await referenceIndex(col, NEW);
    const ids = ["returned-1", "returned-2"];
    await lp["patient"]!["createManyAndReturn"]!({
      data: ids.map((id) => patient(NEW, { id })),
    });
    await expectIndexWritten(col, ids, { newIndex });
  });

  // The shape a backfill batch has (PROCEDURE.md §6.3 rule 2): the write is
  // issued on the transaction client the extended client hands the callback.
  it("update inside an interactive transaction writes it", async () => {
    const s = await seed(col);
    await (
      prisma as unknown as { $transaction: (fn: (tx: unknown) => Promise<void>) => Promise<void> }
    ).$transaction(async (tx) => {
      await (tx as LooseClient)["patient"]!["update"]!({
        where: { id: s.id },
        data: { [col.field]: NEW },
      });
    });
    await expectIndexWritten(col, [s.id], s);
  });

  it("updateMany inside an interactive transaction writes it", async () => {
    const s = await seed(col);
    await (
      prisma as unknown as { $transaction: (fn: (tx: unknown) => Promise<void>) => Promise<void> }
    ).$transaction(async (tx) => {
      await (tx as LooseClient)["patient"]!["updateMany"]!({
        where: { id: s.id },
        data: { [col.field]: NEW },
      });
    });
    await expectIndexWritten(col, [s.id], s);
  });
});
