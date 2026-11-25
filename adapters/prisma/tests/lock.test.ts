/**
 * The declaration lockfile's pure logic (#317): build, parse, compare, render.
 * The end-to-end behaviour through a real `prisma generate` is in
 * `generator.test.ts`.
 */

import { describe, expect, it } from "vitest";

import type { FieldInput, ModelInput } from "../src/declarations.ts";
import { buildFieldMap } from "../src/generator/emit.ts";
import {
  buildLock,
  compareLocks,
  type Lock,
  parseLock,
  reconcileLock,
  renderLock,
  suiteText,
} from "../src/generator/lock.ts";

const TABLE = "018f3c2e-0000-7000-8000-0000000000aa";
const COL = "018f3c2e-0000-7000-8000-000000000001";

interface Opts {
  tableUuid?: string;
  columnUuid?: string;
  as?: string;
  storage?: "binary" | "base64";
  tenantBound?: boolean;
  indexId?: string;
  idf?: string;
  normalize?: string;
  truncateBits?: number;
  suiteId?: string;
  argon?: [number, number];
  projectedPopulation?: number;
  onUnindexable?: string;
  /** Prisma names and physical mappings */
  modelName?: string;
  tableMap?: string | null;
  emailName?: string;
  emailMap?: string | null;
  bidxName?: string;
  bidxMap?: string | null;
  noIndex?: boolean;
}

function model(o: Opts = {}): ModelInput {
  const storage = o.storage ?? "binary";
  const emailName = o.emailName ?? "email";
  const bidxName = o.bidxName ?? "emailBidx";
  const enc =
    `@fieldseal(encrypted, column_uuid: "${o.columnUuid ?? COL}"` +
    `${storage === "base64" ? ', storage: "base64"' : ""}` +
    `${o.as !== undefined ? `, as: "${o.as}"` : ""}` +
    `${o.tenantBound === true ? ", tenant_bound" : ""})`;
  const idf = o.idf ?? "hmac-sha512";
  const idx =
    `@fieldseal(index: "${emailName}", index_id: "${o.indexId ?? "exact"}", ` +
    `suite_id: "${o.suiteId ?? "0xFF01"}", idf: "${idf}", ` +
    `normalize: "${o.normalize ?? "nfc-casefold-v1"}", truncate_bits: ${String(o.truncateBits ?? 15)}, ` +
    `projected_population: ${String(o.projectedPopulation ?? 100000)}` +
    `${o.onUnindexable !== undefined ? `, on_unindexable: "${o.onUnindexable}"` : ""}` +
    `${o.argon !== undefined ? `, argon2_time_cost: ${String(o.argon[0])}, argon2_memory_kib: ${String(o.argon[1])}` : ""})`;
  const f = (name: string, type: string, extra: Partial<FieldInput>): FieldInput => ({
    name, type, kind: "scalar", isList: false, isRequired: true, ...extra,
  });
  return {
    name: o.modelName ?? "Patient",
    dbName: o.tableMap ?? null,
    documentation: `@fieldseal(table_uuid: "${o.tableUuid ?? TABLE}")`,
    fields: [
      f("id", "String", { isId: true }),
      f(emailName, storage === "base64" ? "String" : "Bytes", {
        documentation: enc,
        dbName: o.emailMap ?? null,
      }),
      ...(o.noIndex === true
        ? []
        : [f(bidxName, "Bytes", { isRequired: false, documentation: idx, dbName: o.bidxMap ?? null })]),
    ],
  };
}

function lockOf(o: Opts = {}) {
  const m = model(o);
  return buildLock({ models: [m] }, buildFieldMap({ models: [m] }, "test"));
}

/** Refusal attributes of old -> new. */
function refused(a: Opts, b: Opts): string[] {
  const { lock: old } = lockOf(a);
  const next = lockOf(b);
  return compareLocks(old, next.lock, next.origins).map((r) => r.attribute);
}

describe("buildLock", () => {
  it("keys by physical names and stores the compared attributes only", () => {
    const { lock } = lockOf({ tableMap: "patients", emailMap: "email_enc", bidxMap: "email_bidx" });
    expect(lock).toEqual({
      version: 1,
      tables: {
        patients: {
          tableUuid: TABLE,
          columns: {
            email_bidx: {
              kind: "index", source: "email_enc", indexId: "exact", suiteId: 0xff01,
              idf: "hmac-sha512", normalize: "nfc-casefold-v1", truncateBits: 15,
            },
            email_enc: {
              kind: "encrypted", columnUuid: COL, valueType: "string",
              storage: "binary", tenantBound: false,
            },
          },
        },
      },
    });
  });

  it("falls back to the Prisma names when nothing is mapped", () => {
    expect(Object.keys(lockOf().lock.tables)).toEqual(["Patient"]);
    expect(Object.keys(lockOf().lock.tables["Patient"]!.columns)).toEqual(["email", "emailBidx"]);
  });

  it("omits models that declare nothing", () => {
    const bare: ModelInput = {
      name: "Plain",
      fields: [{ name: "id", type: "String", kind: "scalar", isList: false, isRequired: true, isId: true }],
    };
    const lock = buildLock({ models: [bare] }, buildFieldMap({ models: [bare] }, "t")).lock;
    expect(lock.tables).toEqual({});
  });

  it("records the Argon2 cost as declared", () => {
    const { lock } = lockOf({ idf: "argon2id", argon: [3, 65536] });
    expect(lock.tables["Patient"]!.columns["emailBidx"]).toMatchObject({
      argon2: { timeCost: 3, memoryKib: 65536 },
    });
  });
});

describe("renderLock", () => {
  it("is stable, ends with a newline, and round-trips through parseLock", () => {
    const { lock } = lockOf({ idf: "argon2id", argon: [3, 65536] });
    const text = renderLock(lock);
    expect(text.endsWith("}\n")).toBe(true);
    expect(renderLock(lockOf({ idf: "argon2id", argon: [3, 65536] }).lock)).toBe(text);
    expect(renderLock(parseLock(text, "x"))).toBe(text);
  });

  it("sorts tables and columns", () => {
    const a = model({ modelName: "Zed" });
    const b = model({ modelName: "Alpha", emailName: "zmail", bidxName: "abidx" });
    const map = buildFieldMap({ models: [a, b] }, "t");
    const { lock } = buildLock({ models: [a, b] }, map);
    expect(Object.keys(lock.tables)).toEqual(["Alpha", "Zed"]);
    expect(Object.keys(lock.tables["Alpha"]!.columns)).toEqual(["abidx", "zmail"]);
  });

  it("does not change when only unlisted attributes do", () => {
    const base = renderLock(lockOf().lock);
    expect(renderLock(lockOf({ projectedPopulation: 500000 }).lock)).toBe(base);
    expect(renderLock(lockOf({ onUnindexable: "bucket" }).lock)).toBe(base);
  });
});

describe("compareLocks: refused", () => {
  it.each<[string, Opts, string]>([
    ["column_uuid", { columnUuid: "018f3c2e-0000-7000-8000-000000000002" }, "column_uuid"],
    ["value type", { as: "int" }, "as"],
    ["storage", { storage: "base64" }, "storage"],
    ["tenant_bound", { tenantBound: true }, "tenant_bound"],
    ["table_uuid", { tableUuid: "018f3c2e-0000-7000-8000-0000000000bb" }, "table_uuid"],
    ["index_id", { indexId: "other" }, "index_id"],
    ["idf", { idf: "argon2id" }, "idf"],
    ["normalize", { normalize: "identity" }, "normalize"],
    ["truncate_bits", { truncateBits: 12 }, "truncate_bits"],
    ["suite_id", { suiteId: "0xFF02" }, "suite_id"],
  ])("%s", (_n, change, attribute) => {
    expect(refused({}, change)).toContain(attribute);
  });

  it("refuses the Argon2 cost only when both sides are argon2id", () => {
    const base: Opts = { idf: "argon2id", argon: [3, 65536] };
    expect(refused(base, { ...base, argon: [4, 65536] })).toEqual(["argon2_time_cost"]);
    expect(refused(base, { ...base, argon: [3, 131072] })).toEqual(["argon2_memory_kib"]);
    // as declared: unstated -> value is a change
    expect(refused({ idf: "argon2id" }, base)).toEqual(["argon2_time_cost", "argon2_memory_kib"]);
    // a changed idf is reported alone, not with a cost it no longer has
    expect(refused({ idf: "hmac-sha512" }, base)).toEqual(["idf"]);
    expect(refused(base, { idf: "hmac-sha512" })).toEqual(["idf"]);
  });

  it("refuses a repointed index source, in physical names", () => {
    const old = lockOf({ emailMap: "email_enc" });
    const m = model({ emailMap: "other_col" });
    const next = buildLock({ models: [m] }, buildFieldMap({ models: [m] }, "t"));
    // the column itself is a new entry, but the index's source moved
    const r = compareLocks(old.lock, next.lock, next.origins);
    expect(r.map((x) => x.attribute)).toEqual(["index"]);
    expect(r[0]).toMatchObject({ before: "email_enc", after: "other_col" });
  });

  it("refuses a kind change on the same physical column", () => {
    const old = lockOf();
    const next = lockOf();
    const col = next.lock.tables["Patient"]!.columns;
    const swapped: Lock = {
      version: 1,
      tables: {
        Patient: { tableUuid: TABLE, columns: { ...col, emailBidx: col["email"]! } },
      },
    };
    const r = compareLocks(old.lock, swapped, next.origins);
    expect(r.map((x) => x.attribute)).toEqual(["kind"]);
    expect(r[0]!.before).toBe("index");
  });

  it("reports several refusals together, naming model, field and physical names", () => {
    const old = lockOf({ tableMap: "patients", emailMap: "email_enc", bidxMap: "email_bidx" });
    const m = model({
      tableMap: "patients", emailMap: "email_enc", bidxMap: "email_bidx",
      columnUuid: "018f3c2e-0000-7000-8000-000000000002", indexId: "other", suiteId: "0xFF02",
    });
    const next = buildLock({ models: [m] }, buildFieldMap({ models: [m] }, "t"));
    let msg = "";
    try {
      reconcileLock(renderLock(old.lock), next.lock, next.origins, "fieldseal.lock.json");
    } catch (e) {
      msg = (e as Error).message;
    }
    expect(msg).toContain("3 declaration change(s) refused");
    expect(msg).toContain("Patient.email (patients.email_enc): column_uuid changed");
    expect(msg).toContain("Patient.emailBidx (patients.email_bidx): index_id changed exact → other");
    expect(msg).toContain("suite_id changed 0xff01 → 0xff02");
    expect(msg).toContain('delete tables["patients"].columns["email_bidx"] from fieldseal.lock.json');
    expect(msg).toContain("issues/315");
    expect(msg).toContain("§7.8");
    expect(msg).toContain("§6.1");
  });
});

describe("compareLocks: let through", () => {
  it.each<[string, Opts]>([
    ["projected_population", { projectedPopulation: 5 }],
    ["on_unindexable", { onUnindexable: "bucket" }],
    ["a Prisma field rename keeping @map", { emailName: "mail", bidxName: "mailBidx" }],
    ["a model rename keeping @@map", { modelName: "Person" }],
  ])("%s", (_n, change) => {
    const base: Opts = { tableMap: "patients", emailMap: "email_enc", bidxMap: "email_bidx" };
    expect(refused(base, { ...base, ...change })).toEqual([]);
  });

  it("lets a renamed source field through when its @map is kept", () => {
    const base: Opts = { emailMap: "email_enc" };
    expect(refused(base, { ...base, emailName: "mail" })).toEqual([]);
  });

  it("lets a column be added or removed", () => {
    const withIndex = lockOf();
    const without = lockOf({ noIndex: true });
    expect(compareLocks(withIndex.lock, without.lock, without.origins)).toEqual([]);
    expect(compareLocks(without.lock, withIndex.lock, withIndex.origins)).toEqual([]);
    expect(compareLocks(withIndex.lock, { version: 1, tables: {} }, {})).toEqual([]);
  });

  it("lets table_uuid go null -> value and value -> null", () => {
    const { lock } = lockOf();
    const nul: Lock = { version: 1, tables: { Patient: { tableUuid: null, columns: lock.tables["Patient"]!.columns } } };
    expect(compareLocks(nul, lock, {})).toEqual([]);
    expect(compareLocks(lock, nul, {})).toEqual([]);
  });
});

describe("parseLock: fail closed", () => {
  const good = renderLock(lockOf().lock);
  const mutate = (f: (o: any) => void): string => {
    const o = JSON.parse(good);
    f(o);
    return JSON.stringify(o);
  };
  it.each<[string, string]>([
    ["unparseable JSON", "{not json"],
    ["empty file", ""],
    ["not an object", "[]"],
    ["wrong version", mutate((o) => (o.version = 2))],
    ["missing version", mutate((o) => delete o.version)],
    ["unknown top-level key", mutate((o) => (o.extra = 1))],
    ["tables not an object", mutate((o) => (o.tables = []))],
    ["table not an object", mutate((o) => (o.tables.Patient = 1))],
    ["table with unknown key", mutate((o) => (o.tables.Patient.x = 1))],
    ["bad tableUuid", mutate((o) => (o.tables.Patient.tableUuid = 5))],
    ["unknown kind", mutate((o) => (o.tables.Patient.columns.email.kind = "plain"))],
    ["missing attribute", mutate((o) => delete o.tables.Patient.columns.email.columnUuid)],
    ["wrong attribute type", mutate((o) => (o.tables.Patient.columns.email.tenantBound = "no"))],
    ["unknown entry key", mutate((o) => (o.tables.Patient.columns.email.x = 1))],
    ["non-integer suiteId", mutate((o) => (o.tables.Patient.columns.emailBidx.suiteId = "0xff01"))],
    ["bad argon2", mutate((o) => (o.tables.Patient.columns.emailBidx.argon2 = { timeCost: 1 }))],
  ])("refuses %s", (_n, text) => {
    expect(() => parseLock(text, "fieldseal.lock.json")).toThrow(/malformed/);
  });

  it("is never treated as missing: reconcileLock throws rather than creating", () => {
    expect(() => reconcileLock("garbage", lockOf().lock, {}, "x")).toThrow(/malformed/);
  });
});

describe("reconcileLock", () => {
  it("creates when there is no lockfile, and reports unchanged/updated after", () => {
    const { lock, origins } = lockOf();
    const created = reconcileLock(null, lock, origins, "x");
    expect(created.outcome).toBe("created");
    expect(reconcileLock(created.text, lock, origins, "x")).toEqual({ text: null, outcome: "unchanged" });
    const without = lockOf({ noIndex: true });
    const updated = reconcileLock(created.text, without.lock, without.origins, "x");
    expect(updated.outcome).toBe("updated");
    expect(updated.text).toBe(renderLock(without.lock));
  });
});

describe("suiteText", () => {
  it("prints hex, and tolerates a non-integer", () => {
    expect(suiteText(0xff01)).toBe("0xff01");
    expect(suiteText(1)).toBe("0x0001");
    expect(suiteText("0xFF01")).toBe('"0xFF01"');
  });
});
