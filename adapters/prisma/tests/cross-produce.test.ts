/**
 * A local guard on the cross-language producer (`tests/cross/produce.ts`).
 *
 * The real cross-language leg runs in CI, where the **Python** core decrypts
 * what Prisma wrote. What runs here is the half that catches the producer
 * breaking: the file is a well-formed `cross/v1` document, and a core client
 * built independently from the shared key file decrypts every case.
 *
 * Independently matters. The producer's own client is configured through
 * `fieldsealExtension`; the client below is built straight from
 * `vectors/keys/test-keys.json`, so a case only passes if the adapter's stored
 * bytes are readable from the key material and the emitted context alone --
 * which is all a consumer in another language has.
 *
 * The producer runs in a subprocess: it clears and rewrites the fixture
 * database, which is the same file the rest of the suite drives, and running it
 * in-process would have it share this file's Prisma client and its
 * `AsyncLocalStorage`.
 */

import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { beforeAll, describe, expect, it } from "vitest";

import { type FieldContext, Fieldseal, StaticKeyProvider } from "@fieldseal/core";

const ADAPTER = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const REPO = resolve(ADAPTER, "../..");

interface CrossCase {
  id: string;
  key_ref: string;
  context: {
    table_uuid: string;
    column_uuid: string;
    tenant_id: string | null;
    row_id: string | null;
    purpose: string;
  };
  plaintext: string;
  envelope: string;
}

interface CrossDoc {
  schema: string;
  producer: { implementation: string; version: string; commit: string; produced_at: string };
  suite_id: string;
  cases: CrossCase[];
}

interface KeyEntry {
  suite_id: string;
  key_id: string;
  tenant_dek: string;
  tenant_index_key: string;
}

const H = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "hex"));

function produce(): CrossDoc {
  const out = join(mkdtempSync(join(tmpdir(), "fieldseal-cross-")), "cross-prisma.json");
  execFileSync(
    process.execPath,
    ["--no-warnings=ExperimentalWarning", join(ADAPTER, "tests", "cross", "produce.ts"), "--out", out],
    { cwd: ADAPTER, encoding: "utf-8" },
  );
  return JSON.parse(readFileSync(out, "utf-8")) as CrossDoc;
}

function keys(): Record<string, KeyEntry> {
  return (
    JSON.parse(readFileSync(join(REPO, "vectors", "keys", "test-keys.json"), "utf-8")) as {
      keys: Record<string, KeyEntry>;
    }
  ).keys;
}

function caseNamed(doc: CrossDoc, suffix: string): CrossCase {
  const found = doc.cases.find((c) => c.id.endsWith(`/${suffix}`));
  expect(found, `no case ${suffix}`).toBeDefined();
  return found!;
}

const text = (c: CrossCase): string => Buffer.from(c.plaintext, "hex").toString("utf8");

describe("cross-language producer (docs/14 §3)", () => {
  let doc: CrossDoc;
  beforeAll(() => {
    doc = produce();
  });

  it("is a well-formed cross/v1 document", () => {
    // The schema is the point: every existing consumer reads this file
    // unmodified, so the adapter joins the N x N matrix as one more producer
    // rather than needing a bespoke checker.
    expect(doc.schema).toBe("fieldseal-vectors/cross/v1");
    expect(doc.producer.implementation).toBe("prisma");
    expect(doc.suite_id).toBe("0xFF01");
    expect(doc.cases.length).toBeGreaterThan(0);
  });

  it("decrypts every case from the shared key material alone", () => {
    // What a consumer in another language actually has: the envelope bytes, the
    // caller-side context, and a `key_ref` into the public key file.
    const material = keys();
    for (const c of doc.cases) {
      const k = material[c.key_ref]!;
      const suiteId = parseInt(k.suite_id.slice(2), 16);
      const client = new Fieldseal({
        keyProvider: new StaticKeyProvider({
          dek: H(k.tenant_dek),
          indexKey: H(k.tenant_index_key),
          keyId: H(k.key_id),
        }),
        allowedSuites: [suiteId],
        writeSuite: suiteId,
        onWarning: () => {},
      });
      const ctx: FieldContext = {
        tableUuid: H(c.context.table_uuid),
        columnUuid: H(c.context.column_uuid),
        tenantId: c.context.tenant_id === null ? null : H(c.context.tenant_id),
        rowId: c.context.row_id === null ? null : H(c.context.row_id),
        purpose: c.context.purpose,
      };
      const got = Buffer.from(client.decrypt(H(c.envelope), ctx)).toString("hex");
      expect(got, c.id).toBe(c.plaintext);
    }
  });

  it("covers the decisions no core test reaches", () => {
    // The codec's rendering, the storage form, and context assembly. A case
    // list that lost any of them would still pass every assertion above.
    const ids = new Set(doc.cases.map((c) => c.id.split("/").pop()));
    for (const needed of [
      "text-non-ascii", // UTF-8, not an ASCII-only accident
      "text-empty", // a value, not an absence
      "tenant-bound", // context assembled from the AsyncLocalStorage
      "storage-base64", // the envelope arrives base64-encoded in the column
      "indexed-column", // being indexed changes nothing about the envelope
    ]) {
      expect(ids, needed).toContain(needed);
    }
  });

  it("pins every `as:` rendering, because Prisma is where `as:` exists", () => {
    // The schema type is the *storage* type in Prisma, so the logical type is
    // an adapter declaration and its rendering is an adapter decision. A
    // consumer that expected a platform integer encoding, or a locale-aware
    // date, would decrypt successfully and read the wrong value -- so these are
    // asserted as expected plaintext, not merely round-tripped.
    expect(text(caseNamed(doc, "as-int"))).toBe("45");
    expect(text(caseNamed(doc, "as-boolean"))).toBe("true");
    expect(text(caseNamed(doc, "as-float"))).toBe("1.5");
    expect(text(caseNamed(doc, "as-datetime"))).toBe("1815-12-10T11:22:33.000Z");
    expect(caseNamed(doc, "as-bytes").plaintext).toBe("0001feff");
  });

  it("emits the decoded envelope for a base64 column, not the column text", () => {
    // A consumer handed the column's own ASCII would fail at the length gate
    // with an error pointing at the envelope rather than at the column.
    const c = caseNamed(doc, "storage-base64");
    const envelope = Buffer.from(c.envelope, "hex");
    expect(envelope[0]).toBe(0x01); // spec §3.1 fmt_ver
    expect(envelope.length).toBeGreaterThanOrEqual(111); // §3.1's floor
  });

  it("binds the tenant into the context it emits", () => {
    const c = caseNamed(doc, "tenant-bound");
    expect(c.context.tenant_id).toBe(Buffer.from("tenant-0001", "utf8").toString("hex"));
    // Every other case is tenantless, and says so rather than omitting it.
    expect(caseNamed(doc, "text-email").context.tenant_id).toBeNull();
  });

  it("writes a fresh nonce and msg_seed on every run (spec §4.4)", () => {
    // The producer uses the real path -- runtime CSPRNG, no test-mode injection
    // -- so two runs that agreed would mean it had drifted onto the injection
    // seam. The plaintexts must still match, or the comparison proves nothing.
    const second = produce();
    expect(second.cases.map((c) => c.envelope)).not.toEqual(doc.cases.map((c) => c.envelope));
    expect(second.cases.map((c) => c.plaintext)).toEqual(doc.cases.map((c) => c.plaintext));
  });
});
