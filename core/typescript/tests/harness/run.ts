/**
 * The conformance harness (docs/08 §5) for the TypeScript core, emitting the
 * docs/14 §4 report. Both `tests/vectors.test.ts` (vitest) and
 * `tests/run_vectors.ts` (the CI report script) run exactly this code, so the
 * report and the test suite cannot disagree.
 *
 * Order of work (docs/17 §3): every expected value below is compared, never
 * consulted. The core was written from the specification; a mismatch here is
 * recorded in the M2 divergence report, not tuned away.
 */

import { timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { Fieldseal, MAX_PLAINTEXT_LEN } from "../../src/api.ts";
import { argon2Salt, idf, truncateBits, type IdfId } from "../../src/blindindex.ts";
import { COMMIT_INFO, computeCommitment } from "../../src/commitment.ts";
import { aad as buildAad, canonicalContext, type FieldContext, type ResolvedContext } from "../../src/context.ts";
import { FieldsealError } from "../../src/errors.ts";
import { INDEX_KEY_SALT, deriveIndexKey, deriveRecordKey } from "../../src/kdf.ts";
import { StaticKeyProvider } from "../../src/keyprovider.ts";
import { CASEFOLD_UNICODE_VERSION, normalize, type NormalizerId } from "../../src/normalize.ts";
import { FMT_VER, SUITE_FF01, getSuite, isProvisionalId } from "../../src/registry.ts";
import { encrypt_with_materials } from "../../src/testing/index.ts";
import { hex, hexOrNull, loadSuite, parseSuiteId, type LoadedSuite } from "./suite.ts";

export type Status = "pass" | "fail" | "skipped";

export interface Result {
  id: string;
  status: Status;
  reason?: string;
  /** Free-form, non-normative diagnostics (e.g. intermediates agreement, reproducibility flags). */
  details?: Record<string, unknown>;
}

export interface OutOfBand {
  id: string;
  status: "pass" | "fail" | "not-verified";
  method: string;
  reason?: string;
}

export interface Report {
  schema: "fieldseal-conformance/v1";
  implementation: { name: string; version: string; commit: string; language: string };
  vector_suite_version: string;
  spec_version: string;
  claimed_levels: Record<string, boolean>;
  suites_supported: string[];
  provisional_suites: boolean;
  environment: Record<string, string>;
  /** Spec §9 [PROVISIONAL G5]: the decrypt-path error precedence this implementation pins. */
  pinned_decisions: Record<string, string>;
  harness_notes: string[];
  results: Result[];
  held_out: { path: string; status: "not-run"; reason: string }[];
  out_of_band: OutOfBand[];
  async_companions: false;
  summary: { pass: number; fail: number; skipped: number; held_out: number };
}

const TEST_MODE_ENV = "FIELDSEAL_TEST_MODE";

function eq(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && (a.length === 0 || timingSafeEqual(a, b));
}

function toHex(b: Uint8Array): string {
  return Buffer.from(b).toString("hex");
}

function ctxFromVector(c: Record<string, unknown>): FieldContext {
  return {
    tableUuid: hex(c.table_uuid as string),
    columnUuid: hex(c.column_uuid as string),
    tenantId: hexOrNull(c.tenant_id as string | null),
    rowId: hexOrNull(c.row_id as string | null),
    purpose: c.purpose as string,
  };
}

function errCode(e: unknown): string {
  if (e instanceof FieldsealError) return e.code;
  return `UNTYPED(${e instanceof Error ? `${e.name}: ${e.message}` : String(e)})`;
}

/** Map a vector's normalizer identifier onto the shipped set (docs/09 §7). */
const NORMALIZER_ALIASES: Record<string, NormalizerId> = {
  // The pinned vectors say "nfc-casefold"; docs/09 §7 declares "nfc-casefold-v1".
  // Recorded as divergence D-07 in the M2 report; mapped here, not silently.
  "nfc-casefold": "nfc-casefold-v1",
  "nfc-casefold-v1": "nfc-casefold-v1",
  identity: "identity",
  "digits-only-v1": "digits-only-v1",
};

function mismatch(what: string, got: Uint8Array | string | number | undefined, want: Uint8Array | string | number | undefined): string {
  const g = got instanceof Uint8Array ? toHex(got) : String(got);
  const w = want instanceof Uint8Array ? toHex(want) : String(want);
  return `${what}: computed ${g} but the vector expects ${w}`;
}

// ---------------------------------------------------------------------------
// Family runners

function runAssertion(v: Record<string, unknown>): Result {
  // Assertion vectors carry only literal expected values and no inputs, so
  // the only thing an implementation can check is the literal relation.
  // Recorded as divergence D-08; reported as pass with reproducible=false.
  const ex = v.expected as Record<string, unknown>;
  const vals = Object.entries(ex).filter(([k]) => k !== "must_be_equal").map(([, x]) => x as string);
  const allEqual = vals.every((x) => x === vals[0]);
  const want = ex.must_be_equal as boolean;
  const ok = allEqual === want;
  return {
    id: v.id as string,
    status: ok ? "pass" : "fail",
    ...(ok ? {} : { reason: `literal values ${allEqual ? "are" : "are not"} all equal; must_be_equal=${want}` }),
    details: { reproducible: false, note: "assertion vector carries no inputs; only the literal relation between its expected values was checked" },
  };
}

function client(dek: Uint8Array, keyId: Uint8Array, extra: Partial<ConstructorParameters<typeof Fieldseal>[0]> = {}): Fieldseal {
  return new Fieldseal(
    {
      keyProvider: new StaticKeyProvider({ dek, keyId }),
      allowedSuites: [SUITE_FF01],
      writeSuite: SUITE_FF01,
      readMode: "strict",
      ...extra,
    },
    { armProvisionalSuites: true },
  );
}

function runEnvelope(v: Record<string, unknown>): Result[] {
  const id = v.id as string;
  const suiteId = parseSuiteId(v.suite_id as string);
  const ex = v.expected as Record<string, string | number>;
  const inter = (v.intermediates ?? {}) as Record<string, string>;
  if (suiteId !== SUITE_FF01) {
    const reason = `suite ${v.suite_id as string} not implemented`;
    return [
      { id, status: "skipped", reason },
      { id: `${id}#decrypt`, status: "skipped", reason },
    ];
  }
  const dek = hex(v.tenant_dek as string);
  const keyId = hex(v.key_id as string);
  const msgSeed = hex(v.msg_seed as string);
  const nonce = hex(v.nonce as string);
  const plaintext = hex(v.plaintext as string);
  const ctx = ctxFromVector(v.context as Record<string, unknown>);
  const fs = client(dek, keyId);
  const wantEnv = hex(ex.envelope as string);

  // Encrypt direction (normative: envelope, canonical_context, aad; envelope_bytes).
  const enc: Result = { id, status: "pass", details: {} };
  try {
    const resolved: ResolvedContext = { ...ctx, suiteId };
    const cc = canonicalContext(resolved);
    const aad = buildAad(FMT_VER, keyId, msgSeed, cc);
    const problems: string[] = [];
    if (!eq(cc, hex(ex.canonical_context as string))) problems.push(mismatch("canonical_context", cc, hex(ex.canonical_context as string)));
    if (!eq(aad, hex(ex.aad as string))) problems.push(mismatch("aad", aad, hex(ex.aad as string)));
    const env = encrypt_with_materials(fs, plaintext, ctx, msgSeed, nonce);
    if (!eq(env, wantEnv)) problems.push(mismatch("envelope", env, wantEnv));
    if (env.length !== ex.envelope_bytes) problems.push(mismatch("envelope_bytes", env.length, ex.envelope_bytes));
    if (problems.length > 0) {
      enc.status = "fail";
      enc.reason = problems.join("; ");
    }
    // Non-normative intermediates (docs/08 §4.1): checked, never failed on alone.
    const suite = getSuite(suiteId)!;
    const rk = deriveRecordKey(suite, dek, keyId, msgSeed, cc);
    const cm = computeCommitment(rk);
    enc.details = {
      intermediates: {
        record_key: inter.record_key === undefined ? "absent" : eq(rk, hex(inter.record_key)) ? "agree" : "DISAGREE",
        commitment: inter.commitment === undefined ? "absent" : eq(cm, hex(inter.commitment)) ? "agree" : "DISAGREE",
      },
    };
  } catch (e) {
    enc.status = "fail";
    enc.reason = `encrypt raised ${errCode(e)}`;
  }

  // Decrypt direction.
  const dec: Result = { id: `${id}#decrypt`, status: "pass" };
  try {
    const pt = fs.decrypt(wantEnv, ctx);
    if (!eq(pt, plaintext)) {
      dec.status = "fail";
      dec.reason = mismatch("plaintext", pt, plaintext);
    }
  } catch (e) {
    dec.status = "fail";
    dec.reason = `decrypt raised ${errCode(e)}`;
  }
  return [enc, dec];
}

function runKdf(v: Record<string, unknown>): Result {
  const id = v.id as string;
  if (v.assertion !== undefined) return runAssertion(v);
  const suiteId = parseSuiteId(v.suite_id as string);
  const ex = v.expected as Record<string, string>;
  const ctx = ctxFromVector(v.context as Record<string, unknown>);
  const problems: string[] = [];
  try {
    if (id.startsWith("kdf/record-key/")) {
      const suite = getSuite(suiteId)!;
      const keyId = hex(v.key_id as string);
      const msgSeed = hex(v.msg_seed as string);
      const cc = canonicalContext({ ...ctx, suiteId });
      const salt = new Uint8Array([...keyId, ...msgSeed]);
      if (!eq(salt, hex(ex.salt!))) problems.push(mismatch("salt", salt, hex(ex.salt!)));
      if (!eq(cc, hex(ex.info!))) problems.push(mismatch("info", cc, hex(ex.info!)));
      const rk = deriveRecordKey(suite, hex(v.tenant_dek as string), keyId, msgSeed, cc);
      if (!eq(rk, hex(ex.record_key!))) problems.push(mismatch("record_key", rk, hex(ex.record_key!)));
    } else {
      // kdf/index-key: the vector's context carries purpose "encrypt" with a
      // separate index_id; the spec's derivation uses purpose "index:<id>"
      // (divergence D-06 in the M2 report). The harness builds the spec's
      // context from the two fields.
      const indexId = v.index_id as string;
      const resolved: ResolvedContext = { ...ctx, purpose: `index:${indexId}`, rowId: null, suiteId };
      const cc = canonicalContext(resolved);
      if (!eq(INDEX_KEY_SALT, hex(ex.salt!))) problems.push(mismatch("salt", INDEX_KEY_SALT, hex(ex.salt!)));
      if (!eq(cc, hex(ex.info!))) problems.push(mismatch("info", cc, hex(ex.info!)));
      const ik = deriveIndexKey(hex(v.tenant_index_key as string), resolved);
      if (!eq(ik, hex(ex.index_key!))) problems.push(mismatch("index_key", ik, hex(ex.index_key!)));
    }
  } catch (e) {
    problems.push(`raised ${errCode(e)}`);
  }
  return problems.length === 0 ? { id, status: "pass" } : { id, status: "fail", reason: problems.join("; ") };
}

function runContext(v: Record<string, unknown>): Result {
  const id = v.id as string;
  if (v.assertion !== undefined) return runAssertion(v);
  const ex = v.expected as Record<string, string | number>;
  const ctx = ctxFromVector(v.context as Record<string, unknown>);
  const problems: string[] = [];
  try {
    // The context family carries no suite_id while canonical_context
    // includes one (spec §6.2); the harness assumes 0xFF01 (divergence D-05).
    const cc = canonicalContext({ ...ctx, suiteId: SUITE_FF01 });
    const presence = (ctx.tenantId != null ? 1 : 0) | (ctx.rowId != null ? 2 : 0);
    if (presence !== ex.presence) problems.push(mismatch("presence", presence, ex.presence));
    if (!eq(cc, hex(ex.canonical_context as string))) problems.push(mismatch("canonical_context", cc, hex(ex.canonical_context as string)));
    if (cc.length !== ex.length) problems.push(mismatch("length", cc.length, ex.length));
  } catch (e) {
    problems.push(`raised ${errCode(e)}`);
  }
  return problems.length === 0
    ? { id, status: "pass", details: { assumed_suite_id: "0xFF01" } }
    : { id, status: "fail", reason: problems.join("; ") };
}

function runCommitment(v: Record<string, unknown>): Result {
  const id = v.id as string;
  if (v.assertion !== undefined) return runAssertion(v);
  const ex = v.expected as Record<string, string | number>;
  const problems: string[] = [];
  try {
    if (!eq(COMMIT_INFO, hex(ex.info as string))) problems.push(mismatch("info", COMMIT_INFO, hex(ex.info as string)));
    const cm = computeCommitment(hex(v.record_key as string));
    if (!eq(cm, hex(ex.commitment as string))) problems.push(mismatch("commitment", cm, hex(ex.commitment as string)));
    if (cm.length !== ex.length) problems.push(mismatch("length", cm.length, ex.length));
  } catch (e) {
    problems.push(`raised ${errCode(e)}`);
  }
  return problems.length === 0 ? { id, status: "pass" } : { id, status: "fail", reason: problems.join("; ") };
}

interface IndexKeyOrigin {
  tenantIndexKey: Uint8Array;
  ctx: FieldContext;
  indexId: string;
  suiteId: number;
}

function runBlindIndex(v: Record<string, unknown>, fileStem: string, origins: Map<string, IndexKeyOrigin>): Result[] {
  const id = v.id as string;
  if (v.assertion !== undefined) return [runAssertion(v)];
  const ex = v.expected as Record<string, string | number>;
  const which: IdfId = fileStem === "hmac-sha512" ? "hmac-sha512" : "argon2id";
  const indexKey = hex(v.index_key as string);
  const b = v.b_bits as number;
  const normId = NORMALIZER_ALIASES[v.normalizer as string];
  const results: Result[] = [];
  const problems: string[] = [];
  const details: Record<string, unknown> = {};
  try {
    if (normId === undefined) throw new Error(`unknown normalizer ${String(v.normalizer)}`);
    details.normalizer_mapped_to = normId;
    const input = new TextEncoder().encode(v.plaintext_utf8 as string);
    const normalized = normalize(normId, input);
    if (!eq(normalized, hex(ex.normalized as string))) problems.push(mismatch("normalized", normalized, hex(ex.normalized as string)));
    const params = v.argon2_params as Record<string, number> | undefined;
    const raw = idf(which, indexKey, normalized, params ? { timeCost: params.t!, memoryKib: params.m_kib! } : undefined);
    if (!eq(raw, hex(ex.raw as string))) problems.push(mismatch("raw", raw, hex(ex.raw as string)));
    if (which === "argon2id" && typeof ex.salt === "string") {
      const salt = argon2Salt(indexKey);
      if (!eq(salt, hex(ex.salt))) problems.push(mismatch("salt", salt, hex(ex.salt)));
    }
    const bi = truncateBits(raw, b);
    if (!eq(bi, hex(ex.blind_index as string))) problems.push(mismatch("blind_index", bi, hex(ex.blind_index as string)));
    // Spec §7.11 stored form: the raw truncated bytes, exactly ⌈b/8⌉ of them.
    if (!eq(bi, hex(ex.stored as string))) problems.push(mismatch("stored", bi, hex(ex.stored as string)));
    if (bi.length !== ex.stored_bytes || bi.length !== Math.ceil(b / 8)) problems.push(mismatch("stored_bytes", bi.length, ex.stored_bytes));
    details.stored_hex = toHex(bi); // the §7.11 lowercase-hex alternative, asserted against `stored` above
  } catch (e) {
    problems.push(`raised ${errCode(e)}`);
  }
  results.push(problems.length === 0 ? { id, status: "pass", details } : { id, status: "fail", reason: problems.join("; "), details });

  // Full client pipeline, when the vector's index_key is the output of a
  // kdf/index-key vector (then the tenant index key and context are known).
  const origin = origins.get(toHex(indexKey));
  if (origin !== undefined && normId !== undefined) {
    const pid = `${id}#pipeline`;
    try {
      const P = 2 ** (b + 1); // inside the §7.4 band for any b ≥ 2: P·2^−b = 2, √P > 2
      const fs = new Fieldseal(
        {
          keyProvider: new StaticKeyProvider({ dek: new Uint8Array(32).fill(0xaa), keyId: new Uint8Array(16), indexKey: origin.tenantIndexKey }),
          allowedSuites: [origin.suiteId],
          writeSuite: origin.suiteId,
          indexes: [
            {
              tableUuid: origin.ctx.tableUuid,
              columnUuid: origin.ctx.columnUuid,
              indexId: origin.indexId,
              idf: which,
              ...(which === "argon2id" ? { argon2: { timeCost: (v.argon2_params as Record<string, number>).t!, memoryKib: (v.argon2_params as Record<string, number>).m_kib! } } : {}),
              normalize: normId,
              truncateBits: b,
              projectedPopulation: P,
            },
          ],
        },
        { armProvisionalSuites: true },
      );
      const out = fs.blindIndex(new TextEncoder().encode(v.plaintext_utf8 as string), {
        ...origin.ctx,
        purpose: `index:${origin.indexId}`,
        rowId: hex("deadbeef"), // must be ignored by index derivation (spec §7.2 row_id = null)
      });
      results.push(
        eq(out, hex(ex.stored as string))
          ? { id: pid, status: "pass", details: { via: "Fieldseal.blindIndex with tenant index key from kdf/index-key" } }
          : { id: pid, status: "fail", reason: mismatch("blindIndex()", out, hex(ex.stored as string)) },
      );
    } catch (e) {
      results.push({ id: pid, status: "fail", reason: `blindIndex raised ${errCode(e)}` });
    }
  }
  return results;
}

// ---------------------------------------------------------------------------
// Out-of-band: spec §3.5 length bound (docs/08 §5 item 8)

function runLengthBound(): OutOfBand[] {
  const out: OutOfBand[] = [];
  const fs = client(new Uint8Array(32), new Uint8Array(16));
  const ctx: FieldContext = { tableUuid: new Uint8Array(16), columnUuid: new Uint8Array(16), tenantId: null, rowId: null, purpose: "encrypt" };
  // encrypt side
  try {
    const big = new Uint8Array(MAX_PLAINTEXT_LEN + 1); // 2^31 bytes; lazily committed by the allocator
    let status: OutOfBand["status"] = "fail";
    let reason: string | undefined;
    try {
      fs.encrypt(big, ctx);
      reason = "encrypt accepted a 2^31-byte plaintext";
    } catch (e) {
      if (errCode(e) === "LENGTH_EXCEEDED") status = "pass";
      else reason = `encrypt raised ${errCode(e)} instead of LENGTH_EXCEEDED`;
    }
    out.push({ id: "spec/3.5/length-bound", status, method: "unit test: a 2^31-byte plaintext is refused with LENGTH_EXCEEDED before key acquisition", ...(reason ? { reason } : {}) });
  } catch (e) {
    out.push({ id: "spec/3.5/length-bound", status: "not-verified", method: "unit test: a 2^31-byte plaintext", reason: `could not allocate the input on this runtime: ${errCode(e)}` });
  }
  // decrypt side: an envelope implying a 2^31-byte plaintext.
  try {
    const suite = getSuite(SUITE_FF01)!;
    const overhead = 51 + suite.nonceLen + suite.tagLen + suite.commitLen;
    const env = Buffer.allocUnsafe(overhead + MAX_PLAINTEXT_LEN + 1);
    env[0] = FMT_VER;
    env[1] = 0xff;
    env[2] = 0x01;
    let status: OutOfBand["status"] = "fail";
    let reason: string | undefined;
    try {
      fs.decrypt(env, ctx);
      reason = "decrypt accepted an envelope implying a 2^31-byte plaintext";
    } catch (e) {
      if (errCode(e) === "LENGTH_EXCEEDED") status = "pass";
      else reason = `decrypt raised ${errCode(e)} instead of LENGTH_EXCEEDED`;
    }
    out.push({ id: "spec/3.5/length-bound#decrypt", status, method: "unit test: an envelope whose implied plaintext length is 2^31 bytes is refused with LENGTH_EXCEEDED before allocation", ...(reason ? { reason } : {}) });
  } catch (e) {
    out.push({ id: "spec/3.5/length-bound#decrypt", status: "not-verified", method: "unit test: a 2^31+overhead-byte envelope", reason: `could not allocate the input on this runtime: ${errCode(e)}` });
  }
  return out;
}

// ---------------------------------------------------------------------------

export interface RunOptions {
  vectorsDir?: string;
  commit?: string;
}

export function runSuite(opts: RunOptions = {}): Report {
  const prevTestMode = process.env[TEST_MODE_ENV];
  process.env[TEST_MODE_ENV] = "1";
  try {
    const suite = loadSuite(opts.vectorsDir);
    const results: Result[] = [];
    const origins = indexKeyOrigins(suite);
    for (const [path, doc] of suite.files) {
      const stem = path.split("/").pop()!.replace(/\.json$/, "");
      for (const v of doc.vectors) {
        switch (doc.group) {
          case "envelope":
            results.push(...runEnvelope(v));
            break;
          case "kdf":
            results.push(runKdf(v));
            break;
          case "context":
            results.push(runContext(v));
            break;
          case "commitment":
            results.push(runCommitment(v));
            break;
          case "blind-index":
            results.push(...runBlindIndex(v, stem, origins));
            break;
          default:
            results.push({ id: v.id as string, status: "fail", reason: `no runner for family ${doc.group}` });
        }
      }
    }
    const outOfBand = runLengthBound();
    const heldOut = suite.manifest.held_out.map((h) => ({ path: h.path, status: "not-run" as const, reason: h.reason }));
    const summary = {
      pass: results.filter((r) => r.status === "pass").length,
      fail: results.filter((r) => r.status === "fail").length + outOfBand.filter((o) => o.status !== "pass").length,
      skipped: results.filter((r) => r.status === "skipped").length,
      held_out: heldOut.length,
    };
    const suitesSupported = ["0xFF01"];
    const pkg = JSON.parse(readFileSync(new URL("../../package.json", import.meta.url), "utf-8")) as { version: string };
    return {
      schema: "fieldseal-conformance/v1",
      implementation: { name: "typescript-core", version: pkg.version, commit: opts.commit ?? process.env.GITHUB_SHA ?? "unknown", language: "typescript" },
      vector_suite_version: suite.manifest.vector_suite_version,
      spec_version: suite.manifest.spec_version,
      // L0 requires every family the supported suite reaches, with fail = 0.
      // A green run against a provisional suite is L0 conformance to the
      // PROVISIONAL suite 0xFF01 -- not to any frozen format (PRD §8, Gate 0b).
      claimed_levels: { L0: summary.fail === 0, L1: false, L2: false, L3: false, L4: false },
      suites_supported: suitesSupported,
      provisional_suites: suitesSupported.some((s) => isProvisionalId(parseSuiteId(s))),
      environment: {
        runtime: `Node ${process.versions.node}`,
        os: `${process.platform} ${process.arch}`,
        crypto_backend: `OpenSSL ${process.versions.openssl}`,
        unicode_platform: `ICU ${process.versions.icu} / Unicode ${process.versions.unicode} (NFC)`,
        unicode_casefold_table: `CaseFolding-${CASEFOLD_UNICODE_VERSION}.txt (vendored; C+F)`,
      },
      pinned_decisions: PINNED_DECISIONS,
      harness_notes: HARNESS_NOTES,
      results,
      held_out: heldOut,
      out_of_band: outOfBand,
      async_companions: false,
      summary,
    };
  } finally {
    if (prevTestMode === undefined) delete process.env[TEST_MODE_ENV];
    else process.env[TEST_MODE_ENV] = prevTestMode;
  }
}

function indexKeyOrigins(suite: LoadedSuite): Map<string, IndexKeyOrigin> {
  const m = new Map<string, IndexKeyOrigin>();
  const doc = suite.files.get("kdf/index-key.json");
  if (doc === undefined) return m;
  for (const v of doc.vectors) {
    if (v.assertion !== undefined) continue;
    const ex = v.expected as Record<string, string>;
    m.set(ex.index_key!, {
      tenantIndexKey: hex(v.tenant_index_key as string),
      ctx: ctxFromVector(v.context as Record<string, unknown>),
      indexId: v.index_id as string,
      suiteId: parseSuiteId(v.suite_id as string),
    });
  }
  return m;
}

/** Spec §9 [PROVISIONAL G5] obliges a Gate 0a implementation to pin an order and declare it here. */
export const PINNED_DECISIONS: Record<string, string> = {
  "decrypt-order":
    "recognition (len<3 | fmt_ver≠0x01 | suite unregistered | len<suite minimum → NOT_CIPHERTEXT in strict, pass-through in permissive/readonly; " +
    "fmt_ver=0x02 with len≥111 → UNKNOWN_FORMAT_VERSION in every mode) → LENGTH_EXCEEDED (§3.5 decrypt side) → SUITE_NOT_ALLOWED → KEY_UNAVAILABLE (provider returned no candidate) → " +
    "per candidate: HKDF record key, constant-time commitment verify, then AEAD open; open failure after a verified commitment → TAG_INVALID; " +
    "no candidate's commitment verifies → COMMITMENT_INVALID",
  "aad-mismatch": "AAD_MISMATCH is never raised on the 0xFF01 decrypt path: under §6.3 dual binding a context mismatch changes the record key and is indistinguishable from key confusion at the commitment check (G5). The optional diagnostic re-derivation docs/09 §3.2 describes is not implemented.",
  "unknown-format-version-set": "reserved-known-future fmt_ver values = {0x02}; all other non-0x01 first bytes are NOT_CIPHERTEXT (docs/09 §3.2 footnote; docs/08 §4.6)",
  "api-boundary-order": "encrypt/rotate: MODE_VIOLATION → SUITE_PROVISIONAL → LENGTH_EXCEEDED → context validation (INVALID_ARGUMENT, non-§9); all before key acquisition",
  "provisional-arming": "second constructor argument { armProvisionalSuites: true } or environment variable FIELDSEAL_ARM_PROVISIONAL_SUITES=1; read at construction; never part of the config object",
  "unimplemented-registered-suite": "0xFF02 is registered (isCiphertext → true) but refused at construction if allow-listed or set as writeSuite (CONFIGURATION_ERROR naming G7); no §9 code is reachable for it because no client can be built that accepts it",
  "commitment-construction": 'HKDF-SHA-512(ikm = record_key, salt = "", info = "fieldseal-commit-v1", 32) -- from the G1 issue draft\'s proposed direction; spec §4.6 itself states no formula',
  "rotate-in-permissive": "rotate() on non-envelope input in permissive mode encrypts the pass-through value (decrypt ∘ encrypt, literally composed)",
};

export const HARNESS_NOTES: string[] = [
  "docs/08 §5 item 2 (JSON-Schema validation) could not be performed: vectors/schema/ is empty in the checkout this harness ran against. The harness performs its own structural validation of every vector object before running it.",
  "Envelope vectors are reported twice: '<id>' is the encrypt direction (envelope, canonical_context, aad, envelope_bytes) and '<id>#decrypt' is the decrypt direction.",
  "'<id>#pipeline' results run blind-index vectors through Fieldseal.blindIndex() end to end, using the tenant index key recovered from the kdf/index-key vector that produced the vector's index_key.",
  "Assertion vectors (assertion: distinct|equal) carry no inputs; only the literal relation between their expected values is checked (details.reproducible = false).",
  "The context family carries no suite_id; 0xFF01 was assumed. The kdf/index-key family carries purpose 'encrypt' plus a separate index_id; the spec's purpose 'index:<id>' was constructed from both. The blind-index family names normalizer 'nfc-casefold'; it was mapped to the shipped 'nfc-casefold-v1'. See the M2 divergence report.",
  "blind-index/argon2id.json is held out (MANIFEST.held_out) and was not iterated; it is reported as not-run. Nothing about Argon2id contributes to this report's summary.",
];
