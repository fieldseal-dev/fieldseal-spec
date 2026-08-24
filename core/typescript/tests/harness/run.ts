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
import type { ReadMode } from "../../src/config.ts";
import { argon2Salt, idf, truncateBits, type IdfId } from "../../src/blindindex.ts";
import { COMMIT_INFO, computeCommitment } from "../../src/commitment.ts";
import { aad as buildAad, canonicalContext, type FieldContext, type ResolvedContext } from "../../src/context.ts";
import { FieldsealError } from "../../src/errors.ts";
import { INDEX_KEY_SALT, deriveIndexKey, deriveRecordKey } from "../../src/kdf.ts";
import { StaticKeyProvider } from "../../src/keyprovider.ts";
import { UNICODE_VERSION, normalize, type NormalizerId } from "../../src/normalize.ts";
import { FMT_VER, SUITE_FF01, getSuite, isProvisionalId } from "../../src/registry.ts";
import { encrypt_with_materials } from "../../src/testing/index.ts";
import { hex, hexOrNull, loadSuite, parseSuiteId } from "./suite.ts";

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

/** The shipped normalizer set (docs/09 §7). Suite 0.2.0 uses these identifiers verbatim (D-07 resolved). */
const NORMALIZERS: Record<string, NormalizerId> = {
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
  // Suite 0.2.0: assertion vectors carry the inputs of both sides (D-08
  // resolved), so each side is reproduced and then the relation is checked.
  const id = v.id as string;
  const ex = v.expected as Record<string, unknown>;
  const inp = v.inputs as Record<string, unknown>;
  const want = ex.must_be_equal as boolean;
  const suiteId = parseSuiteId(v.suite_id as string);
  const problems: string[] = [];
  try {
    let a: Uint8Array;
    let b: Uint8Array;
    let wantA: string;
    let wantB: string;
    if (id.startsWith("context/")) {
      a = canonicalContext({ ...ctxFromVector(inp.context_a as Record<string, unknown>), suiteId });
      b = canonicalContext({ ...ctxFromVector(inp.context_b as Record<string, unknown>), suiteId });
      [wantA, wantB] = [ex.tenant_absent as string, ex.tenant_zero_length as string];
    } else if (id.startsWith("kdf/record-key/")) {
      const suite = getSuite(suiteId)!;
      const keyId = hex(inp.key_id as string);
      const cc = canonicalContext({ ...ctxFromVector(inp.context as Record<string, unknown>), suiteId });
      a = deriveRecordKey(suite, hex(inp.tenant_dek as string), keyId, hex(inp.msg_seed_a as string), cc);
      b = deriveRecordKey(suite, hex(inp.tenant_dek as string), keyId, hex(inp.msg_seed_b as string), cc);
      [wantA, wantB] = [ex.key_a as string, ex.key_b as string];
    } else if (id.startsWith("kdf/index-key/")) {
      const tik = hex(inp.tenant_index_key as string);
      a = deriveIndexKey(tik, { ...ctxFromVector(inp.context_a as Record<string, unknown>), suiteId });
      b = deriveIndexKey(tik, { ...ctxFromVector(inp.context_b as Record<string, unknown>), suiteId });
      [wantA, wantB] = [ex.key_a as string, ex.key_b as string];
    } else if (id.startsWith("commitment/")) {
      a = computeCommitment(hex(inp.record_key_a as string));
      b = computeCommitment(hex(inp.record_key_b as string));
      [wantA, wantB] = [ex.commitment_a as string, ex.commitment_b as string];
    } else if (id.startsWith("blind-index/")) {
      const which = inp.idf as IdfId;
      const normId = NORMALIZERS[inp.normalize as string];
      if (normId === undefined) throw new Error(`unknown normalizer ${String(inp.normalize)}`);
      const ik = hex(inp.index_key as string);
      const bits = inp.truncate_bits as number;
      a = truncateBits(idf(which, ik, normalize(normId, new TextEncoder().encode(inp.plaintext_preimage_a as string))), bits);
      b = truncateBits(idf(which, ik, normalize(normId, new TextEncoder().encode(inp.plaintext_preimage_b as string))), bits);
      [wantA, wantB] = [ex.index_a as string, ex.index_b as string];
    } else {
      throw new Error("no assertion runner for this family");
    }
    if (!eq(a, hex(wantA))) problems.push(mismatch("side a", a, hex(wantA)));
    if (!eq(b, hex(wantB))) problems.push(mismatch("side b", b, hex(wantB)));
    if (eq(a, b) !== want) problems.push(`sides ${eq(a, b) ? "are" : "are not"} equal; must_be_equal=${want}`);
  } catch (e) {
    problems.push(`raised ${errCode(e)}`);
  }
  return problems.length === 0 ? { id, status: "pass" } : { id, status: "fail", reason: problems.join("; ") };
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
      // kdf/index-key: since suite 0.2.0 the vector's context carries the
      // index purpose itself (D-06 resolved); it is used exactly as given.
      const resolved: ResolvedContext = { ...ctx, suiteId };
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
    const cc = canonicalContext({ ...ctx, suiteId: parseSuiteId(v.suite_id as string) });
    const presence = (ctx.tenantId != null ? 1 : 0) | (ctx.rowId != null ? 2 : 0);
    if (presence !== ex.presence) problems.push(mismatch("presence", presence, ex.presence));
    if (!eq(cc, hex(ex.canonical_context as string))) problems.push(mismatch("canonical_context", cc, hex(ex.canonical_context as string)));
    if (cc.length !== ex.length) problems.push(mismatch("length", cc.length, ex.length));
  } catch (e) {
    problems.push(`raised ${errCode(e)}`);
  }
  return problems.length === 0 ? { id, status: "pass" } : { id, status: "fail", reason: problems.join("; ") };
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

function runBlindIndex(v: Record<string, unknown>): Result[] {
  const id = v.id as string;
  if (v.assertion !== undefined) return [runAssertion(v)];
  const ex = v.expected as Record<string, unknown>;
  const stored = ex.stored as Record<string, string | number>;
  const which = v.idf as IdfId;
  const indexKey = hex(v.index_key as string);
  const b = v.truncate_bits as number;
  const normId = NORMALIZERS[v.normalize as string];
  const params = v.idf_params as Record<string, number>;
  const argon2 = which === "argon2id" ? { timeCost: params.time_cost!, memoryKib: params.memory_kib! } : undefined;
  const results: Result[] = [];
  const problems: string[] = [];
  try {
    if (normId === undefined) throw new Error(`unknown normalizer ${String(v.normalize)}`);
    // docs/08 §4.4: `plaintext` (already normalized) is the normative input;
    // the preimage checks the shipped normalizer against it.
    const wantNormalized = hex(v.plaintext as string);
    const normalized = normalize(normId, new TextEncoder().encode(v.plaintext_preimage as string));
    if (!eq(normalized, wantNormalized)) problems.push(mismatch("normalizer", normalized, wantNormalized));
    const raw = idf(which, indexKey, wantNormalized, argon2);
    if (!eq(raw, hex(ex.raw as string))) problems.push(mismatch("raw", raw, hex(ex.raw as string)));
    if (which === "argon2id" && typeof params.salt === "string") {
      const salt = argon2Salt(indexKey);
      if (!eq(salt, hex(params.salt as unknown as string))) problems.push(mismatch("salt", salt, hex(params.salt as unknown as string)));
    }
    const bi = truncateBits(raw, b);
    if (!eq(bi, hex(ex.index as string))) problems.push(mismatch("index", bi, hex(ex.index as string)));
    // Spec §7.11 stored form: the raw truncated bytes, exactly ⌈b/8⌉ of them;
    // lowercase hex is the declared-per-column alternative.
    if (!eq(bi, hex(stored.binary as string))) problems.push(mismatch("stored.binary", bi, hex(stored.binary as string)));
    if (toHex(bi) !== stored.hex) problems.push(mismatch("stored.hex", toHex(bi), stored.hex));
    if (bi.length !== stored.octets || bi.length !== Math.ceil(b / 8)) problems.push(mismatch("stored.octets", bi.length, stored.octets));
  } catch (e) {
    problems.push(`raised ${errCode(e)}`);
  }
  results.push(problems.length === 0 ? { id, status: "pass" } : { id, status: "fail", reason: problems.join("; ") });

  // Full client pipeline from the tenant index key and context the vector
  // carries (suite 0.2.0), through the public blindIndex operation.
  if (normId !== undefined) {
    const pid = `${id}#pipeline`;
    try {
      const ctx = ctxFromVector(v.context as Record<string, unknown>);
      const P = 2 ** (b + 1); // inside the §7.4 band for any b ≥ 2: P·2^−b = 2, √P > 2
      const suiteId = parseSuiteId(v.suite_id as string);
      const fs = new Fieldseal(
        {
          keyProvider: new StaticKeyProvider({ dek: new Uint8Array(32).fill(0xaa), keyId: new Uint8Array(16), indexKey: hex(v.tenant_index_key as string) }),
          allowedSuites: [suiteId],
          writeSuite: suiteId,
          indexes: [
            {
              tableUuid: ctx.tableUuid,
              columnUuid: ctx.columnUuid,
              indexId: v.index_id as string,
              idf: which,
              ...(argon2 ? { argon2 } : {}),
              normalize: normId,
              truncateBits: b,
              projectedPopulation: P,
            },
          ],
        },
        { armProvisionalSuites: true },
      );
      const out = fs.blindIndex(new TextEncoder().encode(v.plaintext_preimage as string), {
        ...ctx,
        rowId: hex("deadbeef"), // must be ignored by index derivation (spec §7.2 row_id = null)
      });
      results.push(
        eq(out, hex(stored.binary as string))
          ? { id: pid, status: "pass", details: { via: "Fieldseal.blindIndex with the vector's tenant index key" } }
          : { id: pid, status: "fail", reason: mismatch("blindIndex()", out, hex(stored.binary as string)) },
      );
    } catch (e) {
      results.push({ id: pid, status: "fail", reason: `blindIndex raised ${errCode(e)}` });
    }
  }
  return results;
}

// ---------------------------------------------------------------------------
// errors/ (docs/08 §4.6): one operation per vector against a client built
// from the vector's config. `input` is literal; `expected` is one of
// {error}, {value} (pass-through), {plaintext}, {is_ciphertext}, {index}.

function runErrors(v: Record<string, unknown>): Result {
  const id = v.id as string;
  const cfg = v.config as Record<string, unknown>;
  const ex = v.expected as Record<string, unknown>;
  const op = (v.operation ?? "decrypt") as string;
  const ctx = v.context !== undefined ? ctxFromVector(v.context as Record<string, unknown>) : undefined;
  const input = hex(v.input as string);
  const decl = v.index_declaration as Record<string, unknown> | undefined;
  const want = "error" in ex ? `error ${String(ex.error)}` : JSON.stringify(ex);
  let got: Uint8Array | boolean;
  try {
    const fs = new Fieldseal(
      {
        keyProvider: new StaticKeyProvider({
          dek: hex(v.tenant_dek as string),
          keyId: hex(v.key_id as string),
          ...(v.tenant_index_key !== undefined ? { indexKey: hex(v.tenant_index_key as string) } : {}),
        }),
        allowedSuites: (cfg.allowed_suites as string[]).map(parseSuiteId),
        writeSuite: parseSuiteId(cfg.write_suite as string),
        readMode: cfg.read_mode as ReadMode,
        ...(decl && ctx
          ? {
              indexes: [
                {
                  tableUuid: ctx.tableUuid,
                  columnUuid: ctx.columnUuid,
                  indexId: decl.index_id as string,
                  idf: decl.idf as IdfId,
                  normalize: NORMALIZERS[decl.normalize as string]!,
                  truncateBits: decl.truncate_bits as number,
                  projectedPopulation: 2 ** ((decl.truncate_bits as number) + 1),
                },
              ],
            }
          : {}),
      },
      { armProvisionalSuites: cfg.arm_provisional_suites as boolean },
    );
    switch (op) {
      case "decrypt":
        got = fs.decrypt(input, ctx!);
        break;
      case "rotate":
        got = fs.rotate(input, ctx!);
        break;
      case "encrypt":
        got = fs.encrypt(input, ctx!);
        break;
      case "is_ciphertext":
        got = fs.isCiphertext(input);
        break;
      case "blind_index":
        got = fs.blindIndex(input, { ...ctx!, purpose: `index:${decl!.index_id as string}` });
        break;
      default:
        return { id, status: "fail", reason: `unknown operation ${op}` };
    }
  } catch (e) {
    const code = errCode(e);
    const ok = "error" in ex && ex.error === code;
    return ok ? { id, status: "pass", details: { raised: code } } : { id, status: "fail", reason: `expected ${want}, raised ${code}`, details: { raised: code } };
  }
  if ("error" in ex) return { id, status: "fail", reason: `expected ${want}, no error raised` };
  if ("is_ciphertext" in ex) return got === ex.is_ciphertext ? { id, status: "pass" } : { id, status: "fail", reason: `is_ciphertext returned ${String(got)}, expected ${String(ex.is_ciphertext)}` };
  const wantBytes = hex(((ex.value ?? ex.plaintext ?? ex.index) as string) ?? "");
  const gotBytes = got as Uint8Array;
  return eq(gotBytes, wantBytes) ? { id, status: "pass" } : { id, status: "fail", reason: mismatch(op, gotBytes, wantBytes) };
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
    for (const [, doc] of suite.files) {
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
            results.push(...runBlindIndex(v));
            break;
          case "errors":
            results.push(runErrors(v));
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
        // The platform's Unicode is reported for information only: since the
        // G15 closure `nfc-casefold-v1` reads vendored tables for both
        // normalization and folding, so this core's index values do not
        // depend on the runtime's ICU (docs/09 §7).
        unicode_platform: `ICU ${process.versions.icu} / Unicode ${process.versions.unicode} (not used for nfc-casefold-v1)`,
        unicode_tables: `vendored UCD ${UNICODE_VERSION} (NFC + CaseFolding C+F)`,
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

/** Spec §9 [PROVISIONAL G5] obliges a Gate 0a implementation to pin an order and declare it here. */
export const PINNED_DECISIONS: Record<string, string> = {
  "decrypt-order":
    "recognition (len<3 | fmt_ver≠0x01 | suite unregistered | len<suite minimum → NOT_CIPHERTEXT in strict, pass-through in permissive/readonly; " +
    "fmt_ver=0x02 with len≥111 → UNKNOWN_FORMAT_VERSION in every mode) → LENGTH_EXCEEDED (§3.5 decrypt side) → SUITE_NOT_ALLOWED → KEY_UNAVAILABLE (provider returned no candidate) → " +
    "per candidate: HKDF record key, constant-time commitment verify, then AEAD open; open failure after a verified commitment → TAG_INVALID; " +
    "no candidate's commitment verifies → COMMITMENT_INVALID",
  "aad-mismatch": "AAD_MISMATCH is never raised on the 0xFF01 decrypt path: under §6.3 dual binding a context mismatch changes the record key and is indistinguishable from key confusion at the commitment check (G5). The optional diagnostic re-derivation docs/09 §3.2 describes is not implemented.",
  "api-boundary-order": "encrypt/rotate: MODE_VIOLATION → SUITE_PROVISIONAL → LENGTH_EXCEEDED → context validation (INVALID_ARGUMENT, non-§9); all before key acquisition",
  "unimplemented-registered-suite": "0xFF02 is registered (isCiphertext → true) but refused at construction if allow-listed or set as writeSuite (CONFIGURATION_ERROR naming G7); no §9 code is reachable for it because no client can be built that accepts it",
  "commitment-construction": 'HKDF-SHA-512(ikm = record_key, salt = "", info = "fieldseal-commit-v1", 32) -- as spec §4.6 states under its [PROVISIONAL — G1] marker (since 2026-08-23); provisional until G1 closes',
};
// Retired 2026-08-24 when issue #48 (G15) closed and the specification took
// these over: `unknown-format-version-set` -> spec §3.1/§3.4/§9/§10.3,
// `rotate-in-permissive` -> §11.1, `provisional-arming` -> §4.8,
// `normalizer-text-over-bytes` -> docs/09 §7. A pinned decision records where
// a core had to choose without text behind it; once the text exists there is
// nothing left to declare.

export const HARNESS_NOTES: string[] = [
  "docs/08 §5 item 2 (JSON-Schema validation) could not be performed: vectors/schema/ is empty in the checkout this harness ran against. The harness performs its own structural validation of every vector object before running it.",
  "Envelope vectors are reported twice: '<id>' is the encrypt direction (envelope, canonical_context, aad, envelope_bytes) and '<id>#decrypt' is the decrypt direction.",
  "'<id>#pipeline' results run blind-index vectors through Fieldseal.blindIndex() end to end, using the tenant index key and context the vector carries (suite 0.2.0).",
  "Assertion vectors (assertion: distinct|equal) carry their inputs since suite 0.2.0; both sides are reproduced and the relation checked.",
  "errors/ vectors run each operation against a client built from the vector's config; a raised FieldsealError is matched by code, anything else is a failure. blind_index cases pass the preimage bytes under the vector's index_declaration.",
  "blind-index/argon2id.json is held out (MANIFEST.held_out) and was not iterated; it is reported as not-run. Nothing about Argon2id contributes to this report's summary.",
];
