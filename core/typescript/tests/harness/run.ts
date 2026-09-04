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
import { ARGON2_OUTPUT_LEN, ARGON2_P, ARGON2_VERSION, argon2Salt, idf, idfAsync, truncateBits, UNINDEXABLE_PREIMAGE, type Argon2Params, type IdfId } from "../../src/blindindex.ts";
import { COMMIT_INFO, computeCommitment } from "../../src/commitment.ts";
import { aad as buildAad, canonicalContext, type FieldContext, type ResolvedContext } from "../../src/context.ts";
import { FieldsealError } from "../../src/errors.ts";
import { INDEX_KEY_SALT, deriveIndexKey, deriveRecordKey } from "../../src/kdf.ts";
import { StaticKeyProvider } from "../../src/keyprovider.ts";
import { UNICODE_VERSION, normalize, type NormalizerId } from "../../src/normalize.ts";
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
  async_companions: boolean;
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

/**
 * docs/08 §4.4: the Argon2id cost comes from the vector, never from this
 * core's defaults. Spec §7.3 states `t` and `m` as minima a deployment may
 * raise, so a vector at a raised cost is authorable (a G2 obligation), and
 * only a harness that passes the stated cost through lets such a vector test
 * the core rather than the harness — dropping it fails a correct core and
 * points the failure at the primitive (#62).
 */
/**
 * The cost an Argon2id vector declares (docs/08 §4.4), never this core's
 * default: a vector at a raised cost tests the core only if the harness
 * derives at the declared cost (issue #62). A missing cost is a malformed
 * vector; the throw lands in the caller's per-vector boundary as a recorded
 * failure. The fields spec §7.3 pins outright are checked rather than read:
 * a vector declaring another `version`, `parallelism` or `output_len` is one
 * this core cannot derive at, and deriving at the constant regardless would
 * be the silent assumption #62 exists to catch (#108 review).
 */
function argon2Of(v: Record<string, unknown>): Argon2Params | undefined {
  if (v.idf !== "argon2id") return undefined;
  const p = v.idf_params as Record<string, number> | undefined;
  if (p?.time_cost === undefined || p.memory_kib === undefined) {
    throw new Error("argon2id vector without idf_params.time_cost / .memory_kib");
  }
  const fixed: [string, number | undefined, number][] = [
    ["version", p.version, ARGON2_VERSION],
    ["parallelism", p.parallelism, ARGON2_P],
    ["output_len", p.output_len, ARGON2_OUTPUT_LEN],
  ];
  for (const [name, declared, pinned] of fixed) {
    if (declared !== undefined && declared !== pinned) {
      throw new Error(`argon2id vector declares idf_params.${name}=${declared}; spec §7.3 pins ${pinned} and this core cannot derive at anything else`);
    }
  }
  return { timeCost: p.time_cost, memoryKib: p.memory_kib };
}

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
      const cost = argon2Of(inp);
      a = truncateBits(idf(which, ik, normalize(normId, new TextEncoder().encode(inp.plaintext_preimage_a as string)), cost), bits);
      b = truncateBits(idf(which, ik, normalize(normId, new TextEncoder().encode(inp.plaintext_preimage_b as string)), cost), bits);
      [wantA, wantB] = [ex.index_a as string, ex.index_b as string];
    } else {
      throw new Error("no assertion runner for this family");
    }
    problems.push(...judgeSides(a, b, wantA, wantB, want));
  } catch (e) {
    problems.push(`raised ${errCode(e)}`);
  }
  return problems.length === 0 ? { id, status: "pass" } : { id, status: "fail", reason: problems.join("; ") };
}

/** Both sides against their expected bytes, then the relation between them. */
function judgeSides(a: Uint8Array, b: Uint8Array, wantA: string, wantB: string, want: boolean): string[] {
  const problems: string[] = [];
  if (!eq(a, hex(wantA))) problems.push(mismatch("side a", a, hex(wantA)));
  if (!eq(b, hex(wantB))) problems.push(mismatch("side b", b, hex(wantB)));
  if (eq(a, b) !== want) problems.push(`sides ${eq(a, b) ? "are" : "are not"} equal; must_be_equal=${want}`);
  return problems;
}

/**
 * `runAssertion` for the async pass. Only `blind-index/` assertions have an
 * operation with a §11.1 companion; every other family re-runs the
 * synchronous check, which is what makes the second pass the entire suite.
 */
async function runAssertionAsync(v: Record<string, unknown>): Promise<Result> {
  const id = v.id as string;
  if (!id.startsWith("blind-index/")) return runAssertion(v);
  const ex = v.expected as Record<string, unknown>;
  const inp = v.inputs as Record<string, unknown>;
  const want = ex.must_be_equal as boolean;
  const problems: string[] = [];
  try {
    const which = inp.idf as IdfId;
    const normId = NORMALIZERS[inp.normalize as string];
    if (normId === undefined) throw new Error(`unknown normalizer ${String(inp.normalize)}`);
    const ik = hex(inp.index_key as string);
    const bits = inp.truncate_bits as number;
    const cost = argon2Of(inp);
    const side = async (preimage: string): Promise<Uint8Array> =>
      truncateBits(await idfAsync(which, ik, normalize(normId, new TextEncoder().encode(preimage)), cost), bits);
    const a = await side(inp.plaintext_preimage_a as string);
    const b = await side(inp.plaintext_preimage_b as string);
    problems.push(...judgeSides(a, b, ex.index_a as string, ex.index_b as string, want));
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

/**
 * docs/09 §7.2, the `on_unindexable` shapes. Kept out of `runAssertion`
 * because these are not two-sided relations: one pins the reserved marker's
 * bytes, the other pins that a refused value lands on them while the default
 * still refuses.
 *
 * The marker's bytes matter as much as its behaviour. Two cores that derived
 * different markers would put their unindexable rows in two different
 * buckets, and a lookup across them would silently return nothing — the exact
 * failure `on_unindexable` exists to prevent, reintroduced by the fix.
 */
function runUnindexable(v: Record<string, unknown>): Result {
  const inp = v.inputs as Record<string, unknown>;
  return judgeUnindexable(v, () => {
    const marker = truncateBits(idf(inp.idf as IdfId, hex(inp.index_key as string), UNINDEXABLE_PREIMAGE, argon2Of(inp)), inp.truncate_bits as number);
    const api = unindexableClient(inp, "bucket").unindexableMarker(indexCtx(inp));
    return { marker, api };
  }, (value) => {
    const bucketed = unindexableClient(inp, "bucket").blindIndex(value, indexCtx(inp));
    let refused = "NONE";
    try {
      unindexableClient(inp, "refuse").blindIndex(value, indexCtx(inp));
    } catch (e) {
      refused = errCode(e);
    }
    return { bucketed, refused };
  });
}

/**
 * `runUnindexable` through the §11.1 companions. The refusal half is the
 * only place in the whole second pass where a companion is required to
 * produce a §9 *error*: `errors/`'s two blind_index vectors are both
 * positive controls. `await` inside the `try` is what makes the rejection
 * land in `errCode` rather than escaping as an unhandled rejection.
 */
async function runUnindexableAsync(v: Record<string, unknown>): Promise<Result> {
  const inp = v.inputs as Record<string, unknown>;
  return judgeUnindexableAsync(
    v,
    async () => {
      const marker = truncateBits(
        await idfAsync(inp.idf as IdfId, hex(inp.index_key as string), UNINDEXABLE_PREIMAGE, argon2Of(inp)),
        inp.truncate_bits as number,
      );
      const api = await unindexableClient(inp, "bucket").unindexableMarkerAsync(indexCtx(inp));
      return { marker, api };
    },
    async (value) => {
      const bucketed = await unindexableClient(inp, "bucket").blindIndexAsync(value, indexCtx(inp));
      let refused = "NONE";
      try {
        await unindexableClient(inp, "refuse").blindIndexAsync(value, indexCtx(inp));
      } catch (e) {
        refused = errCode(e);
      }
      return { bucketed, refused };
    },
  );
}

interface MarkerSides {
  marker: Uint8Array;
  api: Uint8Array;
}
interface BucketSides {
  bucketed: Uint8Array;
  refused: string;
}

/** The checks both unindexable shapes make, given the derived values. */
function unindexableProblems(v: Record<string, unknown>, sides: MarkerSides | BucketSides): string[] {
  const ex = v.expected as Record<string, unknown>;
  const inp = v.inputs as Record<string, unknown>;
  const want = hex(ex.index as string);
  const problems: string[] = [];
  if ("marker" in sides) {
    if (!eq(hex(inp.reserved_preimage as string), UNINDEXABLE_PREIMAGE)) {
      problems.push(mismatch("reserved preimage", UNINDEXABLE_PREIMAGE, hex(inp.reserved_preimage as string)));
    }
    if (!eq(sides.marker, want)) problems.push(mismatch("marker", sides.marker, want));
    // ...and that the public API agrees with the primitive.
    if (!eq(sides.api, want)) problems.push(mismatch("unindexableMarker()", sides.api, want));
  } else {
    if (!eq(sides.bucketed, want)) problems.push(mismatch("bucketed index", sides.bucketed, want));
    // Both halves matter: a `bucket` that never fires is useless, and a
    // `refuse` that stopped refusing would be a silent policy change.
    const wantRefused = ex.on_unindexable_refuse as string;
    if (sides.refused !== wantRefused) problems.push(`on_unindexable="refuse" gave ${sides.refused}, want ${wantRefused}`);
  }
  return problems;
}

function unindexableVerdict(id: string, problems: string[]): Result {
  return problems.length === 0 ? { id, status: "pass" } : { id, status: "fail", reason: problems.join("; ") };
}

function judgeUnindexable(
  v: Record<string, unknown>,
  // At the vector's declared cost, like every other derivation here. Until
  // the #108 review the marker call omitted the cost and derived at this
  // core's default -- invisible while every vector sat at the minima, and
  // the reason unindexable-marker-t4-b15 now exists.
  marker: () => MarkerSides,
  bucket: (value: string) => BucketSides,
): Result {
  const problems: string[] = [];
  try {
    const inp = v.inputs as Record<string, unknown>;
    problems.push(...unindexableProblems(v, v.assertion === "unindexable-marker" ? marker() : bucket(inp.plaintext_preimage as string)));
  } catch (e) {
    problems.push(`raised ${errCode(e)}`);
  }
  return unindexableVerdict(v.id as string, problems);
}

async function judgeUnindexableAsync(
  v: Record<string, unknown>,
  marker: () => Promise<MarkerSides>,
  bucket: (value: string) => Promise<BucketSides>,
): Promise<Result> {
  const problems: string[] = [];
  try {
    const inp = v.inputs as Record<string, unknown>;
    problems.push(...unindexableProblems(v, v.assertion === "unindexable-marker" ? await marker() : await bucket(inp.plaintext_preimage as string)));
  } catch (e) {
    problems.push(`raised ${errCode(e)}`);
  }
  return unindexableVerdict(v.id as string, problems);
}

function indexCtx(inp: Record<string, unknown>): FieldContext {
  const c = ctxFromVector(inp.context as Record<string, unknown>);
  return { ...c, purpose: `index:${inp.index_id as string}` };
}

function unindexableClient(inp: Record<string, unknown>, onUnindexable: "refuse" | "bucket"): Fieldseal {
  const c = ctxFromVector(inp.context as Record<string, unknown>);
  return new Fieldseal(
    {
      keyProvider: new StaticKeyProvider({
        dek: new Uint8Array(32).fill(0xaa),
        keyId: new Uint8Array(16),
        indexKey: hex(inp.tenant_index_key as string),
      }),
      allowedSuites: [SUITE_FF01],
      writeSuite: SUITE_FF01,
      readMode: "strict",
      indexes: [
        {
          tableUuid: c.tableUuid,
          columnUuid: c.columnUuid,
          indexId: inp.index_id as string,
          idf: inp.idf as IdfId,
          ...(argon2Of(inp) ? { argon2: argon2Of(inp) as Argon2Params } : {}),
          normalize: inp.normalize as NormalizerId,
          truncateBits: inp.truncate_bits as number,
          projectedPopulation: 65536,
          onUnindexable,
          ...(onUnindexable === "bucket"
            ? { unindexableOverride: { reason: "vector harness", approvedBy: "vectors", date: "2026-08-25" } }
            : {}),
        },
      ],
    },
    { armProvisionalSuites: true },
  );
}

interface BlindIndexInputs {
  which: IdfId;
  indexKey: Uint8Array;
  b: number;
  normId: NormalizerId | undefined;
  params: Record<string, number>;
  argon2: Argon2Params | undefined;
  costError: unknown;
}

function blindIndexInputs(v: Record<string, unknown>): BlindIndexInputs {
  // The cost is read inside a boundary like everything else in the vector: a
  // malformed cost is this vector's recorded failure (both results), not the
  // run's abort.
  let argon2: Argon2Params | undefined;
  let costError: unknown;
  try {
    argon2 = argon2Of(v);
  } catch (e) {
    costError = e;
  }
  return {
    which: v.idf as IdfId,
    indexKey: hex(v.index_key as string),
    b: v.truncate_bits as number,
    normId: NORMALIZERS[v.normalize as string],
    params: v.idf_params as Record<string, number>,
    argon2,
    costError,
  };
}

/**
 * The normalized value the primitive derives from, and the normalizer check
 * that comes with it. docs/08 §4.4: `plaintext` (already normalized) is the
 * normative input; the preimage checks the shipped normalizer against it.
 */
function blindIndexNormalized(v: Record<string, unknown>, i: BlindIndexInputs, problems: string[]): Uint8Array {
  if (i.normId === undefined) throw new Error(`unknown normalizer ${String(v.normalize)}`);
  if (i.costError !== undefined) throw i.costError;
  const wantNormalized = hex(v.plaintext as string);
  const normalized = normalize(i.normId, new TextEncoder().encode(v.plaintext_preimage as string));
  if (!eq(normalized, wantNormalized)) problems.push(mismatch("normalizer", normalized, wantNormalized));
  return wantNormalized;
}

/** Everything the primitive result asserts once `raw` is in hand. */
function blindIndexProblems(v: Record<string, unknown>, i: BlindIndexInputs, raw: Uint8Array): string[] {
  const ex = v.expected as Record<string, unknown>;
  const stored = ex.stored as Record<string, string | number>;
  const problems: string[] = [];
  if (!eq(raw, hex(ex.raw as string))) problems.push(mismatch("raw", raw, hex(ex.raw as string)));
  if (i.which === "argon2id" && typeof i.params.salt === "string") {
    const salt = argon2Salt(i.indexKey);
    if (!eq(salt, hex(i.params.salt as unknown as string))) problems.push(mismatch("salt", salt, hex(i.params.salt as unknown as string)));
  }
  const bi = truncateBits(raw, i.b);
  if (!eq(bi, hex(ex.index as string))) problems.push(mismatch("index", bi, hex(ex.index as string)));
  // Spec §7.11 stored form: the raw truncated bytes, exactly ⌈b/8⌉ of them;
  // lowercase hex is the declared-per-column alternative.
  if (!eq(bi, hex(stored.binary as string))) problems.push(mismatch("stored.binary", bi, hex(stored.binary as string)));
  if (toHex(bi) !== stored.hex) problems.push(mismatch("stored.hex", toHex(bi), stored.hex));
  if (bi.length !== stored.octets || bi.length !== Math.ceil(i.b / 8)) problems.push(mismatch("stored.octets", bi.length, stored.octets));
  return problems;
}

/**
 * The client the `#pipeline` result derives through: the tenant index key
 * and context the vector carries (suite 0.2.0), declared as a column.
 */
function pipelineClient(v: Record<string, unknown>, i: BlindIndexInputs, ctx: FieldContext): Fieldseal {
  const P = 2 ** (i.b + 1); // inside the §7.4 band for any b ≥ 2: P·2^−b = 2, √P > 2
  const suiteId = parseSuiteId(v.suite_id as string);
  return new Fieldseal(
    {
      keyProvider: new StaticKeyProvider({ dek: new Uint8Array(32).fill(0xaa), keyId: new Uint8Array(16), indexKey: hex(v.tenant_index_key as string) }),
      allowedSuites: [suiteId],
      writeSuite: suiteId,
      indexes: [
        {
          tableUuid: ctx.tableUuid,
          columnUuid: ctx.columnUuid,
          indexId: v.index_id as string,
          idf: i.which,
          ...(i.argon2 ? { argon2: i.argon2 } : {}),
          normalize: i.normId as NormalizerId,
          truncateBits: i.b,
          projectedPopulation: P,
        },
      ],
    },
    { armProvisionalSuites: true },
  );
}

/** The context the pipeline call passes, row_id included deliberately. */
function pipelineCtx(v: Record<string, unknown>): FieldContext {
  return {
    ...ctxFromVector(v.context as Record<string, unknown>),
    rowId: hex("deadbeef"), // must be ignored by index derivation (spec §7.2 row_id = null)
  };
}

function pipelineVerdict(pid: string, out: Uint8Array, v: Record<string, unknown>, via: string): Result {
  const stored = (v.expected as Record<string, unknown>).stored as Record<string, string | number>;
  return eq(out, hex(stored.binary as string))
    ? { id: pid, status: "pass", details: { via } }
    : { id: pid, status: "fail", reason: mismatch("blindIndex()", out, hex(stored.binary as string)) };
}

function runBlindIndex(v: Record<string, unknown>): Result[] {
  const id = v.id as string;
  if (v.assertion === "unindexable-marker" || v.assertion === "unindexable-bucket") return [runUnindexable(v)];
  if (v.assertion !== undefined) return [runAssertion(v)];
  const i = blindIndexInputs(v);
  const results: Result[] = [];
  const problems: string[] = [];
  try {
    const normalized = blindIndexNormalized(v, i, problems);
    problems.push(...blindIndexProblems(v, i, idf(i.which, i.indexKey, normalized, i.argon2)));
  } catch (e) {
    problems.push(`raised ${errCode(e)}`);
  }
  results.push(problems.length === 0 ? { id, status: "pass" } : { id, status: "fail", reason: problems.join("; ") });

  // Full client pipeline through the public blindIndex operation.
  if (i.normId !== undefined) {
    const pid = `${id}#pipeline`;
    try {
      if (i.costError !== undefined) throw i.costError;
      const out = pipelineClient(v, i, ctxFromVector(v.context as Record<string, unknown>)).blindIndex(
        new TextEncoder().encode(v.plaintext_preimage as string),
        pipelineCtx(v),
      );
      results.push(pipelineVerdict(pid, out, v, "Fieldseal.blindIndex with the vector's tenant index key"));
    } catch (e) {
      results.push({ id: pid, status: "fail", reason: `blindIndex raised ${errCode(e)}` });
    }
  }
  return results;
}

/**
 * `runBlindIndex` for the async pass: the same checks with the derivation
 * routed through `idfAsync` and the pipeline through
 * `Fieldseal.blindIndexAsync`. The primitive goes through the real async
 * primitive rather than comparing a copy, so `<id>#async` is a genuine check
 * of `crypto.argon2` against the vectors at both cost points.
 */
async function runBlindIndexAsync(v: Record<string, unknown>): Promise<Result[]> {
  const id = v.id as string;
  if (v.assertion === "unindexable-marker" || v.assertion === "unindexable-bucket") return [await runUnindexableAsync(v)];
  if (v.assertion !== undefined) return [await runAssertionAsync(v)];
  const i = blindIndexInputs(v);
  const results: Result[] = [];
  const problems: string[] = [];
  try {
    const normalized = blindIndexNormalized(v, i, problems);
    problems.push(...blindIndexProblems(v, i, await idfAsync(i.which, i.indexKey, normalized, i.argon2)));
  } catch (e) {
    problems.push(`raised ${errCode(e)}`);
  }
  results.push(problems.length === 0 ? { id, status: "pass" } : { id, status: "fail", reason: problems.join("; ") });

  if (i.normId !== undefined) {
    const pid = `${id}#pipeline`;
    try {
      if (i.costError !== undefined) throw i.costError;
      const out = await pipelineClient(v, i, ctxFromVector(v.context as Record<string, unknown>)).blindIndexAsync(
        new TextEncoder().encode(v.plaintext_preimage as string),
        pipelineCtx(v),
      );
      results.push(pipelineVerdict(pid, out, v, "Fieldseal.blindIndexAsync with the vector's tenant index key"));
    } catch (e) {
      results.push({ id: pid, status: "fail", reason: `blindIndexAsync raised ${errCode(e)}` });
    }
  }
  return results;
}

// ---------------------------------------------------------------------------
// errors/ (docs/08 §4.6): one operation per vector against a client built
// from the vector's config. `input` is literal; `expected` is one of
// {error}, {value} (pass-through), {plaintext}, {is_ciphertext}, {index}.

function errorsClient(v: Record<string, unknown>, ctx: FieldContext | undefined): Fieldseal {
  const cfg = v.config as Record<string, unknown>;
  const decl = v.index_declaration as Record<string, unknown> | undefined;
  return new Fieldseal(
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
}

/** The verdict when the operation (or the client's construction) raised. */
function judgeErrorsRaised(id: string, ex: Record<string, unknown>, want: string, e: unknown): Result {
  const code = errCode(e);
  const ok = "error" in ex && ex.error === code;
  return ok ? { id, status: "pass", details: { raised: code } } : { id, status: "fail", reason: `expected ${want}, raised ${code}`, details: { raised: code } };
}

/** The verdict when it returned. */
function judgeErrorsReturned(id: string, ex: Record<string, unknown>, want: string, op: string, got: Uint8Array | boolean): Result {
  if ("error" in ex) return { id, status: "fail", reason: `expected ${want}, no error raised` };
  if ("is_ciphertext" in ex) return got === ex.is_ciphertext ? { id, status: "pass" } : { id, status: "fail", reason: `is_ciphertext returned ${String(got)}, expected ${String(ex.is_ciphertext)}` };
  const wantBytes = hex(((ex.value ?? ex.plaintext ?? ex.index) as string) ?? "");
  const gotBytes = got as Uint8Array;
  return eq(gotBytes, wantBytes) ? { id, status: "pass" } : { id, status: "fail", reason: mismatch(op, gotBytes, wantBytes) };
}

function runErrors(v: Record<string, unknown>): Result {
  const id = v.id as string;
  const ex = v.expected as Record<string, unknown>;
  const op = (v.operation ?? "decrypt") as string;
  const ctx = v.context !== undefined ? ctxFromVector(v.context as Record<string, unknown>) : undefined;
  const input = hex(v.input as string);
  const decl = v.index_declaration as Record<string, unknown> | undefined;
  const want = "error" in ex ? `error ${String(ex.error)}` : JSON.stringify(ex);
  let got: Uint8Array | boolean;
  try {
    const fs = errorsClient(v, ctx);
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
    return judgeErrorsRaised(id, ex, want, e);
  }
  return judgeErrorsReturned(id, ex, want, op, got);
}

/**
 * `runErrors` for the async pass. Only `blind_index` has a companion; the
 * other four operations re-run their synchronous form, which is what the
 * `#async` twin of an `envelope`-family error vector means.
 *
 * Both `blind_index` error vectors are positive controls -- they expect an
 * index value, not an error -- so this swap on its own proves no error-code
 * parity. That obligation is carried by the `unindexable-bucket` vectors'
 * refusal half, the `#async` out-of-band entry, and
 * `tests/async-companions.test.ts`.
 */
async function runErrorsAsync(v: Record<string, unknown>): Promise<Result> {
  const op = (v.operation ?? "decrypt") as string;
  if (op !== "blind_index") return runErrors(v);
  const id = v.id as string;
  const ex = v.expected as Record<string, unknown>;
  const ctx = v.context !== undefined ? ctxFromVector(v.context as Record<string, unknown>) : undefined;
  const input = hex(v.input as string);
  const decl = v.index_declaration as Record<string, unknown> | undefined;
  const want = "error" in ex ? `error ${String(ex.error)}` : JSON.stringify(ex);
  let got: Uint8Array;
  try {
    got = await errorsClient(v, ctx).blindIndexAsync(input, { ...ctx!, purpose: `index:${decl!.index_id as string}` });
  } catch (e) {
    return judgeErrorsRaised(id, ex, want, e);
  }
  return judgeErrorsReturned(id, ex, want, op, got);
}

// ---------------------------------------------------------------------------
// Out-of-band: spec §3.5 length bound (docs/08 §5 item 8)

/**
 * docs/09 §7.1: the index boundary takes text, and refuses an unpaired
 * surrogate *distinguishably* (G16 part A).
 *
 * This has no vector and cannot have one. The `blind-index/` family keys its
 * input as hex bytes, and an unpaired surrogate has no UTF-8 encoding, so the
 * case is inexpressible in the family's own shape. Widening the field to text
 * would not fix it either: Go string literals may not hold a surrogate value
 * and rune conversion substitutes U+FFFD, and Rust's `String` is UTF-8 by
 * invariant — so two of the five target languages cannot carry the operand at
 * all, and a core in either would report `not-run` rather than `pass`.
 *
 * That is exactly what `out_of_band` is for (docs/14 §4, the G10 precedent):
 * a normative requirement verified by a test the report would otherwise never
 * mention is indistinguishable from one nobody checked.
 */
const INDEX_BOUNDARY_ID = "docs/09/7.1/lone-surrogate-refusal";
const INDEX_BOUNDARY_METHOD =
  "unit test: two distinct unpaired surrogates passed as text to blindIndex are both refused, with messages that name different code points";

interface Refusal {
  code: string;
  message: string;
}

function indexBoundaryClient(): { fs: Fieldseal; ctx: FieldContext } {
  const fs = new Fieldseal(
    {
      // An index key is required here: without one, key acquisition fails
      // before normalization runs and this check would pass or fail for
      // reasons that have nothing to do with what it is asserting.
      keyProvider: new StaticKeyProvider({
        dek: new Uint8Array(32).fill(0xaa),
        keyId: new Uint8Array(16),
        indexKey: new Uint8Array(32).fill(0xbb),
      }),
      allowedSuites: [SUITE_FF01],
      writeSuite: SUITE_FF01,
      readMode: "strict",
      indexes: [
        {
          tableUuid: new Uint8Array(16),
          columnUuid: new Uint8Array(16),
          idf: "hmac-sha512",
          normalize: "nfc-casefold-v1",
          truncateBits: 15,
          projectedPopulation: 65536,
        },
      ],
    },
    { armProvisionalSuites: true },
  );
  const ctx: FieldContext = {
    tableUuid: new Uint8Array(16),
    columnUuid: new Uint8Array(16),
    tenantId: null,
    rowId: null,
    purpose: "index:exact",
  };
  return { fs, ctx };
}

function judgeIndexBoundary(id: string, method: string, high: Refusal, low: Refusal): OutOfBand[] {
  let status: OutOfBand["status"] = "pass";
  let reason: string | undefined;
  if (high.code !== "INVALID_ARGUMENT" || low.code !== "INVALID_ARGUMENT") {
    status = "fail";
    reason = `expected INVALID_ARGUMENT for both, got ${high.code} and ${low.code}`;
  } else if (high.message === low.message) {
    // Same outcome is not enough. If the diagnosis is identical the two values
    // are indistinguishable to the caller, which is the property the refusal
    // exists to deny them.
    status = "fail";
    reason = "both surrogates produced the same message; the refusal does not distinguish them";
  }
  return [{ id, status, method, ...(reason ? { reason } : {}) }];
}

function runIndexBoundary(): OutOfBand[] {
  const { fs, ctx } = indexBoundaryClient();
  const refuse = (s: string): Refusal => {
    try {
      fs.blindIndex(s, ctx);
      return { code: "NONE", message: "" };
    } catch (e) {
      return { code: errCode(e), message: (e as Error).message };
    }
  };
  return judgeIndexBoundary(INDEX_BOUNDARY_ID, INDEX_BOUNDARY_METHOD, refuse("a\uD800b"), refuse("a\uDC00b"));
}

/**
 * The same check through the §11.1 companion, and the async pass's only
 * *error* obligation that a vector cannot carry: spec §11.1 requires the
 * companion to raise the same §9 error for the same condition, and every
 * blind-index error vector in the suite is a positive control.
 */
async function runIndexBoundaryAsync(): Promise<OutOfBand[]> {
  const { fs, ctx } = indexBoundaryClient();
  const refuse = async (s: string): Promise<Refusal> => {
    try {
      await fs.blindIndexAsync(s, ctx);
      return { code: "NONE", message: "" };
    } catch (e) {
      return { code: errCode(e), message: (e as Error).message };
    }
  };
  return judgeIndexBoundary(
    `${INDEX_BOUNDARY_ID}#async`,
    `${INDEX_BOUNDARY_METHOD}, through blindIndexAsync (both refusals arrive as rejections)`,
    await refuse("a\uD800b"),
    await refuse("a\uDC00b"),
  );
}

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

/**
 * One pass over the whole suite. `"async"` routes every operation that has a
 * spec §11.1 companion through it; the families that have none re-run the
 * synchronous operation, so that docs/08 §5 item 10's "the entire suite"
 * stays the entire suite rather than a selection of it (the twins that
 * cannot differ are identical by construction, and the harness note says so).
 *
 * One loop for both passes: a second copy could gain a family the first has
 * and nobody would notice.
 */
async function runPass(suite: LoadedSuite, pass: "sync" | "async"): Promise<Result[]> {
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
          results.push(...(pass === "async" ? await runBlindIndexAsync(v) : runBlindIndex(v)));
          break;
        case "errors":
          results.push(pass === "async" ? await runErrorsAsync(v) : runErrors(v));
          break;
        default:
          results.push({ id: v.id as string, status: "fail", reason: `no runner for family ${doc.group}` });
      }
    }
  }
  return results;
}

export async function runSuite(opts: RunOptions = {}): Promise<Report> {
  const prevTestMode = process.env[TEST_MODE_ENV];
  process.env[TEST_MODE_ENV] = "1";
  // The arming window must span both passes: `encrypt_with_materials` reads
  // this variable at call time, so de-arming between them would turn every
  // envelope twin into a failure.
  try {
    const suite = loadSuite(opts.vectorsDir);
    const results = await runPass(suite, "sync");
    // docs/08 §5 item 10: the entire suite, a second time, through the
    // companions. The suffix is applied to the synchronous *result* id at the
    // pass boundary, so it lands last: `<id>#decrypt#async`, `<id>#pipeline#async`.
    const second = await runPass(suite, "async");
    results.push(...second.map((r) => ({ ...r, id: `${r.id}#async` })));
    const outOfBand = [...runLengthBound(), ...runIndexBoundary(), ...(await runIndexBoundaryAsync())];
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
      async_companions: true,
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
  "key-material-ownership":
    "provider-owned (docs/09 §8.1): the core never mutates or erases what `encryptionKey` or `decryptionKeys` returned. `#encryptionKey` validates and copies (api.ts:196), so the encrypt and blind-index paths erase their own copy; the decrypt candidate loop borrows and erases nothing. Erasure steps performed: docs/09 §3.1 step 13 and §3.2 record_key (both, Uint8Array), the intermediate plaintext buffer, the untruncated IDF output, the Argon2id salt (spec §7.3 makes it key-equivalent for the column), and §8.3 cache eviction. None skipped. Candidate reads do not count against max_uses. " +
    "In the §11.1 asynchronous companions both index keys are erased as soon as `idfAsync` returns -- the Argon2id salt is derived from them synchronously, so nothing the in-flight derivation holds reads them; the threadpool job is already queued by then, and captured the salt and the copy rather than the key -- and the normalized value is copied rather than borrowed across the await, because under `identity` it is the caller's own array and on the marker path it is the process-wide reserved preimage; neither original is ever zeroed. The copy is what makes erasing the buffer handed to the backend safe: on the shipped backend node copies it synchronously, so the caller is not relying on the copy for that.",
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
  "'<result-id>#async' is the docs/08 §5 item 10 pass: the entire suite run a second time with every operation that has a spec §11.1 asynchronous companion routed through it, asserting identical bytes and identical error codes. The suffix is applied to the synchronous result id, so it comes last ('<id>#decrypt#async', '<id>#pipeline#async'). This core ships companions for blind_index and unindexable_marker only: blind-index/ primitives and their #pipeline results derive through idfAsync / Fieldseal.blindIndexAsync / Fieldseal.unindexableMarkerAsync, and errors/ blind_index cases through blindIndexAsync (both are positive controls, so the companions' error-code parity rests on the unindexable refusal check, the '#async' out-of-band entry and tests/async-companions.test.ts instead). envelope/, kdf/, context/, commitment/ and the other errors/ operations have no companion, and their '#async' twins re-run the synchronous operation.",
  "blind-index/argon2id.json is pinned as of suite 0.6.0-provisional (docs/07 §7) and is iterated like any other family; Argon2id contributes to this report's summary. Each vector derives at the cost it declares in idf_params, not at this core's default (docs/08 §4.4), and the declared salt is asserted on its own. A vector this core cannot derive at (a missing or non-§7.3 idf_params) is a recorded failure, not an abort.",
];
