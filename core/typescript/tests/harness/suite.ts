/**
 * Vector-suite loading (docs/08 §5 items 1-2): MANIFEST.json, file hashes,
 * pinned/held-out status, and structural validation of every vector object.
 *
 * docs/08 §5 item 2 asks for JSON-Schema validation against
 * `vectors/schema/`. That directory is empty in this checkout (recorded in
 * the M2 report), so the harness validates the shape it depends on itself --
 * loudly, before any vector runs -- rather than skipping the step silently.
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const VECTORS_DIR = resolve(dirname(fileURLToPath(import.meta.url)), "../../../../vectors");

export interface ManifestFile {
  path: string;
  sha256: string;
  bytes: number;
}

export interface ManifestHeldOut extends ManifestFile {
  reason: string;
  unblocks_when: string;
  tracking?: string;
}

export interface Manifest {
  vector_suite_version: string;
  spec_version: string;
  provisional: boolean;
  files: ManifestFile[];
  /** Non-family files the suite ships (keys/); hashed, never iterated. */
  support?: ManifestFile[];
  held_out: ManifestHeldOut[];
}

export interface VectorFile {
  schema: string;
  vector_suite_version: string;
  group: string;
  spec_version: string;
  status: string;
  vectors: Record<string, unknown>[];
  retired: unknown[];
}

export interface LoadedSuite {
  manifest: Manifest;
  files: Map<string, VectorFile>; // keyed by manifest path
}

export class SuiteIntegrityError extends Error {
  constructor(msg: string) {
    super(msg);
    this.name = "SuiteIntegrityError";
  }
}

export function loadSuite(dir: string = VECTORS_DIR): LoadedSuite {
  const manifest = JSON.parse(readFileSync(join(dir, "MANIFEST.json"), "utf-8")) as Manifest;
  if (!Array.isArray(manifest.files) || manifest.files.length === 0) throw new SuiteIntegrityError("MANIFEST.files is empty");
  if (typeof manifest.vector_suite_version !== "string") throw new SuiteIntegrityError("MANIFEST.vector_suite_version missing");
  const held = new Set((manifest.held_out ?? []).map((h) => h.path));
  const files = new Map<string, VectorFile>();
  for (const f of manifest.files) {
    if (held.has(f.path)) throw new SuiteIntegrityError(`${f.path} is listed both in files and held_out`);
    const bytes = readFileSync(join(dir, f.path));
    const sha = createHash("sha256").update(bytes).digest("hex");
    if (sha !== f.sha256) throw new SuiteIntegrityError(`${f.path}: sha256 ${sha} != manifest ${f.sha256}`);
    if (bytes.length !== f.bytes) throw new SuiteIntegrityError(`${f.path}: ${bytes.length} bytes != manifest ${f.bytes}`);
    const doc = JSON.parse(bytes.toString("utf-8")) as VectorFile;
    if (doc.status !== "pinned") throw new SuiteIntegrityError(`${f.path}: status ${JSON.stringify(doc.status)} is not "pinned"`);
    if (doc.vector_suite_version !== manifest.vector_suite_version) {
      throw new SuiteIntegrityError(`${f.path}: vector_suite_version ${doc.vector_suite_version} != manifest ${manifest.vector_suite_version}`);
    }
    if (!Array.isArray(doc.vectors)) throw new SuiteIntegrityError(`${f.path}: vectors is not an array`);
    validateShape(f.path, doc);
    files.set(f.path, doc);
  }
  // Support files (keys/test-keys.json) are hashed like everything else and
  // never run: nothing in them has an expected value.
  for (const f of manifest.support ?? []) {
    const bytes = readFileSync(join(dir, f.path));
    const sha = createHash("sha256").update(bytes).digest("hex");
    if (sha !== f.sha256) throw new SuiteIntegrityError(`${f.path} (support): sha256 ${sha} != manifest ${f.sha256}`);
  }
  // A held-out file is checked for integrity (it is part of the published
  // suite as an artifact) but is NEVER iterated by a conformance run.
  for (const h of manifest.held_out ?? []) {
    const bytes = readFileSync(join(dir, h.path));
    const sha = createHash("sha256").update(bytes).digest("hex");
    if (sha !== h.sha256) throw new SuiteIntegrityError(`${h.path} (held out): sha256 mismatch`);
    const doc = JSON.parse(bytes.toString("utf-8")) as VectorFile;
    if (doc.status !== "held-out") throw new SuiteIntegrityError(`${h.path}: held out but status is ${JSON.stringify(doc.status)}`);
    if (!h.reason || !h.unblocks_when) throw new SuiteIntegrityError(`${h.path}: held out without reason/unblocks_when`);
  }
  return { manifest, files };
}

const HEX_RE = /^([0-9a-f]{2})*$/;

export function isHex(v: unknown): v is string {
  return typeof v === "string" && HEX_RE.test(v);
}

function req(path: string, id: string, v: Record<string, unknown>, key: string, pred: (x: unknown) => boolean, what: string): void {
  if (!pred(v[key])) throw new SuiteIntegrityError(`${path} ${id}: field ${key} is not ${what}`);
}

const isSuiteId = (x: unknown): boolean => typeof x === "string" && /^0x[0-9A-F]{4}$/.test(x);
const isObj = (x: unknown): x is Record<string, unknown> => typeof x === "object" && x !== null;
const isHexOrNull = (x: unknown): boolean => x === null || isHex(x);

function validateContext(path: string, id: string, c: unknown): void {
  if (!isObj(c)) throw new SuiteIntegrityError(`${path} ${id}: context is not an object`);
  req(path, id, c, "table_uuid", (x) => isHex(x) && x.length === 32, "32 hex chars");
  req(path, id, c, "column_uuid", (x) => isHex(x) && x.length === 32, "32 hex chars");
  req(path, id, c, "tenant_id", isHexOrNull, "hex or null");
  req(path, id, c, "row_id", isHexOrNull, "hex or null");
  req(path, id, c, "purpose", (x) => typeof x === "string", "a string");
}

/** Structural validation of the fields each family runner relies on. */
function validateShape(path: string, doc: VectorFile): void {
  const seen = new Set<string>();
  for (const v of doc.vectors) {
    if (!isObj(v) || typeof v.id !== "string") throw new SuiteIntegrityError(`${path}: a vector has no id`);
    const id = v.id;
    if (seen.has(id)) throw new SuiteIntegrityError(`${path}: duplicate id ${id}`);
    seen.add(id);
    if (!id.startsWith(`${doc.group}/`)) throw new SuiteIntegrityError(`${path} ${id}: id does not start with group '${doc.group}/'`);
    req(path, id, v, "spec_ref", (x) => typeof x === "string", "a string");
    if (!isObj(v.expected)) throw new SuiteIntegrityError(`${path} ${id}: expected is not an object`);
    const ex = v.expected;
    if (v.assertion !== undefined) {
      // Suite 0.3.0 adds the two docs/09 §7.2 shapes. Kept fail-closed: an
      // unrecognised assertion is an error, never a skip, or a core could
      // silently ignore a whole class of requirement and still report green.
      const ASSERTIONS = ["distinct", "equal", "unindexable-marker", "unindexable-bucket"];
      if (typeof v.assertion !== "string" || !ASSERTIONS.includes(v.assertion)) {
        throw new SuiteIntegrityError(`${path} ${id}: unknown assertion ${String(v.assertion)}`);
      }
      // Suite 0.2.0: assertion vectors carry the inputs of both sides (D-08).
      req(path, id, v, "inputs", isObj, "an object");
      if (v.assertion === "distinct" || v.assertion === "equal") {
        req(path, id, ex, "must_be_equal", (x) => typeof x === "boolean", "a boolean");
      } else {
        req(path, id, ex, "index", isHex, "hex");
      }
      continue;
    }
    req(path, id, v, "suite_id", isSuiteId, "a 0xXXXX suite id");
    switch (doc.group) {
      case "envelope":
        for (const k of ["tenant_dek", "key_id", "msg_seed", "nonce", "plaintext"]) req(path, id, v, k, isHex, "hex");
        validateContext(path, id, v.context);
        for (const k of ["envelope", "canonical_context", "aad"]) req(path, id, ex, k, isHex, "hex");
        req(path, id, ex, "envelope_bytes", Number.isInteger, "an integer");
        break;
      case "kdf":
        validateContext(path, id, v.context);
        for (const k of ["salt", "info"]) req(path, id, ex, k, isHex, "hex");
        if (id.startsWith("kdf/record-key/")) {
          for (const k of ["tenant_dek", "key_id", "msg_seed"]) req(path, id, v, k, isHex, "hex");
          req(path, id, ex, "record_key", isHex, "hex");
        } else if (id.startsWith("kdf/index-key/")) {
          req(path, id, v, "tenant_index_key", isHex, "hex");
          req(path, id, v, "index_id", (x) => typeof x === "string", "a string");
          req(path, id, ex, "index_key", isHex, "hex");
        } else throw new SuiteIntegrityError(`${path} ${id}: unknown kdf vector kind`);
        break;
      case "context":
        validateContext(path, id, v.context);
        req(path, id, ex, "presence", Number.isInteger, "an integer");
        req(path, id, ex, "canonical_context", isHex, "hex");
        req(path, id, ex, "length", Number.isInteger, "an integer");
        break;
      case "commitment":
        req(path, id, v, "record_key", isHex, "hex");
        req(path, id, ex, "info", isHex, "hex");
        req(path, id, ex, "commitment", isHex, "hex");
        req(path, id, ex, "length", Number.isInteger, "an integer");
        break;
      case "blind-index": {
        // docs/08 §4.4 shape (suite 0.2.0; D-07 resolved).
        req(path, id, v, "idf", (x) => typeof x === "string", "a string");
        req(path, id, v, "idf_params", isObj, "an object");
        req(path, id, v, "index_key", isHex, "hex");
        req(path, id, v, "tenant_index_key", isHex, "hex");
        req(path, id, v, "index_id", (x) => typeof x === "string", "a string");
        validateContext(path, id, v.context);
        req(path, id, v, "normalize", (x) => typeof x === "string", "a string");
        req(path, id, v, "plaintext", isHex, "hex");
        req(path, id, v, "plaintext_preimage", (x) => typeof x === "string", "a string");
        req(path, id, v, "truncate_bits", Number.isInteger, "an integer");
        for (const k of ["raw", "index"]) req(path, id, ex, k, isHex, "hex");
        if (!isObj(ex.stored)) throw new SuiteIntegrityError(`${path} ${id}: expected.stored is not an object`);
        req(path, id, ex.stored, "binary", isHex, "hex");
        req(path, id, ex.stored, "hex", isHex, "hex");
        req(path, id, ex.stored, "octets", Number.isInteger, "an integer");
        break;
      }
      case "errors": {
        // docs/08 §4.6 shape. `input` is literal bytes; `operation` defaults to decrypt.
        req(path, id, v, "config", isObj, "an object");
        const cfg = v.config as Record<string, unknown>;
        req(path, id, cfg, "allowed_suites", Array.isArray, "an array");
        req(path, id, cfg, "write_suite", isSuiteId, "a 0xXXXX suite id");
        req(path, id, cfg, "read_mode", (x) => x === "strict" || x === "permissive" || x === "readonly", "a read mode");
        req(path, id, cfg, "arm_provisional_suites", (x) => typeof x === "boolean", "a boolean");
        req(path, id, v, "key_id", isHex, "hex");
        req(path, id, v, "tenant_dek", isHex, "hex");
        req(path, id, v, "input", isHex, "hex");
        if (v.context !== undefined) validateContext(path, id, v.context);
        const op = v.operation ?? "decrypt";
        if (!["decrypt", "encrypt", "rotate", "is_ciphertext", "blind_index"].includes(op as string)) throw new SuiteIntegrityError(`${path} ${id}: unknown operation ${String(op)}`);
        if (op === "blind_index") {
          req(path, id, v, "tenant_index_key", isHex, "hex");
          req(path, id, v, "index_declaration", isObj, "an object");
        }
        const kinds = ["error", "value", "plaintext", "is_ciphertext", "index"].filter((k) => k in ex);
        if (kinds.length !== 1) throw new SuiteIntegrityError(`${path} ${id}: expected must carry exactly one of error/value/plaintext/is_ciphertext/index`);
        break;
      }
      default:
        throw new SuiteIntegrityError(`${path}: unknown group ${doc.group}`);
    }
  }
}

export function hex(s: string): Uint8Array {
  return new Uint8Array(Buffer.from(s, "hex"));
}

export function hexOrNull(s: string | null): Uint8Array | null {
  return s === null ? null : hex(s);
}

export function parseSuiteId(s: string): number {
  return parseInt(s.slice(2), 16);
}
