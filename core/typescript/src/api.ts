/**
 * The Fieldseal client: the five synchronous operations of spec §11.1 plus
 * `warm` (spec §11.2), over an immutable configuration (docs/09 §2).
 *
 * Operation pipelines follow docs/09 §3 step for step. Where the spec leaves
 * an order unpinned (the G5 decrypt-path precedence; the relative order of
 * the three API-boundary refusals), the order chosen here is stated in the
 * conformance report this core emits, as spec §9 requires.
 */

import { randomBytes } from "node:crypto";
import { gcmOpen, gcmSeal } from "./aead/gcm.ts";
import { idf, truncateBits, type ValidatedIndex } from "./blindindex.ts";
import {
  ARMING_MECHANISM_DESCRIPTION,
  validateConfig,
  type ArmingOptions,
  type FieldsealConfig,
  type ReadMode,
  type ValidatedConfig,
  type Warning,
} from "./config.ts";
import { computeCommitment, verifyCommitment } from "./commitment.ts";
import { aad as buildAad, canonicalContext, indexIdOf, validateFieldContext, type FieldContext, type ResolvedContext } from "./context.ts";
import { isCiphertext as recognizeCiphertext, recognize, serialize, type EnvelopeHeader, type ParsedEnvelope } from "./envelope.ts";
import {
  CommitmentInvalidError,
  ConfigurationError,
  FieldsealError,
  InvalidArgumentError,
  KeyUnavailableError,
  LengthExceededError,
  ModeViolationError,
  NotCiphertextError,
  SuiteNotAllowedError,
  SuiteProvisionalError,
  TagInvalidError,
  UnknownFormatVersionError,
} from "./errors.ts";
import { INTERNALS } from "./internal.ts";
import { deriveIndexKey, deriveRecordKey } from "./kdf.ts";
import { indexRegistryKey } from "./blindindex.ts";
import { normalize } from "./normalize.ts";
import { FMT_VER, KEY_ID_LEN, MSG_SEED_LEN, getSuite, type Suite } from "./registry.ts";
import type { EncryptionKey } from "./keyprovider.ts";

/** Spec §3.5: 2^31 − 1 bytes. */
export const MAX_PLAINTEXT_LEN = 2 ** 31 - 1;

export const TEST_MODE_ENV = "FIELDSEAL_TEST_MODE";

export class Fieldseal {
  readonly #cfg: ValidatedConfig;

  constructor(config: FieldsealConfig, arming: ArmingOptions = {}) {
    this.#cfg = validateConfig(config, arming);
    // Construction-time warnings go through the hook, never a log side effect
    // (docs/09 §8.2), so embedders can escalate them to a hard failure.
    if (this.#cfg.keyProvider.developmentOnly === true && process.env[TEST_MODE_ENV] !== "1") {
      this.#warn("static-key-provider", "StaticKeyProvider is for test and development use only (spec §8); this process is not in test configuration");
    }
    if (this.#cfg.readMode === "permissive") {
      this.#warn("permissive-mode", "read mode 'permissive' is active: non-envelope input is returned as plaintext; migration use only (spec §10.3)");
    } else if (this.#cfg.readMode === "readonly") {
      this.#warn("readonly-mode", "read mode 'readonly' is active: non-envelope input is returned as plaintext and ciphertext-producing operations are refused (spec §10.3)");
    }
    INTERNALS.set(this, {
      encryptWithMaterials: (pt, ctx, seed, nonce) => this.#encryptPipeline("encrypt", pt, ctx, seed, nonce),
    });
    Object.freeze(this);
  }

  get readMode(): ReadMode {
    return this.#cfg.readMode;
  }

  get writeSuite(): number {
    return this.#cfg.writeSuite;
  }

  get allowedSuites(): ReadonlySet<number> {
    return this.#cfg.allowedSuites;
  }

  /** Whether spec §4.8 provisional writing was armed for this client. */
  get provisionalArmed(): boolean {
    return this.#cfg.provisionalArmed;
  }

  // -------------------------------------------------------------------------
  // encrypt (docs/09 §3.1)

  encrypt(plaintext: Uint8Array, ctx: FieldContext): Buffer {
    // No seed or nonce parameter exists on this method, in any form (docs/08 §6).
    return this.#encryptPipeline("encrypt", plaintext, ctx, undefined, undefined);
  }

  /**
   * Steps 1-3 of docs/09 §3.1 in this pinned order (all at the API boundary,
   * before key acquisition and before any cryptographic processing):
   *   MODE_VIOLATION → SUITE_PROVISIONAL → [operand checks]
   * The two configuration-derived refusals come before any look at the
   * input; between them, the mode is the more fundamental property of the
   * client. LENGTH_EXCEEDED follows because it depends on the operand.
   */
  #apiBoundaryForWrite(operation: "encrypt" | "rotate"): void {
    if (this.#cfg.readMode === "readonly") throw new ModeViolationError(operation, this.#cfg.readMode);
    const suite = getSuite(this.#cfg.writeSuite) as Suite;
    if (suite.provisional && !this.#cfg.provisionalArmed) {
      throw new SuiteProvisionalError(suite.id, ARMING_MECHANISM_DESCRIPTION);
    }
  }

  #encryptPipeline(
    operation: "encrypt" | "rotate",
    plaintext: Uint8Array,
    ctx: FieldContext,
    seedIn: Uint8Array | undefined,
    nonceIn: Uint8Array | undefined,
  ): Buffer {
    // docs/08 §6 arming gate, enforced at the seam itself, not only in the
    // testing/ wrapper: caller-supplied materials must never reach the
    // pipeline in an unarmed process, whatever path delivered them.
    if ((seedIn !== undefined || nonceIn !== undefined) && process.env[TEST_MODE_ENV] !== "1") {
      throw new ConfigurationError(
        `caller-supplied msg_seed/nonce reached the encrypt pipeline without ${TEST_MODE_ENV}=1; the injection seam is inert unless armed (docs/08 §6)`,
      );
    }
    // The injection path re-runs the boundary checks so that a test-mode
    // encrypt is refused on exactly the terms a production encrypt is
    // (docs/08 §6: "the full production pipeline except CSPRNG generation").
    this.#apiBoundaryForWrite(operation);
    if (!(plaintext instanceof Uint8Array)) {
      throw new InvalidArgumentError("plaintext must be a Uint8Array (strings are never accepted; encoding is the adapter's job)");
    }
    if (plaintext.length > MAX_PLAINTEXT_LEN) throw new LengthExceededError("encrypt", plaintext.length, MAX_PLAINTEXT_LEN);
    validateFieldContext(ctx, "encrypt");

    const suite = getSuite(this.#cfg.writeSuite) as Suite;
    if (seedIn !== undefined && (!(seedIn instanceof Uint8Array) || seedIn.length !== MSG_SEED_LEN)) {
      throw new InvalidArgumentError(`msg_seed must be ${MSG_SEED_LEN} bytes`);
    }
    if (nonceIn !== undefined && (!(nonceIn instanceof Uint8Array) || nonceIn.length !== suite.nonceLen)) {
      throw new InvalidArgumentError(`nonce must be ${suite.nonceLen} bytes for suite ${suite.name}`);
    }
    const resolved: ResolvedContext = { ...ctx, suiteId: suite.id };
    const ek = this.#encryptionKey(resolved, suite.keyLen);
    // docs/09 §3.1 steps 5-6: the only entropy draws in the pipeline. The
    // testing seam replaces exactly these two values and nothing else.
    const msgSeed = seedIn ?? randomBytes(MSG_SEED_LEN);
    const nonce = nonceIn ?? randomBytes(suite.nonceLen);

    const cc = canonicalContext(resolved);
    const recordKey = deriveRecordKey(suite, ek.key, ek.keyId, msgSeed, cc);
    try {
      const commitment = computeCommitment(recordKey);
      const aad = buildAad(FMT_VER, ek.keyId, msgSeed, cc);
      const { ciphertext, tag } = gcmSeal(recordKey, nonce, plaintext, aad);
      return serialize(suite, ek.keyId, msgSeed, nonce, ciphertext, tag, commitment);
    } finally {
      recordKey.fill(0); // best-effort zeroization (docs/11 §5)
      ek.key.fill(0);
    }
  }

  #encryptionKey(ctx: ResolvedContext, expectedLen: number): EncryptionKey {
    let ek: EncryptionKey;
    try {
      ek = this.#cfg.keyProvider.encryptionKey(ctx);
    } catch (e) {
      if (e instanceof FieldsealError) throw e;
      // A provider that throws anything else (an SDK exception, a bug) must
      // still surface as a typed §9 error: the key is unavailable.
      throw new KeyUnavailableError(null, `key provider failed: ${errorMessage(e)}`);
    }
    if (!(ek?.key instanceof Uint8Array) || ek.key.length !== expectedLen) {
      throw new KeyUnavailableError(null, `key provider returned a key of the wrong length (expected ${expectedLen} bytes)`);
    }
    if (!(ek.keyId instanceof Uint8Array) || ek.keyId.length !== KEY_ID_LEN) {
      throw new KeyUnavailableError(null, `key provider returned a key_id of the wrong length (expected ${KEY_ID_LEN} bytes)`);
    }
    return { key: new Uint8Array(ek.key), keyId: new Uint8Array(ek.keyId) };
  }

  // -------------------------------------------------------------------------
  // decrypt (docs/09 §3.2; order pinned under G5, declared in the report)

  decrypt(input: Uint8Array, ctx: FieldContext): Buffer {
    validateFieldContext(ctx, "encrypt");
    const rec = recognize(input);
    if (rec.kind === "not-ciphertext") {
      if (this.#cfg.readMode === "strict") throw new NotCiphertextError(rec.detail);
      // permissive and readonly: pass-through, with the §10.3 warning and metric.
      this.#warn("plaintext-read", `non-envelope input returned as-is in read mode '${this.#cfg.readMode}' (${rec.detail})`);
      this.#cfg.metrics.plaintextReads?.();
      return copyOut(input);
    }
    if (rec.kind === "unknown-format-version") {
      throw this.#count(new UnknownFormatVersionError(rec.fmtVer));
    }
    const env = rec.parsed;
    // Spec §3.5 decrypt side: computable from the byte count alone, before
    // any allocation; its position is immaterial and deliberately early.
    if (env.ciphertext.length > MAX_PLAINTEXT_LEN) {
      throw this.#count(new LengthExceededError("decrypt", env.ciphertext.length, MAX_PLAINTEXT_LEN));
    }
    if (!this.#cfg.allowedSuites.has(env.suite.id)) throw this.#count(new SuiteNotAllowedError(env.suite.id));
    return this.#open(env, ctx);
  }

  #open(env: ParsedEnvelope, ctx: FieldContext): Buffer {
    const header: EnvelopeHeader = env.header;
    // docs/09 §3.2 step 4: the suite comes from the parsed, allow-listed
    // header -- never from writeSuite.
    const resolved: ResolvedContext = { ...ctx, suiteId: env.suite.id };
    let candidates: Uint8Array[];
    try {
      candidates = this.#cfg.keyProvider.decryptionKeys(header);
    } catch (e) {
      if (e instanceof FieldsealError) throw this.#count(e);
      throw this.#count(new KeyUnavailableError(header.keyId, `key provider failed: ${errorMessage(e)}`));
    }
    if (!Array.isArray(candidates)) candidates = [];
    candidates = candidates.filter((k) => k instanceof Uint8Array && k.length === env.suite.keyLen);
    if (candidates.length === 0) throw this.#count(new KeyUnavailableError(header.keyId));

    const cc = canonicalContext(resolved);
    const aad = buildAad(header.fmtVer, header.keyId, header.msgSeed, cc);
    // The candidate `dek` buffers are deliberately NOT zeroized here: the §8
    // interface gives this client no ownership of them, and a custom provider
    // may return buffers it still needs (docs/11 §5 documented exception).
    for (const dek of candidates) {
      const recordKey = deriveRecordKey(env.suite, dek, header.keyId, header.msgSeed, cc);
      try {
        if (!verifyCommitment(recordKey, env.commitment)) continue;
        const pt = gcmOpen(recordKey, header.nonce, env.ciphertext, env.tag, aad);
        if (pt === null) throw this.#count(new TagInvalidError(env.suite.id, header.keyId));
        const out = copyOut(pt);
        pt.fill(0); // the intermediate is ours; the caller gets the only live copy
        return out;
      } finally {
        recordKey.fill(0);
      }
    }
    throw this.#count(new CommitmentInvalidError(env.suite.id, header.keyId, candidates.length));
  }

  // -------------------------------------------------------------------------
  // blind_index (docs/09 §3.3)

  blindIndex(plaintext: Uint8Array, ctx: FieldContext): Buffer {
    // Permitted in every mode, including readonly (spec §10.3).
    if (!(plaintext instanceof Uint8Array)) {
      throw new InvalidArgumentError("plaintext must be a Uint8Array (strings are never accepted; encoding is the adapter's job)");
    }
    validateFieldContext(ctx, "index");
    const indexId = indexIdOf(ctx.purpose) as string;
    const decl = this.#cfg.indexes.get(indexRegistryKey(ctx.tableUuid, ctx.columnUuid, indexId));
    if (decl === undefined) {
      // Fail closed; never fall back to a default IDF (docs/09 §3.3 step 2).
      throw new ConfigurationError(`no blind index '${indexId}' is declared for this table/column; indexes are declared at construction (spec §7.8)`);
    }
    return this.#index(decl, plaintext, ctx);
  }

  #index(decl: ValidatedIndex, plaintext: Uint8Array, ctx: FieldContext): Buffer {
    const suite = getSuite(this.#cfg.writeSuite) as Suite;
    const resolved: ResolvedContext = { ...ctx, suiteId: suite.id };
    const material = this.#encryptionKey(resolved, 32); // the tenant INDEX key (spec §8)
    try {
      const indexKey = deriveIndexKey(material.key, resolved);
      try {
        const normalized = normalize(decl.normalize, plaintext);
        const raw = idf(decl.idf, indexKey, normalized, decl.argon2);
        try {
          return copyOut(truncateBits(raw, decl.truncateBits));
        } finally {
          raw.fill(0); // the untruncated IDF output reveals more than the stored index value
        }
      } finally {
        indexKey.fill(0);
      }
    } finally {
      material.key.fill(0);
    }
  }

  // -------------------------------------------------------------------------
  // is_ciphertext (docs/09 §3.4)

  isCiphertext(value: Uint8Array): boolean {
    return recognizeCiphertext(value);
  }

  // -------------------------------------------------------------------------
  // rotate (docs/09 §3.5)

  /**
   * `rotate` is ciphertext-to-ciphertext in every mode (spec §11.1).
   *
   * The §10.3 pass-through is a *read* behaviour -- its column is
   * "non-envelope input on read" -- and the decrypt inside `rotate` is not a
   * read whose result reaches the application. Composing the two literally
   * would make `rotate` encrypt unmigrated plaintext in `permissive` and
   * raise on the same bytes in `strict`: the operation's domain would depend
   * on a mode setting that has nothing to do with rotation.
   *
   * A reserved future version byte still raises `UNKNOWN_FORMAT_VERSION`
   * rather than `NOT_CIPHERTEXT` -- recognition (spec §3.4) distinguishes
   * them, and a v2 envelope is not unmigrated plaintext.
   */
  rotate(input: Uint8Array, ctx: FieldContext): Buffer {
    this.#apiBoundaryForWrite("rotate");
    const rec = recognize(input);
    if (rec.kind === "not-ciphertext") {
      throw new NotCiphertextError(
        `rotate requires an envelope; this input is not one (${rec.detail}) -- use encrypt() to migrate unencrypted values`,
      );
    }
    const plaintext = this.decrypt(input, ctx);
    try {
      return this.#encryptPipeline("rotate", plaintext, ctx, undefined, undefined);
    } finally {
      plaintext.fill(0);
    }
  }

  // -------------------------------------------------------------------------
  // warm (docs/09 §3.6)

  async warm(contexts: Iterable<FieldContext>): Promise<void> {
    const w = this.#cfg.keyProvider.warm;
    if (w === undefined) return;
    await w.call(this.#cfg.keyProvider, contexts);
  }

  // -------------------------------------------------------------------------

  #warn(kind: Warning["kind"], message: string): void {
    this.#cfg.onWarning({ kind, message });
  }

  #count<E extends FieldsealError>(e: E): E {
    this.#cfg.metrics.decryptErrors?.(e.code);
    return e;
  }
}

function errorMessage(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}

/**
 * Copy into an unpooled Buffer before returning it (docs/11 §5 aliasing
 * rule). `Buffer.from(bytes)` copies too, but into Node's shared 8 KiB
 * Buffer pool: the result's `.buffer` is the pool's backing ArrayBuffer,
 * shared with unrelated allocations across the process, and a caller doing
 * `new Uint8Array(out.buffer)` (or transferring it) would see them.
 * `Buffer.alloc` never uses the pool.
 */
function copyOut(src: Uint8Array): Buffer {
  const out = Buffer.alloc(src.length);
  out.set(src);
  return out;
}
