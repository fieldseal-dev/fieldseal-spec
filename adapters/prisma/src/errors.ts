/**
 * Adapter-level exceptions.
 *
 * The core's error taxonomy (spec §9) covers what the *core* refuses. This
 * module covers what the *adapter* refuses, which is a different list: paths
 * where Prisma would otherwise write plaintext, or return a wrong answer, if
 * the adapter stayed quiet.
 *
 * Spec §10.2 is the rule these exist to keep: *where a path would silently
 * return wrong results, the adapter MUST throw, not degrade silently.* Every
 * throw site in this package names the shape it refuses, the spec clause that
 * refuses it, and the supported alternative -- a refusal that does not say
 * what to do instead is a dead end, and the caller's next move is usually
 * `$queryRaw`, which is the one path this adapter cannot protect at all.
 *
 * On identifiers, deliberately: refusals here carry no `Exxx`/`Wxxx` id. Those
 * identifiers belong to Django's system-check framework, which reports
 * declaration problems at startup; they are check ids, not exception codes,
 * and that adapter's runtime refusals are likewise uncoded. Prisma has no
 * check framework, and this adapter answers the same need at `prisma generate`
 * time instead (see `generator/`). Identity here is the message and the class.
 *
 * **On `code`, and a divergence worth naming.** The core's `ErrorCode` is a
 * closed union -- the ten spec §9 codes plus `CONFIGURATION_ERROR` and
 * `INVALID_ARGUMENT` -- and none of them means "the adapter refuses this
 * shape". The Python core has a generic `FIELDSEAL_ERROR` default that the
 * Django adapter inherits; this one does not, so the same refusal reports a
 * different `code` in the two adapters. Discriminate on the class
 * (`instanceof FieldsealNotSupported`) or on `name`, never on `code`. Nothing
 * in the vector suite or the `docs/14` §4 report covers adapter error codes,
 * so this divergence is invisible to CI -- which is the argument for writing
 * it down here rather than leaving it to be discovered.
 */

import { FieldsealError } from "@fieldseal/core";

/**
 * Base for every refusal this adapter adds to the core's §9 set.
 *
 * It extends the core's base deliberately: application code that already
 * catches `FieldsealError` around a write should not silently miss an adapter
 * refusal, because the two mean the same thing to a caller -- this value did
 * not get stored, or read, the way you asked.
 */
export class FieldsealAdapterError extends FieldsealError {
  constructor(message: string, code: "CONFIGURATION_ERROR" | "INVALID_ARGUMENT") {
    super(code, message);
    this.name = "FieldsealAdapterError";
  }
}

/**
 * A Prisma path the adapter cannot serve correctly (spec §10.2).
 *
 * Raised rather than degraded. This is the single most important behavioural
 * difference between this adapter and `prisma-field-encryption`, which
 * encrypts un-rewritten filter operands and returns zero rows with no error
 * (`docs/04` §3).
 */
export class FieldsealNotSupported extends FieldsealAdapterError {
  constructor(message: string) {
    // INVALID_ARGUMENT rather than CONFIGURATION_ERROR: the deployment is
    // configured correctly and this particular call is not serveable.
    super(message, "INVALID_ARGUMENT");
    this.name = "FieldsealNotSupported";
  }
}

/**
 * A declaration the adapter refuses when the extension is constructed.
 *
 * Most declaration errors should surface at `prisma generate` instead, where
 * the generator reports *every* problem at once and names the model and field
 * (`docs/13` §1: "a malformed annotation is a construction-time error, never a
 * runtime skip"). This is for what only the runtime knows: options passed to
 * `fieldsealExtension`, and disagreements between those options and the
 * generated field map.
 */
export class FieldsealConfigurationError extends FieldsealAdapterError {
  constructor(message: string) {
    super(message, "CONFIGURATION_ERROR");
    this.name = "FieldsealConfigurationError";
  }
}
