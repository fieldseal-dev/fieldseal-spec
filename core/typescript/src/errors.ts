/**
 * The spec §9 error taxonomy as typed errors (docs/09 §9).
 *
 * Every failure the core can produce is a `FieldsealError` carrying a
 * machine-readable `code`. The ten codes below are exactly the §9 set. Two
 * additional codes are implementation-local, as docs/09 §9 permits:
 * `CONFIGURATION_ERROR` for construction-time refusals (which never reach the
 * crypto path or the vectors) and `INVALID_ARGUMENT` for a call whose
 * non-byte arguments are malformed (a 15-byte table UUID, a purpose string
 * outside the §6.1 grammar at call time). Neither is a §9 code and neither is
 * ever raised for the *bytes* of an envelope -- arbitrary bytes handed to
 * `decrypt` always resolve to a §9 code.
 *
 * Messages never contain plaintext, key material, or derived keys (§9).
 * `suite_id` and `key_id` are public envelope content and may appear.
 */

export const ERROR_CODES = [
  "UNKNOWN_FORMAT_VERSION",
  "SUITE_NOT_ALLOWED",
  "KEY_UNAVAILABLE",
  "AAD_MISMATCH",
  "TAG_INVALID",
  "COMMITMENT_INVALID",
  "NOT_CIPHERTEXT",
  "MODE_VIOLATION",
  "LENGTH_EXCEEDED",
  "SUITE_PROVISIONAL",
] as const;

export type SpecErrorCode = (typeof ERROR_CODES)[number];

export type LocalErrorCode = "CONFIGURATION_ERROR" | "INVALID_ARGUMENT";

export type ErrorCode = SpecErrorCode | LocalErrorCode;

export class FieldsealError extends Error {
  readonly code: ErrorCode;

  constructor(code: ErrorCode, message: string) {
    super(message);
    this.name = "FieldsealError";
    this.code = code;
  }
}

export class UnknownFormatVersionError extends FieldsealError {
  readonly fmtVer: number;
  constructor(fmtVer: number) {
    super(
      "UNKNOWN_FORMAT_VERSION",
      `envelope format version 0x${hex8(fmtVer)} is not recognized by this implementation (this core reads 0x01); the data may have been written by a newer implementation`,
    );
    this.name = "UnknownFormatVersionError";
    this.fmtVer = fmtVer;
  }
}

export class SuiteNotAllowedError extends FieldsealError {
  readonly suiteId: number;
  constructor(suiteId: number) {
    super(
      "SUITE_NOT_ALLOWED",
      `suite ${suiteHex(suiteId)} is registered but not on this client's decrypt allow-list (spec §4.3)`,
    );
    this.name = "SuiteNotAllowedError";
    this.suiteId = suiteId;
  }
}

export class KeyUnavailableError extends FieldsealError {
  readonly keyId: Uint8Array | null;
  constructor(keyId: Uint8Array | null, detail?: string) {
    super(
      "KEY_UNAVAILABLE",
      `${keyId ? `no key is available for key_id ${toHex(keyId)}` : "no key is available for this context"}${detail ? `: ${detail}` : ""} (spec §9 -- key destroyed, key service unreachable, or wrong tenant context)`,
    );
    this.name = "KeyUnavailableError";
    this.keyId = keyId;
  }
}

export class AadMismatchError extends FieldsealError {
  constructor(detail: string) {
    super("AAD_MISMATCH", `context does not match the envelope: ${detail}`);
    this.name = "AadMismatchError";
  }
}

export class TagInvalidError extends FieldsealError {
  constructor(suiteId: number, keyId: Uint8Array) {
    super(
      "TAG_INVALID",
      `authentication failed under suite ${suiteHex(suiteId)}, key_id ${toHex(keyId)}: key and context verified by commitment, so the ciphertext or tag is corrupted or tampered`,
    );
    this.name = "TagInvalidError";
  }
}

export class CommitmentInvalidError extends FieldsealError {
  constructor(suiteId: number, keyId: Uint8Array, candidates: number) {
    super(
      "COMMITMENT_INVALID",
      `key commitment did not verify under any of ${candidates} candidate key(s) for suite ${suiteHex(suiteId)}, key_id ${toHex(keyId)}: wrong key, wrong context (spec §6.3 dual binding makes these indistinguishable here -- see G5), or a partitioning-oracle attempt`,
    );
    this.name = "CommitmentInvalidError";
  }
}

export class NotCiphertextError extends FieldsealError {
  constructor(detail: string) {
    super(
      "NOT_CIPHERTEXT",
      `input is not a recognizable Fieldseal envelope (${detail}); in strict read mode unmigrated plaintext is an error (spec §3.4, §10.3)`,
    );
    this.name = "NotCiphertextError";
  }
}

export class ModeViolationError extends FieldsealError {
  readonly operation: string;
  readonly mode: string;
  constructor(operation: string, mode: string) {
    // §9: the message MUST name both the rejected operation and the active mode.
    super(
      "MODE_VIOLATION",
      `operation '${operation}' is not permitted in read mode '${mode}' (spec §10.3): this client is configured not to produce ciphertext for storage`,
    );
    this.name = "ModeViolationError";
    this.operation = operation;
    this.mode = mode;
  }
}

export class LengthExceededError extends FieldsealError {
  constructor(side: "encrypt" | "decrypt", length: number, bound: number) {
    super(
      "LENGTH_EXCEEDED",
      side === "encrypt"
        ? `plaintext of ${length} bytes exceeds the spec §3.5 bound of ${bound} bytes`
        : `envelope implies a plaintext of ${length} bytes, which exceeds the spec §3.5 bound of ${bound} bytes; refused before allocation`,
    );
    this.name = "LengthExceededError";
  }
}

export class SuiteProvisionalError extends FieldsealError {
  readonly suiteId: number;
  constructor(suiteId: number, armingMechanism: string) {
    // §9: the message MUST name the provisional suite_id and the arming mechanism.
    super(
      "SUITE_PROVISIONAL",
      `suite ${suiteHex(suiteId)} is provisional (spec §4.8): its constructions have not been independently reviewed and may change. Writing under it requires an affirmative out-of-band arming act: ${armingMechanism}. Arming does not make the suite reviewed; it records that the operator was told.`,
    );
    this.name = "SuiteProvisionalError";
    this.suiteId = suiteId;
  }
}

export class ConfigurationError extends FieldsealError {
  constructor(message: string) {
    super("CONFIGURATION_ERROR", message);
    this.name = "ConfigurationError";
  }
}

export class InvalidArgumentError extends FieldsealError {
  constructor(message: string) {
    super("INVALID_ARGUMENT", message);
    this.name = "InvalidArgumentError";
  }
}

export function suiteHex(suiteId: number): string {
  return `0x${suiteId.toString(16).toUpperCase().padStart(4, "0")}`;
}

function hex8(b: number): string {
  return b.toString(16).padStart(2, "0");
}

export function toHex(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += hex8(b);
  return s;
}
