/**
 * @fieldseal/core -- public entry.
 *
 * Nothing under `testing/` is exported from here (docs/11 §3); it is reached
 * only through the `@fieldseal/core/testing` subpath, which is inert unless
 * FIELDSEAL_TEST_MODE=1.
 *
 * Status: PROVISIONAL. Suite 0xFF01's constructions are marked [PROVISIONAL]
 * in the specification and have not been independently reviewed (Gate 0b,
 * docs/01-prd.md §8). Writing requires arming (spec §4.8). Not for
 * production use.
 */

export { Fieldseal, MAX_PLAINTEXT_LEN } from "./api.ts";
export type { FieldContext } from "./context.ts";
export { canonicalContext, aad, isValidIndexId, isValidPurpose } from "./context.ts";
export type { ResolvedContext } from "./context.ts";
export type { FieldsealConfig, ArmingOptions, ReadMode, Warning, WarningKind, Metrics } from "./config.ts";
export { ARM_PROVISIONAL_ENV } from "./config.ts";
export type { EnvelopeHeader } from "./envelope.ts";
export { isCiphertext } from "./envelope.ts";
export {
  FieldsealError,
  UnknownFormatVersionError,
  SuiteNotAllowedError,
  KeyUnavailableError,
  AadMismatchError,
  TagInvalidError,
  CommitmentInvalidError,
  NotCiphertextError,
  ModeViolationError,
  LengthExceededError,
  SuiteProvisionalError,
  ConfigurationError,
  InvalidArgumentError,
  ERROR_CODES,
} from "./errors.ts";
export type { ErrorCode, SpecErrorCode, LocalErrorCode } from "./errors.ts";
export {
  StaticKeyProvider,
  DerivedKeyProvider,
  EnvelopeKeyProvider,
  InMemoryKeyDirectory,
} from "./keyprovider.ts";
export type {
  KeyProvider,
  EncryptionKey,
  StaticKeyProviderOptions,
  DerivedKeyProviderOptions,
  EnvelopeKeyProviderOptions,
  Wrapper,
  WrappedKeySet,
  WrappedKeyVersion,
  KeyDirectory,
} from "./keyprovider.ts";
export { DekCache } from "./cache.ts";
export type { CachePolicy, CacheHooks, CacheMetrics, EvictionCause } from "./cache.ts";
export type { IndexDeclaration, IdfId, Argon2Params, CardinalityOverride, ValidatedIndex, OnUnindexable } from "./blindindex.ts";
export { indexRegistryKey, validateIndexDeclaration } from "./blindindex.ts";
export { NORMALIZER_IDS, normalize } from "./normalize.ts";
export type { NormalizerId } from "./normalize.ts";
// docs/09 §7.1, normative: "Cores MUST still export the assigned-code-point
// check (`first_unassigned` / `firstUnassigned`) for adapters that hold the
// text earlier and can give a better-sited error." That MUST had never reached
// a package root -- `normalize.ts` re-exported it and the `exports` map stops
// at `./dist/index.js`, so it was unreachable by construction rather than by
// omission. G22 (#88). `UNICODE_VERSION` travels with it: an adapter rendering
// "not assigned in Unicode 17.0.0" needs the version the check was made
// against, and reading it from a constant of its own is how two copies drift.
export { firstUnassigned, UNICODE_VERSION } from "./normalize.ts";
export type { Unassigned } from "./normalize.ts";
export { SUITE_FF01, SUITE_FF02, FMT_VER, isProvisionalId, registeredSuiteIds } from "./registry.ts";
export type { Suite } from "./registry.ts";
