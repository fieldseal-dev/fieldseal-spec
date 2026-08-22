/**
 * Client configuration and its construction-time validation (docs/09 §2).
 *
 * Everything that can be refused at construction is refused here as a
 * `ConfigurationError`, so that nothing malformed reaches the value path.
 */

import { validateIndexDeclaration, type IndexDeclaration, type ValidatedIndex } from "./blindindex.ts";
import { validateCachePolicy, type CachePolicy } from "./cache.ts";
import { ConfigurationError, suiteHex } from "./errors.ts";
import type { KeyProvider } from "./keyprovider.ts";
import { getSuite, isRegistered } from "./registry.ts";

export type ReadMode = "strict" | "permissive" | "readonly";
export const READ_MODES: readonly ReadMode[] = ["strict", "permissive", "readonly"];

export type WarningKind = "static-key-provider" | "permissive-mode" | "readonly-mode" | "plaintext-read";

export interface Warning {
  readonly kind: WarningKind;
  readonly message: string;
}

export interface Metrics {
  readonly plaintextReads?: () => void;
  readonly decryptErrors?: (code: string) => void;
}

export interface FieldsealConfig {
  readonly keyProvider: KeyProvider;
  /** Explicit decrypt allow-list (spec §4.3). No default; must be non-empty. */
  readonly allowedSuites: readonly number[];
  /** Must be in allowedSuites. */
  readonly writeSuite: number;
  /** Default "strict" (spec §10.3). */
  readonly readMode?: ReadMode;
  /** Validated for §5.5 bounds when given; EnvelopeKeyProvider carries its own cache. */
  readonly cache?: CachePolicy;
  readonly indexes?: readonly IndexDeclaration[];
  readonly onWarning?: (w: Warning) => void;
  readonly metrics?: Metrics;
}

/**
 * Spec §4.8 arming. Deliberately a SEPARATE constructor argument from
 * `FieldsealConfig`, so that it cannot be inherited by copying the ordinary
 * configuration object that carries `allowedSuites` and `writeSuite`. The
 * alternative is the environment variable named below.
 */
export interface ArmingOptions {
  readonly armProvisionalSuites?: boolean;
}

export const ARM_PROVISIONAL_ENV = "FIELDSEAL_ARM_PROVISIONAL_SUITES";
export const ARMING_MECHANISM_DESCRIPTION = `set the environment variable ${ARM_PROVISIONAL_ENV}=1, or pass { armProvisionalSuites: true } as the second constructor argument (never inside the config object)`;

export function provisionalArmedByEnv(): boolean {
  return process.env[ARM_PROVISIONAL_ENV] === "1";
}

export interface ValidatedConfig {
  readonly keyProvider: KeyProvider;
  readonly allowedSuites: ReadonlySet<number>;
  readonly writeSuite: number;
  readonly readMode: ReadMode;
  readonly indexes: ReadonlyMap<string, ValidatedIndex>;
  readonly onWarning: (w: Warning) => void;
  readonly metrics: Metrics;
  readonly provisionalArmed: boolean;
}

export function validateConfig(config: FieldsealConfig, arming: ArmingOptions = {}): ValidatedConfig {
  if (config === null || typeof config !== "object") throw new ConfigurationError("config must be an object");
  const kp = config.keyProvider;
  if (kp === null || typeof kp !== "object" || typeof kp.encryptionKey !== "function" || typeof kp.decryptionKeys !== "function") {
    throw new ConfigurationError("config.keyProvider must implement encryptionKey() and decryptionKeys() (spec §8)");
  }
  if (!Array.isArray(config.allowedSuites) || config.allowedSuites.length === 0) {
    throw new ConfigurationError("config.allowedSuites must be a non-empty list (spec §4.3): there is deliberately no implicit 'all registered'");
  }
  const allowed = new Set<number>();
  for (const id of config.allowedSuites) {
    if (!Number.isInteger(id) || id < 0 || id > 0xffff) throw new ConfigurationError(`allowedSuites: ${String(id)} is not a 16-bit suite identifier`);
    if (!isRegistered(id)) throw new ConfigurationError(`allowedSuites: ${suiteHex(id)} is not a registered suite (spec §4.2)`);
    const s = getSuite(id);
    if (s !== undefined && !s.implemented) {
      // Registered but unbuilt (0xFF02, gap G7). Allow-listing a suite this
      // core cannot perform would make a config claim the code cannot honor;
      // the only honest §9 outcome for such an envelope would be a
      // SUITE_NOT_ALLOWED that contradicts the operator's own allow-list.
      // Fail closed at construction instead, and say why.
      throw new ConfigurationError(
        `allowedSuites: ${suiteHex(id)} (${s.name}) is registered but not implemented by this core -- its AEAD has no citable normative definition (spec §4.2, gap G7). It is recognized by isCiphertext() and cannot be decrypted or written here.`,
      );
    }
    allowed.add(id);
  }
  const ws = config.writeSuite;
  if (!Number.isInteger(ws) || !allowed.has(ws)) {
    throw new ConfigurationError(`config.writeSuite ${Number.isInteger(ws) ? suiteHex(ws) : String(ws)} must be one of allowedSuites`);
  }
  const mode = config.readMode ?? "strict";
  if (!READ_MODES.includes(mode)) throw new ConfigurationError(`config.readMode must be one of ${READ_MODES.join(", ")} (spec §10.3)`);
  if (config.cache !== undefined) validateCachePolicy(config.cache);

  const indexes = new Map<string, ValidatedIndex>();
  for (const d of config.indexes ?? []) {
    const v = validateIndexDeclaration(d);
    if (indexes.has(v.key)) throw new ConfigurationError(`duplicate index declaration ${v.key}`);
    indexes.set(v.key, v);
  }
  const onWarning = config.onWarning ?? (() => {});
  if (config.onWarning !== undefined && typeof config.onWarning !== "function") {
    throw new ConfigurationError("config.onWarning must be a function");
  }
  const armedByArg = arming.armProvisionalSuites === true;
  return {
    keyProvider: kp,
    allowedSuites: allowed,
    writeSuite: ws,
    readMode: mode,
    indexes,
    onWarning,
    metrics: config.metrics ?? {},
    provisionalArmed: armedByArg || provisionalArmedByEnv(),
  };
}
