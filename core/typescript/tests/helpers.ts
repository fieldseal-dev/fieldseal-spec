import { Fieldseal, type FieldsealConfig, type ArmingOptions, type Warning } from "../src/index.ts";
import { StaticKeyProvider } from "../src/keyprovider.ts";
import type { FieldContext, ResolvedContext } from "../src/context.ts";
import type { EnvelopeHeader } from "../src/envelope.ts";
import type { EncryptionKey, KeyProvider } from "../src/keyprovider.ts";
import { SUITE_FF01 } from "../src/registry.ts";
import { codeOfError } from "./errcode.ts";

export const DEK = new Uint8Array(32).map((_, i) => i);
export const INDEX_KEY = new Uint8Array(32).map((_, i) => 0x20 + i);
export const KEY_ID = new Uint8Array(Buffer.from("0123456789abcdef0123456789abcdef", "hex"));
export const TABLE = new Uint8Array(Buffer.from("3f2504e04f8911d39a0c0305e82c3301", "hex"));
export const COLUMN = new Uint8Array(Buffer.from("7d4448409dc011d1b2455ffdce74fad2", "hex"));

export const CTX: FieldContext = {
  tableUuid: TABLE,
  columnUuid: COLUMN,
  tenantId: new TextEncoder().encode("tenant-0001"),
  rowId: null,
  purpose: "encrypt",
};

export function makeClient(
  over: Partial<FieldsealConfig> = {},
  arming: ArmingOptions = { armProvisionalSuites: true },
  warnings?: Warning[],
): Fieldseal {
  return new Fieldseal(
    {
      keyProvider: new StaticKeyProvider({ dek: DEK, keyId: KEY_ID, indexKey: INDEX_KEY }),
      allowedSuites: [SUITE_FF01],
      writeSuite: SUITE_FF01,
      readMode: "strict",
      ...(warnings ? { onWarning: (w: Warning) => warnings.push(w) } : {}),
      ...over,
    },
    arming,
  );
}

export function codeOf(fn: () => unknown): string {
  try {
    fn();
  } catch (e) {
    return codeOfError(e);
  }
  return "NO_ERROR";
}

/**
 * `codeOf` for a call that may reject. A thunk rather than a promise so that
 * a *synchronous* throw from a nominally asynchronous entry point is caught
 * here too: spec §11.1 requires the companion to fail the same way as the
 * synchronous form, and "the same code, but thrown instead of rejected" is
 * a difference a caller's `.catch()` would miss.
 */
export async function codeOfAsync(fn: () => Promise<unknown> | unknown): Promise<string> {
  try {
    await fn();
  } catch (e) {
    return codeOfError(e);
  }
  return "NO_ERROR";
}

export function messageOf(fn: () => unknown): string {
  try {
    fn();
  } catch (e) {
    return e instanceof Error ? e.message : String(e);
  }
  return "";
}

export function withEnv<T>(name: string, value: string | undefined, fn: () => T): T {
  const prev = process.env[name];
  if (value === undefined) delete process.env[name];
  else process.env[name] = value;
  try {
    return fn();
  } finally {
    if (prev === undefined) delete process.env[name];
    else process.env[name] = prev;
  }
}

export const bytes = (s: string): Uint8Array => new TextEncoder().encode(s);
export const hex = (s: string): Uint8Array => new Uint8Array(Buffer.from(s, "hex"));

/**
 * A `KeyProvider` that hands out references to its own buffers, so a core
 * that erased provider-owned material corrupts *this object* and fails the
 * assertion rather than doing it invisibly (docs/09 §8.1, the pinned
 * key-material-ownership decision).
 *
 * Each field is a fresh copy of the module constant it mirrors, never the
 * constant itself: the constants are the pristine values the assertions
 * compare against, so a provider that lent one out directly would let a
 * misbehaving core corrupt every later test instead of failing one.
 *
 * Shared because `providers.test.ts` and `async-companions.test.ts` had
 * identical copies (#111 review): the sync and async paths must make the
 * *same* promise about borrowed material, and two definitions of the
 * provider is how they would quietly stop doing so.
 */
export class BorrowingProvider implements KeyProvider {
  readonly dek = new Uint8Array(DEK);
  readonly indexKey = new Uint8Array(INDEX_KEY);
  readonly keyId = new Uint8Array(KEY_ID);
  encryptionKey(ctx: ResolvedContext): EncryptionKey {
    return { key: ctx.purpose === "encrypt" ? this.dek : this.indexKey, keyId: this.keyId };
  }
  decryptionKeys(_header: EnvelopeHeader): Uint8Array[] {
    return [this.dek];
  }
}

/**
 * A value carrying U+0378, unassigned in every Unicode version so far, so it
 * stands in for "a character the pin does not define" without waiting for
 * 18.0. `OTHER_UNPINNED` is a second one: the two must land in the same
 * bucket and that is only demonstrable with two distinct values.
 */
export const UNPINNED = "a͸b";
export const OTHER_UNPINNED = "z͸z";

/** The boilerplate `unindexableOverride` for tests that need `bucket`. */
export const OVERRIDE = { reason: "legal name column; refusing a customer's name is worse", approvedBy: "test", date: "2026-08-25" };

/**
 * The index-declaration fields every test column shares. Spread it and add
 * `idf` (and `indexId` where more than one column is declared) — what varies
 * between tests is what the test is about, and this is the part that is not.
 */
export const INDEX_BASE = {
  tableUuid: CTX.tableUuid,
  columnUuid: CTX.columnUuid,
  normalize: "nfc-casefold-v1" as const,
  truncateBits: 15,
  projectedPopulation: 65536,
};
