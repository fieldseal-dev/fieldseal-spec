import { Fieldseal, type FieldsealConfig, type ArmingOptions, type Warning } from "../src/index.ts";
import { StaticKeyProvider } from "../src/keyprovider.ts";
import type { FieldContext } from "../src/context.ts";
import { FieldsealError } from "../src/errors.ts";
import { SUITE_FF01 } from "../src/registry.ts";

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
    if (e instanceof FieldsealError) return e.code;
    return `UNTYPED(${e instanceof Error ? `${e.name}: ${e.message}` : String(e)})`;
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
    if (e instanceof FieldsealError) return e.code;
    return `UNTYPED(${e instanceof Error ? `${e.name}: ${e.message}` : String(e)})`;
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
