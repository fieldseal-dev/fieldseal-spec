/**
 * `@fieldseal/core/testing` -- the determinism-injection namespace (docs/08 §6).
 *
 * Nonces and derivation seeds are fixed in vectors so outputs are
 * deterministic and comparable. **This is a testing affordance only.** Spec
 * §3.1 and §4.4 require a fresh CSPRNG seed and nonce on every real
 * encryption, including UPDATEs; *"an implementation that accepts a
 * caller-supplied nonce or seed outside of vector-test mode is
 * non-conformant"* (vectors/README.md).
 *
 * Arming gate: every function here throws unless the environment variable
 * `FIELDSEAL_TEST_MODE=1` is set at call time. The main entry
 * (`@fieldseal/core`) never re-exports this module and has no code path that
 * reaches it; the production `encrypt()` takes no seed or nonce in any form.
 *
 * The function name is deliberately snake_case, contrary to local
 * convention: docs/09 §12 fixes the *same* name across languages so the
 * injection surface is greppable in any repository.
 */

import { TEST_MODE_ENV, type Fieldseal } from "../api.ts";
import type { FieldContext } from "../context.ts";
import { ConfigurationError } from "../errors.ts";
import { INTERNALS } from "../internal.ts";

export class TestModeNotArmedError extends ConfigurationError {
  constructor(fn: string) {
    super(
      `${fn} is a vector-test affordance and is inert unless ${TEST_MODE_ENV}=1 is set in the environment. ` +
        "An implementation that accepts a caller-supplied nonce or seed outside of vector-test mode is non-conformant (spec §3.1, §4.4; vectors/README.md).",
    );
    this.name = "TestModeNotArmedError";
  }
}

export function isTestModeArmed(): boolean {
  return process.env[TEST_MODE_ENV] === "1";
}

function requireArmed(fn: string): void {
  if (!isTestModeArmed()) throw new TestModeNotArmedError(fn);
}

/**
 * Runs the client's full production encrypt pipeline -- same boundary checks
 * (MODE_VIOLATION, SUITE_PROVISIONAL, LENGTH_EXCEEDED), same KDF, same AAD,
 * same commitment path -- with the caller's `msg_seed` and `nonce` in place
 * of the two CSPRNG draws, and nothing else replaced.
 */
export function encrypt_with_materials(
  client: Fieldseal,
  plaintext: Uint8Array,
  ctx: FieldContext,
  msgSeed: Uint8Array,
  nonce: Uint8Array,
): Buffer {
  requireArmed("encrypt_with_materials");
  const internals = INTERNALS.get(client);
  if (internals === undefined) throw new ConfigurationError("encrypt_with_materials: first argument must be a Fieldseal client");
  return internals.encryptWithMaterials(plaintext, ctx, msgSeed, nonce);
}
