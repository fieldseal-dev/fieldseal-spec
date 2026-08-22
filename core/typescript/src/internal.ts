/**
 * The determinism-injection seam (docs/08 §6).
 *
 * `api.ts` registers, per client, the one function that runs the encrypt
 * pipeline with caller-supplied `msg_seed` and `nonce`. This module is NOT
 * re-exported from `index.ts`, is not a `package.json` subpath export, and is
 * imported only by `testing/index.ts`, which is itself inert unless
 * `FIELDSEAL_TEST_MODE=1`. The production `encrypt()` has no path to it.
 */

import type { FieldContext } from "./context.ts";

export interface ClientInternals {
  encryptWithMaterials(plaintext: Uint8Array, ctx: FieldContext, msgSeed: Uint8Array, nonce: Uint8Array): Buffer;
}

export const INTERNALS = new WeakMap<object, ClientInternals>();
