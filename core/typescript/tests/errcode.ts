/**
 * One definition of "what code did this failure carry", shared by the test
 * helpers and the conformance harness.
 *
 * It lived in three places until the #111 review pointed at it: `codeOf` and
 * `codeOfAsync` in `helpers.ts`, and `errCode` in `harness/run.ts`, all with
 * byte-identical bodies. Three copies of the rule that turns an exception into
 * a report string is three chances for a report and a test to describe the
 * same failure differently — which is precisely the kind of divergence the
 * conformance report exists to make visible rather than produce.
 *
 * A leaf module rather than an export from either consumer: `harness/run.ts`
 * is what `run_vectors.ts` runs to emit the published report, and it should
 * not import the test fixtures in `helpers.ts` to get one function. Both
 * consumers are peers, so the shared thing sits below both, and this file
 * imports nothing but the error type.
 */

import { FieldsealError } from "../src/errors.ts";

/**
 * A typed §9 error contributes its code; anything else is reported verbatim
 * and marked `UNTYPED(...)`.
 *
 * The `UNTYPED` wrapper is the load-bearing half. A harness that mapped an
 * unexpected exception onto some §9 code would let a core that crashed for
 * the wrong reason pass a negative vector, so an error the taxonomy does not
 * cover has to stay visibly outside it — and carry its class and message,
 * because "something threw" is not a diagnosis.
 */
export function codeOfError(e: unknown): string {
  if (e instanceof FieldsealError) return e.code;
  return `UNTYPED(${e instanceof Error ? `${e.name}: ${e.message}` : String(e)})`;
}
