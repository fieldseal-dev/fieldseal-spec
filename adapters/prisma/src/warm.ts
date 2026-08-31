/**
 * L4 -- key acquisition inside the value path (`docs/13` §5, spec §10.1).
 *
 * Every field hook in Django, SQLAlchemy, Hibernate and GORM is synchronous,
 * so `docs/09` §8.2 confines KMS unwrapping to `warm()` and forbids the value
 * path from blocking on the network. The consequence is exact and Django's own
 * warm tests state it: an `EnvelopeKeyProvider` deployment whose cache is cold
 * serves `KEY_UNAVAILABLE` for **every** read until something warms it, and
 * that something has to be an operator, a management command, or a startup
 * hook that guessed the right tenants.
 *
 * Prisma is the one Phase 1 adapter that does not have to guess.
 * `$allOperations` is `async` and runs **before the query engine acquires a
 * connection** (`docs/04` §3), so an `await` here blocks one caller's promise
 * rather than holding a pooled connection open across a KMS round trip. That is
 * the whole reason spec §10.1 marks L4 reachable for Prisma and for almost
 * nothing else, and it is the flagship demonstration of why the core separates
 * `warm` from the sync value path.
 *
 * **The core's rule is not bent to do it.** The value path still never performs
 * I/O: `encrypt`, `decrypt` and `blindIndex` stay synchronous and still raise
 * `KEY_UNAVAILABLE` on a cache miss. What changes is what the *adapter* does
 * with that refusal -- it awaits `warm()` between two synchronous core calls
 * and runs the pass again. `tests/l4.test.ts` asserts the distinction directly,
 * by instrumenting a provider that fails the test if `unwrap` is ever observed
 * inside a synchronous core operation.
 *
 * ## Why reactive, and not a pre-flight check
 *
 * There is no public cache-membership probe, and there should not be one: the
 * only honest answer to "is this key cached" is the attempt itself, because a
 * §5.5 cache can evict between the probe and the use. `KeyProvider.encryptionKey`
 * would answer it, but calling it to ask rather than to use would advance the
 * §5.5 use counter for a key nobody used (`docs/09` §8.3) -- a probe that
 * corrupts the accounting it probes. So the miss is the signal.
 *
 * ## Termination
 *
 * Each cycle warms every context the failed attempt asked for. A further cycle
 * runs only if the next attempt asks for a context no previous cycle warmed --
 * strict progress, over a set an operation can only build finitely many
 * members of. If an attempt fails on a context that *was* already warmed, the
 * warm did not help (key destroyed, wrong tenant, an eviction faster than the
 * operation) and the error is raised rather than retried, because blocking a
 * query on repeated KMS round trips is the availability failure spec §8.1's
 * "the key service becomes a hard dependency in the read path" warns about.
 */

import { FieldsealError, type FieldContext, type Fieldseal, type KeyProvider } from "@fieldseal/core";

import type { Journal } from "./journal.ts";

/** Does this provider have anything to warm? */
export function providerCanWarm(provider: KeyProvider): boolean {
  return typeof provider.warm === "function";
}

/**
 * A `KEY_UNAVAILABLE` from anywhere in the pass, however it was re-thrown.
 *
 * Discriminated on `code`, not on the class: `unindexable.ts` passes a
 * `KeyUnavailableError` through untouched (deliberately -- "a KEY_UNAVAILABLE
 * must not be re-dressed as a data-quality problem"), but the adapter's own
 * `FieldsealAdapterError` shares the base class, so `instanceof` alone would
 * catch refusals that no amount of warming can fix.
 */
export function isKeyUnavailable(e: unknown): boolean {
  return e instanceof FieldsealError && e.code === "KEY_UNAVAILABLE";
}

/**
 * Every `FieldContext` one operation built, and which of them have been warmed.
 *
 * Filled by `context.ts` as the passes run, which is why L4 needs no second
 * walk of the arguments to find out what keys an operation wants: the passes
 * report what they asked for, including the index-key siblings (spec §5.2),
 * which a warm derived from value contexts alone would miss.
 */
export class ContextLedger {
  readonly #seen = new Map<string, FieldContext>();
  readonly #warmed = new Set<string>();

  add(ctx: FieldContext): void {
    this.#seen.set(key(ctx), ctx);
  }

  /** The contexts no cycle has warmed yet -- empty means no progress is left. */
  pending(): FieldContext[] {
    const out: FieldContext[] = [];
    for (const [k, ctx] of this.#seen) if (!this.#warmed.has(k)) out.push(ctx);
    return out;
  }

  markWarmed(contexts: readonly FieldContext[]): void {
    for (const ctx of contexts) this.#warmed.add(key(ctx));
  }
}

function key(ctx: FieldContext): string {
  const tenant = ctx.tenantId ?? null;
  return [
    hex(ctx.tableUuid),
    hex(ctx.columnUuid),
    tenant === null ? "-" : hex(tenant),
    ctx.purpose,
  ].join("/");
}

function hex(b: Uint8Array): string {
  return Buffer.from(b).toString("hex");
}

/**
 * Run one synchronous pass, warming and retrying on a key miss.
 *
 * The journal is rolled back before **every** retry and before every escaping
 * error, so `run` always starts from the tree as the caller wrote it. Without
 * that a retry would re-encrypt the envelope the first attempt wrote, or hand
 * an already-decrypted value back to the column codec -- see `journal.ts`.
 *
 * With no ledger (no `warm` on the provider, or `warmOnKeyMiss: false`) this is
 * exactly the old behaviour plus the rollback: one attempt, and the error out.
 */
export async function runPass<T>(
  run: () => T,
  journal: Journal,
  client: Fieldseal,
  ledger: ContextLedger | null,
): Promise<T> {
  for (;;) {
    try {
      return run();
    } catch (e) {
      journal.rollback();
      if (ledger === null || !isKeyUnavailable(e)) throw e;
      const pending = ledger.pending();
      if (pending.length === 0) throw e;
      await client.warm(pending);
      ledger.markWarmed(pending);
    }
  }
}
