/**
 * The §7.5 opt-out: `candidateScope(fn)`.
 *
 * Django's escape hatch is a queryset method -- `.candidates()` returns a
 * chained queryset with re-verification switched off (`docs/12` §3.2, decision
 * C). Prisma has nothing to chain: an operation is a single call with a plain
 * arguments object, and the extension sees `(model, operation, args)` with no
 * object of the caller's to hang a flag on. So the scope is the callback, in
 * the same shape and for the same reason as `tenantScope` beside it: an
 * `AsyncLocalStorage` survives `await`, which is the only thing that can
 * reach an extension running arbitrarily deep inside a request.
 *
 * **What it hands over.** A blind index is a filter over a §7.4 bucket that
 * *mandates* collisions, so what comes back inside this scope is a **superset**
 * of the answer -- some rows will not hold the value asked for. Spec §7.5 says
 * the candidates must be decrypted and compared before they are treated as
 * results; inside this scope that obligation is the caller's.
 *
 * **What it buys**, and why it exists at all: the shapes the *database* answers.
 * Prisma's extension cannot turn one operation into another, so a `count`, a
 * `take`/`skip` page, a `findFirst`, a `deleteMany` -- everything whose answer
 * is computed below the extension -- cannot be served with re-verification and
 * is refused. This is the way to say "bucket semantics are what I want".
 *
 * **What it does not lift.**
 *
 *  - The G20 family: ordering, grouping, `DISTINCT` and byte-reading aggregates
 *    over an encrypted column. Bucket semantics are a meaningful thing for a
 *    caller to accept; ciphertext order has no semantics to accept.
 *  - `not` / `notIn` over an encrypted column. Django's `.candidates()` does
 *    lift its `exclude()` analogue, and the divergence is deliberate: there,
 *    the rewrite happens in the field layer whether the queryset verifies or
 *    not, so lifting it costs nothing. Here the rewrite is the adapter's own
 *    and spec §7.10 has a row for membership and **none** for negated
 *    membership -- which is what G21 ([#87]) was filed to settle. Serving it
 *    inside this scope would be deciding G21 by engineering judgment.
 *  - A value the column's normalizer refuses under `on_unindexable: "refuse"`.
 *    That error is about the operand, not about verification.
 *
 * **The cost of the callback shape, stated plainly:** the scope covers every
 * fieldseal operation awaited inside it, not just the next one. The documented
 * idiom is therefore one operation per scope. A wide callback silently takes
 * §7.5 off operations the caller never meant to opt out of, and nothing in the
 * adapter can tell the difference.
 *
 * **The boundary is dispatch, not construction.** A Prisma promise is lazy, so
 * the scope covers whatever *dispatches* while it is open -- and that cuts both
 * ways (both measured): a promise constructed inside the callback but returned
 * unawaited escapes the scope (the caveat `candidateScope` itself closes by
 * awaiting), and a promise constructed *outside* the scope but first awaited
 * *inside* it dispatches inside and is served at bucket semantics, even though
 * the caller wrote it where verification looked to be on. Construct the
 * operation inside the callback, and nowhere else.
 */

import { AsyncLocalStorage } from "node:async_hooks";

const storage = new AsyncLocalStorage<true>();

/**
 * Run `fn` with spec §7.5 re-verification switched off for every fieldseal
 * operation inside it. What comes back is the raw index candidates: a superset
 * of the answer, and the caller takes on decrypt-and-compare.
 *
 * **It awaits inside the scope, and it has to.** A Prisma client method returns
 * a lazy `PrismaPromise`: nothing is dispatched until something calls `.then`.
 * A synchronous `storage.run(true, fn)` would therefore hand the promise back
 * and *exit the scope before the query ran*, so the extension would read
 * `inCandidateScope() === false` and re-verify anyway -- an opt-out that
 * silently does nothing, which is worse than not having one. Measured against
 * Prisma 7.10.0, and pinned by the "measures why" tests in `tests/l2.test.ts`:
 * they assert the collision row *is* returned here, so an opt-out that stopped
 * working would fail them.
 *
 * The consequence for callers is that the result must be awaited from this
 * function, not from a promise the callback merely constructs:
 *
 *     await candidateScope(() => prisma.patient.count({ where: { email: v } }))
 */
export function candidateScope<T>(fn: () => T | Promise<T>): Promise<T> {
  return storage.run(true, async () => await fn());
}

/** Whether the current async context is inside a `candidateScope`. */
export function inCandidateScope(): boolean {
  return storage.getStore() === true;
}
