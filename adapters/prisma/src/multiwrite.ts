/**
 * The #250 opt-in: `sharedEnvelopeScope(fn)`.
 *
 * **The defect this exists for.** A multi-row statement (`updateMany`,
 * `updateManyAndReturn`) carries one `data` payload for every row its `where`
 * matches. The extension sees the payload before the engine sees the
 * statement, so it cannot know how many rows will match, and Prisma offers no
 * per-row payload for that shape. Encrypting there therefore produces **one**
 * envelope -- one `msg_seed`, one nonce, one ciphertext -- stored byte for byte
 * on every matched row. Spec §3.1 and §4.4 are worded per encryption
 * *operation*, and the statement performs one, so the bytes are not
 * nonce-reused in the sense SP 800-38D warns about (the key, nonce, plaintext
 * and context are all the same). What is lost is the other half of what
 * randomized encryption buys: for a column with no declared blind index —
 * where nothing else reveals it — two rows given the same value by one
 * statement are visibly equal, and `AGENTS.md`'s commitment 2 ("fresh nonce on
 * every write, including UPDATEs") is the promise they break.
 *
 * So the adapter refuses by default (`write.ts`, spec §10.2: throw rather than
 * degrade), and this scope is how a caller says the same plaintext into every
 * matched row is exactly what they mean — setting one status on every expired
 * row — and that they accept the equality it stores.
 *
 * **What it does not change.** The payload is still encrypted once, with a
 * fresh `msg_seed` and nonce, and the index siblings are still derived for
 * every declared index (the scope lifts the refusal and nothing else). There is
 * no second code path through the write pass.
 *
 * **There is nothing to re-verify, and that is the cost.** `candidateScope`
 * hands the caller a superset they can decrypt and compare; the loss here is
 * in the stored bytes, and no later read recovers per-row randomization. That
 * is why this is a separate scope rather than a flag on the operation: opening
 * it is the acknowledgement, and it is visible where the call is written.
 *
 * **The boundary is dispatch, not construction** — the same measurement, and
 * the same consequence, as `candidateScope` (`candidates.ts`): a Prisma promise
 * is lazy, so the scope covers whatever *dispatches* while it is open. A
 * promise constructed inside the callback but awaited outside escapes the
 * scope, and a promise constructed outside but first awaited inside dispatches
 * inside. Construct the operation inside the callback, and await it there:
 *
 *     await sharedEnvelopeScope(() =>
 *       prisma.patient.updateMany({ where: { expired: true }, data: { note: "archived" } }),
 *     );
 */

import { AsyncLocalStorage } from "node:async_hooks";

const storage = new AsyncLocalStorage<true>();

/**
 * Run `fn` with the multi-row write refusal lifted for every fieldseal
 * operation inside it.
 *
 * **It awaits inside the scope, and it has to.** An `updateMany` returns a lazy
 * `PrismaPromise`; nothing is dispatched until something calls `.then`, so a
 * synchronous `storage.run(true, fn)` would exit the scope before the statement
 * ran and the extension would refuse it anyway — an opt-in that silently does
 * nothing, which is worse than not having one. So the result must be awaited
 * from this function, not from a promise the callback merely constructs.
 */
export function sharedEnvelopeScope<T>(fn: () => T | Promise<T>): Promise<T> {
  return storage.run(true, async () => await fn());
}

/** Whether the current async context is inside a `sharedEnvelopeScope`. */
export function inSharedEnvelopeScope(): boolean {
  return storage.getStore() === true;
}
