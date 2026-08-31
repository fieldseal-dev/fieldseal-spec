/**
 * The undo journal: every pass either completes or leaves the tree as it
 * found it.
 *
 * The visitors mutate in place, deliberately (`write.ts`: rebuilding the tree
 * would mean reconstructing every shape this adapter does not understand). The
 * cost of that choice is that a pass which throws half way leaves a half
 * transformed tree behind -- a `data` object with two columns encrypted and the
 * third still plaintext, or a result row with four values decrypted and the
 * fifth still an envelope.
 *
 * Until L4 that was only untidy: the operation threw, the exception left, and
 * nothing read the wreckage. **L4 makes it a correctness problem.**
 * `warm()`-on-miss runs the pass again, and a retry over a half transformed
 * tree is silent corruption of the worst kind: `write.ts` would read the
 * envelope it wrote as if it were the caller's value and encrypt it a second
 * time, and `read.ts` would hand an already decrypted string back to
 * `fromColumn`, which refuses it as a storage mismatch. Neither failure names
 * its cause.
 *
 * **Whose tree it is** (measured, Prisma 7.10.0, 2026-08-31): Prisma hands the
 * extension a **copy** of the caller's arguments -- `args.data` is not the
 * object the caller passed -- so this is not a promise that a refused write
 * leaves your own object alone. It cannot be observed from outside the
 * extension at all. It is an internal invariant about the tree the pipeline
 * walks, and the retry is the only thing that depends on it. Worth stating
 * plainly, because the stronger-sounding claim is the one a reader would
 * assume, and it is false.
 *
 * So every mutation the visitors make is recorded here first, and a failed pass
 * is rolled back before anything looks at the tree again. Restoration is exact
 * rather than approximate -- the previous value and whether the key was present
 * at all -- and runs in reverse order, which is what makes a read-modify-write
 * site correct too (`rewrite.ts` appends to `AND`; undoing the append means
 * restoring the value that was there before *that* append, not before the
 * first).
 *
 * **The invariant, stated so it can be tested:** after a pass throws, the
 * argument tree and the result tree hold exactly what they held before it ran.
 * `tests/l4.test.ts` asserts it through the retry -- a column encrypted twice
 * or decrypted twice is what a missed journal site produces -- rather than by
 * trusting that every future mutation site remembers to call in here.
 *
 * The journal is not conditional on L4 being armed. Making it conditional would
 * mean two mutation paths through the visitors, one of them exercised only in
 * deployments that use a KMS, which is the arrangement least likely to be
 * right.
 */

interface Entry {
  readonly obj: Record<string, unknown>;
  readonly key: string;
  /** Whether the key was present at all -- `delete` and `= undefined` differ. */
  readonly had: boolean;
  readonly prev: unknown;
}

export class Journal {
  readonly #entries: Entry[] = [];

  /** Record and apply `obj[key] = value`. */
  set(obj: Record<string, unknown>, key: string, value: unknown): void {
    this.#record(obj, key);
    obj[key] = value;
  }

  /** Record and apply `delete obj[key]`. */
  remove(obj: Record<string, unknown>, key: string): void {
    this.#record(obj, key);
    delete obj[key];
  }

  /** How many mutations are outstanding. Used by the tests, not the pipeline. */
  get size(): number {
    return this.#entries.length;
  }

  /**
   * Undo every recorded mutation, most recent first, and empty the journal.
   *
   * Idempotent: a second call restores nothing, so a caller that rolls back and
   * then throws cannot accidentally undo the retry's work as well.
   */
  rollback(): void {
    for (let i = this.#entries.length - 1; i >= 0; i--) {
      const e = this.#entries[i]!;
      if (e.had) e.obj[e.key] = e.prev;
      else delete e.obj[e.key];
    }
    this.#entries.length = 0;
  }

  /** Accept the recorded mutations: they are now the tree's own state. */
  commit(): void {
    this.#entries.length = 0;
  }

  #record(obj: Record<string, unknown>, key: string): void {
    // `in` rather than `obj[key] !== undefined`: Prisma distinguishes an absent
    // key from one explicitly set to `undefined` (the "do not touch this field"
    // contract `write.ts` relies on), so a rollback that turned the first into
    // the second would change the meaning of the operation it is restoring.
    this.#entries.push({ obj, key, had: key in obj, prev: obj[key] });
  }
}
