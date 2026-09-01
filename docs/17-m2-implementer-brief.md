# M2 Implementer Brief — building a second core in isolation

**Date:** 2026-08-22 · **Status:** Draft 1 · **Purpose:** the handoff given to whoever builds the second reference core. It exists so that the independence rule (`docs/11` §6) is a protocol someone can follow rather than a sentence someone remembers.

**Who this is for:** the implementer of `core/typescript/` in Phase 1, and thereafter anyone building the third, fourth or fifth core (`docs/07` §2, WS-B onward). It is written for TypeScript because that is the next one; the language-specific paragraphs are marked and the rest is general.

---

## 1. Why isolation, and why it is the whole point

M1 is the Python core passing the vector suite. On its own it establishes very little. The vectors and that core were written by the same author, so agreement between them may mean nothing more than that one assumption was made twice and checked against itself.

`docs/08` §7 states the standard: *the generator is not an oracle; agreement of two independent implementations is.* M2 is where the project's central claim — a value encrypted by one implementation is decryptable by another — stops being an assertion.

That value is destroyed by reading the first implementation. Not reduced: destroyed. A second core written with the first one open is a transcription, and a transcription agrees with its source by construction.

**The prohibition, concretely.** Do not open, read, grep, or list:

- `core/python/**`
- `tools/vector-gen/**`

If you enter either tree by accident, say so in your final report rather than continuing quietly. A disclosed compromise is recoverable and `docs/07` §7 has a place to record it. An undisclosed one makes every downstream conformance claim false, which is worse than having no second core at all.

`docs/07` M2 already anticipates the weaker case: if one person writes both cores, *say so in the report* — it weakens the independence claim, and the honest move is stating it.

## 2. What to read

| Path | What you need from it |
|---|---|
| [`docs/02-spec-v0.1.md`](02-spec-v0.1.md) | **The authority.** §3 envelope · §4 suites · §5 key hierarchy · §6 context binding · §7 blind indexes · §9 errors · §10.3 read modes · §11.1 API |
| [`docs/09-core-architecture.md`](09-core-architecture.md) | Language-agnostic architecture: module responsibilities, decrypt ordering |
| [`docs/11-core-typescript.md`](11-core-typescript.md) | *(TypeScript)* toolchain, dependency decisions, module layout §3, API shape §4 |
| [`docs/08-test-vector-spec.md`](08-test-vector-spec.md) | Vector file formats, harness contract §5, determinism-injection contract §6 |
| [`docs/14-conformance-ci.md`](14-conformance-ci.md) | The conformance report format you must emit |
| `vectors/` | The suite itself — see §3 |

Sections marked **[PROVISIONAL]** in the specification are normative for you. They are answers the project adopted under Gate 0a (PRD §8) so that implementation could begin, and they are expected to change after cryptographic review. Implement them exactly as written; do not improve them.

## 3. Working with the vectors — the part that goes wrong

Each vector file carries inputs *and* expected outputs in the same JSON object. You will see the expected values. That is unavoidable and it is fine.

What matters is the order you work in:

1. **Implement from the specification first.** Derive what the output should be from §3/§5/§6/§7, not from the file.
2. Then run the harness.
3. **When something mismatches, do not adjust your code until it goes green.**

Step 3 is the exercise. A mismatch means one of three things, and they are not equally likely:

- your bug;
- the first implementation's bug;
- **an ambiguity in the specification that two implementers resolved differently.**

The third is the most valuable finding this project can produce at this stage, and it is invisible if a constant is quietly tuned until a test passes. It is also the only failure mode the vector suite cannot detect on its own, because both cores would be self-consistently wrong.

For every mismatch record: the vector `id`, what you computed, what the file expected, the spec clause you were reading, and which of the three you believe it is. Deliver that list **even if it is empty** — "no divergences" is a result, and one worth being able to cite later.

## 4. Scope

**Implement suite `0xFF01`** — AES-256-GCM, HKDF-SHA-512, explicit 32-byte commitment.

**Do not implement `0xFF02`.** Its AEAD has no citable normative definition; that is open gap [G7](issues/G07-xchacha-normative-source.md), and the suite is registered and deliberately unbuilt. Decide for yourself what your core should do when configured with a suite it cannot perform — §9's error taxonomy constrains the answer, and the reasoning you use is worth recording.

**`blind-index/argon2id.json` is held out of the suite.** *(True when this brief was written; not since 2026-08-31, when the family was pinned — `docs/07` §7. A harness written today iterates it like any other family and derives at the cost each vector declares, `docs/08` §4.4. The paragraph stands as the instruction M2 was given.)* `MANIFEST.json` lists it under `held_out`; the file itself carries `"status": "held-out"`. Your harness MUST iterate `MANIFEST.files` and MUST NOT iterate `held_out`. You may implement Argon2id — §7.3 pins the invocation — but it MUST NOT count toward any conformance claim, and your report MUST show it as `not-run` rather than passed or skipped. The reason it is held out is in `docs/08` §9; read it, because it is an instance of exactly the failure this brief exists to prevent.

## 5. Deliverables

1. **The core**, per the module layout and API shape in the language binding doc. Every value-path operation is **synchronous** and performs **no I/O** — §11.1 explains why, and it is not negotiable regardless of what the host language makes convenient.
2. **A vector harness** implementing `docs/08` §5, emitting the `docs/14` §4 conformance report.
3. **Tests for what vectors structurally cannot cover.** A vector proves an operation succeeds; it cannot prove one is refused. At minimum: the §4.8 provisional-suite gate on ciphertext-producing operations *and what it deliberately does not gate*; the §10.3 read modes; the `docs/08` §6 determinism-injection arming gate, together with the rule that a production encrypt accepts no caller-supplied nonce or seed in any form; and that **every** failure path yields a typed §9 error rather than a runtime exception, including on arbitrary, truncated and malformed input.
4. **A divergence report** — §3's list, plus anywhere the specification was ambiguous, underspecified or self-contradictory *even where you guessed right*. Style it after [`docs/06-verification-log.md`](06-verification-log.md): the entries that say "this was wrong" are the ones that make the document worth trusting.
5. **A note on any deviation** from the binding doc's dependency choices, with reasons. Several entries there are marked **[VERIFY]** and were assessed from documentation rather than from current packages; confirming or correcting them is part of the job, not a favour.

## 6. Definition of done

- Every vector in every file listed in `MANIFEST.files` passes, in both directions where the family requires it.
- The conformance report validates against `docs/14` §4 and reflects the suite's provisional status honestly — a green run is not conformance to a frozen format, because no format has been frozen (PRD §8, Gate 0b).
- The divergence report exists.
- You have not read the other core or the generator.

## 7. What a good outcome looks like

If your implementation agrees with the existing one across the pinned suite, the project's central claim survives its first real test and `docs/07` M3's cross-implementation matrix becomes meaningful.

If it does not agree, you have found something worth more than a green run. The correct response is to write it down, not to make it go away.

Both outcomes are successes. Only a silent reconciliation is a failure.
