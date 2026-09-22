# G26 — docs/14 §4 gives an out-of-band entry whose operand the language cannot represent no passing status, so no Java or .NET core can claim L0, and no Go core either

**Labels:** docs/14 §4 · docs/08 §5 · spec §3.5 · docs/09 §7.1 · conformance
**Blocks:** Phase 2 entry (`docs/26-phase-2-plan.md` §1 item 2, milestone P2-M0): it is decided before any Phase 2 core emits a conformance report. Through `docs/25` §10 item 3, which says a core that passes with `not-run` entries does not count toward PRD metric M1, it also blocks the PRD Phase 2 exit criterion for three of the five languages. It changes no envelope byte, no derived value and no error code, and it has no bearing on Gate 0b.
**Found:** 2026-09-19, while reviewing the design plans for the Java and .NET cores. The need was recorded as out of scope in the closure comment on [#167](https://github.com/fieldseal-dev/fieldseal-spec/issues/167) (2026-09-20), which left it unfiled until a Phase 2 core was real. Phase 2 opened on 2026-09-22 (`docs/25` §10), so it is filed now.
**Status:** open — tracker [#176](https://github.com/fieldseal-dev/fieldseal-spec/issues/176), filed 2026-09-22. **Direction revised the same day after review** ([comment](https://github.com/fieldseal-dev/fieldseal-spec/issues/176#issuecomment-5784498270)): the sections *Proposed direction*, *What breaks* and *Vector obligations* below are the draft as posted and are superseded there. In short: the status vocabulary is `pass | fail | not-run`, and the TypeScript harness's `not-verified` is a bug; a `basis` field (`direct`, `seam`, `representability`); the length-bound seam is open to any core, is named as architecture in `docs/09` §4, and `#decrypt` is defined by implied length ≥ 2³¹; the lone-surrogate entry splits, with its bytes layer becoming `blind-index/` vectors (G15's unshipped invalid-UTF-8 obligation, a suite bump to `0.8.0-provisional`) and its text layer recorded with `basis: representability` for Go and Rust. Candidate A in item 3 below tested the wrong clause and is withdrawn. Open for the maintainer: whether that last entry is `pass` or a non-blocking `not-run`.

## Gap

`docs/14` §4 carries normative requirements that have no vector in an `out_of_band` block. It says a harness that cannot run one "records `"status": "not-run"` with the reason … a `not-run` entry is not `pass` and blocks the level claim on the same terms as a failure". `docs/08` §5 items 8 and 9 say the same from the harness side. Two requirements qualify:

- **`spec/3.5/length-bound`** and **`#decrypt`**: a 2³¹-byte plaintext, and an envelope implying one, MUST be refused with `LENGTH_EXCEEDED`. "A runtime that cannot allocate the operand records `not-run`."
- **`docs/09/7.1/lone-surrogate-refusal`**: two distinct unpaired surrogates MUST be refused, and refused distinguishably. `docs/08` §5 item 9: "A harness in a language whose string type cannot represent an unpaired surrogate (Go, Rust) records `not-run` with that reason."

`docs/14` §4 then separates the two kinds of exclusion itself: the first is excluded "by *size*, which is an accident of the test harness; the second is excluded by *representability*, which is a property of the requirement itself and will not go away." It names the category, and it gives the category no way to pass.

**The size case is a representability case too, for three of the five target languages.**

| Core | Length bound (spec §3.5) | Lone surrogate (docs/09 §7.1) |
|---|---|---|
| Python, TypeScript (shipped) | representable, and verified directly (`docs/18` §2) | representable, and verified |
| Java | `byte[].length` is `int`, so a 2³¹-byte operand **does not exist** on any JVM | representable: `java.lang.String` is UTF-16 |
| .NET | `byte[].Length` is `int`, and the runtime caps arrays at `Array.MaxLength` = 0x7FFFFFC7 (2³¹−57), so the operand does not exist | representable: `System.String` is UTF-16 |
| Go | representable: slice lengths are `int`, 64-bit on 64-bit platforms | **not representable**, per `docs/14` §4 and `docs/08` §5 item 9 |

Read literally, then, the Java and .NET cores record `not-run` on the length-bound pair and the Go core on the lone-surrogate entry, forever. None of the three can claim L0 for a requirement its type system satisfies by construction. No harness improvement fixes this, because nothing is wrong with the harness.

A smaller item for the same change: `docs/14` §4 specifies the status `not-run`, while the TypeScript harness's report type also admits `not-verified` (reported in the #167 closure comment and in the JVM design's review). One vocabulary, not two.

## Proposed direction

A new status is not proposed. What is proposed is a rule for when an unrepresentable-operand entry records `pass`:

1. **An `out_of_band` entry whose operand the implementation's language cannot represent records `pass` when both of these hold:**
   - **(a)** the refusal is proven on a *synthetic* operand, through the same internal path every public call takes. For the length bound, that means a length-typed seam: an internal operand that reports length 2³¹ (encrypt) or 2³¹+111 (decrypt, suite `0xFF01`) and throws on any content access, driven through the pipeline the public `byte[]` methods enter, with assertions of `LENGTH_EXCEEDED`, zero key-provider calls and zero content reads. The test must fail when the guard is moved one statement later.
   - **(b)** the entry's `method` states the representability argument ("`byte[]` length is `int`; a 2³¹-byte operand is unrepresentable on this runtime"), and the core's binding doc states it too, in the buffer section `docs/09` §4 already requires of every binding.
2. **`not-run` keeps its meaning** for everything else: an operand that exists but the runner could not allocate, a family the harness skipped, a requirement nobody tested. It still blocks the level claim.
3. **The lone-surrogate case needs its own reading of (a)**, and the discussion should settle it rather than this draft. Where the language cannot hold the operand at all, no internal path accepts it, so there is nothing synthetic to drive. One candidate: the entry records `pass` when the method states the argument and a test shows that the nearest representable input, the surrogate code points' generalized-UTF-8 byte sequences (`ED A0 80`, `ED B0 80`), is refused as invalid UTF-8 and refused distinguishably. Another: this case stays `not-run`, and the level-claim rule stops counting it. The second is simpler, but it lets a requirement drop out of a level claim, which `docs/14` §4's own paragraph warns about: "A requirement that cannot be a vector in every target language is exactly the requirement most likely to be quietly skipped."
4. **Vocabulary:** `not-verified` is removed from any harness type that admits it, or `docs/14` §4 defines it. The draft prefers removal, since `not-run` already carries a reason.
5. **The report records which route an entry took:** a `pass` reached under rule 1 carries a field saying so, such as `"basis": "representability"`, so a reader can tell a directly verified refusal from one proven on a synthetic operand. `cross-core-result-ids` compares entry ids, not bases, so nothing there changes.

## What breaks

Nothing shipped. The Python and TypeScript reports verify both entry kinds directly (`docs/18` §2), so neither report changes except under rule 4, if its harness type admits `not-verified`. `docs/14` §4 and `docs/08` §5 items 8 and 9 change wording, and `docs/14` §4's report schema gains the optional `basis` field.

The forward-looking effect is the point: the Java and .NET designs can plan the length-bound entries as `pass` instead of `not-run`, and the Go core's lone-surrogate entry gets a defined outcome before its design is written.

If the direction is rejected, those cores report `not-run` and do not count toward metric M1, and the Phase 2 exit criterion ("five languages passing identical vectors", PRD §8) has to be restated as a decision in `docs/07` §7. It is not met by reading `not-run` as a pass.

## Vector obligations

**None.** Both requirements are out-of-band because they cannot be vectors: spec §3.5 and §12 and the `docs/08` §4.6 row exempt the length bound from the literal-bytes rule, and `blind-index/` keys its input as hex bytes, which an unpaired surrogate has no UTF-8 encoding for. The change is to the report format and the level-claim rule.

## Cryptographic review

**No bearing on any Gate 0b question.** The length bound is an API-boundary refusal upstream of every cryptographic operation, and the lone-surrogate refusal is a normalizer input check. The question is what a conformance report may claim, which needs a maintainer decision rather than a cryptographer.
