# G16 — docs/09 §7, §7.1; §7.6, §10.2: the index boundary can lose information before the core sees it, and the Unicode pin has no currency policy

**Labels:** docs/09 §7 · docs/09 §7.1 · §7.5 · §7.6 · §10.2 · docs/12 · docs/13 · spec-gap
**Blocks:** the adapter obligation `docs/09` §7.1 already claims is written down and is not; the `on_unindexable` field of `IndexDeclaration`; the `blind-index/` vectors that would pin a text-typed boundary; the pin bump that is free now and expensive after freeze.
**Found:** 2026-08-24 while closing G15 (issue [#48](https://github.com/fieldseal-dev/fieldseal-spec/issues/48)), written up in `internal/product-decision-indexing-edge-cases.md`. Neither finding is a defect in either core — both do exactly what `docs/09` §7.1 now says. Both are questions about what it should say next.

**Status:** OPEN — tracker [#60](https://github.com/fieldseal-dev/fieldseal-spec/issues/60), posted 2026-08-25. **All four parts carry decided directions** (product owner, 2026-08-25); what remains is the normative edits, the vectors and one core change, not a decision.

> **Part C landed 2026-08-25**, ahead of A and B: `docs/09` §7.1 carries *Pin currency (normative)*, and `tools/ucd-gen` has the fetch guards plus `test_generate.py` in CI. The 18.0 bump itself is **not** done and cannot be until the release stops redirecting.
>
> **Part A landed 2026-08-25.** `blindIndex` takes `string | Uint8Array`; §7.1's note is normative on an index API accepting text; `docs/10` and `docs/11` record the deliberate `encrypt`/`blind_index` asymmetry. **One vector obligation below could not be met and was rerouted** — see *Vector obligations*: the lone-surrogate case is not portably expressible, so it is an `out_of_band` entry in both cores' reports instead.
>
> **Part B landed 2026-08-25.** New normative `docs/09` §7.2; `docs/12` §10 and `docs/13` §9 carry the adapter obligation and the message rules, closing the dangling pointer this issue was partly filed about. Vector suite bumped to `0.3.0-provisional` with three vectors. **One design correction, recorded in §7.2 rather than substituted quietly:** part B below has every indexed lookup additionally probe the marker, which is unnecessary — the marker is derived from the value's *normalization*, so a query for an unindexable value derives it unaided, and the query path needs no special case. See *Part B — decided direction*, item 1, and `docs/07` §7.
>
> **All four parts are now landed.** What remains before this issue closes: the 18.0 pin bump (part C), which waits on the release, and nothing else. No spec or `docs/09` text carries a `[PROVISIONAL]` marker for any of this, and none is needed: nothing here waits on a reviewer.

## Why one issue

Three consequences of the G15 closure, sharing one closure shape — amend `docs/09` §7 and §7.1, write the adapter obligation into `docs/12` and `docs/13`, add `blind-index/` vectors, sweep the `G16` markers. None needs cryptographic review. Part D asked whether one of them should nevertheless be shown to the Gate 0b reviewers, and answers no; it is kept as a part rather than deleted so that the question is on the record as asked and answered.

---

## Part A — docs/09 §7.1: a bytes-only index API cannot enforce its own refusal

### Gap

`docs/09` §7.1 clause 5 refuses invalid UTF-8, and its indented note explains why a bytes-only core cannot enforce the lone-surrogate case: `TextEncoder` substitutes U+FFFD rather than failing, U+FFFD is assigned, so the core receives well-formed UTF-8 and two distinct lone surrogates reach the same index value. The note then places the obligation on the caller — "a core that accepts bytes only MUST expose the assigned-code-point check … and an adapter encoding on the core's behalf MUST apply it before encoding."

That obligation is unenforceable and, in the TypeScript core, actively countermanded. **The two cores do not agree on the type of the value being normalized:**

| | Signature | Lone surrogate `"a\uD800b"` |
|---|---|---|
| Python | `blind_index(value: str \| bytes, …)` (`core/python/src/fieldseal/api.py:235`) | `first_unassigned` returns `0xD800` → `INVALID_ARGUMENT`. The bytes route also fails loudly: `str.encode("utf-8")` raises `UnicodeEncodeError` at the caller. |
| TypeScript | `blindIndex(plaintext: Uint8Array, …)` (`core/typescript/src/api.ts:251`) | Unreachable. The core throws on a string with *"strings are never accepted; encoding is the adapter's job"* — pointing the caller at `TextEncoder`, which substitutes. |

Measured 2026-08-25, Node 24: `new TextEncoder().encode("a\uD800b")` and `…("a\uDC00b")` both produce `61 ef bf bd 62`. Two distinct inputs, one index value. Python's `first_unassigned` distinguishes them (`0xD800` vs `0xDC00`) and refuses both.

So option A of the write-up — "the adapter's job" — is today's behavior, and today's behavior is a documented instruction to perform the lossy conversion. The false match that clause 5 refuses invalid UTF-8 to prevent is reintroduced one frame up the stack, where no core, vector or conformance report can see it. This is a **false-match primitive in the one feature built to prevent false matches**, and it is invisible to the whole verification apparatus.

Realistic cause, in order of likelihood: naive fixed-length truncation of a JavaScript string (the ordinary way to write it splits surrogate pairs, which is most emoji and every supplementary-plane script); data imported from a system with different text rules; some file and network parsing paths; crafted input. Exploiting it deliberately requires getting one's own damaged value into the same column as the target's and then searching — reachable in a multi-tenant or user-content system, not in most others. The everyday version is not an attack: it is a truncation bug quietly giving two customers one fingerprint.

### Decided direction (2026-08-25)

**Widen the TypeScript core's index boundary to accept text, keep the caller-side check as documented advice, and do not add a U+FFFD rule to the core.**

1. **`blindIndex` accepts `string | Uint8Array`.** A `string` reaches clause 1 directly, as Python's already does; a `Uint8Array` is decoded strict-UTF-8 as clause 5 requires. This is a widening, not a break: no existing call stops compiling, and no stored byte changes. `docs/09` §7.1's note is rewritten from "a bytes-only core MUST expose the check" to "**an index API MUST accept text**", with the bytes-only fallback and its exported check kept for languages that have no other option.
2. **The asymmetry with `encrypt` is deliberate and is stated.** `encrypt(plaintext: bytes)` stays bytes-only; `blind_index` takes text. Python has shipped exactly this asymmetry since the core existed and it is principled — normalization is a text operation and encryption is not. `docs/11` records it rather than treating it as an inconsistency to be tidied away later.
3. **Option A survives as advice, not as the mechanism.** `docs/12` and `docs/13` keep the instruction to validate at whatever boundary first holds the text, because an adapter can give a better error message than the core can. It is no longer the only thing standing between a truncation bug and a shared fingerprint.
4. **No core-level U+FFFD rejection.** Available as an opt-in per-column validator, off by default; see the alternative below for why it is not the mechanism.

### Alternatives recorded

- **Reject any indexed value containing U+FFFD** (the write-up's recommendation). Rejected as the primary mechanism, kept as an opt-in validator. Three reasons. It does not close the class: the same naive truncation can cut between a base character and its combining marks, or mid-grapheme in a legitimately composed name, producing *valid* text that is silently wrong, and this catches none of it — it catches one visible symptom of one cause. It fixes a false match by manufacturing a missed match, since a legitimate U+FFFD then makes the row unindexable, which is Part B's failure mode arriving through a different door. And it cannot distinguish "was always U+FFFD" from "was broken on the way in", so its error message can never be accurate. Its one real advantage over option A — needing no cooperation from integrators — is an advantage over option A, not over this part's item 1, which removes the trap rather than adding a backstop behind it.
- **Leave it to integrations unchanged.** This is the status quo and it is what the TypeScript core's error message currently pushes people away from doing correctly. Recorded as the do-nothing baseline.

---

## Part B — docs/09 §7, §7.6, §10.2: a value that encrypts but cannot be indexed

### Gap

Encryption and index derivation are separate operations and only one of them normalizes. `encrypt` consults no Unicode table; `nfc-casefold-v1` refuses any code point unassigned in the pinned version (§7.1 clause 1). So a value containing a post-pin character **encrypts perfectly well and cannot be fingerprinted**, and the adapter is left with a choice no document makes:

1. refuse the write — the user cannot enter their own data; or
2. store the row with no index — the write succeeds and the row is invisible to every indexed lookup, silently.

`docs/09` §7.1 says this is "a product decision this document does not make" and that it "is recorded in §12 of `docs/12` and `docs/13` as an adapter obligation to state explicitly." **It is not.** `docs/12` ends at §9 and `docs/13` at §8; neither mentions unassigned code points anywhere. The forward pointer that was supposed to carry the decision into adapter design is dangling, so the decision is flagged in exactly one place and lands nowhere.

Option 2 is also the pattern spec §10.2 forbids by name — "where a path … would silently return wrong results, the adapter **MUST throw**, not degrade silently." Choosing it would be a conscious exception to a normative rule, which is a thing to record deliberately, not to arrive at by default.

### Decided direction (2026-08-25)

**A per-column setting defaulting to refuse, whose relaxed value is a re-verified fallback rather than a silent miss.**

1. **`IndexDeclaration` (docs/09 §7) gains `on_unindexable`**, with two values:
   - `refuse` (**default**) — index derivation raises `INVALID_ARGUMENT`; the adapter fails the write.
   - `bucket` — the row is stored, and its index value is a **reserved marker** rather than absent. ~~Every indexed lookup on that column also matches the reserved value~~ — **superseded 2026-08-25 during implementation:** no additional probe is needed. The marker is derived from the value's *normalization*, which does not depend on the direction of travel, so a query for an unindexable value derives the marker unaided and matches the bucketed rows; a query for an indexable value never touches the bucket. The candidates are then decrypted and compared like any others under spec §7.5, which the specification already mandates as unconditional. The lookup returns the right answer instead of silently returning fewer rows, and the query path needs no special case. The version above would have doubled every query's candidate set and widened the leak below for nothing. `docs/09` §7.2 carries the corrected form.
2. **`bucket` requires the same ceremony as a §7.6 override**: an explicit, logged, reviewed declaration carrying `{ reason, approved_by, date }`. The precedent is exact — §7.6 already gates a per-column relaxation of a default-deny rule on precisely that shape — and it keeps relaxation a visible, recorded act rather than a config default someone copies between columns.
3. **`bucket`'s cost is stated in §7 and repeated in the adapter docs, not buried.** The reserved value is a visible attribute set: an observer of the index column learns which rows contain a post-pin character. That is a real correlation the threat model must accept, and it is a set an adversary who can write to the column can grow. The mitigation is that the set is expected to be tiny and that §7.5 re-verification bounds the cost of scanning it, not that the leak is absent. A column where that leak is unacceptable keeps `refuse`.
4. **Neither value is the §10.2 forbidden pattern**, which is the point of choosing `bucket` over "save with no index and log a warning". A log line is not seen by the person running the query; a re-verified fallback returns the correct rows. The specification does not need an exception written into it.
5. **`docs/12` §10 and `docs/13` §9 gain the obligation** `docs/09` §7.1 already claims they carry: state the column's `on_unindexable`, state what the user sees under `refuse`, and state the leak under `bucket`.

### The user-facing message under `refuse` (docs/12, docs/13)

A refusal is only humane if support can still store the real value, so `refuse` is specified together with `bucket` as its escape hatch — a per-column relaxation an operator can apply, not a dead end. The message is normative in shape, not in wording:

> **We can't save this name yet.** Our systems don't recognise the character 𠮷 (3rd character). This is a gap on our side, not a problem with your name — it's a recently added character we haven't added support for yet.
> [Save with a different spelling] [Contact support — we can enter it manually]

Three rules the adapter docs state, because "unsupported character" fails all three: **name the specific character and its position**; **attribute the fault to the system, not to the user**; **offer a path that ends with the real value stored**.

### Alternatives recorded

- **Per-column, relaxed value = save with no index, logged and counted** (the write-up's option B). This is the §10.2 forbidden pattern and needs a written exception to a normative rule. Rejected because `bucket` reaches the same availability outcome without one.
- **One global rule, always refuse.** Smallest surface and no new field. Rejected because it deletes the escape hatch the message above depends on, leaving support with no way to store a value the system refuses.
- **One global rule, always save unindexed.** Rejected on §10.2 alone.

---

## Part C — docs/09 §7.1, tools/ucd-gen: the pin has no currency policy, and the bump is booby-trapped

### Gap

Two distinct problems, one deadline.

**C-1. Nothing says when the pin moves.** §7.1 pins Unicode 17.0.0 and says a later `nfc-casefold-v2` re-pins, because the identifier is the definition and stored values change. It does not say what triggers that, so the default is drift: 18.0 is targeted for September 2026, 19.0 a year later, and the project ships pinned one version behind on its own launch day with no recorded reason.

The window is narrower than "before there is production data." Because the identifier *is* the definition, moving the pin after freeze means minting `nfc-casefold-v2` and leaving a dead `v1` in a deliberately closed set forever. Before freeze it is a redefinition in place. **Nothing is frozen** — Gate 0b is open, the registry holds provisional suites only, the vector suite is `0.2.0-provisional` — so the real deadline is **Gate 0b or format freeze, whichever comes first**, and Gate 0b outreach is live.

**C-2. Bumping `VERSION` today silently pins the draft.** Measured 2026-08-25:

```
https://www.unicode.org/Public/17.0.0/ucd/UnicodeData.txt   200
https://www.unicode.org/Public/18.0.0/ucd/UnicodeData.txt   302 → http://www.unicode.org/Public/draft/ucd/UnicodeData.txt
```

All three files this project consumes redirect; 18.0.0 is not yet a frozen release and the version-numbered path is an alias for a moving target. `tools/ucd-gen/generate.py` uses `urllib.request.urlopen`, which follows redirects by default, and then prints the **requested** URL (`generate.py:280`) rather than the served one. Setting `VERSION = "18.0.0"` today therefore produces tables built from the draft, labelled `18.0.0`, with a build log asserting it fetched 18.0.0. Re-run after the next draft revision and the bytes differ — CI's `--check` fails with no indication why. The redirect also **downgrades to plaintext `http://`**, so the tables deciding every blind index value would be fetched unauthenticated.

### Decided direction (2026-08-25)

1. **State the policy in §7.1.** *Until format freeze, `nfc-casefold-v1` tracks the most recent released Unicode version, and the pin is moved by redefining `v1` in place — permitted precisely because nothing is frozen and no deployment exists. After freeze, a bump is a new normalizer identifier and a planned re-index, never an in-place change.* This turns a recurring judgment call into a rule and makes the freeze the visible boundary between the two regimes.
2. **Move the pin to 18.0.0 when 18.0.0 stops redirecting**, then regenerate and re-run both cores' vector suites. If freeze arrives first, ship on 17.0.0 and take the `v2` cost knowingly.
3. **Guard the generator now, independently of the bump.** `download()` must assert that the served URL equals the requested one, refuse any redirect, and refuse any non-HTTPS hop. This is worth having permanently: it is the same class of silent drift the pin exists to prevent, one layer down in the build, and it is the reason a bump can be a one-line change safely rather than only apparently.

### Measurement: who the pin actually excludes — the write-up's table is wrong

`internal/product-decision-indexing-edge-cases.md` reports 11,329 of the 13,007 additions as "CJK extensions (Chinese, Japanese, Korean)" and concludes the realistic case is a CJK-market customer whose **legal name** contains a rare character. Recomputed 2026-08-25 from `UnicodeData.txt` (17.0.0 release vs. the draft the 18.0.0 URL serves), expanding `First>`/`Last>` range pairs:

| Category | Added | Share |
|---|---|---|
| **Seal Script**, U+3D000–U+3FC3F — historic Chinese seal/calligraphic script | **11,328** | 87.1% |
| **Jurchen**, U+18E00–U+19191 — extinct script (12th–17th c.) | 914 | 7.0% |
| Other supplementary — historic scripts, notation, musical | 706 | 5.4% |
| BMP additions to living scripts — Armenian, Hebrew, Oriya, combining marks, and 3 currency signs (Rufiyaa, **UAE Dirham**, Omani Rial) | 29 | 0.2% |
| Emoji and pictographs | 27 | 0.2% |
| Tangut Supplement — extinct script | 2 | 0.02% |
| **CJK Unified Ideographs** | **1** | 0.01% |
| Total added | **13,007** | |

Unicode names these blocks itself: the 11,328-point block is `<Seal Character, First>`, distinct from the `<CJK Ideograph Extension …>` naming the same file uses — and CJK Unified Ideographs gained exactly **one** code point (U+2B81E, Extension D). Seal script is encoded for scholarly and typographic use; it is not the repertoire modern CJK names are written in. **The rare-personal-name scenario is not what this release does**, and the argument built on it does not hold for 18.0.

What is left is a different and smaller exposure, and the frequency ordering inverts the severity ordering: **emoji** are the most likely to appear (keyboards ship them within months, and display-name and free-text fields collect them), and are the easiest case to refuse; the **UAE Dirham sign** is a real, actively promoted modern symbol that will reach address and free-text fields; the **29 BMP additions** — Hebrew points, Oriya signs, Armenian modifier letters — are the genuine living-script, real-names category, and there are 29 of them, not 11,329.

This does not reverse Part B. A per-column setting is still right, because the answer for a login email and the answer for a display name are still different. It replaces the reason: not "do not refuse a customer's legal name in a CJK market", but "an emoji in a display name and a vowel point in a legal name should not be governed by one rule."

Two further results, both bearing on Part D:

- **0** of the 13,007 additions carry a canonical decomposition, and **34** have a non-zero combining class. **No** code point assigned in 17.0.0 changed its combining class or decomposition in the draft. So the concrete normalization-drift exposure of accepting a post-pin code point is confined to those 34 marks appearing adjacent to another combining mark. This is the same shape G15 measured across 16.0 → 17.0.
- Every number above is measured against **the draft**, which is the moving target C-2 is about. They are provisional in exactly the way the pin would be, and must be recomputed against the release.

---

## Part D — decided: none of this goes to the Gate 0b reviewers

**Decided 2026-08-25: all three parts are product concerns and sit outside a cryptographic review.** Nothing here is added to the Gate 0b packet.

The question was worth asking because Part A *sounds* cryptographic — it is a false-match property of an index construction, and false matches are what §7 exists to prevent. It isn't. What Part A found is a lossy type conversion in a caller, and what Part A decides is the type of a function parameter. No construction changes, no key derivation changes, no stored byte changes. A reviewer asked to look at it would be reading a signature, which is not what the Gate 0b brief (`docs/16`) recruits for and not a use of two credentialed reviewers this project can afford to spend.

The same holds for the refusal rule's *breadth*, which was the one item recorded here as a candidate. §7.1 clause 1 refuses every unassigned code point, and the measurement in Part C bounds the actual drift exposure at 34 combining marks. Whether a narrower rule is safe turns on **whether Unicode's block-allocation practice is a guarantee or a pattern** — a question about the UCD's stability policies, not about cryptography. A cryptographer is the wrong expert for it. It stays a product decision, informed by a Unicode-facts input this project can gather itself or take to the UTC, and it is **not** a Gate 0b question.

Consequence for this issue's scheduling: with Part D closed, **G16 carries no reviewer dependency and is not blocked by, and does not block, Gate 0b outreach.** It is an ordinary engineering-judgment issue of the kind that closed G3, G6 and G8–G13.

## Justification

- **A.** `docs/09` §7.1 clause 5 and its own note; the two cores' signatures (`api.py:235`, `api.ts:251`); the `TextEncoder` collision and the Python refusal, both measured 2026-08-25 and reproducible in three lines each. WHATWG Encoding requires `TextEncoder` to substitute U+FFFD for unpaired surrogates rather than fail, so this is a platform property, not a library defect.
- **B.** Spec §10.2 (throw, never degrade), §7.5 (re-verification is unconditional, which is what makes `bucket` correct rather than merely available), §7.6 (the logged-reviewed-override precedent this reuses verbatim). The dangling pointer is checkable: `docs/12` has no §12, `docs/13` has no §12, and neither file contains the word "unassigned".
- **C.** `docs/09` §7.1 clause 1 on the identifier being the definition; PRD §8 on the split gate, which is what makes an in-place redefinition legitimate today and illegitimate later; the redirect and protocol downgrade measured 2026-08-25 against unicode.org; `generate.py:266`–`282`; the recomputed diff above.

## What it breaks

Nothing stored, under any part — there are no deployments, and no part changes the bytes `nfc-casefold-v1` produces for any input either core accepts today.

**A** widens one signature in one core and rewrites one paragraph of `docs/09` §7.1; existing calls are unaffected. **B** adds a field to `IndexDeclaration` whose default is the current behavior, adds one reserved index value per declaration that opts in, and adds a section to each of `docs/12` and `docs/13`. **C** changes no output until 18.0.0 is released; the generator guard changes only failure behavior. When the pin does move, **every stored `nfc-casefold-v1` value changes** — which is why it happens before freeze and why the policy in C-1 exists to say so out loud.

## Vector obligations

- ~~`blind-index/`, for **A**: a lone high surrogate and a lone low surrogate as text input, each asserting `INVALID_ARGUMENT` and — the point of the pair — asserting they are *distinguishable*.~~ **Not expressible; rerouted 2026-08-25.** `blind-index/` keys its input as hex bytes and an unpaired surrogate has no UTF-8 encoding, so the case cannot be written in the family's shape. Widening that field to text would not rescue it either: **Go string literals may not hold a surrogate value and Rust's `String` is UTF-8 by invariant**, so two of the five target languages cannot carry the operand at all. It is now the `out_of_band` entry `docs/09/7.1/lone-surrogate-refusal` in both cores' conformance reports (docs/14 §4, on the G10 precedent), asserting both the refusal and its distinguishability, and a core in a language that cannot represent the operand records `not-run` rather than `pass`. The remaining part of this obligation — a value containing a legitimate U+FFFD, asserting it indexes normally and is not refused — *is* expressible and lands with **B**'s vectors in one suite bump.
- `blind-index/`, for **B**: a value containing a code point unassigned in the pin under `on_unindexable = refuse`, asserting `INVALID_ARGUMENT`; the same value under `bucket`, asserting the reserved index constant. The reserved constant must be pinned by a vector, since two cores disagreeing on it is a silent cross-implementation miss of exactly the kind the suite exists to catch.
- **C** has no new vector; the whole `blind-index/` family regenerates when the pin moves, which is the cost the policy makes explicit. The generator guard is covered by a unit test in `tools/ucd-gen`, not by a vector.
- `docs/14` §4: until A and B close, each core's report declares `pinned_decisions.index-input-type` and `.on-unindexable`; both keys retire on closure.

## Review flag

**No cryptographic review required, for any part** — all of them are closable by engineering judgment under the rule that closed G3, G6 and G8–G13, and Part D decides that none of it belongs in the Gate 0b packet either. This issue therefore has no reviewer dependency in either direction: it does not wait on Gate 0b, and Gate 0b does not wait on it.

That makes G16 the first issue since G13 that is entirely the project's own to close. Worth stating explicitly, because Part A's subject matter — a false match in a blind index — reads like a reviewer question and is not one.
