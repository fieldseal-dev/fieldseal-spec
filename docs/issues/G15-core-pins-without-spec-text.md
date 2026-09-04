# G15 — §9/§3.4, §11.1/§10.3, §4.8, docs/09 §7: four behaviors both cores had to pin without spec text

**Labels:** §9 · §3.4 · §10.3 · §11.1 · §4.8 · docs/09 §7 · spec-gap
**Blocks:** the `fmt_ver` and `rotate` cases of `errors/`; the `nfc-casefold-v1` vectors that would make the normalizer portable; one operator-facing name.
**Found:** 2026-08-22 in the M2 report (`docs/18-m2-report.md` §3: D-03, D-10, D-13, D-14) and confirmed 2026-08-23 when the Python core was brought to the same pins (PR [#47](https://github.com/fieldseal-dev/fieldseal-spec/pull/47)): two cores now agree on every one of these, and nothing in the specification or the vectors says they have to.

**Status:** OPEN — tracker [#48](https://github.com/fieldseal-dev/fieldseal-spec/issues/48), posted 2026-08-23. Not provisionally adopted; no spec text carries a marker for any part of it.

## Why one issue

`docs/18` §3 lists twenty places where the TypeScript core had to decide something the documents leave open. Most already belong to an open gap (D-01 → G1, D-02 → G5, D-12 → G7) or to the generator (D-05 to D-08, D-15). Four belong to nobody: each is observable from outside, each can split two cores on real data with no vector noticing, and each is a one-paragraph normative change that needs no cryptographic review. They are bundled because they share one closure shape — write the pin into the text, add the vector, retire the corresponding `pinned_decisions` key from `docs/14` §4 — and one closure sweep is cheaper than four. The tracker may split them; the parts are labeled separately below.

Each part states what both cores currently do. That agreement is **not evidence for the pin**: the Python core was aligned to `docs/09`'s proposals and the TypeScript core's declared pins on purpose, so that `errors/` vectors could be authored against one order. Where this issue proposes something other than what the cores do, it says so, and the cost of changing them is stated.

## Part A — §9, §3.4, §10.3: the `UNKNOWN_FORMAT_VERSION` set (D-03)

### Gap

§9 defines `UNKNOWN_FORMAT_VERSION` as "`fmt_ver` unrecognized — data written by a newer implementation". §3.4 requires `is_ciphertext` to be false unless `fmt_ver` is "a recognized version". §10.3 passes non-envelope input through in `permissive` and `readonly`. Read together: an envelope from a newer implementation is not ciphertext, is therefore non-envelope input, and is therefore *returned to the application as plaintext* in the two modes that exist for migration — which is the exact failure §3.4's justification describes for retired suites ("returning ciphertext bytes as application data and, worse, re-encrypting them on the next write"). The code in §9 cannot be raised under §3.4's definition, and no document says which bytes are "a newer implementation" rather than "not an envelope". `docs/09` §3.2's footnote proposes raising only for a *reserved-known-future* version byte at a *plausible* length; `docs/08` §4.6 gives `0x02` as an example. Neither defines the set.

### What both cores do

Reserved set `{0x02}`. Plausible length = 111 bytes, the smallest fixed overhead over the registry (suite `0xFF01`: 1 + 2 + 16 + 32 + 12 + 32 + 16). `decrypt` of a `0x02`-prefixed input of ≥ 111 bytes raises `UNKNOWN_FORMAT_VERSION` in **every** mode, `permissive` and `readonly` included. `is_ciphertext` of the same input is **false** (both cores, checked 2026-08-23). Every other non-`0x01` first byte, and `0x02` under 111 bytes, is `NOT_CIPHERTEXT` in `strict` and pass-through otherwise. Declared in `pinned_decisions.unknown-format-version-set` and `.decrypt-order`.

### Proposed direction (starting point, not a decision)

1. **§3.1 assigns the version byte.** `0x01` is this format. `0x02` is *reserved for the next format version* and MUST NOT be written by any implementation of this specification. `0x00` and `0x03`–`0xFF` are unassigned and MUST be treated as non-envelope input. (Reserving one value, not a range, keeps the false-positive surface below at one byte value in 256.)
2. **§3.4 gains a second outcome.** Recognition has three results, not two: *envelope* (`0x01`, registered suite, suite minimum length met), *reserved-version input* (`0x02`, length ≥ the smallest registered fixed overhead), and *non-envelope*. `is_ciphertext` returns true only for the first — unchanged — and the text says why the second is not true: a future version need not keep `suite_id` at bytes 1–2, so the suite check that makes recognition trustworthy cannot be performed, and an adapter that used a true answer on its write path ("already encrypted, do not encrypt") would leave a `0x02`-prefixed plaintext stored in the clear. Silent plaintext at rest is the outcome this specification ranks below every other.
3. **§9 and §10.3 pin the decrypt side.** `decrypt` of reserved-version input raises `UNKNOWN_FORMAT_VERSION` in every mode; the §10.3 pass-through applies to non-envelope input only, and §10.3's table says so in a footnote. The asymmetry — an input that is "not ciphertext" to `is_ciphertext` and "ciphertext from a newer implementation" to `decrypt` — is deliberate and is stated rather than smoothed: the two predicates protect different paths (the write path must not skip encryption on a guess; the read path must not hand a future envelope to the application), and the safe answer differs.
4. **§10.3 states the cost.** In `permissive` and `readonly`, a genuine plaintext of ≥ 111 bytes whose first byte is `0x02` raises instead of passing through. For the text-like values field-level encryption is for, a leading U+0002 (STX) does not occur; for arbitrary binary values the rate is 1/256 of values long enough, and a column like that should be migrated in `strict` mode after an explicit backfill rather than read through `permissive`. The same false-positive class already exists for `0x01` at a rate of 1/256 × (registered suites)/65 536 and is accepted silently; this makes the larger one visible.

Where the code sits in the decrypt order is G5's; this part fixes only *which bytes* reach it. It should close in coordination with G5's eventual order but does not wait on it, since recognition precedes everything G5 adjudicates.

### Alternatives recorded

- **Drop the code.** Every non-`0x01` first byte is non-envelope input; §9 loses a row; the future-version case is handled by whichever spec version defines `0x02`, which can choose a magic that no v1 implementation passes through. Simplest, and it removes the false positive entirely — but it gives up the one protection that matters during a version-overlap deployment (two cores on two spec versions sharing a database), which is the scenario `permissive` exists for. Recorded as the fallback if the review finds the asymmetry in item 3 unacceptable.
- **Make `is_ciphertext` true for reserved-version input**, so one predicate drives both paths. Rejected for the reason in item 2: it turns a one-byte coincidence into un-encrypted storage on the write path. It becomes defensible only with a format-evolution rule that every future `fmt_ver` keeps bytes 1–2 as a registry `suite_id`, which would let recognition check three bytes at the same false-positive rate `0x01` already has. That rule constrains a format that does not exist yet and is recorded for the reviewers rather than proposed.

## Part B — §11.1, §10.3: `rotate()` on non-envelope input (D-13)

### Gap

§11.1 and `docs/09` §3.5 define `rotate` as a decrypt followed by an encrypt. In `permissive` mode `decrypt` of non-envelope input returns it unchanged (§10.3), so a literal composition *encrypts unmigrated plaintext* and returns an envelope. In `strict` mode the same call raises `NOT_CIPHERTEXT`; in `readonly` it raises `MODE_VIOLATION` before anything runs. The specification does not say whether the `permissive` behavior is the intended one or an artifact of the definition, and the two readings are observably different on a value that every migration window contains.

### What both cores do

Literal composition: it encrypts. Declared in `pinned_decisions.rotate-in-permissive`.

### Proposed direction (starting point, not a decision)

**`rotate` raises `NOT_CIPHERTEXT` on non-envelope input in every mode**, and §11.1 says so in one sentence: `rotate` is a ciphertext-to-ciphertext operation; the §10.3 pass-through is a *read* behavior (the table's column is "non-envelope input on read"), and the decrypt inside `rotate` is not a read whose result reaches the application. Three reasons, in order of weight:

- **No tooling wants the composition.** `docs/15` already separates the two jobs the literal reading would merge: the initial backfill checks `is_ciphertext` and calls `encrypt`; the re-encryption sweep parses the header and calls `rotate` only on envelopes whose `key_id`/`suite_id` are stale (its idempotency row). A `rotate` that silently encrypts would never be reached by the shipped tool's sweep and would only ever fire from a caller that skipped the check.
- **It hides the number the cutover gate needs.** `docs/15` requires `permissive` plaintext-read metrics to be countable per table for the cutover decision. A sweep whose `rotate` converts unmigrated rows reports them as *rotated*, not as *unmigrated-then-encrypted*; the count the gate is waiting on goes down without anyone having run the backfill, and the backfill's own idempotency check (`is_ciphertext` true → skip) then confirms a migration that did not happen on the terms the operator planned.
- **It is the project's stated reflex.** "Adapters throw rather than degrade" (`AGENTS.md`; spec §10.2) is about not mis-serving a request silently. A `rotate` that encrypts is a correct envelope produced by the wrong operation for a reason the caller did not intend, which is the degrade, not the throw.

This **reverses both cores' current pin.** The cost is a mode check of a few lines in each, plus one `errors/` vector; no stored byte changes, because a plaintext that was never rotated is a plaintext either way.

### Alternative recorded

**Keep the literal composition and make it visible**: `rotate` on non-envelope input in `permissive` encrypts, MUST count toward the §10.3 plaintext-read metric, and SHOULD warn. This is what both cores do today and it is exactly what a caller who *meant* "migrate whatever this is" wants. It is recorded as the fallback if the reviewers prefer a larger `rotate` contract to a stricter one; it should not be chosen on the ground that the cores already do it.

## Part C — §4.8: name the arming mechanism (D-14)

### Gap

§4.8 constrains the mechanism that arms provisional suites — affirmative, out of band, an environment variable or an explicit constructor argument, not satisfiable from the ordinary configuration — and then does not name it, while stating that it "deliberately mirrors the `FIELDSEAL_TEST_MODE` gate" that `docs/08` §6 *does* name. §9 requires the `SUITE_PROVISIONAL` message to name "the arming mechanism the deployment failed to set". An operator running two cores will meet whatever two names two implementers chose.

### What both cores do

Environment variable **`FIELDSEAL_ARM_PROVISIONAL_SUITES`**, armed by the exact value `1` and by no other value (`true`, `yes`, and the empty string do not arm — both cores compare for string equality with `"1"`, checked 2026-08-23), read when the client is constructed. The constructor form differs by language, as §4.8 intends: the Python core takes a keyword `arm_provisional_suites=True` on the constructor (it has no separate configuration object); the TypeScript core takes `{ armProvisionalSuites: true }` as a *second* argument, distinct from the configuration object, and ignores the same property placed inside it. `docs/14` §4 has carried the variable's name since 2026-08-23 with the note that it belongs in §4.8. Declared in `pinned_decisions.provisional-arming`.

### Proposed direction (starting point, not a decision)

§4.8 names the variable normatively: **`FIELDSEAL_ARM_PROVISIONAL_SUITES`**, arming iff its value is exactly `1`; read at client construction, so that a process cannot be armed after the fact by an environment change and a client's arming state is a fact about the object. For the in-code form, §4.8 states the *property* — it MUST be a distinct argument or call from the one that carries `allowed_suites` and `write_suite`, and MUST NOT be a field of that configuration — and leaves the name to each language binding, which `docs/10` and `docs/11` record, on the same reasoning §11.1 uses for async companions: no cross-implementation test can observe a constructor's shape, and the operator-facing surface that *must* agree is the environment. `docs/08` §6 is cross-referenced so the two gates read as one convention. The `SUITE_PROVISIONAL` message requirement in §9 then has a name to meet.

No alternative is recorded. The only question is whether the exact-`1` rule is too strict; it is proposed because `FIELDSEAL_TEST_MODE` already works that way, and a gate that also accepted `true` would be the first place the two diverged.

## Part D — docs/09 §7: `nfc-casefold-v1` is four decisions short of portable (D-10)

### Gap

`docs/09` §7 defines `nfc-casefold-v1` as "Unicode NFC, then full case folding, then UTF-8 encode" and flags, in its own bracketed note, that the folding variant and the Unicode version must be pinned before vectors freeze. The M2 report found four underspecified points: (a) the folding variant; (b) the Unicode version of both the normalization and the folding tables; (c) whether a second normalization follows the fold — Unicode §3.13 notes `toCasefold(X)` need not be normalized and defines canonical caseless matching as `NFD(toCasefold(NFD(X)))`, which is a different function; (d) what the bytes-accepting API does with input that is not valid UTF-8. The shipped `blind-index/hmac-sha512.json` vectors pin only that the folding is *full* (`grüße → grüsse`).

Two facts established for this issue, 2026-08-23:

- **(c) is not hypothetical.** Against the Unicode 16.0 tables, 33 assigned code points have a full case folding whose result is not NFC-normalized — U+01F0 (ǰ) folds to U+006A U+030C, which NFC recomposes to U+01F0; likewise U+0390, U+03B0, U+1E96–U+1E99, and 26 in the Greek Extended block (U+1F50–U+1F56 even, U+1FB6, U+1FC6, U+1FD2, U+1FE2 and their neighbours). For each of them, "NFC then fold" and "NFC then fold then NFC" produce different bytes and therefore different blind indexes.
- **(b) is the one the cores already disagree on, and the disagreement is bounded.** The TypeScript core folds with a vendored `CaseFolding-17.0.0.txt`; the Python core folds with the interpreter's table — Unicode 16.0 on CPython 3.14, 15.1 on 3.13, 15.0 on the 3.12 that CI runs. Diffing the official `CaseFolding.txt` for 16.0.0 and 17.0.0 (statuses C and F): **28 mappings added, 0 changed, 0 removed** — the 25 Beria Erfe capitals U+16EA0–U+16EB8 and three Latin Extended-D letters (U+A7CE, U+A7D2 LATIN CAPITAL LETTER DOUBLE THORN, U+A7D4). Diffing `UnicodeData.txt`: 457 code points assigned, of which **34 are combining marks** with non-zero canonical combining class (U+1ACF–U+1ADA and others) and **0 carry a canonical decomposition**; no existing character changed class or decomposition. So a 16.0 core and a 17.0 core produce different `nfc-casefold-v1` output exactly when the input contains one of those 28 letters (folding) or one of those 34 marks next to another combining mark (NFC reordering), and on no other input. That is what the Unicode stability policies predict — Strong Normalization Stability (4.1+) guarantees identical NFC across versions for strings of characters assigned in both; Case Folding Stability (5.2+) guarantees the same for `toCasefold(toNFKC(S))`, which is formally a different composition than this normalizer's, so for folding the guarantee here is the empirical diff rather than the policy. The residual is small and it is real: U+A7D2 in an indexed column today gets one index value from the TypeScript core and another from the Python core, and a lookup across them silently misses.

(a) and (d) the cores agree on without text: statuses C + F, no Turkic `T` mapping; invalid UTF-8 is refused with `INVALID_ARGUMENT` rather than folded through U+FFFD, which would make distinct invalid inputs collide. Both are declared in the Python report's `pinned_decisions.normalizer-text-over-bytes` and in `docs/18` §3 for the TypeScript core.

### Proposed direction (starting point, not a decision)

`docs/09` §7 defines `nfc-casefold-v1` completely, as a versioned function, and the definition is what the normalizer id *means*:

1. **Unicode version: 17.0.0**, for both steps. Input containing any code point unassigned in Unicode 17.0.0 is refused with `INVALID_ARGUMENT` (construction-time or argument error, not a §9 code — `docs/09` §9). Refusing is what makes the pin exact: with input restricted to 17.0.0-assigned characters, Strong Normalization Stability makes every conforming NFC implementation at version ≥ 17.0.0 produce identical output, and a vendored 17.0.0 folding table is exact by construction. A character newer than the pin is precisely the input on which two cores would otherwise disagree, and a visible refusal is preferred to a silent split. A later `nfc-casefold-v2` re-pins; the id changes because the stored values change.
2. **Folding: `CaseFolding-17.0.0.txt`, statuses C and F only**, applied code point by code point to the NFC output; no `T` mappings; no `S`. Every core vendors the table (≈1 600 entries) rather than calling the platform's `casefold`, as the TypeScript core already does; a platform call is permitted only if the core proves, in its own tests, that it agrees with the vendored table on every assigned code point.
3. **NFC: the 17.0.0 result**, from the platform's normalizer when the platform's Unicode version is ≥ 17.0.0, or from vendored normalization data otherwise. The Python core on CPython ≤ 3.14 does not qualify by the first route; CPython 3.15 is expected to ship Unicode 17.0 **[VERIFY before closing]**, and until then that core vendors the normalization data or refuses, on top of item 1, any code point assigned after its platform's version — a narrower refusal that is exact for the same stability reason.
4. **No second normalization after folding.** The output of item 2 is UTF-8 encoded as is. This follows `docs/09`'s literal text and both cores; it is chosen over Unicode's canonical caseless match (`NFD(toCasefold(NFD(X)))`) because that function's output is NFD, which is longer and surprising as a stored value, and because the spec's requirement is *determinism across cores*, not Unicode-conformant caseless matching — any fixed function satisfies the first. The 33 code points above are the test for it.
5. **Bytes input is decoded as strict UTF-8** before item 1; a decoding failure is `INVALID_ARGUMENT`. A text-typed API (Python `str`, JavaScript `string`) reaches item 1 directly; a lone surrogate in a JavaScript string is refused on the same terms since it has no UTF-8 encoding.

`digits-only-v1` and `identity` need no pin; they do not consult Unicode tables.

### Alternative recorded

**Vendor the folding table only, take NFC from whatever the platform has, and document the residual** — the 34-mark reordering case — as a known, bounded divergence in `docs/09` and the conformance report's `environment.unicode_platform`. Cheaper for the Python core, and the residual is confined to combining-mark sequences of a newly encoded script, which no field-level-encrypted column is expected to hold. Recorded because it is a defensible engineering trade; not proposed because a normalizer with a known split is a claim the project would have to caveat every time it is stated, and "a single unsupported claim costs more than ten supported ones earn" is the rule this repository is written under.

## Justification

- **A.** §3.4's own justification (misclassifying ciphertext as plaintext → returned as application data → re-encrypted on the next write) applies to a future-version envelope with more force than to a retired suite, which at least is recognized. The code exists in §9; either its domain is defined or it is unreachable. The asymmetry between `is_ciphertext` and `decrypt` is the conservative choice on each path taken separately, and that is the only argument made for it.
- **B.** The read-mode table in §10.3 is explicitly about reads; `docs/15` already separates backfill from rotation and already requires the plaintext count that literal composition would corrupt. Throwing where two readings of a definition diverge is the §10.2 principle applied to the core's own API.
- **C.** §4.8 says the two gates should share one shape and §9 requires the error to name the mechanism; a name is the missing piece, and the two shipped cores have already converged on one.
- **D.** `docs/09` §7's own flag; Unicode Stability Policies (Strong Normalization Stability, Unicode 4.1+; Case Folding Stability, Unicode 5.2+), read 2026-08-23 at `unicode.org/policies/stability_policy.html`; the 16.0.0 → 17.0.0 diffs above, computed from the published UCD files the same day; the 33 non-NFC-stable foldings, computed with CPython 3.14's `unicodedata` (16.0.0).

## What it breaks

Nothing stored under any part. **A** changes prose in §3.1, §3.4, §9 and §10.3 and matches both cores' behavior exactly. **B**, as proposed, changes both cores' `rotate` by a mode check; as the alternative, changes nothing. **C** changes §4.8 prose and matches both cores. **D** changes `docs/09` §7 and requires the Python core to vendor a folding table and either vendor normalization data or add a narrower refusal; stored `nfc-casefold-v1` index values over characters assigned in Unicode ≤ 16.0 are unchanged under every option (no existing mapping changed between 16.0 and 17.0), so no deployment — there are none, pre-alpha — would need re-indexing. The `docs/14` §4 `pinned_decisions` keys `unknown-format-version-set`, `rotate-in-permissive`, `provisional-arming` and `normalizer-text-over-bytes` retire when their part closes.

## Vector obligations

- `errors/` (the family `docs/08` §4.6 defines and nothing yet emits), for **A**: first byte `0x00`, `0x02`, `0x03`, `0xFF` on an otherwise valid 111-byte `0xFF01` envelope, and `0x02` at 110 bytes, each asserting the code in `strict` and the outcome (pass-through or raise) in `permissive` and `readonly`; plus `is_ciphertext = false` for the `0x02` case.
- `errors/`, for **B**: `rotate` of a non-envelope value in each of the three modes, asserting `NOT_CIPHERTEXT` / `NOT_CIPHERTEXT` / `MODE_VIOLATION` (or, under the alternative, an envelope in `permissive`).
- `blind-index/hmac-sha512.json`, for **D**: U+01F0 and one Greek Extended character, pinning item 4; a value containing U+A7D2 and one containing a Beria Erfe capital, pinning item 1's version; a sequence of two combining marks one of which is U+1AD9, pinning NFC at 17.0.0; an invalid UTF-8 byte sequence and a lone surrogate, asserting `INVALID_ARGUMENT`; an input containing a code point unassigned in 17.0.0, asserting `INVALID_ARGUMENT`.
- **C** has no vector: arming is out of band by design. The conformance report's `pinned_decisions.provisional-arming` carries the name until §4.8 does, then the key retires.
- Harness contract (`docs/08` §5): until the parts close, the report's `pinned_decisions` names which reading of each the core is built against; `errors/` vectors authored before closure pin the cores' *current* readings and are regenerated if a part closes the other way.

## Review flag

**No cryptographic review required** for any part. All four are closable by engineering judgment under the rule that closed G3, G6 and G8–G13. **A** should close in step with G5's ordering but does not depend on its answer; **D** is the only part whose closure changes shipped core code in a way that needs a vector *before* the change (item 4's 33 code points), so that the vendored-table switch in the Python core is checked against the TypeScript core's output rather than against itself.
