# G10 — §3: No plaintext length bound is defined

**Labels:** §3 · spec-gap
**Blocks:** one boundary behavior (rejection consistency), no stored bytes.

## Gap

§3 places no upper bound on plaintext length. Without one, implementations inherit their platform's accidental limits (language array/buffer maxima, AEAD library caps) and diverge at the boundary: one implementation encrypts a value another refuses to decrypt-side-buffer, an interop failure the spec never sanctioned. AES-GCM's own plaintext ceiling (~2³⁹−256 bits ≈ 64 GiB, SP 800-38D §5.2.1.1) is far above anything a database cell should hold, so the practical bound should be an API decision, not a cipher property.

## Proposed direction (starting point, not a decision)

- `encrypt()` MUST reject plaintext longer than **2³¹−1 bytes** with the G6-proposed error class (or a dedicated `LENGTH_EXCEEDED`; the issue picks one).
- `decrypt()` MUST reject envelopes whose implied plaintext length exceeds the same bound *before* allocating.
- Documentation note: this is a field-level encryption spec for database cells; multi-gigabyte values indicate a design error upstream. The bound is deliberately generous (2 GiB) to avoid ever being the binding constraint in legitimate use, while staying below every mainstream language's signed-32-bit buffer cliff. [VERIFY at implementation time: exact buffer maxima for the Phase 1 languages — e.g., Node's `buffer.constants.MAX_LENGTH`, JVM array max — and confirm 2³¹−1 is below all of them.]

## Justification

Cross-implementation agreement on *rejection* is the same interoperability property as agreement on acceptance; a bound chosen by the spec is testable, a bound inherited from a runtime is not. The 2³¹−1 figure is the largest value representable in a signed 32-bit length, the lowest common denominator across the Phase 1/2 target languages (flagged [VERIFY] above rather than asserted per platform).

## What it breaks

Nothing stored. Behavior at a boundary no real deployment should reach.

## Vector obligations

A 2-GiB literal vector is impractical to ship. Obligation satisfied instead by:

- A harness-contract clause (docs/08 §5): the harness MUST verify the limit via a property test using the testing namespace's injection point with a synthetic length declaration, or by an implementation-level unit test asserting the exact bound — and the conformance report MUST state which.
- This deviation from vectors-for-every-normative-change is explicit and justified here, per `CONTRIBUTING.md` (the alternative — shipping a 2 GiB file in git — fails the repository, not the rule).

## Review flag

None.
