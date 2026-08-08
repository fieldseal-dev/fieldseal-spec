# Architecture Decision Records

Decision records for choices that gate implementation. ADRs here do **not** replace the spec-change process (`CONTRIBUTING.md`: issue → citation → breakage statement → vectors); an ADR is where a decision's options, criteria, and evidence live while it is open, and the durable record of *why* after it closes. A closed ADR that changes the spec still goes through a spec issue and PR.

Numbering is chronological. Statuses: `OPEN` (blocking or pending), `ACCEPTED`, `SUPERSEDED (by NNNN)`, `REJECTED`.

| ADR | Title | Status | Blocks |
|---|---|---|---|
| [0001](0001-envelope-format-source.md) | Profile the AWS structured-encryption format, or define fresh | **OPEN — blocks all Phase 1 code** (spec §13.1) | envelope codec, vectors, everything downstream |
| [0002](0002-suite-0x0001-aead.md) | Which FIPS-approvable AEAD for suite 0x0001 | **OPEN — blocks vectors and suite freeze** (spec §13.2) | registry, envelope arithmetic, commitment design (G1 interacts) |

Supporting evidence lives beside the ADR it serves: [Appendix A to 0001](0001-appendix-a-expressibility-mapping.md) — the clause-level §3–§6 → AWS-format expressibility mapping (first pass, 2026-08-08).

Template: [0000-template.md](0000-template.md).
