# G9 — §11.1: Sync-only `blind_index` blocks async runtimes for 10–100 ms per Argon2id term

**Labels:** §11.1 · spec-gap
**Blocks:** nothing in the vector suite; L4 adapter ergonomics (Prisma) and Node service latency.

**Status:** RESOLVED in spec 2026-08-09, **adopted with a modification** — the permission and its constraints are now in docs/02 §11.1, but the API surface is not. The four proposed constraints are normative (sync mandatory and primary; byte-identical output and identical error codes; no sync-implemented-by-blocking-on-async; only L4 adapters may depend on a companion, and an adapter requiring one on a sync ORM is non-conformant), and §10 L4 now covers async index derivation alongside async key acquisition. What was *not* adopted is the proposal's naming (`blind_index_async`): the spec deliberately leaves names and signatures to the language bindings, because a companion is consumed only by an L4 adapter written against one core in one language, so no cross-implementation test can observe its shape and pinning it would constrain a surface before any implementation has shown what it should be. Marker sweep: docs/08 §5 item 10 (dual-path harness run; item 9 when this was written, renumbered by G16 part A), docs/14 §4 (`async_companions` flag, `#async` result ids), docs/09 §11, docs/10 §(scope), docs/11 §2/§6. **Shipped in TypeScript 2026-09-04** (`blindIndexAsync`, `unindexableMarkerAsync`; `docs/07` §7), which is what the deliberate non-naming above anticipated: the names are that binding's, the report carries the second pass, and nothing in the spec had to move. Python ships none, per docs/10. The docs/07 §6 escalation trigger survives in spec §11.1's closing justification and in docs/11 §2. Close tracker issue [#9](https://github.com/fieldseal-dev/fieldseal-spec/issues/9) when this lands.

## Gap

§11.1 makes the core API sync-only — a deliberate commitment, because most target ORMs cannot await in the value path. But `blind_index` over an Argon2id domain costs 10–100 ms per term (§7.3's own honest-cost statement), and in Node that is 10–100 ms of a **blocked event loop** per query term: every concurrent request on the process stalls. For sync frameworks this cost lands on one request (acceptable, documented); for an async-first adapter that *can* await (Prisma — conformance level L4), the spec currently forbids the API shape that would keep the process responsive.

`docs/11-core-typescript.md` §2 sizes this as the hardest constraint on the TypeScript core; `docs/07-implementation-plan.md` §6 tracks the risk that it is a product-killer for Prisma users.

## Proposed direction (starting point, not a decision)

Add optional **async companions** (`blind_index_async`, `warm`-style naming per §11) with these constraints:

- The sync API remains mandatory and primary; async variants are OPTIONAL and additive.
- Async variants MUST produce byte-identical results to their sync counterparts (same vectors apply — no separate vector family).
- Only adapters claiming L4 may rely on them; an adapter that requires the async variant on a sync ORM is non-conformant.
- Implementations MUST NOT implement the sync variant by internally blocking on the async one where that changes error or timing semantics.

Escalation trigger (per the docs/07 §6 risk register): if the WS-C week-one benchmark shows spec-minimum Argon2id parameters unacceptable in a real Prisma request path, this issue escalates from ergonomics to a Phase 1 spec change.

## Justification

§7.3 already declares the cost a product constraint; Node's single-threaded event loop turns a per-request cost into a per-process cost, which is a materially different failure mode (standard Node behavior; no citation dispute). The L4 level (§10) exists precisely because a minority of ORMs can await — this extends the same reasoning from key acquisition to index derivation.

## What it breaks

Nothing — additive API surface. Conformance-matrix touch: §10.1's L4 row gains a note that L4 includes async index derivation if this closes as proposed.

## Vector obligations

None new; the async variants are pinned by the existing `blind-index/` vectors (identical outputs). The harness contract (docs/08 §5) gains one line: implementations exposing async variants MUST run the vector suite through both paths.

## Review flag

None.
