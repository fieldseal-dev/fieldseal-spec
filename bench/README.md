# bench

Not yet implemented. See `docs/01-prd.md` for phasing — the benchmark
programme (PRD DO-4: latency, throughput and storage overhead measured per
operation, per ORM, per suite) is **Phase 2**, and `docs/07` §8 says so
explicitly.

One measurement exists ahead of that, deliberately outside this directory,
because it is decision evidence for a single open question rather than the
start of the programme:

- **The WS-C Argon2id event-loop benchmark** (`docs/07` §6), which decided
  whether the TypeScript core ships `blindIndexAsync`. Two legs —
  `core/typescript/tests/bench/argon2-eventloop.ts` (`npm run bench:argon2`)
  for the mechanism, and `adapters/prisma/tests/bench/argon2-request-path.ts`
  for the criterion `docs/11` §2 actually names, a real request path. Neither
  runs in CI: `docs/14` §7 keeps benchmarks off the gate because CI machines
  produce noise. The result of record is the `docs/07` §7 entry dated
  2026-08-31, not a committed artifact.
