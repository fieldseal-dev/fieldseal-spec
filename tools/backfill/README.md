# backfill

Resumable, rate-limited, idempotent migration tooling: the initial encryption of a table that holds plaintext, and the re-encryption sweep that moves envelopes off an old key version or suite (spec §5.8, PRD AD-6).

| | |
|---|---|
| [`PROCEDURE.md`](PROCEDURE.md) | The one procedure every frontend implements, version 1: state tables, configuration hash, cursor and batch, the `encrypt` and `rotate` jobs, `verify`, required output, and the shared scenarios BF-01 to BF-18 |
| [`docs/15-tooling.md`](../../docs/15-tooling.md) §1 | The design the procedure makes concrete |

**No frontend is built yet, so there is nothing here to run.** The plan (`docs/26` §2.1, WS-R) is a Django management command and a Node CLI for Prisma, then one frontend per Phase 2 adapter, built in that adapter's workstream. The `rotate` job and part of `verify` also wait on a core accessor that does not exist yet (`PROCEDURE.md` §11, D-1).
