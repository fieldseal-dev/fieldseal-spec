# backfill

Resumable, rate-limited, idempotent migration tooling: the initial encryption of a table that holds plaintext, and the re-encryption sweep that moves envelopes off an old key version or suite (spec §5.8, PRD AD-6).

| | |
|---|---|
| [`PROCEDURE.md`](PROCEDURE.md) | The one procedure every frontend implements, version 1: state tables, configuration hash, cursor and batch, the `encrypt` and `rotate` jobs, `verify`, required output, and the shared scenarios BF-01 to BF-20 |
| [`docs/15-tooling.md`](../../docs/15-tooling.md) §1 | The design the procedure makes concrete |

**One frontend exists, and it runs the `encrypt` job only:** the Django management command `manage.py fieldseal_backfill` (`init`, `encrypt`, `resume`, `abandon`), in `adapters/django` and described in `docs/12` §7. It does not convert tenant-bound columns ([#244](https://github.com/fieldseal-dev/fieldseal-spec/issues/244)) and has no `verify` yet. The plan (`docs/26` §2.1, WS-R) continues with a Node CLI for Prisma, then one frontend per Phase 2 adapter, built in that adapter's workstream. The `rotate` job and part of `verify` wait on a core accessor that does not exist yet (`PROCEDURE.md` §11, D-1).
