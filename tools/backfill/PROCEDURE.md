# The backfill procedure

**Procedure version:** 1 · **Date:** 2026-09-30 · **Status:** Draft 1, revised after review round 1 of [#239](https://github.com/fieldseal-dev/fieldseal-spec/pull/239). No frontend implements it yet, so nothing here has been run. It is versioned, not frozen: nothing in this project is frozen before Gate 0b (`docs/01-prd.md` §8).

This is the one procedure every backfill frontend implements: the state tables, the cursor, the batch, the two jobs, `verify`, what the tool must print, and the scenarios a frontend's tests must pass. The design it makes concrete is [`docs/15-tooling.md`](../../docs/15-tooling.md) §1. A frontend is a thin program in one language over one adapter (`docs/26` §5 item 4). A frontend that needs this document changed files an issue and waits; it does not diverge locally (`docs/26` §6).

The words MUST, MUST NOT, SHOULD and MAY are used as in RFC 2119. Statements marked **[flag]** are not verified or not decided, and say which.

---

## 1. What the tool does, and what it does not

Two jobs, one mechanism:

| Job | Spec | What it moves |
|---|---|---|
| `encrypt` | `docs/04` §11 step 3 | Values that are still plaintext become envelopes, and their blind indexes are written |
| `rotate` | spec §5.8, *full background re-encryption* | Envelopes under a stale key version or a stale suite become envelopes under the current ones |

And one check, `verify` (§8), which reads and never writes.

**Not in version 1:**

- **Rebuilding a blind index.** A changed index parameter or a rotated index key is a new index column and a full backfill of it (spec §7.8, §5.8). That is a third job, and this version does not define it.
- **Re-rendering a column whose declared type changed** (spec §3.6).
- **Moving data between databases.**
- **Any DDL on the application's tables.** Adding the ciphertext and index columns (`docs/04` §11 step 1) and dropping the legacy column (step 5) are the deployment's migrations.
- **Parallel batches.** One batch is in flight at a time (`docs/15` §1.1).
- **Shredding a scope.** Crypto-shredding a tenant destroys both its keys (spec §5.2), and PRD SP-18 requires an inventory of every derived artifact, blind-index columns first, with a shred procedure for each. This version has no index-column job (the first item above), so it cannot gate index-key destruction; §8 says what it can gate.

**Limits the tool does not remove**, and which §9 requires it to print where they apply:

- Encrypting a table that already held plaintext does nothing about the copies that already exist. Crypto-shredding claims are void for every backup taken before the migration (`docs/04` §11).
- The tool runs inside an application process that holds the keys. It protects nothing against that process (spec §2.2).
- An `encrypt` run over an Argon2id-indexed column derives one index per value, at 10–100 ms each (spec §7.3). That cost sets the run's speed, and no setting here changes it.
- **A batch holds locks while it derives.** The rows a batch selects are locked until it commits (§5.2 step 4), and the derivations run inside that window, so at the defaults (200 rows, 10–100 ms each) a batch over an Argon2id-indexed column blocks application writes to those rows for 2–20 seconds; on SQLite the lock is the whole database. `batch_size` bounds it proportionally, and is the setting to lower first.

## 2. Preconditions

The tool cannot check most of these. They are stated because each one, if false, produces a wrong result without an error.

1. **Every writer of the table already writes the target form.** For `encrypt`: every application process writes ciphertext (`docs/04` §11 step 2 is deployed everywhere). For `rotate`: every application process writes under the current key version and write suite. The cursor visits each row once; a row written behind it by an old writer is never revisited. `verify`'s census (§8) is what detects a violation.
2. **The frontend holds the adapter's encrypting client.** For Prisma that is the extended client; the base client bypasses encryption silently (`docs/13` §6).
3. **The key material the run needs is reachable.** For `rotate`, a suite being retired stays on the decrypt allow-list until the sweep and its census are done (`docs/09` §3.5).
4. **The read mode fits the job** (spec §10.3). The frontend reads it from the client (`docs/09` §2, configuration reflection) and MUST refuse to start otherwise:

| Job | Required read mode | Why |
|---|---|---|
| `encrypt`, in place (§6.1) | `permissive` | The legacy value is read through the adapter; in `strict` that read raises `NOT_CIPHERTEXT` |
| `encrypt`, two columns (§6.1) | `strict` or `permissive` | Must be able to write |
| `rotate` | `strict` or `permissive` | `rotate` raises `MODE_VIOLATION` in `readonly` |
| `verify` | `readonly` | The check cannot write, by construction (`docs/15` §3) |

## 3. State tables

Two tables, in the **target** database, so that a batch's data writes and its progress record commit in one transaction (§5). A frontend creates them only on an explicit `init` subcommand, or the deployment creates them by its own migration. A frontend MUST refuse to run when either table is missing or lacks a column below.

```sql
CREATE TABLE fieldseal_backfill_runs (
    run_id             VARCHAR(36)   NOT NULL PRIMARY KEY,  -- UUID, lowercase, hyphenated
    procedure_version  INTEGER       NOT NULL,              -- 1
    job                VARCHAR(16)   NOT NULL,              -- 'encrypt' | 'rotate'
    table_uuid         CHAR(32)      NOT NULL,              -- the table's identity, lowercase hex; also in config
    running_table_uuid CHAR(32),                            -- = table_uuid while status = 'running', else NULL
    table_name         VARCHAR(255)  NOT NULL,              -- informational
    config_hash        CHAR(64)      NOT NULL,              -- §4, lowercase hex
    config             TEXT          NOT NULL,              -- §4, the hashed document itself
    status             VARCHAR(16)   NOT NULL,              -- 'running' | 'complete' | 'abandoned'
    batch_seq          BIGINT        NOT NULL,              -- batches committed; starts at 0
    cursor_value       TEXT,                                -- §5.1; NULL before the first batch
    rows_scanned       BIGINT        NOT NULL,
    values_written     BIGINT        NOT NULL,
    values_current     BIGINT        NOT NULL,
    values_null        BIGINT        NOT NULL,
    values_anomalous   BIGINT        NOT NULL,
    values_failed      BIGINT        NOT NULL,
    started_at         VARCHAR(20)   NOT NULL,              -- UTC, YYYY-MM-DDTHH:MM:SSZ
    updated_at         VARCHAR(20)   NOT NULL,
    completed_at       VARCHAR(20),
    frontend           VARCHAR(64)   NOT NULL,              -- e.g. 'django/0.1.0'; informational
    UNIQUE (running_table_uuid)                             -- one running run per table, enforced
);

CREATE TABLE fieldseal_backfill_failures (
    run_id       VARCHAR(36)   NOT NULL,
    row_key      TEXT          NOT NULL,   -- the row's cursor key, encoded as in §5.1
    column_uuid  CHAR(32)      NOT NULL,   -- lowercase hex
    error_code   VARCHAR(32)   NOT NULL,   -- §7
    batch_seq    BIGINT        NOT NULL,
    recorded_at  VARCHAR(20)   NOT NULL,
    PRIMARY KEY (run_id, row_key, column_uuid)
);
```

Types may be spelled as the database requires (`TEXT` for `VARCHAR` on SQLite, for instance); names, nullability, the unique constraint and meanings may not change. Timestamps are text so that every database and every frontend stores the same bytes.

**Version 1 targets Postgres, SQLite and H2**, the databases the shipped adapters and the Hibernate adapter are tested on. MySQL is out of scope: InnoDB refuses a `TEXT` column in a key, and `row_key` is one. A frontend for it needs a sized `row_key` and an issue against this document.

**Neither table ever holds a plaintext value, an envelope, an index value, or key material.** `row_key` is the row's primary key. A deployment whose primary key is itself sensitive should know that it is copied here.

**The counts are per value**, not per row: a row with two encrypted columns in the run contributes two values. `rows_scanned` is per row. At every commit, `values_written + values_current + values_null + values_anomalous + values_failed` equals the number of values scanned.

**One running run per table**, keyed on `table_uuid`, and enforced by the database rather than by a read before an insert: `running_table_uuid` holds the table's UUID while the run is `running` and NULL once it is `complete` or `abandoned`, and the unique constraint on it refuses a second running row. Every database this version targets (above: Postgres, SQLite, H2) allows any number of NULLs under a unique constraint. A start whose insert is refused reports the run that holds the table; the operator resumes that run or marks it `abandoned` with an explicit subcommand. The status change and the clearing of `running_table_uuid` are one statement. A run whose process died stays `running`; that is what makes it resumable.

**A frontend reading a row whose `procedure_version` it does not implement MUST refuse to resume it.**

## 4. The configuration hash

A resumed run must write what the run it resumes was writing. The case that matters most is a changed index declaration: a raised Argon2id cost is a new index under spec §7.8, and a run resumed across the change leaves two index values in one column, the older half unfindable (G18, `docs/issues/`). So a run records what it was started with and refuses to resume under anything else.

The inputs are what decides the bytes a run stores, and nothing operational. Batch size and rate are not inputs; an operator may change them on resume.

`config` is a JSON object with exactly these members. The cursor columns are recorded by name as well as type: a resumed run seeks from the stored cursor into whatever key space the table has now, so a replaced primary key that the hash did not see would skip every row ordered below the cursor, silently.

| Member | Value |
|---|---|
| `procedure_version` | `1` |
| `job` | `"encrypt"` or `"rotate"` |
| `table_uuid` | The table's UUID, 32 lowercase hex digits |
| `write_suite` | The client's write suite as an integer, read from the client (`docs/09` §2) |
| `cursor` | Array, one object per cursor column in key order: `{"name": <the column's SQL name>, "type": <"int", "uuid" or "text">}` (§5.1). A primary key has no `column_uuid`, so its name is the identity recorded; a renamed or replaced key column refuses the resume, and a key replaced by another of the same name and type is not detected |
| `columns` | Array, one object per encrypted column in the run, sorted by `column_uuid` |

Each `columns` element:

| Member | Value |
|---|---|
| `column_uuid` | 32 lowercase hex digits |
| `logical_type` | The spec §3.6 type name the adapter maps the column to |
| `storage` | `"binary"` or `"base64"` (spec §3.3) |
| `source` | `null` for an in-place column; the legacy column's name for the two-column shape (§6.1). Always `null` for `rotate` |
| `indexes` | For `encrypt`: one object per blind index declared on the column, sorted by `index_id`. For `rotate`: `[]`, because rotation does not touch indexes (spec §5.8) |

Each `indexes` element, taken from the client's **validated** registry (`docs/09` §2), never from the declaration as written:

| Member | Value |
|---|---|
| `index_id` | e.g. `"exact"` |
| `idf` | `"argon2id"` or `"hmac-sha512"` |
| `argon2` | `{"memory_kib": m, "time_cost": t}` as resolved, or `null` for `hmac-sha512` |
| `normalize` | The normalizer id |
| `truncate_bits` | `b` |
| `on_unindexable` | `"refuse"` or `"bucket"` |
| `storage` | `"binary"` or `"hex"` (spec §7.11) |

The projected population and the override records are left out: they decide whether a declaration is accepted, not what is stored.

**Serialization.** Members sorted by name in ascending byte order at every level; no whitespace; integers in decimal with no sign, fraction or exponent; `null` for null. Every string MUST consist of ASCII characters `0x20`–`0x7E` other than `"` and `\`, so no escape is ever written; a frontend MUST refuse a `source` or cursor column name outside that set. The result is encoded as ASCII. `config_hash` is the SHA-256 of those bytes, in lowercase hex. The hash is a change detector over public configuration. It is not a cryptographic control, and computing it is not cryptographic code in the sense of AD-1 (spec §11.3).

**Worked example.** A frontend's tests MUST reproduce this hash from these inputs:

```json
{"columns":[{"column_uuid":"018f3c2e7a1b7c3d8e4f5a6b7c8d9e0f","indexes":[{"argon2":{"memory_kib":19456,"time_cost":2},"idf":"argon2id","index_id":"exact","normalize":"nfc-casefold-v1","on_unindexable":"refuse","storage":"binary","truncate_bits":24}],"logical_type":"string","source":null,"storage":"binary"}],"cursor":[{"name":"id","type":"int"}],"job":"encrypt","procedure_version":1,"table_uuid":"018f3c2e7a1b7c3d8e4f5a6b7c8d9e00","write_suite":65281}
```

```
8d437f03246bc98fba1a649865059069f8f171aadbc7fcf1ce2cec53575682a0
```

The numbers in the example are arbitrary inputs to the serialization. They are not recommended parameters.

**On resume**, the frontend rebuilds `config` from the live client and declarations, and compares it to the stored one. If they differ it MUST refuse, and name each member that differs. It prints names and parameters only; there is nothing secret in `config`.

## 5. The cursor and the batch

### 5.1 Cursor

Keyset pagination over the table's **primary key**, ascending, all key columns in their declared order. Never `OFFSET` (`docs/15` §1.1). Version 1 supports key columns of three types:

| Type | Encoding in `cursor_value` and `row_key` |
|---|---|
| `int` | Decimal, as in §4 but with a leading `-` allowed |
| `uuid` | Lowercase, hyphenated, 36 characters |
| `text` | The value itself |

`cursor_value` and `row_key` are a JSON array of strings, one per key column, e.g. `["4182"]` or `["eu","4182"]`. Ordinary JSON string escaping applies here; these values are stored and read back, never hashed.

A table with no primary key, or a key column of another type, MUST be refused at start. `docs/15` §1.1 also allows "created-at + PK tiebreak"; version 1 does not, because a primary key is the one column set every database guarantees unique, indexed and present. **[flag: a primary key that the application updates breaks the cursor. The tool cannot detect it.]**

Ordering and comparison are the database's. The cursor is only ever compared by the database that produced it, so a collation or a UUID byte order that differs from the frontend language's does not matter.

### 5.2 Batch

One batch is one transaction. In order:

1. **Wait** for the rate limiter to grant one batch of `n` rows (§5.3).
2. **Begin** a transaction. On SQLite it MUST take the write lock at the start (`BEGIN IMMEDIATE`).
3. **Claim the batch:** `UPDATE fieldseal_backfill_runs SET batch_seq = batch_seq + 1 WHERE run_id = ? AND batch_seq = ? AND status = 'running'`, with the `batch_seq` this process last read or wrote: the post-increment value after a batch it committed, the stored value after one it rolled back (§5.4). If it changes no row, another process owns the run or the run has ended: roll back and exit with an error. This statement also locks the run row until commit, so two processes cannot interleave.
4. **Select** up to `n` rows with key greater than `cursor_value`, in key order, **locked against concurrent writers until commit** (`SELECT … FOR UPDATE` where the database has it; on SQLite, step 2's lock). The select reads the stored bytes of each target column, not the adapter's decoded value. It MUST NOT skip locked rows. The locks are held through steps 5 to 8, derivations included, so the hold is `n` times the per-value cost: at the defaults, 2–20 seconds over an Argon2id-indexed column, and on SQLite that is the whole database (§1). `batch_size` is the bound.
5. **Classify** each value from its stored bytes (§6.2 or §7.1).
6. **Act** on each `pending` value as the job says. An error raised by the core or the adapter for one value is a value failure (§7.4), and the batch continues. An error from the database aborts the batch (§5.4).
7. **Record:** insert the batch's failure rows; update the run row's counts, `cursor_value` (the key of the last row selected) and `updated_at`. If the select returned fewer than `n` rows, also set `status = 'complete'` and `completed_at`.
8. **Commit.**

The lock in step 4 is what stops a lost update: without it, an application write that lands between the tool's read and the tool's write is overwritten with the value the tool read earlier.

The batch is atomic. A process killed at any point leaves either the whole batch, with its cursor, or none of it.

**`complete` means the cursor reached the end. It does not mean every value was converted.** A complete run can have failures and anomalies, and the final report says so (§9).

### 5.3 Rate limit

There is always a limit. A frontend has no "unlimited" setting.

| Setting | Default | Meaning |
|---|---|---|
| `batch_size` | 200 | Rows per batch, `n` above |
| `rows_per_second` | 200 | Token bucket, capacity one batch, refilled continuously |

**[flag: both defaults are unmeasured.** They are chosen to be slow. `batch_size` is not only a throughput setting: it is the bound on how long a batch holds its locks (§5.2 step 4), and the first frontend's measurement has to settle both. The measurements replace the defaults by an issue against this document.]

The measured rate a run reports (§9) MUST NOT exceed `rows_per_second` over the run, beyond one batch of burst.

**Replication lag (OPTIONAL in version 1).** On Postgres a frontend MAY pause while the largest `replay_lag` in `pg_stat_replication` exceeds a configured threshold. **[flag: not verified against a replicated deployment; the view shows other sessions' rows only to a role with `pg_monitor` or equivalent.]** A frontend that does not implement it, or cannot read the view, MUST say so at start. For every other database the operator throttles by `rows_per_second` (`docs/15` §1.1).

### 5.4 Database errors

On a database error inside a batch: roll back, wait, and retry the same batch. The wait is `min(60 s, 1 s × 2^k)` for the `k`-th consecutive failure, starting at `k = 0`. After 8 consecutive failures the process exits with an error and the run stays `running`. A rolled-back batch changed nothing, so the retry starts from the same cursor with the same `batch_seq`.

## 6. The `encrypt` job

### 6.1 Two shapes

| Shape | Source | Target | When |
|---|---|---|---|
| **In place** | The target column itself | The encrypted column | The legacy column's type can already hold the envelope in the adapter's storage form, and the adapter's `permissive` read passes the legacy value through |
| **Two columns** | A legacy plaintext column (`source` in §4) | A separate encrypted column | Everything else. This is `docs/04` §11's shape |

Which shape an adapter supports for which column types is that adapter's statement, in its binding doc, not this document's.

### 6.2 Classification

From the target column's stored bytes `T` (decoded from base64 first where `storage` is `base64`; a value that does not decode is not an envelope):

| Condition | Class | Action |
|---|---|---|
| `is_ciphertext(T)` | `current` | None. The value MUST NOT be rewritten |
| In place: `T` is NULL. Two columns: the source is NULL and `T` is NULL | `null` | None |
| In place: `T` is not NULL and not an envelope | `pending` | Encrypt |
| Two columns: `T` is NULL and the source is not NULL | `pending` | Encrypt |
| Two columns: `T` is not NULL and not an envelope | `anomalous` | None. The target column holds something this tool did not put there |

The skip test is `is_ciphertext` alone: no decrypt and no key (`docs/15` §1.1). That is what makes a re-run cheap and a resumed run safe.

### 6.3 Encrypting a pending value

1. **Obtain the application value through the adapter's read path.** In place: the adapter's `permissive` read of that row and column. Two columns: the ORM's ordinary read of the source column. A frontend MUST NOT build the plaintext from the stored bytes itself.
2. **Write it through the adapter's encrypting write path**, in the batch's transaction (`docs/15` §1.1, *Safe writes*). Never SQL that copies a column. The paths verified so far are Django's `bulk_update` (`docs/12` §2) and Prisma's `update`/`updateMany` on the extended client (`docs/13` §6).
3. **The same statement writes the blind index** for every index declared on the column. An envelope whose index is missing is a row no equality lookup finds. **Django's `bulk_update` did not do this at `51ae712`** (measured 2026-09-30, Django 6.1.1, SQLite, the adapter's own test model; fixed in [#242](https://github.com/fieldseal-dev/fieldseal-spec/pull/242), which also found `update()` and `save(update_fields=…)` behind the same cause): it never calls `pre_save`, where the adapter derives the index, so after `bulk_update([p], ["email"])` the index sibling held the old value's index and an equality lookup for the new value returned no row; naming the sibling in the field list changed nothing. `docs/12` §2 verified `bulk_update` for the ciphertext only. The Django frontend cannot use that path for an indexed column until #242 is merged; that was an adapter defect with its own issue ([#240](https://github.com/fieldseal-dev/fieldseal-spec/issues/240)), not a procedure change. **[flag: the same question is open for every other adapter's bulk path, and is each frontend's first thing to verify.]**

Rule 1 is what keeps the tool out of spec §3.4's double-encryption case. A reserved-version value (`fmt_ver` `0x02`, 111 bytes or more) is not an envelope to `is_ciphertext`, so it classifies `pending`; but the adapter's read of it raises `UNKNOWN_FORMAT_VERSION` in every mode, so it becomes a failure and is left as it was. A frontend that rendered the plaintext from raw bytes would encrypt it a second time.

Rule 1 also means a legacy value that is not the canonical spec §3.6 rendering of its type fails in place, because readers are as strict as writers. Those rows are failures the operator resolves, or the column is migrated in the two-column shape, where the ORM reads the legacy type and the adapter renders it.

The context of each write is the adapter's own, for that row: the tenant the application's write of that row would bind (spec §6). The frontend establishes it the way the adapter documents, and a row whose context cannot be established is a failure with code `CONTEXT_UNAVAILABLE`. A frontend MUST NOT write a row under a context it guessed.

## 7. The `rotate` job

### 7.1 Classification

From the stored bytes `T`, decoded as in §6.2:

| Condition | Class | Action |
|---|---|---|
| `T` is NULL | `null` | None |
| Not `is_ciphertext(T)` | `anomalous` | None. `rotate` does not encrypt plaintext, in any mode (spec §11.1) |
| Envelope, header `suite_id` = the client's write suite **and** header `key_id` = the write key id for the row's context (§7.2) | `current` | None. The value MUST NOT be rewritten |
| Any other envelope | `pending` | Rotate |

The test reads the header only. It needs no key (`docs/15` §1.1).

**The header is not authenticated until a decrypt.** A damaged or forged envelope whose first 19 bytes look current is classified `current`. The tool is not an integrity check; `verify`'s sampled decrypt is the closest thing to one here (§8).

### 7.2 The write key id

The key id a write under context `c` would carry is the header `key_id` of `encrypt(empty plaintext, c)`. A frontend obtains it that way, at most once per batch for each distinct context with `row_id` removed, and MUST NOT carry it from one batch to the next. A key version activated during a run is therefore picked up at the next batch; rows the run had already passed are stale again, and only the census shows it (§8).

The probe uses public operations only and never touches the provider, which the client does not expose (`docs/09` §2). It costs one encryption per distinct context per batch, and one use of the DEK against the cache's use budget (spec §5.5). The probe's output is discarded and never stored.

**The probe assumes the key id does not depend on `row_id`.** Spec §5.2 makes the DEK scope the tenant, or a documented scope for deployments without one, and `key_id` is the provider's to define (spec §3.1). The probe is sound for every scope a provider can express from the context without its `row_id`; a provider whose key id depends on the row would make every envelope classify `pending` on every run, and every run rewrite the whole table. So §7.3 step 2 checks each rotated envelope against the probe, and a mismatch stops the run rather than letting it converge on nothing.

**[flag: open decision D-5, §11.]**

### 7.3 Rotating a pending value

1. `out = rotate(T, c)` on the core client, with the adapter's context for that row and column.
2. Check `is_ciphertext(out)`. If false, that is a failure with code `INTERNAL`, and nothing is written. Check that `out`'s header `key_id` equals the write key id of §7.2 for this context: if it does not, the provider's key id depends on something the probe does not carry, this run can never classify a row `current`, and the process MUST stop with an error, leaving the run `running` and this value unwritten. This is a process stop, not a value failure: nothing is recorded for it (§7.4). Reading `out`'s header is the parse D-1 (§11) says no core exports yet, like the rest of this job.
3. Write `out`, in the column's storage form, to that row and column only, as a bound parameter, in the batch's transaction.

`rotate` is used, rather than the adapter's read followed by the adapter's write, because spec §11.1 and `docs/09` §3.5 define the sweep that way and because it leaves the plaintext bytes exactly as they were: nothing passes through a codec. The write in step 3 stores an envelope the core just produced, and step 2 checks it. **[flag: open decision D-2, §11. `docs/26` §4 says a frontend works "through the adapter's encrypting write path", which describes `encrypt` and not this step.]**

**Blind-index columns MUST NOT change** during a rotate run (spec §5.8).

### 7.4 Value failures, both jobs

A failure is recorded in `fieldseal_backfill_failures` and counted; the value is left as it was; the run continues. The one exception is §7.3 step 2's key-id mismatch, which stops the process and records nothing, because it says the run cannot converge rather than that one value is bad. The cursor moves past a failed row, so a resumed run does not retry it and a new run does.

`error_code` is the core's code when the core raised: a spec §9 code (`KEY_UNAVAILABLE`, `SUITE_NOT_ALLOWED`, `AAD_MISMATCH`, `TAG_INVALID`, `COMMITMENT_INVALID`, `UNKNOWN_FORMAT_VERSION`, `NOT_CIPHERTEXT`, `LENGTH_EXCEEDED`, `SUITE_PROVISIONAL`, `MODE_VIOLATION`), or `INVALID_ARGUMENT`, which the cores raise for a value a blind index refuses (`docs/09` §7.2). Otherwise it is one of:

| Code | Meaning |
|---|---|
| `RENDERING_REFUSED` | The adapter refused the value under spec §3.6, on read or on write |
| `CONTEXT_UNAVAILABLE` | The row's context could not be established (§6.3) |
| `INTERNAL` | Anything else, including §7.3 step 2 |

No message text is stored, only the code. An error message can carry part of a value, and this table is not a place for one.

`max_failures` (default 100) stops the process, leaving the run `running`, when the number of failures **this process has recorded since it started** reaches it. **The threshold is tested once per batch, at step 7 of §5.2, before the commit**, never between values: a stop always leaves a committed batch, its failure rows recorded and its cursor past them, so the resume starts beyond the rows that failed. Tested per value it would unwind the open batch, and at the defaults (100 against a batch of 200) every resume would replay and unwind the same batch forever. A run that is failing on every row should not walk the whole table. The count is per process, not the run row's cumulative `values_failed`, so a resume makes progress: it starts at zero and stops again only if the failures continue. `max_failures` is an operator setting like `batch_size` and `rows_per_second` (§5.3): not stored, not in the hash, and changeable on resume.

## 8. `verify`

Reads only, under a `readonly` client (§2). It has two parts and reports both.

**Census.** A full pass in cursor order, rate-limited as a run is, reading stored bytes and classifying without decrypting:

- For every column: the number of NULL values, envelopes, and non-envelopes.
- For every column, the number of envelopes per `(suite_id, key_id)`, both in hex. This line needs the header accessor of D-1 (§11) and is blocked until it lands; the line above needs only `is_ciphertext`.

**Sample.** `N` rows (default 1000, or every row if there are fewer), chosen uniformly at random among the rows scanned; the frontend states its method and `N` in the report. Each sampled envelope is decrypted through the adapter's read path. In the two-column shape, while the legacy column still exists, the result is compared with the legacy value. The report gives counts of decrypted, failed (by error code) and mismatched. It never prints a value.

The census goes further than `docs/15` §1.1, which asked for a sample only. A sample cannot show that no plaintext remains, and the plaintext-read metric (spec §10.3) counts only rows that something reads. The census is the direct measurement, and it costs one header-only pass over the table.

`verify` is not a snapshot. It runs while the application writes, so its counts are exact only for rows no one wrote during the pass. Under §2's first precondition that error is one-sided: a concurrent writer can only add envelopes in the target form.

**What an operator may conclude:**

| Decision | Requires |
|---|---|
| Switch to `strict` (`docs/04` §11 step 4) | Census: zero non-envelopes in every column. Sample: zero failures and zero mismatches. And the adapter's plaintext-read count at zero over a window the operator chooses |
| Drop the legacy column (step 5) | The above, with `strict` deployed |
| Retire an old DEK version after a `rotate` run (spec §5.8, §8.2) | Census: zero envelopes under that `key_id`, in **every** table and column that key's scope covers, not only the table just swept. This retires one data-key version and nothing else: index keys are siblings of the DEK (spec §5.2), a rotation leaves every index valid, and this row does not speak to them |
| Crypto-shred a scope, a tenant (spec §5.2, PRD SP-18) | **This procedure cannot gate it.** Shredding destroys the tenant's DEK *and* its index keys, and SP-18 requires an inventory of every derived artifact with a shred procedure for each. `verify` gives one line of that inventory: the census for the DEK, as in the row above. It does not read index columns, and version 1 has no job that rebuilds or clears one (§1), so after the DEK is gone every index value in the scope still stands and still confirms that a plaintext is present to anyone holding the index key. Caches, queues, replicas, exports and backups are not visible to it either. An operator shreds on an inventory this tool does not produce |
| Remove a retired suite from the allow-list (spec §5.9) | Census: zero envelopes under that `suite_id`, in every table and column |

Destroying a key also makes every backup that holds envelopes under it undecryptable for those values. That is the purpose when the goal is erasure, and a loss when it is not. `verify` cannot see backups.

**[flag: the plaintext-read count exists in the Python core (a counter) and the TypeScript core (a hook), and per model and field in the Django and Prisma adapters (`docs/12` §4, `docs/13` §3). The Java core has no metrics hook yet (`docs/27` §4), so a Hibernate deployment has the census and the sample only, which is two of the three inputs the first row needs: **until the hook lands, a Hibernate deployment has no procedure-sanctioned path to `strict` and none to dropping the legacy column.** The last two rows do not need it.]**

## 9. What the tool prints

These are requirements on output, not on documentation (`docs/15` §1.3).

**1. Before a new `encrypt` run on a table that has at least one row**, this text, verbatim, and a refusal to proceed without `--acknowledge-preexisting-backups`:

```
This table already holds data. Encrypting it now does not encrypt the copies
that already exist: every backup, snapshot, replica and export made before this
run still holds these values in plaintext, and destroying a key later will not
erase them. Crypto-shredding claims are permanently void for every backup that
predates this migration. NIST SP 800-88r2 section 3.2.2 allows cryptographic
erase only where no sensitive data was previously stored in plaintext form.
Re-run with --acknowledge-preexisting-backups to proceed.
```

The flag is required on the run that starts, not on a resume.

**2. At the end of every `rotate` run**, verbatim:

```
This run is not proof that the old key is unused. Run verify: an old key version
may be destroyed only when the census shows no envelope under it in any table
and column it covers. Backups that hold envelopes under a destroyed key become
undecryptable.
```

A frontend for an adapter that offers lazy on-read re-encryption MUST also restate spec §5.8: lazy convergence never completes for cold data and never permits old-key destruction on its own. No shipped adapter offers it as of this date.

**3. At start:** the run id, the job, new or resumed, the `config` document, the limits in force, and whether lag throttling is active.

**4. The final report**, human-readable and as JSON: every count in the run row, the failure count by error code, measured rows per second and wall-clock time for this process and for the run, and the run's status. When `values_failed` or `values_anomalous` is not zero, the first line says the table is **not** fully converted. The measured rate is the input PRD DO-5's cost model asks for (`docs/15` §1.3); it is a measurement of one run on one machine.

**5. Never:** a plaintext value, an envelope, an index value, or key material, in any output, log line or error.

## 10. Shared scenarios

`docs/26` §6 requires every frontend to run one shared set of scenarios against a live database, and P2-M5 names resumability, idempotence and rate limit. A frontend's test suite MUST contain a test for each id below and cite the id in the test's name, so a coverage report can score them as the adapters' matrices are scored. "Bytes unchanged" means the stored bytes of the column compare equal before and after.

| Id | Scenario | Passes when |
|---|---|---|
| BF-01 | `encrypt`, fresh table of plaintext rows | Run completes; census shows zero non-envelopes; every value decrypts to its original; every declared index is present and finds its row |
| BF-02 | Kill the process between two batches, then resume | The run continues from the stored cursor; rows converted before the kill have bytes unchanged; the final state equals BF-01's |
| BF-03 | Kill inside a batch, after the data writes and before commit | Neither the rows nor the cursor nor `batch_seq` moved |
| BF-04 | A new run over a table a run already completed | `values_written` is 0; every envelope's bytes unchanged |
| BF-05 | Resume with a changed index parameter; again with a changed write suite | Refused, naming the member that differs; nothing written |
| BF-06 | A second process resumes a run while the first is mid-batch | Exactly one proceeds; the other exits with an error at §5.2 step 3 |
| BF-07 | The application updates a row the current batch has selected | The update is not lost: after both commit, the row holds the application's value, encrypted |
| BF-08 | NULL values, in both shapes | Counted `null`, left NULL, index left NULL |
| BF-09 | A reserved-version value in an in-place column | Recorded as a failure with `UNKNOWN_FORMAT_VERSION`; bytes unchanged |
| BF-10 | `encrypt` on a populated table without the acknowledgement flag | Text 1 printed; nothing written; no run row created |
| BF-11 ⏸ | `rotate` over current, stale-key, stale-suite, NULL and plaintext values | Stale values become current and decrypt to the same plaintext bytes; current values have bytes unchanged; the plaintext is `anomalous` and unchanged; every index column has bytes unchanged |
| BF-12 ⏸ | `rotate`, killed and resumed; then a new run | As BF-02 and BF-04 |
| BF-13 ⏸ | `rotate` with one envelope that cannot be decrypted | A failure row with the spec §9 code; the run continues and completes; the report's first line says not fully converted |
| BF-14 | A run with `rows_per_second` set low enough to bind | Measured rate is at most the limit, beyond one batch of burst |
| BF-15 | `verify` with one planted plaintext; with one planted mismatch in the two-column shape | The census counts the plaintext; the sample, taken over every row, reports the mismatch |
| BF-15k ⏸ | `verify` over envelopes under two key versions and two suites | The census by `(suite_id, key_id)` reports each count |
| BF-16 | Any scenario above that produced output | No plaintext value, envelope or index value appears in any output or in either state table |
| BF-17 | The §4 worked example | The frontend's serializer and hash reproduce it |
| BF-18 | A run row with `procedure_version` 2 | Refused |
| BF-19 | Two processes start a new run on one table at once | Exactly one run row exists; the other start is refused by the unique constraint and names the run that holds the table |
| BF-20 | A run stopped by `max_failures` mid-way through a batch's worth of failing rows, then resumed with the same setting | The stop leaves the run `running`, with the failing batch committed: its failure rows are recorded and `cursor_value` is past every row that failed. The resume starts beyond them, and completes when the failures do not continue |

A frontend reports each scenario in one of three states. **Passed.** **Not applicable**, with the reason, for a scenario its adapter cannot express (an adapter with one shape only, for BF-08's other half). **Blocked**, for a scenario that cannot be built yet for a reason outside the adapter: the rows marked ⏸ (BF-11, BF-12, BF-13 and BF-15k) need the header accessor of D-1 (§11, [#241](https://github.com/fieldseal-dev/fieldseal-spec/issues/241)) and are blocked in every frontend until it lands. A blocked scenario is not a pass and not a gap in the frontend; a coverage report scores it separately so that `docs/26` §6's drift check can tell the two apart.

## 11. Open decisions and what the cores owe

Recorded here so that a frontend is not built on an assumption.

- **D-1. No core exports a header parse** ([#241](https://github.com/fieldseal-dev/fieldseal-spec/issues/241))**.** §7.1 and the census need `suite_id` and `key_id` from stored bytes. `docs/15` §3 says `docs/09` §4 "already provides `EnvelopeHeader`; keep it exported". The type is public in all three cores, and a function that produces one from bytes is public in none: Python's is `fieldseal.envelope.recognize`, outside the package root's `__all__`; TypeScript's `recognize` is not exported from the package entry; Java's codec is under `internal`. It needs #241 decided and an accessor in each core before the `rotate` job or the census by key can be built. The `encrypt` job and the census of envelopes against non-envelopes need only `is_ciphertext`, and are not blocked. A frontend MUST NOT parse the header bytes itself in the meantime.
- **D-2. `rotate` writes the core's output directly** (§7.3), not through the adapter's write path. The alternative is the adapter's read followed by its write, which keeps one write path and passes every value through a codec.
- **D-3. The census** (§8) is an addition to `docs/15` §1.1's sampled verify.
- **D-4. The rate defaults** (§5.3) are unmeasured, and `batch_size` also bounds lock hold (§5.2 step 4).
- **D-5. The write key id by probe** (§7.2). The alternative is a core accessor that reports the key id a write would carry; it would go in D-1's issue.
- **The Java core's metrics hook** (§8's flag) is owed by `docs/27` §4, not by this document.

## 12. Changing this document

`procedure_version` increases when a change alters what is stored in either state table, what a run writes, or how `config` is built. A clarification that changes none of those does not. Every change is an issue first, and updates the shared scenarios with it.
