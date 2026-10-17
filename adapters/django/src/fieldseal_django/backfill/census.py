"""The census of envelopes against non-envelopes (PROCEDURE §8).

A full pass in cursor order, rate-limited as a run is, reading stored bytes
and classifying with `is_ciphertext`: no decrypt, no key, no write and no
lock. The count per `(suite_id, key_id)` is not here; it needs the header
accessor of PROCEDURE §11's D-1.

Internal for now: the `verify` subcommand that reports it is not built.
"""

from __future__ import annotations

from typing import Any

from django.db import connections

from ..apps import get_client
from . import cursor
from .ratelimit import TokenBucket


def census(
    model: Any,
    alias: str,
    pk: Any,
    fields: list[Any],
    *,
    batch_size: int,
    bucket: TokenBucket,
) -> dict[str, dict[str, int]]:
    """Per column, by `column_uuid` hex: NULLs, envelopes, non-envelopes.

    Not a snapshot: it runs while the application writes, so the counts are
    exact only for rows no one wrote during the pass.
    """
    client = get_client()
    connection = connections[alias]
    counts = {f.column_uuid.hex(): {"null": 0, "envelope": 0,
                                    "non_envelope": 0} for f in fields}
    targets = [(f, None) for f in fields]
    after = None
    while True:
        bucket.take(batch_size)
        rows = cursor.select_batch(
            connection, model, pk, targets,
            after=after, limit=batch_size, lock=False)
        for row in rows:
            for f, stored in zip(fields, row.stored, strict=True):
                tally = counts[f.column_uuid.hex()]
                if stored is None:
                    tally["null"] += 1
                    continue
                blob = cursor.stored_bytes(stored, f.storage)
                if blob is not None and client.is_ciphertext(blob):
                    tally["envelope"] += 1
                else:
                    tally["non_envelope"] += 1
        if len(rows) < batch_size:
            return counts
        after = rows[-1].key
