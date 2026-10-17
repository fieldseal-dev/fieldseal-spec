"""The rate limit (PROCEDURE §5.3): a token bucket, capacity one batch.

There is always a limit; nothing here has an "unlimited" setting.
"""

from __future__ import annotations

from collections.abc import Callable


class TokenBucket:
    """Rows per second, refilled continuously, holding at most one batch."""

    def __init__(
        self,
        rows_per_second: float,
        capacity: int,
        clock: Callable[[], float],
        sleep: Callable[[float], None],
    ) -> None:
        self._rate = rows_per_second
        self._capacity = float(capacity)
        self._clock = clock
        self._sleep = sleep
        self._tokens = self._capacity
        self._at = clock()

    def take(self, rows: int) -> None:
        """Block until `rows` tokens are available, then spend them."""
        while True:
            now = self._clock()
            self._tokens = min(
                self._capacity, self._tokens + (now - self._at) * self._rate)
            self._at = now
            # The tolerance is for float rounding: a wait computed to bring
            # the bucket to exactly `rows` can land a hair short, and the
            # next wait would be too small to move the clock at all.
            if self._tokens >= rows - 1e-6:
                self._tokens -= rows
                return
            self._sleep((rows - self._tokens) / self._rate)
