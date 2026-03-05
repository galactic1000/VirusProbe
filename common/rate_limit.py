"""Shared rate-limiting primitives for VirusProbe services."""

from __future__ import annotations

import threading
import time
from collections import deque


class RateLimiter:

    def __init__(self, max_calls: int, period: float = 60.0) -> None:
        self._max_calls = max_calls
        self._period = period
        self._timestamps: deque[float] = deque()
        self._lock = threading.Lock()

    def acquire(self) -> None:
        if self._max_calls <= 0:
            return
        while True:
            with self._lock:
                now = time.monotonic()
                while self._timestamps and now - self._timestamps[0] >= self._period:
                    self._timestamps.popleft()
                if len(self._timestamps) < self._max_calls:
                    self._timestamps.append(now)
                    return
                wait = self._timestamps[0] + self._period - now
            time.sleep(max(0.0, wait))
