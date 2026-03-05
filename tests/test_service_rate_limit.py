from __future__ import annotations

import time

from common.rate_limit import RateLimiter


def test_rate_limiter_allows_up_to_max_calls_immediately() -> None:
    limiter = RateLimiter(max_calls=3, period=60.0)
    start = time.monotonic()
    for _ in range(3):
        limiter.acquire()
    assert time.monotonic() - start < 0.1


def test_rate_limiter_blocks_on_overflow() -> None:
    limiter = RateLimiter(max_calls=2, period=0.2)
    limiter.acquire()
    limiter.acquire()
    start = time.monotonic()
    limiter.acquire()
    assert time.monotonic() - start >= 0.15


def test_rate_limiter_disabled_when_zero() -> None:
    limiter = RateLimiter(max_calls=0)
    start = time.monotonic()
    for _ in range(20):
        limiter.acquire()
    assert time.monotonic() - start < 0.1
