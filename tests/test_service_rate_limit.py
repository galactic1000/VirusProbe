from __future__ import annotations
import time

import pytest

from common.rate_limit import AsyncRateLimiter


async def test_allows_max_calls_immediately() -> None:
    limiter = AsyncRateLimiter(max_calls=3, period=60.0)
    start = time.monotonic()
    for _ in range(3):
        await limiter.acquire()
    elapsed = time.monotonic() - start
    assert elapsed < 0.1


async def test_blocks_on_overflow() -> None:
    limiter = AsyncRateLimiter(max_calls=2, period=0.2)
    await limiter.acquire()
    await limiter.acquire()
    start = time.monotonic()
    await limiter.acquire()
    elapsed = time.monotonic() - start
    assert elapsed >= 0.15


async def test_disabled_when_zero() -> None:
    limiter = AsyncRateLimiter(max_calls=0)
    start = time.monotonic()
    for _ in range(20):
        await limiter.acquire()
    elapsed = time.monotonic() - start
    assert elapsed < 0.1
