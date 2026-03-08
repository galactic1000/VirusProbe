from __future__ import annotations

import asyncio
import time

from common.rate_limit import AsyncRateLimiter


def test_rate_limiter_allows_up_to_max_calls_immediately() -> None:
    async def _run() -> float:
        limiter = AsyncRateLimiter(max_calls=3, period=60.0)
        start = time.monotonic()
        for _ in range(3):
            await limiter.acquire()
        return time.monotonic() - start

    elapsed = asyncio.run(_run())
    assert elapsed < 0.1


def test_rate_limiter_blocks_on_overflow() -> None:
    async def _run() -> float:
        limiter = AsyncRateLimiter(max_calls=2, period=0.2)
        await limiter.acquire()
        await limiter.acquire()
        start = time.monotonic()
        await limiter.acquire()
        return time.monotonic() - start

    elapsed = asyncio.run(_run())
    assert elapsed >= 0.15


def test_rate_limiter_disabled_when_zero() -> None:
    async def _run() -> float:
        limiter = AsyncRateLimiter(max_calls=0)
        start = time.monotonic()
        for _ in range(20):
            await limiter.acquire()
        return time.monotonic() - start

    elapsed = asyncio.run(_run())
    assert elapsed < 0.1
