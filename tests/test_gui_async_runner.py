from __future__ import annotations

import asyncio
import pytest

from gui.async_runner import BackgroundAsyncRunner


@pytest.fixture
def runner():
    r = BackgroundAsyncRunner()
    yield r
    r.close()


# ---------------------------------------------------------------------------
# submit
# ---------------------------------------------------------------------------


def test_submit_returns_result(runner) -> None:
    async def _coro():
        return 42

    assert runner.submit(_coro()).result(timeout=2) == 42


def test_submit_propagates_exception(runner) -> None:
    async def _coro():
        raise ValueError("boom")

    with pytest.raises(ValueError, match="boom"):
        runner.submit(_coro()).result(timeout=2)


def test_submit_runs_concurrently(runner) -> None:
    """Two coroutines that await each other's events prove concurrent execution."""
    ev_a = asyncio.Event()

    async def _set_b_wait_a():
        runner.submit(_set_a(ev_a))  # schedule second coro from within first
        await asyncio.wait_for(ev_a.wait(), timeout=1)
        return "b_done"

    async def _set_a(ev):
        ev.set()

    result = runner.submit(_set_b_wait_a()).result(timeout=2)
    assert result == "b_done"


# ---------------------------------------------------------------------------
# close
# ---------------------------------------------------------------------------


def test_close_stops_thread(runner) -> None:
    thread = runner._thread
    runner.close()
    thread.join(timeout=2)
    assert not thread.is_alive()


def test_close_sets_loop_none(runner) -> None:
    runner.close()
    assert runner._loop is None


def test_close_idempotent() -> None:
    r = BackgroundAsyncRunner()
    r.close()
    r.close()  # second call must not raise


def test_submit_after_close_raises() -> None:
    r = BackgroundAsyncRunner()
    r.close()

    async def _coro():
        return 1

    coro = _coro()
    with pytest.raises(RuntimeError, match="not available"):
        r.submit(coro)
    coro.close()


# ---------------------------------------------------------------------------
# pending task cancellation on close
# ---------------------------------------------------------------------------


def test_close_cancels_pending_tasks() -> None:
    r = BackgroundAsyncRunner()
    started = asyncio.Event()
    cancelled = asyncio.Event()

    async def _long_running():
        started.set()
        try:
            await asyncio.sleep(60)
        except asyncio.CancelledError:
            cancelled.set()
            raise

    r.submit(_long_running())
    # wait until the coroutine is actually running in the background loop
    started_fut = r.submit(_wait_for_event(started))
    started_fut.result(timeout=2)

    r.close()

    # After close, the task should have been cancelled
    # loop is gone after close; check via the shared event set before loop stopped
    assert cancelled.is_set()


async def _wait_for_event(ev: asyncio.Event) -> None:
    await asyncio.wait_for(ev.wait(), timeout=2)
