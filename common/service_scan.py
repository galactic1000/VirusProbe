"""Scan orchestration."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Awaitable, Callable, Iterable
from pathlib import Path
from typing import Any

from .models import ScanResult, ScanTarget


async def scan_many_async(
    semaphore: asyncio.Semaphore,
    scan_func: Callable[[Any], Awaitable[ScanResult]],
    items: Iterable[Any],
    on_result: Callable[[ScanResult], None] | None = None,
    cancel_event: threading.Event | None = None,
    cancelled_result: Callable[[Any], ScanResult] | None = None,
) -> list[ScanResult]:
    item_list = list(items)
    if not item_list:
        return []
    if cancel_event is not None and cancel_event.is_set():
        if cancelled_result is None:
            return []
        cancelled_results: list[ScanResult] = [cancelled_result(item) for item in item_list]
        if on_result is not None:
            for result in cancelled_results:
                on_result(result)
        return cancelled_results
    results: list[ScanResult | None] = [None] * len(item_list)

    async def _run_one(index: int, item: Any) -> None:
        async with semaphore:
            if cancel_event is not None and cancel_event.is_set():
                if cancelled_result is not None:
                    result = cancelled_result(item)
                    results[index] = result
                    if on_result is not None:
                        on_result(result)
                return
            result = await scan_func(item)
            results[index] = result
            if on_result is not None:
                on_result(result)

    async with asyncio.TaskGroup() as tg:
        for index, item in enumerate(item_list):
            tg.create_task(_run_one(index, item))
    return [result for result in results if result is not None]


async def scan_directory_async(
    directory_target: ScanTarget,
    scan_targets_fn: Callable[
        [Iterable[ScanTarget], Callable[[ScanResult], None] | None, threading.Event | None],
        Awaitable[list[ScanResult]],
    ],
    error_result: Callable[[ScanTarget, str], ScanResult],
    on_result: Callable[[ScanResult], None] | None = None,
    cancel_event: threading.Event | None = None,
) -> list[ScanResult]:
    path = Path(directory_target.value)
    try:
        if not path.is_dir():
            raise NotADirectoryError(f"'{directory_target.value}' does not exist or is not a directory")
        file_targets = (
            ScanTarget.from_file_path(str(file_path))
            for file_path in (path.rglob("*") if directory_target.recursive else path.iterdir())
            if file_path.is_file()
        )
    except Exception as exc:
        result = error_result(directory_target, str(exc))
        if on_result is not None:
            on_result(result)
        return [result]
    return await scan_targets_fn(file_targets, on_result, cancel_event)


async def scan_deduped_large_batch_async(
    *,
    items: list[ScanTarget],
    worker_count: int,
    semaphore: asyncio.Semaphore,
    prepare_item: Callable[[ScanTarget], Awaitable[tuple[ScanResult | None, ScanTarget | None]]],
    scan_unresolved: Callable[[ScanTarget], Awaitable[ScanResult]],
    cancelled_prepared: Callable[[ScanTarget], ScanResult],
    cancelled_unresolved: Callable[[ScanTarget], ScanResult],
    file_hash_key: Callable[[ScanTarget], str],
    emit_result: Callable[[int, ScanResult], None],
    emit_completed_for_index: Callable[[int, str], None],
    unresolved_by_index: dict[int, ScanTarget],
    completed_results_by_hash: dict[str, ScanResult],
    cancel_event: threading.Event | None = None,
) -> None:
    prepare_queue: asyncio.Queue[tuple[int, ScanTarget] | None] = asyncio.Queue()
    for idx, item in enumerate(items):
        prepare_queue.put_nowait((idx, item))
    for _ in range(worker_count):
        prepare_queue.put_nowait(None)

    unique_queue: asyncio.Queue[str | None] = asyncio.Queue()
    completed_queue: asyncio.Queue[tuple[str, ScanResult] | None] = asyncio.Queue()
    pending_indices: dict[str, list[int]] = {}
    pending_unresolved: dict[str, ScanTarget] = {}

    async with asyncio.TaskGroup() as tg:
        async def _prepare_worker() -> None:
            while True:
                queue_item = await prepare_queue.get()
                try:
                    if queue_item is None:
                        return
                    result_idx, raw_item = queue_item
                    if cancel_event is not None and cancel_event.is_set():
                        emit_result(result_idx, cancelled_prepared(raw_item))
                        continue
                    immediate, unresolved = await prepare_item(raw_item)
                    if immediate is not None:
                        emit_result(result_idx, immediate)
                        continue
                    assert unresolved is not None
                    hash_key = file_hash_key(unresolved)
                    unresolved_by_index[result_idx] = unresolved
                    if hash_key in completed_results_by_hash:
                        emit_completed_for_index(result_idx, hash_key)
                        continue
                    waiters = pending_indices.get(hash_key)
                    if waiters is None:
                        pending_indices[hash_key] = [result_idx]
                        pending_unresolved[hash_key] = unresolved
                        await unique_queue.put(hash_key)
                    else:
                        waiters.append(result_idx)
                finally:
                    prepare_queue.task_done()

        async def _live_worker() -> None:
            while True:
                hash_key = await unique_queue.get()
                try:
                    if hash_key is None:
                        return
                    async with semaphore:
                        unresolved = pending_unresolved[hash_key]
                        if cancel_event is not None and cancel_event.is_set():
                            await completed_queue.put((hash_key, cancelled_unresolved(unresolved)))
                            continue
                        await completed_queue.put((hash_key, await scan_unresolved(unresolved)))
                finally:
                    unique_queue.task_done()

        async def _completion_worker() -> None:
            while True:
                queue_item = await completed_queue.get()
                try:
                    if queue_item is None:
                        return
                    hash_key, result = queue_item
                    completed_results_by_hash[hash_key] = result
                    pending_unresolved.pop(hash_key, None)
                    waiter_indices = pending_indices.pop(hash_key, [])
                    for result_idx in waiter_indices:
                        emit_completed_for_index(result_idx, hash_key)
                finally:
                    completed_queue.task_done()

        async def _close_unique_queue() -> None:
            await prepare_queue.join()
            for _ in range(worker_count):
                await unique_queue.put(None)

        async def _close_completed_queue() -> None:
            await prepare_queue.join()
            await unique_queue.join()
            await completed_queue.put(None)

        for _ in range(worker_count):
            tg.create_task(_prepare_worker())
            tg.create_task(_live_worker())
        tg.create_task(_completion_worker())
        tg.create_task(_close_unique_queue())
        tg.create_task(_close_completed_queue())
