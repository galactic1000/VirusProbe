"""Scan orchestration helpers used by ScannerService."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Awaitable, Callable, Iterable
from pathlib import Path
from typing import Any


async def scan_many_async(
    semaphore: asyncio.Semaphore,
    scan_func: Callable[[Any], Awaitable[dict[str, Any]]],
    items: Iterable[Any],
    on_result: Callable[[dict[str, Any]], None] | None = None,
    cancel_event: threading.Event | None = None,
) -> list[dict[str, Any]]:
    if cancel_event is not None and cancel_event.is_set():
        return []

    item_list = list(items)
    if not item_list:
        return []

    results: list[dict[str, Any] | None] = [None] * len(item_list)

    async def _run_one(idx: int, item: Any) -> None:
        async with semaphore:
            if cancel_event is not None and cancel_event.is_set():
                return
            result = await scan_func(item)
            results[idx] = result
            if on_result is not None:
                on_result(result)

    async with asyncio.TaskGroup() as tg:
        for idx, item in enumerate(item_list):
            if cancel_event is not None and cancel_event.is_set():
                break
            tg.create_task(_run_one(idx, item))

    return [r for r in results if r is not None]


async def scan_files_async(
    semaphore: asyncio.Semaphore,
    scan_file: Callable[[str, threading.Event | None], Awaitable[dict[str, Any]]],
    file_paths: Iterable[str],
    on_result: Callable[[dict[str, Any]], None] | None = None,
    cancel_event: threading.Event | None = None,
) -> list[dict[str, Any]]:
    async def _scan_one(file_path: str) -> dict[str, Any]:
        return await scan_file(file_path, cancel_event)

    return await scan_many_async(semaphore, _scan_one, file_paths, on_result=on_result, cancel_event=cancel_event)


async def scan_hashes_async(
    semaphore: asyncio.Semaphore,
    scan_hash: Callable[[str, threading.Event | None], Awaitable[dict[str, Any]]],
    hashes: Iterable[str],
    on_result: Callable[[dict[str, Any]], None] | None = None,
    cancel_event: threading.Event | None = None,
) -> list[dict[str, Any]]:
    async def _scan_one(hash_value: str) -> dict[str, Any]:
        return await scan_hash(hash_value, cancel_event)

    return await scan_many_async(semaphore, _scan_one, hashes, on_result=on_result, cancel_event=cancel_event)


async def scan_directory_async(
    directory: str,
    scan_files_fn: Callable[
        [Iterable[str], Callable[[dict[str, Any]], None] | None, threading.Event | None],
        Awaitable[list[dict[str, Any]]],
    ],
    error_result: Callable[[str, str, str], dict[str, Any]],
    recursive: bool = False,
    on_result: Callable[[dict[str, Any]], None] | None = None,
    cancel_event: threading.Event | None = None,
) -> list[dict[str, Any]]:
    path = Path(directory)
    if not path.exists():
        result = error_result(directory, "directory", f"Directory '{directory}' does not exist")
        if on_result is not None:
            on_result(result)
        return [result]
    if not path.is_dir():
        result = error_result(directory, "directory", f"'{directory}' is not a directory")
        if on_result is not None:
            on_result(result)
        return [result]
    files = (str(f) for f in (path.rglob("*") if recursive else path.iterdir()) if f.is_file())
    return await scan_files_fn(files, on_result, cancel_event)
