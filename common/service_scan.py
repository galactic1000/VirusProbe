"""Scan orchestration helpers used by ScannerService."""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterable
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path
from typing import Any


def scan_many(
    max_workers: int,
    scan_func: Callable[[str], dict[str, Any]],
    items: Iterable[str],
    on_result: Callable[[dict[str, Any]], None] | None = None,
    cancel_event: threading.Event | None = None,
) -> list[dict[str, Any]]:
    if cancel_event is not None and cancel_event.is_set():
        return []
    item_iter = iter(items)
    results: dict[int, dict[str, Any]] = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_idx: dict[Any, int] = {}
        next_idx = 0

        def _submit_next() -> bool:
            nonlocal next_idx
            try:
                item = next(item_iter)
            except StopIteration:
                return False
            future = executor.submit(scan_func, item)
            future_to_idx[future] = next_idx
            next_idx += 1
            return True

        while len(future_to_idx) < max_workers and _submit_next():
            pass
        if not future_to_idx:
            return []

        while future_to_idx:
            done, _ = wait(tuple(future_to_idx.keys()), return_when=FIRST_COMPLETED)
            for future in done:
                idx = future_to_idx.pop(future)
                result = future.result()
                results[idx] = result
                if on_result is not None:
                    on_result(result)
            if cancel_event is not None and cancel_event.is_set():
                for future in list(future_to_idx):
                    future.cancel()
                for future, idx in list(future_to_idx.items()):
                    try:
                        result = future.result()
                        results[idx] = result
                        if on_result is not None:
                            on_result(result)
                    except Exception:
                        pass
                break
            while len(future_to_idx) < max_workers and _submit_next():
                pass
    return [results[idx] for idx in sorted(results)]


def scan_files(
    max_workers: int,
    scan_file: Callable[[str, threading.Event | None], dict[str, Any]],
    file_paths: Iterable[str],
    on_result: Callable[[dict[str, Any]], None] | None = None,
    cancel_event: threading.Event | None = None,
) -> list[dict[str, Any]]:
    def _scan_one(file_path: str) -> dict[str, Any]:
        return scan_file(file_path, cancel_event)

    return scan_many(max_workers, _scan_one, file_paths, on_result=on_result, cancel_event=cancel_event)


def scan_hashes(
    max_workers: int,
    scan_hash: Callable[[str], dict[str, Any]],
    hashes: Iterable[str],
    on_result: Callable[[dict[str, Any]], None] | None = None,
    cancel_event: threading.Event | None = None,
) -> list[dict[str, Any]]:
    return scan_many(max_workers, scan_hash, hashes, on_result=on_result, cancel_event=cancel_event)


def scan_directory(
    directory: str,
    scan_files: Callable[
        [Iterable[str], Callable[[dict[str, Any]], None] | None, threading.Event | None],
        list[dict[str, Any]],
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
    return scan_files(files, on_result, cancel_event)
