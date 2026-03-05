"""Scan orchestration helpers for ScannerService."""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterable
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from pathlib import Path
from typing import Any


class ScanOrchestrationMixin:
    max_workers: int

    def _scan_many(
        self,
        scan_func: Callable[[str], dict[str, Any]],
        items: Iterable[str],
        on_result: Callable[[dict[str, Any]], None] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> list[dict[str, Any]]:
        item_list = list(items)
        if not item_list:
            return []
        if cancel_event is not None and cancel_event.is_set():
            return []
        if len(item_list) == 1:
            if cancel_event is not None and cancel_event.is_set():
                return []
            result = scan_func(item_list[0])
            if on_result is not None:
                on_result(result)
            return [result]

        results: list[dict[str, Any] | None] = [None] * len(item_list)
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_idx: dict[Any, int] = {}
            next_idx = 0
            while next_idx < len(item_list) and len(future_to_idx) < self.max_workers:
                future = executor.submit(scan_func, item_list[next_idx])
                future_to_idx[future] = next_idx
                next_idx += 1

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
                    break
                while next_idx < len(item_list) and len(future_to_idx) < self.max_workers:
                    future = executor.submit(scan_func, item_list[next_idx])
                    future_to_idx[future] = next_idx
                    next_idx += 1
        return [r for r in results if r is not None]

    def scan_files(
        self,
        file_paths: Iterable[str],
        on_result: Callable[[dict[str, Any]], None] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> list[dict[str, Any]]:
        def _scan_one(file_path: str) -> dict[str, Any]:
            return self.scan_file(file_path, cancel_event=cancel_event)  # type: ignore[attr-defined]

        return self._scan_many(_scan_one, file_paths, on_result=on_result, cancel_event=cancel_event)

    def scan_hashes(
        self,
        hashes: Iterable[str],
        on_result: Callable[[dict[str, Any]], None] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> list[dict[str, Any]]:
        return self._scan_many(self.scan_hash, hashes, on_result=on_result, cancel_event=cancel_event)  # type: ignore[attr-defined]

    def scan_directory(
        self,
        directory: str,
        recursive: bool = False,
        on_result: Callable[[dict[str, Any]], None] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> list[dict[str, Any]]:
        path = Path(directory)
        if not path.exists():
            result = self._error_result(directory, "directory", f"Directory '{directory}' does not exist")  # type: ignore[attr-defined]
            if on_result is not None:
                on_result(result)
            return [result]
        if not path.is_dir():
            result = self._error_result(directory, "directory", f"'{directory}' is not a directory")  # type: ignore[attr-defined]
            if on_result is not None:
                on_result(result)
            return [result]
        files = [str(f) for f in (path.rglob("*") if recursive else path.iterdir()) if f.is_file()]
        return self.scan_files(files, on_result=on_result, cancel_event=cancel_event)
