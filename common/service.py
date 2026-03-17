"""Core scan service shared by CLI and GUI."""

from __future__ import annotations

import asyncio
import contextlib
import sqlite3
from dataclasses import replace
from concurrent.futures import ThreadPoolExecutor
import hashlib
import stat
import threading
from collections.abc import Callable, Iterable
from pathlib import Path

import vt

from .api_errors import NOT_FOUND_ERROR_CODE, is_batch_fatal_api_error
from .cache import ScanCache
from .defaults import DEFAULT_SCAN_WORKERS
from .models import CacheEntry, ScannerConfig, ScanResult, ScanTarget, ScanTargetKind, UploadTarget
from .rate_limit import AsyncRateLimiter
from . import service_results as sr
from . import service_scan
from . import service_upload


class _HashCancelledError(Exception): ...



class ScannerService:
    """VirusTotal scanner backed by ScanCache."""
    CHUNK_SIZE = 1024 * 1024

    def __init__(
        self,
        api_key: str,
        cache_db: Path,
        config: ScannerConfig | None = None,
    ) -> None:
        cfg = config or ScannerConfig()
        self.api_key = api_key
        self.upload_undetected = cfg.upload_undetected
        self.upload_filter = cfg.upload_filter
        effective_workers = (
            cfg.max_workers
            if cfg.max_workers is not None
            else (cfg.requests_per_minute if cfg.requests_per_minute > 0 else DEFAULT_SCAN_WORKERS)
        )
        self.max_workers = max(1, int(effective_workers))
        self._cache = ScanCache(
            cache_db=cache_db,
            cache_expiry_days=cfg.cache_expiry_days,
            cache_max_rows=cfg.cache_max_rows,
            memory_cache_max_entries=cfg.memory_cache_max_entries,
        )
        self._cache_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="virusprobe-cache")
        self._hash_executor = ThreadPoolExecutor(max_workers=self.max_workers, thread_name_prefix="virusprobe-hash")
        self._cache_available = False
        self._requests_per_minute = max(0, int(cfg.requests_per_minute))
        self._upload_timeout_minutes = max(0, int(cfg.upload_timeout_minutes))
        self._session_client: vt.Client | None = None
        self._session_rate_limiter: AsyncRateLimiter | None = None
        self._session_semaphore: asyncio.Semaphore | None = None

    def init_cache(self) -> None:
        if self._cache_available:
            return
        try:
            self._init_cache_sync()
        except Exception:
            self._mark_cache_init_failed()

    async def init_cache_async(self) -> None:
        if self._cache_available:
            return
        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(self._cache_executor, self._init_cache_sync)
        except Exception:
            self._mark_cache_init_failed()

    def _init_cache_sync(self) -> None:
        self._cache.init()
        self._cache_available = True

    def _mark_cache_init_failed(self) -> None:
        self._cache_available = False
        with contextlib.suppress(Exception):
            self._cache.close()

    def clear_cache(self) -> int:
        if not self._cache_available:
            return 0
        return self._cache.clear()

    async def clear_cache_async(self) -> int:
        if not self._cache_available:
            return 0
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._cache_executor, self._cache.clear)

    def close(self) -> None:
        self._close_session_sync()
        try:
            self._cache_executor.shutdown(wait=True)
            self._hash_executor.shutdown(wait=True)
        finally:
            self._cache.close()

    async def close_async(self) -> None:
        await self._close_session_async()
        await asyncio.to_thread(self.close)

    async def __aenter__(self) -> ScannerService:
        await self.init_cache_async()
        if self._session_client is None:
            self._session_client = vt.Client(self.api_key)
            self._session_rate_limiter = AsyncRateLimiter(self._requests_per_minute)
            self._session_semaphore = asyncio.Semaphore(self.max_workers)
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        await self._close_session_async()

    def _close_session_sync(self) -> None:
        if self._session_client is not None:
            with contextlib.suppress(Exception):
                self._session_client.close()
        self._session_client = None
        self._session_rate_limiter = None
        self._session_semaphore = None

    async def _close_session_async(self) -> None:
        if self._session_client is not None:
            with contextlib.suppress(Exception):
                await self._session_client.close_async()
        self._session_client = None
        self._session_rate_limiter = None
        self._session_semaphore = None

    async def _cache_get_entry_async(self, file_hash: str) -> CacheEntry | None:
        if not self._cache_available:
            return None
        if cached := self._cache.peek_memory_entry(file_hash):
            return cached
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._cache_executor, self._cache.get_entry, file_hash)

    async def _cache_get_async(self, file_hash: str) -> tuple[int, int, int, int] | None:
        cached = await self._cache_get_entry_async(file_hash)
        if cached is None:
            return None
        if cached.is_not_found:
            return None
        return cached.stats

    async def _cache_save_async(self, file_hash: str, stats: tuple[int, int, int, int]) -> None:
        if not self._cache_available:
            return
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(self._cache_executor, self._cache.save, file_hash, stats)

    async def _cache_save_not_found_async(self, file_hash: str) -> None:
        if not self._cache_available:
            return
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(self._cache_executor, self._cache.save_not_found, file_hash)

    def hash_file(self, file_path: str, cancel_event: threading.Event | None = None) -> str:
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            while chunk := f.read(self.CHUNK_SIZE):
                if cancel_event is not None and cancel_event.is_set():
                    raise _HashCancelledError()
                hasher.update(chunk)
        return hasher.hexdigest()

    async def hash_file_async(self, file_path: str, cancel_event: threading.Event | None = None) -> str:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._hash_executor, self.hash_file, file_path, cancel_event)

    async def _cached_result_async(self, *, item: str, kind: ScanTargetKind, file_hash: str) -> ScanResult | None:
        cached_entry = await self._cache_get_entry_async(file_hash)
        if cached_entry is None:
            return None
        if cached_entry.is_not_found:
            if kind is ScanTargetKind.HASH:
                result = sr.not_found_result(file_hash)
            else:
                result = sr.not_found_file_result(item, file_hash)
            return replace(result, was_cached=True, message="Using cached result")
        cached = cached_entry.stats
        if kind is ScanTargetKind.HASH:
            item = sr.format_hash(file_hash)
        return sr.stats_result(
            item=item,
            kind=kind,
            file_hash=file_hash,
            stats=cached,
            was_cached=True,
        )

    async def _prepare_file_scan_async(
        self,
        target: ScanTarget,
        cancel_event: threading.Event | None = None,
    ) -> tuple[ScanResult | None, ScanTarget | None]:
        file_path = target.value
        if cancel_event is not None and cancel_event.is_set():
            return sr.cancelled_result(file_path, ScanTargetKind.FILE), None
        path = Path(file_path)
        try:
            path_stat = path.stat()
        except FileNotFoundError:
            return sr.error_result(file_path, ScanTargetKind.FILE, f"File '{file_path}' does not exist"), None
        except OSError as exc:
            return sr.error_result(file_path, ScanTargetKind.FILE, str(exc)), None
        if not stat.S_ISREG(path_stat.st_mode):
            return sr.error_result(file_path, ScanTargetKind.FILE, f"'{file_path}' is not a file"), None
        try:
            file_hash = await self.hash_file_async(file_path, cancel_event)
        except _HashCancelledError:
            return sr.cancelled_result(file_path, ScanTargetKind.FILE), None
        except OSError as exc:
            return sr.error_result(file_path, ScanTargetKind.FILE, str(exc)), None
        cached = await self._cached_result_async(item=file_path, kind=ScanTargetKind.FILE, file_hash=file_hash)
        if cached is not None:
            return cached, None
        return None, ScanTarget.from_file(file_hash, file_path)

    async def _prepare_hash_scan_async(
        self,
        target: ScanTarget,
        cancel_event: threading.Event | None = None,
    ) -> tuple[ScanResult | None, ScanTarget | None]:
        file_hash = target.value
        if cancel_event is not None and cancel_event.is_set():
            return sr.cancelled_result(str(file_hash), ScanTargetKind.HASH), None
        normalized_input = file_hash.strip()
        if not sr.is_valid_hash(normalized_input):
            return sr.hash_error(normalized_input, "Invalid hash format (expected MD5, SHA-1, or SHA-256)", normalized_input.lower()), None
        normalized_hash = normalized_input.lower()
        cached = await self._cached_result_async(
            item=normalized_hash,
            kind=ScanTargetKind.HASH,
            file_hash=normalized_hash,
        )
        if cached is not None:
            return cached, None
        return None, ScanTarget.from_hash(normalized_hash)

    async def _query_virustotal_async(
        self,
        client: vt.Client,
        rate_limiter: AsyncRateLimiter,
        file_hash: str,
        *,
        check_cache: bool = True,
    ) -> tuple[tuple[int, int, int, int], bool]:
        if check_cache:
            cached = await self._cache_get_async(file_hash)
            if cached is not None:
                return cached, True
        await rate_limiter.acquire()
        obj = await client.get_object_async(f"/files/{file_hash}")
        stats = sr.extract_stats(obj)
        try:
            await self._cache_save_async(file_hash, stats)
        except sqlite3.Error:
            pass
        return stats, False

    async def _upload_and_scan_async(
        self,
        client: vt.Client,
        rate_limiter: AsyncRateLimiter,
        file_path: str,
        file_hash: str,
        cancel_event: threading.Event | None = None,
    ) -> ScanResult:
        return await service_upload.upload_and_scan_async(
            upload_file_fn=lambda fp: service_upload.upload_file_async(client, rate_limiter, fp),
            poll_analysis_fn=lambda aid, ce: service_upload.poll_analysis_async(
                client, rate_limiter, self._requests_per_minute, self._upload_timeout_minutes, aid, ce
            ),
            cache_save=self._cache_save_async,
            classify_threat=sr.classify_threat,
            error_result=sr.error_result,
            cancelled_result=sr.cancelled_result,
            file_path=file_path,
            file_hash=file_hash,
            cancel_event=cancel_event,
        )

    async def _upload_file_direct_async(
        self,
        client: vt.Client,
        rate_limiter: AsyncRateLimiter,
        file_path: str,
        file_hash: str,
        cancel_event: threading.Event | None = None,
    ) -> ScanResult:
        if cancel_event is not None and cancel_event.is_set():
            return sr.cancelled_result(file_path, ScanTargetKind.FILE, file_hash)
        path = Path(file_path)
        try:
            path_stat = path.stat()
        except FileNotFoundError:
            return sr.error_result(file_path, ScanTargetKind.FILE, f"File not found: {file_path}", file_hash)
        except OSError as exc:
            return sr.error_result(file_path, ScanTargetKind.FILE, str(exc), file_hash)
        if not stat.S_ISREG(path_stat.st_mode):
            return sr.error_result(file_path, ScanTargetKind.FILE, f"Not a file: {file_path}", file_hash)
        if not file_hash:
            try:
                file_hash = await self.hash_file_async(file_path, cancel_event)
            except _HashCancelledError:
                return sr.cancelled_result(file_path, ScanTargetKind.FILE)
            except OSError as exc:
                return sr.error_result(file_path, ScanTargetKind.FILE, str(exc))
        return await self._upload_and_scan_async(client, rate_limiter, file_path, file_hash, cancel_event)

    async def _scan_live_async(
        self,
        client: vt.Client,
        rate_limiter: AsyncRateLimiter,
        unresolved: ScanTarget,
        cancel_event: threading.Event | None = None,
    ) -> ScanResult:
        file_hash = unresolved.hash
        file_path = unresolved.file_path
        item = file_path if file_path is not None else sr.format_hash(file_hash)

        async def not_found_result() -> ScanResult:
            if file_path is not None:
                if self.upload_undetected and (self.upload_filter is None or self.upload_filter(file_path)):
                    return await self._upload_and_scan_async(client, rate_limiter, file_path, file_hash, cancel_event)
            with contextlib.suppress(sqlite3.Error):
                await self._cache_save_not_found_async(file_hash)
            if file_path is not None:
                return sr.not_found_file_result(file_path, file_hash)
            return sr.not_found_result(file_hash)

        def error_result(message: str) -> ScanResult:
            if file_path is not None:
                return sr.error_result(item, ScanTargetKind.FILE, message, file_hash)
            return sr.hash_error(file_hash, message, file_hash)

        try:
            (malicious, suspicious, harmless, undetected), was_cached = await self._query_virustotal_async(
                client, rate_limiter, file_hash, check_cache=False
            )
        except vt.APIError as exc:
            if is_batch_fatal_api_error(exc):
                raise
            if exc.code == NOT_FOUND_ERROR_CODE:
                return await not_found_result()
            return error_result(str(exc))
        except Exception as exc:
            return error_result(str(exc))

        return sr.stats_result(
            item=item,
            kind=unresolved.kind,
            file_hash=file_hash,
            stats=(malicious, suspicious, harmless, undetected),
            was_cached=was_cached,
        )

    def _require_session_state(self) -> tuple[vt.Client, AsyncRateLimiter, asyncio.Semaphore]:
        if self._session_client is None or self._session_rate_limiter is None or self._session_semaphore is None:
            raise RuntimeError("ScannerService async methods require 'async with service:'")
        return self._session_client, self._session_rate_limiter, self._session_semaphore

    async def _scan_pipeline_async(
        self,
        targets: list[ScanTarget],
        on_result: Callable[[ScanResult], None] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> list[ScanResult]:
        if not targets:
            return []
        target_kind = targets[0].kind
        if target_kind is ScanTargetKind.DIRECTORY:
            raise ValueError("Directory targets must be handled before entering the scan pipeline")

        client, rate_limiter, semaphore = self._require_session_state()

        results: list[ScanResult] = [None] * len(targets)  # type: ignore[list-item]
        worker_count = self.max_workers

        def _emit_result(result_idx: int, result: ScanResult) -> None:
            results[result_idx] = result
            if on_result is not None:
                on_result(result)

        async def _prepare_item(raw_target: ScanTarget) -> tuple[ScanResult | None, ScanTarget | None]:
            if raw_target.kind is ScanTargetKind.FILE:
                return await self._prepare_file_scan_async(raw_target, cancel_event)
            return await self._prepare_hash_scan_async(raw_target, cancel_event)

        async def _scan_unresolved(unresolved: ScanTarget) -> ScanResult:
            return await self._scan_live_async(client, rate_limiter, unresolved, cancel_event)

        def _cancelled_prepared(raw_target: ScanTarget) -> ScanResult:
            return sr.cancelled_result(raw_target.value, raw_target.kind)

        if target_kind is ScanTargetKind.HASH:
            async def _run_one_hash(raw_target: ScanTarget) -> ScanResult:
                if cancel_event is not None and cancel_event.is_set():
                    return sr.cancelled_result(raw_target.value, ScanTargetKind.HASH)
                immediate, unresolved = await self._prepare_hash_scan_async(raw_target, cancel_event)
                if immediate is not None:
                    return immediate
                assert unresolved is not None
                return await _scan_unresolved(unresolved)

            return await service_scan.scan_many_async(
                semaphore,
                _run_one_hash,
                targets,
                on_result=on_result,
                cancel_event=cancel_event,
                cancelled_result=lambda raw_target: sr.cancelled_result(raw_target.value, ScanTargetKind.HASH),
            )

        def _cancelled_unresolved(unresolved: ScanTarget) -> ScanResult:
            return sr.cancelled_result(
                unresolved.file_path if unresolved.file_path is not None else sr.format_hash(unresolved.hash),
                unresolved.kind,
                unresolved.hash,
            )

        def _emit_for_unresolved(result: ScanResult, unresolved: ScanTarget) -> ScanResult:
            if unresolved.file_path is not None:
                return replace(result, item=unresolved.file_path, kind=ScanTargetKind.FILE, file_hash=unresolved.hash)
            return replace(result, item=sr.format_hash(unresolved.hash), kind=ScanTargetKind.HASH, file_hash=unresolved.hash)

        def _file_hash_key(unresolved: ScanTarget) -> str:
            return unresolved.hash

        unresolved_by_index: dict[int, ScanTarget] = {}
        completed_results_by_hash: dict[str, ScanResult] = {}

        def _emit_completed_for_index(result_idx: int, file_hash_key: str) -> None:
            unresolved = unresolved_by_index.pop(result_idx, None)
            completed = completed_results_by_hash[file_hash_key]
            if unresolved is None:
                _emit_result(result_idx, completed)
                return
            _emit_result(result_idx, _emit_for_unresolved(completed, unresolved))

        if len(targets) <= self.max_workers:
            live_tasks: dict[str, asyncio.Task[ScanResult]] = {}
            task_lock = asyncio.Lock()

            async def _run_one(result_idx: int, raw_target: ScanTarget) -> None:
                if cancel_event is not None and cancel_event.is_set():
                    _emit_result(result_idx, _cancelled_prepared(raw_target))
                    return
                immediate, unresolved = await _prepare_item(raw_target)
                if immediate is not None:
                    _emit_result(result_idx, immediate)
                    return
                assert unresolved is not None
                file_hash_key = _file_hash_key(unresolved)
                unresolved_by_index[result_idx] = unresolved
                async with task_lock:
                    completed = completed_results_by_hash.get(file_hash_key)
                    if completed is not None:
                        _emit_completed_for_index(result_idx, file_hash_key)
                        return
                    live_task = live_tasks.get(file_hash_key)
                    if live_task is None:
                        live_task = asyncio.create_task(_scan_unresolved(unresolved))
                        live_tasks[file_hash_key] = live_task
                result = await live_task
                async with task_lock:
                    completed_results_by_hash[file_hash_key] = result
                _emit_completed_for_index(result_idx, file_hash_key)

            async with asyncio.TaskGroup() as tg:
                for result_idx, raw_target in enumerate(targets):
                    tg.create_task(_run_one(result_idx, raw_target))
        else:
            await service_scan.scan_deduped_large_batch_async(
                items=targets,
                worker_count=worker_count,
                semaphore=semaphore,
                prepare_item=_prepare_item,
                scan_unresolved=_scan_unresolved,
                cancelled_prepared=_cancelled_prepared,
                cancelled_unresolved=_cancelled_unresolved,
                file_hash_key=_file_hash_key,
                emit_result=_emit_result,
                emit_completed_for_index=_emit_completed_for_index,
                unresolved_by_index=unresolved_by_index,
                completed_results_by_hash=completed_results_by_hash,
                cancel_event=cancel_event,
            )

        return results

    async def scan_targets(
        self,
        targets: Iterable[ScanTarget],
        on_result: Callable[[ScanResult], None] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> list[ScanResult]:
        target_list = list(targets)
        if not target_list:
            return []
        results: list[ScanResult] = []
        seen_hashes: set[str] = set()

        async def _flush_batch(batch: list[ScanTarget]) -> None:
            if not batch:
                return
            results.extend(await self._scan_pipeline_async(batch, on_result=on_result, cancel_event=cancel_event))
            batch.clear()

        batch: list[ScanTarget] = []
        batch_kind: ScanTargetKind | None = None

        for target in target_list:
            if target.kind is ScanTargetKind.DIRECTORY:
                await _flush_batch(batch)
                batch_kind = None
                results.extend(
                    await service_scan.scan_directory_async(
                        target,
                        scan_targets_fn=lambda next_targets, on_r, ce: self.scan_targets(
                            next_targets,
                            on_result=on_r,
                            cancel_event=ce,
                        ),
                        error_result=lambda directory_target, message: sr.error_result(
                            directory_target.value,
                            directory_target.kind,
                            message,
                        ),
                        on_result=on_result,
                        cancel_event=cancel_event,
                    )
                )
                continue

            if target.kind is ScanTargetKind.HASH:
                normalized = target.value.strip().lower()
                if sr.is_valid_hash(normalized):
                    if normalized in seen_hashes:
                        continue
                    seen_hashes.add(normalized)

            if batch_kind is not None and target.kind is not batch_kind:
                await _flush_batch(batch)
            batch_kind = target.kind
            batch.append(target)

        await _flush_batch(batch)
        return results

    async def upload_files_direct(
        self,
        entries: list[UploadTarget],
        on_result: Callable[[ScanResult], None] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> list[ScanResult]:
        client, rate_limiter, semaphore = self._require_session_state()
        hash_by_path = {entry.file_path: entry.file_hash for entry in entries}

        async def _upload_one(fp: str) -> ScanResult:
            return await self._upload_file_direct_async(
                client, rate_limiter, fp, hash_by_path[fp], cancel_event
            )

        return await service_scan.scan_many_async(
            semaphore,
            _upload_one,
            [entry.file_path for entry in entries],
            on_result=on_result,
            cancel_event=cancel_event,
            cancelled_result=lambda fp: sr.cancelled_result(fp, ScanTargetKind.FILE, hash_by_path[fp]),
        )
