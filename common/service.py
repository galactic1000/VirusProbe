"""Core scan service shared by CLI and GUI."""

from __future__ import annotations

import asyncio
import contextlib
from concurrent.futures import ThreadPoolExecutor
import hashlib
import threading
from collections.abc import Callable, Iterable
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import vt

from .api_errors import BATCH_FATAL_API_ERROR_CODES
from .cache import ScanCache
from .defaults import DEFAULT_REQUESTS_PER_MINUTE, DEFAULT_SCAN_WORKERS, DEFAULT_UPLOAD_TIMEOUT_MINUTES
from .rate_limit import AsyncRateLimiter
from . import service_scan
from . import service_upload


class _HashCancelled(Exception):
    """Raised internally when file hashing is interrupted by cancel_event."""


def _is_batch_fatal_api_error(exc: vt.APIError) -> bool:
    return exc.code in BATCH_FATAL_API_ERROR_CODES


class ScannerService:
    """VirusTotal scanner backed by ScanCache."""

    _HEX_CHARS: frozenset[str] = frozenset("0123456789abcdefABCDEF")

    def __init__(
        self,
        api_key: str,
        cache_db: Path,
        cache_expiry_days: int = 7,
        cache_max_rows: int = 10000,
        memory_cache_max_entries: int = 512,
        max_workers: int | None = None,
        requests_per_minute: int = DEFAULT_REQUESTS_PER_MINUTE,
        upload_timeout_minutes: int = DEFAULT_UPLOAD_TIMEOUT_MINUTES,
        upload_undetected: bool = False,
        upload_filter: Callable[[str], bool] | None = None,
    ) -> None:
        self.api_key = api_key
        self.upload_undetected = upload_undetected
        self.upload_filter = upload_filter
        effective_workers = (
            max_workers
            if max_workers is not None
            else (requests_per_minute if requests_per_minute > 0 else DEFAULT_SCAN_WORKERS)
        )
        self.max_workers = max(1, int(effective_workers))
        self._cache = ScanCache(
            cache_db=cache_db,
            cache_expiry_days=cache_expiry_days,
            cache_max_rows=cache_max_rows,
            memory_cache_max_entries=memory_cache_max_entries,
        )
        self._cache_executor = ThreadPoolExecutor(max_workers=1, thread_name_prefix="virusprobe-cache")
        self._hash_executor = ThreadPoolExecutor(max_workers=self.max_workers, thread_name_prefix="virusprobe-hash")
        self._cache_available = True
        self._requests_per_minute = max(0, int(requests_per_minute))
        self._upload_timeout_minutes = max(0, int(upload_timeout_minutes))
        self._session_client: vt.Client | None = None
        self._session_rate_limiter: AsyncRateLimiter | None = None
        self._session_semaphore: asyncio.Semaphore | None = None

    def init_cache(self) -> None:
        try:
            self._cache.init()
            self._cache_available = True
        except Exception:
            self._cache_available = False
            with contextlib.suppress(Exception):
                self._cache.close()

    async def init_cache_async(self) -> None:
        loop = asyncio.get_running_loop()
        try:
            await loop.run_in_executor(self._cache_executor, self._cache.init)
            self._cache_available = True
        except Exception:
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
        try:
            self._cache_executor.shutdown(wait=True)
            self._hash_executor.shutdown(wait=True)
        finally:
            self._cache.close()

    async def _cache_get_async(self, file_hash: str) -> tuple[int, int, int, int] | None:
        if not self._cache_available:
            return None
        cached = self._cache.peek_memory(file_hash)
        if cached is not None:
            return cached
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._cache_executor, self._cache.get, file_hash)

    async def _cache_save_async(self, file_hash: str, stats: tuple[int, int, int, int]) -> None:
        if not self._cache_available:
            return
        loop = asyncio.get_running_loop()
        await loop.run_in_executor(self._cache_executor, self._cache.save, file_hash, stats)

    @staticmethod
    def hash_file(file_path: str, cancel_event: threading.Event | None = None) -> str:
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                if cancel_event is not None and cancel_event.is_set():
                    raise _HashCancelled()
                hasher.update(chunk)
        return hasher.hexdigest()

    async def hash_file_async(self, file_path: str, cancel_event: threading.Event | None = None) -> str:
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(self._hash_executor, ScannerService.hash_file, file_path, cancel_event)

    @staticmethod
    def _hash_item(value: object) -> str:
        return f"SHA-256 hash: {value}"

    @staticmethod
    def _base_result(item: str, item_type: str, file_hash: str, threat_level: str, status: str, message: str) -> dict[str, Any]:
        return {
            "item": item,
            "type": item_type,
            "file_hash": file_hash,
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "threat_level": threat_level,
            "status": status,
            "message": message,
            "was_cached": False,
            "was_uploaded": False,
        }

    @staticmethod
    def _error_result(item: str, item_type: str, message: str, file_hash: str = "") -> dict[str, Any]:
        return ScannerService._base_result(item, item_type, file_hash, "Error", "error", message)

    @staticmethod
    def _cancelled_result(item: str, item_type: str, file_hash: str = "") -> dict[str, Any]:
        return ScannerService._base_result(item, item_type, file_hash, "Cancelled", "cancelled", "Cancelled by user")

    @classmethod
    def _hash_error(cls, value: object, message: str, file_hash: str = "") -> dict[str, Any]:
        return cls._error_result(item=cls._hash_item(value), item_type="hash", message=message, file_hash=file_hash)

    @classmethod
    def _not_found_result(cls, normalized_hash: str) -> dict[str, Any]:
        return cls._base_result(cls._hash_item(normalized_hash), "hash", normalized_hash, "Undetected", "undetected", "No VirusTotal record found")

    @staticmethod
    def is_sha256(value: str) -> bool:
        return len(value) == 64 and all(c in ScannerService._HEX_CHARS for c in value)

    @staticmethod
    def classify_threat(malicious: int, suspicious: int = 0) -> str:
        if malicious >= 10:
            return "Malicious"
        if malicious > 0 or suspicious >= 3:
            return "Suspicious"
        return "Clean"

    @staticmethod
    def _extract_stats(obj: vt.Object) -> tuple[int, int, int, int]:
        stats = obj.last_analysis_stats
        if not isinstance(stats, dict):
            raise ValueError("VirusTotal response missing analysis stats")
        return (
            int(stats["malicious"]),
            int(stats["suspicious"]),
            int(stats["harmless"]),
            int(stats["undetected"]),
        )

    def _stats_result(
        self,
        *,
        item: str,
        item_type: str,
        file_hash: str,
        stats: tuple[int, int, int, int],
        was_cached: bool,
    ) -> dict[str, Any]:
        malicious, suspicious, harmless, undetected = stats
        return {
            "item": item,
            "type": item_type,
            "file_hash": file_hash,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "threat_level": self.classify_threat(malicious, suspicious),
            "status": "ok",
            "message": "Using cached result" if was_cached else "Queried VirusTotal API",
            "was_cached": was_cached,
            "was_uploaded": False,
        }

    async def _cached_result_async(self, *, item: str, item_type: str, file_hash: str) -> dict[str, Any] | None:
        cached = await self._cache_get_async(file_hash)
        if cached is None:
            return None
        if item_type == "hash":
            item = self._hash_item(file_hash)
        return self._stats_result(
            item=item,
            item_type=item_type,
            file_hash=file_hash,
            stats=cached,
            was_cached=True,
        )

    async def _prepare_file_scan_async(
        self,
        file_path: str,
        cancel_event: threading.Event | None = None,
    ) -> tuple[dict[str, Any] | None, tuple[str, str] | None]:
        if cancel_event is not None and cancel_event.is_set():
            return self._cancelled_result(file_path, "file"), None
        path = Path(file_path)
        if not path.exists():
            return self._error_result(file_path, "file", f"File '{file_path}' does not exist"), None
        if not path.is_file():
            return self._error_result(file_path, "file", f"'{file_path}' is not a file"), None
        try:
            file_hash = await self.hash_file_async(file_path, cancel_event)
        except _HashCancelled:
            return self._cancelled_result(file_path, "file"), None
        except OSError as exc:
            return self._error_result(file_path, "file", str(exc)), None
        cached = await self._cached_result_async(item=file_path, item_type="file", file_hash=file_hash)
        if cached is not None:
            return cached, None
        return None, (file_path, file_hash)

    async def _prepare_hash_scan_async(
        self,
        file_hash: str,
        cancel_event: threading.Event | None = None,
    ) -> tuple[dict[str, Any] | None, str | None]:
        if cancel_event is not None and cancel_event.is_set():
            return self._cancelled_result(str(file_hash), "hash"), None
        if not isinstance(file_hash, str):
            return self._hash_error(file_hash, "Invalid SHA-256 hash format"), None
        normalized_input = file_hash.strip()
        if not self.is_sha256(normalized_input):
            return self._hash_error(normalized_input, "Invalid SHA-256 hash format", normalized_input.lower()), None
        normalized_hash = normalized_input.lower()
        cached = await self._cached_result_async(item=normalized_hash, item_type="hash", file_hash=normalized_hash)
        if cached is not None:
            return cached, None
        return None, normalized_hash

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
        stats = self._extract_stats(obj)
        try:
            await self._cache_save_async(file_hash, stats)
        except Exception:
            pass
        return stats, False

    async def _upload_and_scan_async(
        self,
        client: vt.Client,
        rate_limiter: AsyncRateLimiter,
        file_path: str,
        file_hash: str,
        cancel_event: threading.Event | None = None,
    ) -> dict[str, Any]:
        return await service_upload.upload_and_scan_async(
            upload_file_fn=lambda fp: service_upload.upload_file_async(client, rate_limiter, fp),
            poll_analysis_fn=lambda aid, ce: service_upload.poll_analysis_async(
                client, rate_limiter, self._requests_per_minute, self._upload_timeout_minutes, aid, ce
            ),
            cache_save=self._cache_save_async,
            classify_threat=self.classify_threat,
            error_result=self._error_result,
            cancelled_result=self._cancelled_result,
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
    ) -> dict[str, Any]:
        if cancel_event is not None and cancel_event.is_set():
            return self._cancelled_result(file_path, "file", file_hash)
        path = Path(file_path)
        if not path.exists():
            return self._error_result(file_path, "file", f"File not found: {file_path}", file_hash)
        if not path.is_file():
            return self._error_result(file_path, "file", f"Not a file: {file_path}", file_hash)
        if not file_hash:
            try:
                file_hash = await self.hash_file_async(file_path, cancel_event)
            except _HashCancelled:
                return self._cancelled_result(file_path, "file")
            except OSError as exc:
                return self._error_result(file_path, "file", str(exc))
        return await self._upload_and_scan_async(client, rate_limiter, file_path, file_hash, cancel_event)

    async def _scan_file_live_async(
        self,
        client: vt.Client,
        rate_limiter: AsyncRateLimiter,
        file_path: str,
        file_hash: str,
        cancel_event: threading.Event | None = None,
    ) -> dict[str, Any]:
        try:
            (malicious, suspicious, harmless, undetected), was_cached = await self._query_virustotal_async(
                client, rate_limiter, file_hash, check_cache=False
            )
        except vt.APIError as exc:
            if _is_batch_fatal_api_error(exc):
                raise
            if exc.code == "NotFoundError" and self.upload_undetected and (
                self.upload_filter is None or self.upload_filter(file_path)
            ):
                return await self._upload_and_scan_async(client, rate_limiter, file_path, file_hash, cancel_event)
            if exc.code == "NotFoundError":
                result = self._not_found_result(file_hash)
                result.update({"item": file_path, "type": "file"})
                return result
            return self._error_result(file_path, "file", str(exc), file_hash)
        except ValueError as exc:
            return self._error_result(file_path, "file", f"Unexpected VT response: {exc}", file_hash)
        except Exception as exc:
            result = self._hash_error(file_hash, str(exc), file_hash)
            result.update({"item": file_path, "type": "file"})
            return result

        return self._stats_result(
            item=file_path,
            item_type="file",
            file_hash=file_hash,
            stats=(malicious, suspicious, harmless, undetected),
            was_cached=was_cached,
        )

    async def _scan_hash_live_async(
        self,
        client: vt.Client,
        rate_limiter: AsyncRateLimiter,
        normalized_hash: str,
    ) -> dict[str, Any]:
        try:
            (malicious, suspicious, harmless, undetected), was_cached = await self._query_virustotal_async(
                client, rate_limiter, normalized_hash, check_cache=False
            )
        except vt.APIError as exc:
            if _is_batch_fatal_api_error(exc):
                raise
            if exc.code == "NotFoundError":
                return self._not_found_result(normalized_hash)
            return self._hash_error(normalized_hash, str(exc), normalized_hash)
        except ValueError:
            return self._not_found_result(normalized_hash)
        except Exception as exc:
            return self._hash_error(normalized_hash, str(exc), normalized_hash)

        return self._stats_result(
            item=self._hash_item(normalized_hash),
            item_type="hash",
            file_hash=normalized_hash,
            stats=(malicious, suspicious, harmless, undetected),
            was_cached=was_cached,
        )

    async def _scan_files_small_batch_async(
        self,
        client: vt.Client,
        rate_limiter: AsyncRateLimiter,
        file_list: list[str],
        on_result: Callable[[dict[str, Any]], None] | None,
        cancel_event: threading.Event | None,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any] | None] = [None] * len(file_list)

        async def _run_one(idx: int, file_path: str) -> None:
            if cancel_event is not None and cancel_event.is_set():
                result = self._cancelled_result(file_path, "file")
                results[idx] = result
                if on_result is not None:
                    on_result(result)
                return
            immediate, unresolved = await self._prepare_file_scan_async(file_path, cancel_event)
            if immediate is not None:
                result = immediate
            else:
                assert unresolved is not None
                unresolved_path, file_hash = unresolved
                result = await self._scan_file_live_async(client, rate_limiter, unresolved_path, file_hash, cancel_event)
            results[idx] = result
            if on_result is not None:
                on_result(result)

        async with asyncio.TaskGroup() as tg:
            for idx, file_path in enumerate(file_list):
                tg.create_task(_run_one(idx, file_path))

        return [result for result in results if result is not None]

    async def _scan_hashes_small_batch_async(
        self,
        client: vt.Client,
        rate_limiter: AsyncRateLimiter,
        hash_list: list[str],
        on_result: Callable[[dict[str, Any]], None] | None,
        cancel_event: threading.Event | None,
    ) -> list[dict[str, Any]]:
        results: list[dict[str, Any] | None] = [None] * len(hash_list)

        async def _run_one(idx: int, raw_hash: str) -> None:
            if cancel_event is not None and cancel_event.is_set():
                result = self._cancelled_result(raw_hash, "hash")
                results[idx] = result
                if on_result is not None:
                    on_result(result)
                return
            immediate, unresolved = await self._prepare_hash_scan_async(raw_hash, cancel_event)
            if immediate is not None:
                result = immediate
            else:
                assert unresolved is not None
                result = await self._scan_hash_live_async(client, rate_limiter, unresolved)
            results[idx] = result
            if on_result is not None:
                on_result(result)

        async with asyncio.TaskGroup() as tg:
            for idx, raw_hash in enumerate(hash_list):
                tg.create_task(_run_one(idx, raw_hash))

        return [result for result in results if result is not None]

    @asynccontextmanager
    async def _client_context(self):
        if self._session_client is not None:
            assert self._session_rate_limiter is not None
            assert self._session_semaphore is not None
            yield self._session_client, self._session_rate_limiter, self._session_semaphore
        else:
            rate_limiter = AsyncRateLimiter(self._requests_per_minute)
            semaphore = asyncio.Semaphore(self.max_workers)
            async with vt.Client(self.api_key) as client:
                yield client, rate_limiter, semaphore

    @asynccontextmanager
    async def async_session(self):
        """Open a single shared vt.Client for the duration of the block.

        Use this to avoid opening a new connection for each scan_files /
        scan_hashes / scan_directory / upload_files_direct call:

            async with scanner.async_session():
                await scanner.scan_files(...)
                await scanner.scan_hashes(...)
        """
        rate_limiter = AsyncRateLimiter(self._requests_per_minute)
        semaphore = asyncio.Semaphore(self.max_workers)
        async with vt.Client(self.api_key) as client:
            self._session_client = client
            self._session_rate_limiter = rate_limiter
            self._session_semaphore = semaphore
            try:
                yield self
            finally:
                self._session_client = None
                self._session_rate_limiter = None
                self._session_semaphore = None

    async def scan_files(
        self,
        file_paths: Iterable[str],
        on_result: Callable[[dict[str, Any]], None] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> list[dict[str, Any]]:
        file_list = list(file_paths)
        if not file_list:
            return []
        results: list[dict[str, Any] | None] = [None] * len(file_list)
        async with self._client_context() as (client, rate_limiter, semaphore):
            if len(file_list) <= self.max_workers:
                return await self._scan_files_small_batch_async(
                    client, rate_limiter, file_list, on_result, cancel_event
                )
            prepare_queue: asyncio.Queue[tuple[int, str] | None] = asyncio.Queue()
            live_queue: asyncio.Queue[tuple[int, str, str] | None] = asyncio.Queue()
            worker_count = self.max_workers

            for idx, file_path in enumerate(file_list):
                prepare_queue.put_nowait((idx, file_path))
            for _ in range(worker_count):
                prepare_queue.put_nowait(None)

            async def _scan_one(idx: int, file_path: str, file_hash: str) -> None:
                result = await self._scan_file_live_async(client, rate_limiter, file_path, file_hash, cancel_event)
                results[idx] = result
                if on_result is not None:
                    on_result(result)

            async with asyncio.TaskGroup() as tg:
                async def _prepare_worker() -> None:
                    while True:
                        item = await prepare_queue.get()
                        try:
                            if item is None:
                                return
                            idx, file_path = item
                            if cancel_event is not None and cancel_event.is_set():
                                result = self._cancelled_result(file_path, "file")
                                results[idx] = result
                                if on_result is not None:
                                    on_result(result)
                                continue
                            immediate, unresolved = await self._prepare_file_scan_async(file_path, cancel_event)
                            if immediate is not None:
                                results[idx] = immediate
                                if on_result is not None:
                                    on_result(immediate)
                                continue
                            if unresolved is not None:
                                unresolved_path, file_hash = unresolved
                                await live_queue.put((idx, unresolved_path, file_hash))
                        finally:
                            prepare_queue.task_done()

                async def _live_worker() -> None:
                    while True:
                        item = await live_queue.get()
                        try:
                            if item is None:
                                return
                            idx, unresolved_path, file_hash = item
                            async with semaphore:
                                if cancel_event is not None and cancel_event.is_set():
                                    result = self._cancelled_result(unresolved_path, "file", file_hash)
                                    results[idx] = result
                                    if on_result is not None:
                                        on_result(result)
                                    continue
                                await _scan_one(idx, unresolved_path, file_hash)
                        finally:
                            live_queue.task_done()

                async def _close_live_queue() -> None:
                    await prepare_queue.join()
                    for _ in range(worker_count):
                        await live_queue.put(None)

                for _ in range(worker_count):
                    tg.create_task(_prepare_worker())
                    tg.create_task(_live_worker())
                tg.create_task(_close_live_queue())
        return [result for result in results if result is not None]

    async def scan_hashes(
        self,
        hashes: Iterable[str],
        on_result: Callable[[dict[str, Any]], None] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> list[dict[str, Any]]:
        hash_list = list(hashes)
        if not hash_list:
            return []
        results: list[dict[str, Any] | None] = [None] * len(hash_list)
        async with self._client_context() as (client, rate_limiter, semaphore):
            if len(hash_list) <= self.max_workers:
                return await self._scan_hashes_small_batch_async(
                    client, rate_limiter, hash_list, on_result, cancel_event
                )
            prepare_queue: asyncio.Queue[tuple[int, str] | None] = asyncio.Queue()
            unique_queue: asyncio.Queue[str | None] = asyncio.Queue()
            completed_queue: asyncio.Queue[tuple[str, dict[str, Any]] | None] = asyncio.Queue()
            worker_count = self.max_workers
            pending_indices: dict[str, list[int]] = {}
            completed_results: dict[str, dict[str, Any]] = {}

            for idx, file_hash in enumerate(hash_list):
                prepare_queue.put_nowait((idx, file_hash))
            for _ in range(worker_count):
                prepare_queue.put_nowait(None)

            async with asyncio.TaskGroup() as tg:
                async def _prepare_worker() -> None:
                    while True:
                        item = await prepare_queue.get()
                        try:
                            if item is None:
                                return
                            idx, file_hash = item
                            if cancel_event is not None and cancel_event.is_set():
                                result = self._cancelled_result(str(file_hash), "hash")
                                results[idx] = result
                                if on_result is not None:
                                    on_result(result)
                                continue
                            immediate, unresolved = await self._prepare_hash_scan_async(file_hash, cancel_event)
                            if immediate is not None:
                                results[idx] = immediate
                                if on_result is not None:
                                    on_result(immediate)
                                continue
                            if unresolved is None:
                                continue
                            cached_result = completed_results.get(unresolved)
                            if cached_result is not None:
                                result = dict(cached_result)
                                results[idx] = result
                                if on_result is not None:
                                    on_result(result)
                                continue
                            waiters = pending_indices.get(unresolved)
                            if waiters is None:
                                pending_indices[unresolved] = [idx]
                                await unique_queue.put(unresolved)
                            else:
                                waiters.append(idx)
                        finally:
                            prepare_queue.task_done()

                async def _live_worker() -> None:
                    while True:
                        normalized_hash = await unique_queue.get()
                        try:
                            if normalized_hash is None:
                                return
                            async with semaphore:
                                if cancel_event is not None and cancel_event.is_set():
                                    await completed_queue.put((normalized_hash, self._cancelled_result(normalized_hash, "hash")))
                                    continue
                                result = await self._scan_hash_live_async(client, rate_limiter, normalized_hash)
                                await completed_queue.put((normalized_hash, result))
                        finally:
                            unique_queue.task_done()

                async def _completion_worker() -> None:
                    while True:
                        item = await completed_queue.get()
                        try:
                            if item is None:
                                return
                            normalized_hash, result = item
                            completed_results[normalized_hash] = result
                            for idx in pending_indices.pop(normalized_hash, []):
                                emitted = dict(result)
                                results[idx] = emitted
                                if on_result is not None:
                                    on_result(emitted)
                        finally:
                            completed_queue.task_done()

                async def _close_unique_queue() -> None:
                    await prepare_queue.join()
                    for _ in range(worker_count):
                        await unique_queue.put(None)

                async def _close_completed_queue() -> None:
                    await unique_queue.join()
                    await completed_queue.put(None)

                for _ in range(worker_count):
                    tg.create_task(_prepare_worker())
                    tg.create_task(_live_worker())
                tg.create_task(_completion_worker())
                tg.create_task(_close_unique_queue())
                tg.create_task(_close_completed_queue())
        return [result for result in results if result is not None]

    async def scan_directory(
        self,
        directory: str,
        recursive: bool = False,
        on_result: Callable[[dict[str, Any]], None] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> list[dict[str, Any]]:
        async def _scan_files_fn(
            fps: Iterable[str],
            on_r: Callable[[dict[str, Any]], None] | None,
            ce: threading.Event | None,
        ) -> list[dict[str, Any]]:
            return await self.scan_files(fps, on_result=on_r, cancel_event=ce)

        return await service_scan.scan_directory_async(
            directory,
            scan_files_fn=_scan_files_fn,
            error_result=self._error_result,
            recursive=recursive,
            on_result=on_result,
            cancel_event=cancel_event,
        )

    async def upload_files_direct(
        self,
        entries: list[tuple[str, str]],
        on_result: Callable[[dict[str, Any]], None] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> list[dict[str, Any]]:
        hash_by_path = {fp: fh for fp, fh in entries}
        async with self._client_context() as (client, rate_limiter, semaphore):
            async def _upload_one(fp: str) -> dict[str, Any]:
                return await self._upload_file_direct_async(
                    client, rate_limiter, fp, hash_by_path[fp], cancel_event
                )
            return await service_scan.scan_many_async(
                semaphore, _upload_one, [fp for fp, _ in entries], on_result=on_result, cancel_event=cancel_event
            )
