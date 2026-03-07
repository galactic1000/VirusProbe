"""Core scan service shared by CLI and GUI."""

from __future__ import annotations

import hashlib
import threading
from collections.abc import Callable, Iterable
from contextlib import suppress
from pathlib import Path
from typing import Any

import vt

from .cache import ScanCache
from .rate_limit import RateLimiter
from . import service_scan
from . import service_upload

DEFAULT_SCAN_WORKERS = 4
DEFAULT_REQUESTS_PER_MINUTE = 4
DEFAULT_UPLOAD_TIMEOUT_MINUTES = service_upload.DEFAULT_UPLOAD_TIMEOUT_MINUTES


class _HashCancelled(Exception):
    """Raised internally when file hashing is interrupted by cancel_event."""


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
        self._rate_limiter = RateLimiter(max_calls=max(0, int(requests_per_minute)))
        self._client_local = threading.local()
        self._clients: list[vt.Client] = []
        self._clients_lock = threading.Lock()
        self._requests_per_minute = max(0, int(requests_per_minute))
        self._upload_timeout_minutes = max(0, int(upload_timeout_minutes))
        self._closed = False

    def init_cache(self) -> None:
        self._cache.init()

    def clear_cache(self) -> int:
        return self._cache.clear()

    def close(self) -> None:
        self._cache.close()
        with self._clients_lock:
            self._closed = True
            clients = self._clients
            self._clients = []
        for client in clients:
            with suppress(Exception):
                client.close()

    def _get_client(self) -> vt.Client:
        if self._closed:
            raise RuntimeError("ScannerService has been closed")
        client = getattr(self._client_local, "client", None)
        if client is None:
            client = vt.Client(self.api_key)
            self._client_local.client = client
            with self._clients_lock:
                self._clients.append(client)
        return client

    @staticmethod
    def hash_file(file_path: str, cancel_event: threading.Event | None = None) -> str:
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                if cancel_event is not None and cancel_event.is_set():
                    raise _HashCancelled()
                hasher.update(chunk)
        return hasher.hexdigest()

    @staticmethod
    def _hash_item(value: object) -> str:
        return f"SHA-256 hash: {value}"

    @staticmethod
    def _error_result(item: str, item_type: str, message: str, file_hash: str = "") -> dict[str, Any]:
        return {
            "item": item,
            "type": item_type,
            "file_hash": file_hash,
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "threat_level": "Error",
            "status": "error",
            "message": message,
            "was_cached": False,
            "was_uploaded": False,
        }

    @staticmethod
    def _cancelled_result(item: str, item_type: str, file_hash: str = "") -> dict[str, Any]:
        return {
            "item": item,
            "type": item_type,
            "file_hash": file_hash,
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "threat_level": "Cancelled",
            "status": "cancelled",
            "message": "Cancelled by user",
            "was_cached": False,
            "was_uploaded": False,
        }

    @classmethod
    def _hash_error(cls, value: object, message: str, file_hash: str = "") -> dict[str, Any]:
        return cls._error_result(item=cls._hash_item(value), item_type="hash", message=message, file_hash=file_hash)

    @classmethod
    def _not_found_result(cls, normalized_hash: str) -> dict[str, Any]:
        return {
            "item": cls._hash_item(normalized_hash),
            "type": "hash",
            "file_hash": normalized_hash,
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "threat_level": "Undetected",
            "status": "undetected",
            "message": "No VirusTotal record found",
            "was_cached": False,
            "was_uploaded": False,
        }

    def scan_file(self, file_path: str, cancel_event: threading.Event | None = None) -> dict[str, Any]:
        if cancel_event is not None and cancel_event.is_set():
            return self._cancelled_result(file_path, "file")
        path = Path(file_path)
        if not path.exists():
            return self._error_result(file_path, "file", f"File '{file_path}' does not exist")
        if not path.is_file():
            return self._error_result(file_path, "file", f"'{file_path}' is not a file")
        return self._scan_file_verified(file_path, cancel_event=cancel_event)

    def _scan_file_verified(self, file_path: str, cancel_event: threading.Event | None = None) -> dict[str, Any]:
        try:
            file_hash = self.hash_file(file_path, cancel_event)
        except _HashCancelled:
            return self._cancelled_result(file_path, "file")
        except OSError as exc:
            return self._error_result(file_path, "file", str(exc))

        try:
            (malicious, suspicious, harmless, undetected), was_cached = self._query_virustotal(file_hash)
        except vt.APIError as exc:
            if exc.code == "NotFoundError" and self.upload_undetected and (self.upload_filter is None or self.upload_filter(file_path)):
                if cancel_event is None:
                    return self._upload_and_scan(file_path, file_hash)
                return self._upload_and_scan(file_path, file_hash, cancel_event=cancel_event)
            if exc.code == "NotFoundError":
                result = self._not_found_result(file_hash)
                result.update({"item": file_path, "type": "file"})
                return result
            result = self._hash_error(file_hash, str(exc), file_hash)
            result.update({"item": file_path, "type": "file"})
            return result
        except ValueError as exc:
            result = self._error_result(file_path, "file", f"Unexpected VT response: {exc}", file_hash)
            return result
        except Exception as exc:
            result = self._hash_error(file_hash, str(exc), file_hash)
            result.update({"item": file_path, "type": "file"})
            return result

        return {
            "item": file_path,
            "type": "file",
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

    def scan_hash(self, file_hash: str, cancel_event: threading.Event | None = None) -> dict[str, Any]:
        if cancel_event is not None and cancel_event.is_set():
            return self._cancelled_result(str(file_hash), "hash")
        if not isinstance(file_hash, str):
            return self._hash_error(file_hash, "Invalid SHA-256 hash format")
        normalized_input = file_hash.strip()
        if not self.is_sha256(normalized_input):
            return self._hash_error(normalized_input, "Invalid SHA-256 hash format", normalized_input.lower())

        normalized_hash = normalized_input.lower()
        try:
            (malicious, suspicious, harmless, undetected), was_cached = self._query_virustotal(normalized_hash)
        except vt.APIError as exc:
            if exc.code == "NotFoundError":
                return self._not_found_result(normalized_hash)
            return self._hash_error(normalized_hash, str(exc), normalized_hash)
        except ValueError:
            return self._not_found_result(normalized_hash)
        except Exception as exc:
            return self._hash_error(normalized_hash, str(exc), normalized_hash)

        return {
            "item": self._hash_item(normalized_hash),
            "type": "hash",
            "file_hash": normalized_hash,
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
    def _extract_stats(response: dict[str, Any]) -> tuple[int, int, int, int]:
        stats: Any = None
        if isinstance(response, dict):
            stats = response.get("data", {}).get("attributes", {}).get("last_analysis_stats")
        if not isinstance(stats, dict):
            raise ValueError("VirusTotal response missing analysis stats")
        return (
            int(stats["malicious"]),
            int(stats["suspicious"]),
            int(stats["harmless"]),
            int(stats["undetected"]),
        )

    def _query_virustotal(self, file_hash: str) -> tuple[tuple[int, int, int, int], bool]:
        cached = self._cache.get(file_hash)
        if cached is not None:
            return cached, True
        self._rate_limiter.acquire()
        client = self._get_client()
        response_json = client.get(f"/files/{file_hash}").json()
        stats = self._extract_stats(response_json)
        try:
            self._cache.save(file_hash, stats)
        except Exception:
            pass
        return stats, False

    def _upload_file(self, file_path: str) -> str:
        return service_upload.upload_file(
            get_client=self._get_client,
            rate_limit_acquire=self._rate_limiter.acquire,
            file_path=file_path,
        )

    def _poll_analysis(self, analysis_id: str, cancel_event: threading.Event | None = None) -> tuple[int, int, int, int]:
        return service_upload.poll_analysis(
            get_client=self._get_client,
            rate_limit_acquire=self._rate_limiter.acquire,
            requests_per_minute=self._requests_per_minute,
            timeout_minutes=self._upload_timeout_minutes,
            analysis_id=analysis_id,
            cancel_event=cancel_event,
        )

    def _upload_and_scan(self, file_path: str, file_hash: str, cancel_event: threading.Event | None = None) -> dict[str, Any]:
        return service_upload.upload_and_scan(
            upload_file_fn=self._upload_file,
            poll_analysis_fn=self._poll_analysis,
            cache_save=self._cache.save,
            classify_threat=self.classify_threat,
            error_result=self._error_result,
            cancelled_result=self._cancelled_result,
            file_path=file_path,
            file_hash=file_hash,
            cancel_event=cancel_event,
        )

    def upload_file_direct(
        self,
        file_path: str,
        file_hash: str,
        cancel_event: threading.Event | None = None,
    ) -> dict[str, Any]:
        """Upload a file directly, skipping the VirusTotal hash lookup."""
        if cancel_event is not None and cancel_event.is_set():
            return self._cancelled_result(file_path, "file", file_hash)
        path = Path(file_path)
        if not path.exists():
            return self._error_result(file_path, "file", f"File not found: {file_path}", file_hash)
        if not path.is_file():
            return self._error_result(file_path, "file", f"Not a file: {file_path}", file_hash)
        if not file_hash:
            try:
                file_hash = self.hash_file(file_path, cancel_event)
            except _HashCancelled:
                return self._cancelled_result(file_path, "file")
            except OSError as exc:
                return self._error_result(file_path, "file", str(exc))
        return self._upload_and_scan(file_path, file_hash, cancel_event=cancel_event)

    def upload_files_direct(
        self,
        entries: list[tuple[str, str]],
        on_result: Callable[[dict[str, Any]], None] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> list[dict[str, Any]]:
        """Upload files directly using known hashes, skipping the VirusTotal hash lookup."""
        hash_by_path = {file_path: file_hash for file_path, file_hash in entries}

        def _upload_one(file_path: str) -> dict[str, Any]:
            return self.upload_file_direct(file_path, hash_by_path[file_path], cancel_event=cancel_event)

        return service_scan.scan_many(
            self.max_workers,
            _upload_one,
            [fp for fp, _ in entries],
            on_result=on_result,
            cancel_event=cancel_event,
        )

    def scan_files(
        self,
        file_paths: Iterable[str],
        on_result: Callable[[dict[str, Any]], None] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> list[dict[str, Any]]:
        return service_scan.scan_files(
            max_workers=self.max_workers,
            scan_file=self.scan_file,
            file_paths=file_paths,
            on_result=on_result,
            cancel_event=cancel_event,
        )

    def scan_hashes(
        self,
        hashes: Iterable[str],
        on_result: Callable[[dict[str, Any]], None] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> list[dict[str, Any]]:
        return service_scan.scan_hashes(
            max_workers=self.max_workers,
            scan_hash=self.scan_hash,
            hashes=hashes,
            on_result=on_result,
            cancel_event=cancel_event,
        )

    def scan_directory(
        self,
        directory: str,
        recursive: bool = False,
        on_result: Callable[[dict[str, Any]], None] | None = None,
        cancel_event: threading.Event | None = None,
    ) -> list[dict[str, Any]]:
        return service_scan.scan_directory(
            directory,
            scan_files=self.scan_files,
            error_result=self._error_result,
            recursive=recursive,
            on_result=on_result,
            cancel_event=cancel_event,
        )

