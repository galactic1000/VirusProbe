"""Core scan service shared by CLI and GUI."""

from __future__ import annotations

import hashlib
import threading
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from itertools import chain
from pathlib import Path
from typing import Any

import vt

from .cache import ScanCache

DEFAULT_SCAN_WORKERS = 4
_HEX_CHARS: frozenset[str] = frozenset("0123456789abcdefABCDEF")


class ScannerService:
    """VirusTotal scanner backed by ScanCache."""

    def __init__(
        self,
        api_key: str,
        cache_db: Path,
        cache_expiry_days: int = 7,
        cache_max_rows: int = 10000,
        memory_cache_max_entries: int = 512,
        max_workers: int = DEFAULT_SCAN_WORKERS,
    ) -> None:
        self.api_key = api_key
        self.max_workers = max(1, int(max_workers))
        self._cache = ScanCache(
            cache_db=cache_db,
            cache_expiry_days=cache_expiry_days,
            cache_max_rows=cache_max_rows,
            memory_cache_max_entries=memory_cache_max_entries,
        )
        self._client_local = threading.local()
        self._clients: list[vt.Client] = []
        self._clients_lock = threading.Lock()

    def init_cache(self) -> None:
        self._cache.init()

    def clear_cache(self) -> int:
        return self._cache.clear()

    def close(self) -> None:
        self._cache.close()
        with self._clients_lock:
            clients = self._clients
            self._clients = []
        for client in clients:
            with suppress(Exception):
                client.close()

    def _get_client(self) -> vt.Client:
        client = getattr(self._client_local, "client", None)
        if client is None:
            client = vt.Client(self.api_key)
            self._client_local.client = client
            with self._clients_lock:
                self._clients.append(client)
        return client

    @staticmethod
    def hash_file(file_path: str) -> str:
        """Returns SHA256 hash for a file."""
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
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
        }

    def _scan_many(self, scan_func: Callable[[str], dict[str, Any]], items: Iterable[str]) -> list[dict[str, Any]]:
        item_iter = iter(items)
        try:
            first = next(item_iter)
        except StopIteration:
            return []
        try:
            second = next(item_iter)
        except StopIteration:
            return [scan_func(first)]
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            return list(executor.map(scan_func, chain((first, second), item_iter)))

    def scan_files(self, file_paths: Iterable[str]) -> list[dict[str, Any]]:
        return self._scan_many(self.scan_file, file_paths)

    def scan_hashes(self, hashes: Iterable[str]) -> list[dict[str, Any]]:
        return self._scan_many(self.scan_hash, hashes)

    def scan_file(self, file_path: str) -> dict[str, Any]:
        """Scans a file path by hash."""
        path = Path(file_path)
        if not path.exists():
            return self._error_result(file_path, "file", f"File '{file_path}' does not exist")
        if not path.is_file():
            return self._error_result(file_path, "file", f"'{file_path}' is not a file")
        return self._scan_file_verified(file_path)

    def _scan_file_verified(self, file_path: str) -> dict[str, Any]:
        try:
            file_hash = self.hash_file(file_path)
        except OSError as exc:
            return self._error_result(file_path, "file", str(exc))
        result = self.scan_hash(file_hash)
        result.update({"item": file_path, "type": "file", "file_hash": file_hash})
        return result

    def scan_hash(self, file_hash: str) -> dict[str, Any]:
        """Scans a hash and returns a normalized result payload."""
        if not isinstance(file_hash, str):
            return self._hash_error(file_hash, "Invalid SHA-256 hash format")

        normalized_input = file_hash.strip()
        if not self.is_sha256(normalized_input):
            return self._hash_error(normalized_input, "Invalid SHA-256 hash format", normalized_input.lower())

        normalized_hash = normalized_input.lower()
        try:
            vt_response, was_cached = self._query_virustotal(normalized_hash)
            malicious, suspicious, harmless, undetected = self._extract_stats(vt_response)
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
            "threat_level": self.classify_threat(malicious),
            "status": "ok",
            "message": "Using cached result" if was_cached else "Queried VirusTotal API",
            "was_cached": was_cached,
        }

    def scan_directory(self, directory: str, recursive: bool = False) -> list[dict[str, Any]]:
        """Scans files in a directory concurrently."""
        path = Path(directory)
        if not path.exists():
            raise FileNotFoundError(f"Directory '{directory}' does not exist")
        if not path.is_dir():
            raise NotADirectoryError(f"'{directory}' is not a directory")
        files = (str(f) for f in (path.rglob("*") if recursive else path.iterdir()) if f.is_file())
        return self.scan_files(files)

    def scan_items(self, items: list[str]) -> list[dict[str, Any]]:
        """Scans a mixed list of file paths and hashes."""
        return self._scan_many(lambda item: self.scan_hash(item) if self.is_sha256(item) else self.scan_file(item), items)

    @staticmethod
    def is_sha256(value: str) -> bool:
        return len(value) == 64 and all(c in _HEX_CHARS for c in value)

    @staticmethod
    def classify_threat(malicious_count: int) -> str:
        if malicious_count >= 10:
            return "Malicious"
        if malicious_count > 0:
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

    def _query_virustotal(self, file_hash: str) -> tuple[dict[str, Any], bool]:
        cached = self._cache.get(file_hash)
        if cached is not None:
            return cached, True

        client = self._get_client()
        response_json = client.get(f"/files/{file_hash}").json()
        self._cache.save(file_hash, self._extract_stats(response_json))
        return response_json, False

