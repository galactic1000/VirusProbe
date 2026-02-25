"""Core scan service shared by CLI and GUI."""

from __future__ import annotations

import hashlib
import sqlite3
import struct
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any

import vt

_HEX_CHARS: frozenset[str] = frozenset("0123456789abcdefABCDEF")


class ScannerService:
    """VirusTotal scanner with bounded memory + SQLite cache."""

    def __init__(
        self,
        api_key: str,
        cache_db: Path,
        cache_expiry_days: int = 7,
        cache_max_rows: int = 10000,
        memory_cache_max_entries: int = 512,
    ) -> None:
        self.api_key = api_key
        self.cache_db = cache_db
        self.cache_expiry_days = cache_expiry_days
        self.cache_max_rows = cache_max_rows
        self.memory_cache_max_entries = memory_cache_max_entries
        self._cache_expiry_seconds: int = cache_expiry_days * 24 * 60 * 60
        self.memory_cache: OrderedDict[str, tuple[int, int, int, int]] = OrderedDict()

    def init_cache(self) -> None:
        """Initializes and compacts SQLite cache."""
        self.cache_db.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.cache_db)
        try:
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.execute("PRAGMA table_info(scans)")
            existing_columns = {row[1] for row in cursor.fetchall()}
            if existing_columns and not {"hash", "stats", "timestamp"}.issubset(existing_columns):
                cursor.execute("DROP TABLE IF EXISTS scans")

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    hash BLOB PRIMARY KEY,
                    stats BLOB NOT NULL,
                    timestamp INTEGER NOT NULL
                )
                """
            )
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp)")
            cutoff_ts = int(time.time()) - self._cache_expiry_seconds
            cursor.execute("DELETE FROM scans WHERE timestamp < ?", (cutoff_ts,))
            cursor.execute("SELECT COUNT(*) FROM scans")
            row_count = int(cursor.fetchone()[0])
            if row_count > self.cache_max_rows:
                to_delete = row_count - self.cache_max_rows
                cursor.execute(
                    """
                    DELETE FROM scans
                    WHERE rowid IN (
                        SELECT rowid FROM scans
                        ORDER BY timestamp ASC
                        LIMIT ?
                    )
                    """,
                    (to_delete,),
                )
            conn.commit()
        finally:
            conn.close()

    def clear_cache(self) -> int:
        """Clears cached scan rows and returns the number of deleted entries."""
        self.cache_db.parent.mkdir(parents=True, exist_ok=True)
        self.memory_cache.clear()
        conn = sqlite3.connect(self.cache_db)
        try:
            cursor = conn.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    hash BLOB PRIMARY KEY,
                    stats BLOB NOT NULL,
                    timestamp INTEGER NOT NULL
                )
                """
            )
            cursor.execute("SELECT COUNT(*) FROM scans")
            deleted = int(cursor.fetchone()[0])
            cursor.execute("DELETE FROM scans")
            cursor.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            conn.commit()
        finally:
            conn.close()
        return deleted

    @staticmethod
    def hash_file(file_path: str) -> str:
        """Returns SHA256 hash for file."""
        hasher = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                hasher.update(chunk)
        return hasher.hexdigest()

    @staticmethod
    def _error_result(item: str, item_type: str, message: str, file_hash: str = "") -> dict[str, Any]:
        """Builds a standardized error result payload."""
        return {
            "item": item,
            "type": item_type,
            "file_hash": file_hash,
            "malicious": 0,
            "suspicious": 0,
            "harmless": 0,
            "undetected": 0,
            "threat_level": "Undetected",
            "status": "error",
            "message": message,
            "was_cached": False,
        }

    def scan_file(self, file_path: str) -> dict[str, Any]:
        """Scans a file path by hash."""
        path = Path(file_path)
        if not path.exists():
            return self._error_result(file_path, "file", f"File '{file_path}' does not exist")
        if not path.is_file():
            return self._error_result(file_path, "file", f"'{file_path}' is not a file")
        return self._scan_file_verified(file_path)

    def _scan_file_verified(self, file_path: str) -> dict[str, Any]:
        """Scans a file path assuming it exists and is a file."""
        try:
            file_hash = self.hash_file(file_path)
        except OSError as exc:
            return self._error_result(file_path, "file", str(exc))

        result = self.scan_hash(file_hash)
        result["item"] = file_path
        result["type"] = "file"
        result["file_hash"] = file_hash
        return result

    def scan_hash(self, file_hash: str) -> dict[str, Any]:
        """Scans a hash and returns normalized result payload."""
        normalized_hash = self._normalize_hash(file_hash)
        try:
            vt_response, was_cached = self._query_virustotal(normalized_hash)
            malicious, suspicious, harmless, undetected = self._extract_stats(vt_response)
        except vt.APIError as exc:
            if exc.code == "NotFoundError":
                return {
                    "item": f"SHA-256 Hash: {normalized_hash}",
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
            return self._error_result(
                item=f"SHA-256 Hash: {normalized_hash}",
                item_type="hash",
                message=str(exc),
                file_hash=normalized_hash,
            )
        except ValueError:
            return {
                "item": f"SHA-256 Hash: {normalized_hash}",
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
        except Exception as exc:
            return self._error_result(
                item=f"SHA-256 Hash: {normalized_hash}",
                item_type="hash",
                message=str(exc),
                file_hash=normalized_hash,
            )

        result = {
            "item": f"SHA-256 Hash: {normalized_hash}",
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
        return result

    def scan_directory(self, directory: str, recursive: bool = False) -> list[dict[str, Any]]:
        """Scans files in directory."""
        path = Path(directory)
        if not path.exists():
            raise FileNotFoundError(f"Directory '{directory}' does not exist")
        if not path.is_dir():
            raise NotADirectoryError(f"'{directory}' is not a directory")

        files = [f for f in (path.rglob("*") if recursive else path.iterdir()) if f.is_file()]
        results: list[dict[str, Any]] = []
        for file_path in files:
            try:
                results.append(self.scan_file(str(file_path)))
            except Exception as exc:
                results.append(self._error_result(str(file_path), "file", str(exc)))
        return results

    def scan_items(self, items: list[str]) -> list[dict[str, Any]]:
        """Scans mixed file paths and hashes."""
        results: list[dict[str, Any]] = []
        for item in items:
            if self.is_sha256(item):
                results.append(self.scan_hash(item))
                continue
            path = Path(item)
            # Skip invalid file inputs so callers can decide how to report them.
            if not path.exists() or not path.is_file():
                continue
            results.append(self._scan_file_verified(item))
        return results

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
    def _normalize_hash(file_hash: str) -> str:
        return file_hash.lower()

    def _hash_hex_to_bytes(self, file_hash: str) -> bytes:
        return bytes.fromhex(self._normalize_hash(file_hash))

    def _cache_cutoff_ts(self) -> int:
        return int(time.time()) - self._cache_expiry_seconds

    @staticmethod
    def _build_vt_like_response(stats: tuple[int, int, int, int]) -> dict[str, Any]:
        malicious, suspicious, harmless, undetected = stats
        return {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": malicious,
                        "suspicious": suspicious,
                        "harmless": harmless,
                        "undetected": undetected,
                    }
                }
            }
        }

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

    @staticmethod
    def _pack_stats(stats: tuple[int, int, int, int]) -> bytes:
        return struct.pack(">4I", *stats)

    @staticmethod
    def _unpack_stats(blob: bytes) -> tuple[int, int, int, int]:
        return struct.unpack(">4I", blob)

    def _memory_cache_get(self, file_hash: str) -> tuple[int, int, int, int] | None:
        result = self.memory_cache.get(file_hash)
        if result is not None:
            self.memory_cache.move_to_end(file_hash)
        return result

    def _memory_cache_set(self, file_hash: str, stats: tuple[int, int, int, int]) -> None:
        self.memory_cache[file_hash] = stats
        self.memory_cache.move_to_end(file_hash)
        if len(self.memory_cache) > self.memory_cache_max_entries:
            self.memory_cache.popitem(last=False)

    def _get_from_cache(self, file_hash: str) -> dict[str, Any] | None:
        hash_bytes = self._hash_hex_to_bytes(file_hash)
        conn = sqlite3.connect(self.cache_db)
        try:
            cursor = conn.cursor()
            cursor.execute("SELECT stats, timestamp FROM scans WHERE hash = ?", (hash_bytes,))
            result = cursor.fetchone()
            if result:
                stats_blob, timestamp = result
                if int(timestamp) >= self._cache_cutoff_ts():
                    return self._build_vt_like_response(self._unpack_stats(stats_blob))
                cursor.execute("DELETE FROM scans WHERE hash = ?", (hash_bytes,))
                conn.commit()
            return None
        finally:
            conn.close()

    def _save_to_cache(self, file_hash: str, response: dict[str, Any]) -> None:
        stats = self._extract_stats(response)
        self._memory_cache_set(file_hash, stats)

        conn = sqlite3.connect(self.cache_db)
        try:
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO scans (hash, stats, timestamp) VALUES (?, ?, ?)",
                (self._hash_hex_to_bytes(file_hash), self._pack_stats(stats), int(time.time())),
            )
            cursor.execute(
                """
                DELETE FROM scans
                WHERE rowid IN (
                    SELECT rowid FROM scans
                    ORDER BY timestamp ASC
                    LIMIT (
                        SELECT CASE WHEN COUNT(*) > ? THEN COUNT(*) - ? ELSE 0 END FROM scans
                    )
                )
                """,
                (self.cache_max_rows, self.cache_max_rows),
            )
            conn.commit()
        finally:
            conn.close()

    def _query_virustotal(self, file_hash: str) -> tuple[dict[str, Any], bool]:
        normalized_hash = self._normalize_hash(file_hash)
        in_memory_stats = self._memory_cache_get(normalized_hash)
        if in_memory_stats:
            return self._build_vt_like_response(in_memory_stats), True

        cached_response = self._get_from_cache(normalized_hash)
        if cached_response:
            self._memory_cache_set(normalized_hash, self._extract_stats(cached_response))
            return cached_response, True

        with vt.Client(self.api_key) as client:
            response = client.get(f"/files/{normalized_hash}")
            response_json = response.json()

        self._extract_stats(response_json)
        self._save_to_cache(normalized_hash, response_json)
        return response_json, False
