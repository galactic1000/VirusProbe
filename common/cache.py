"""SQLite + in-memory LRU cache for VirusTotal scan results."""

from __future__ import annotations

import sqlite3
import struct
import threading
import time
from collections import OrderedDict
from pathlib import Path
from typing import Any


class ScanCache:
    """Two-level cache: bounded in-memory LRU backed by SQLite."""

    _TRIM_INTERVAL_WRITES = 50
    _WAL_AUTOCHECKPOINT_PAGES = 1000
    _CACHE_SIZE_KIB = 4096

    def __init__(
        self,
        cache_db: Path,
        cache_expiry_days: int = 7,
        cache_max_rows: int = 10000,
        memory_cache_max_entries: int = 512,
    ) -> None:
        self.cache_db = cache_db
        self._expiry_seconds: int = cache_expiry_days * 24 * 60 * 60
        self._max_rows = cache_max_rows
        self._memory: OrderedDict[str, tuple[int, int, int, int]] = OrderedDict()
        self._memory_max = memory_cache_max_entries
        self._conn: sqlite3.Connection | None = None
        self._lock = threading.Lock()
        self._writes_since_trim = 0

    def _get_conn(self) -> sqlite3.Connection:
        """Returns the persistent connection, opening it if needed. Must be called with _lock held."""
        if self._conn is None:
            self.cache_db.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(self.cache_db), check_same_thread=False)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.execute(f"PRAGMA wal_autocheckpoint={self._WAL_AUTOCHECKPOINT_PAGES}")
            self._conn.execute(f"PRAGMA cache_size=-{self._CACHE_SIZE_KIB}")
            self._conn.execute("PRAGMA temp_store=MEMORY")
        return self._conn

    def close(self) -> None:
        """Closes the persistent connection."""
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def init(self) -> None:
        """Creates the DB table and prunes expired/excess rows."""
        with self._lock:
            conn = self._get_conn()
            cursor = conn.cursor()
            self._ensure_schema(cursor)
            self._prune_locked(cursor)
            conn.commit()

    def clear(self) -> int:
        """Deletes all cached rows and returns the count deleted."""
        with self._lock:
            self._memory.clear()
            conn = self._get_conn()
            cursor = conn.cursor()
            self._ensure_schema(cursor)
            cursor.execute("SELECT COUNT(*) FROM scans")
            deleted = int(cursor.fetchone()[0])
            cursor.execute("DELETE FROM scans")
            cursor.execute("PRAGMA wal_checkpoint(TRUNCATE)")
            conn.commit()
        return deleted

    def get(self, file_hash: str) -> dict[str, Any] | None:
        """Returns a VT-like response dict if cached and fresh, else None."""
        with self._lock:
            stats = self._memory_get(file_hash)
            if stats is not None:
                return self._build_response(stats)

            conn = self._get_conn()
            cursor = conn.cursor()
            hash_bytes = self._to_bytes(file_hash)
            cursor.execute("SELECT stats, timestamp FROM scans WHERE hash = ?", (hash_bytes,))
            row = cursor.fetchone()
            if row:
                stats_blob, timestamp = row
                if int(timestamp) >= self._cutoff_ts():
                    stats = self._unpack(stats_blob)
                    self._memory_set(file_hash, stats)
                    return self._build_response(stats)
                cursor.execute("DELETE FROM scans WHERE hash = ?", (hash_bytes,))
                conn.commit()
        return None

    def save(self, file_hash: str, stats: tuple[int, int, int, int]) -> None:
        """Saves scan stats to memory and SQLite."""
        with self._lock:
            self._memory_set(file_hash, stats)
            conn = self._get_conn()
            cursor = conn.cursor()
            cursor.execute(
                "INSERT OR REPLACE INTO scans (hash, stats, timestamp) VALUES (?, ?, ?)",
                (self._to_bytes(file_hash), self._pack(stats), int(time.time())),
            )
            self._writes_since_trim += 1
            if self._writes_since_trim >= self._TRIM_INTERVAL_WRITES:
                cursor.execute("DELETE FROM scans WHERE timestamp < ?", (self._cutoff_ts(),))
                self._enforce_row_cap_locked(cursor)
                self._writes_since_trim = 0
            conn.commit()

    @staticmethod
    def _create_scans_table_sql() -> str:
        return (
            "CREATE TABLE IF NOT EXISTS scans ("
            "hash BLOB PRIMARY KEY, "
            "stats BLOB NOT NULL, "
            "timestamp INTEGER NOT NULL"
            ") WITHOUT ROWID"
        )

    @staticmethod
    def _has_required_columns(cursor: sqlite3.Cursor) -> bool:
        cursor.execute("PRAGMA table_info(scans)")
        existing_columns = {row[1] for row in cursor.fetchall()}
        return {"hash", "stats", "timestamp"}.issubset(existing_columns)

    @staticmethod
    def _is_without_rowid(cursor: sqlite3.Cursor) -> bool:
        cursor.execute("SELECT sql FROM sqlite_master WHERE type='table' AND name='scans'")
        row = cursor.fetchone()
        if not row or not row[0]:
            return False
        return "WITHOUT ROWID" in str(row[0]).upper()

    def _ensure_schema(self, cursor: sqlite3.Cursor) -> None:
        cursor.execute(self._create_scans_table_sql())
        if not self._has_required_columns(cursor):
            cursor.execute("DROP TABLE IF EXISTS scans")
            cursor.execute(self._create_scans_table_sql())
        elif not self._is_without_rowid(cursor):
            cursor.execute("DROP TABLE IF EXISTS scans_new")
            cursor.execute(
                """
                CREATE TABLE scans_new (
                    hash BLOB PRIMARY KEY,
                    stats BLOB NOT NULL,
                    timestamp INTEGER NOT NULL
                ) WITHOUT ROWID
                """
            )
            cursor.execute("INSERT OR REPLACE INTO scans_new (hash, stats, timestamp) SELECT hash, stats, timestamp FROM scans")
            cursor.execute("DROP TABLE scans")
            cursor.execute("ALTER TABLE scans_new RENAME TO scans")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp)")

    def _enforce_row_cap_locked(self, cursor: sqlite3.Cursor) -> None:
        cursor.execute("SELECT COUNT(*) FROM scans")
        overflow = int(cursor.fetchone()[0]) - self._max_rows
        if overflow > 0:
            cursor.execute(
                """
                DELETE FROM scans
                WHERE hash IN (
                    SELECT hash FROM scans
                    ORDER BY timestamp ASC
                    LIMIT ?
                )
                """,
                (overflow,),
            )

    def _prune_locked(self, cursor: sqlite3.Cursor) -> None:
        cursor.execute("DELETE FROM scans WHERE timestamp < ?", (self._cutoff_ts(),))
        self._enforce_row_cap_locked(cursor)

    def _cutoff_ts(self) -> int:
        return int(time.time()) - self._expiry_seconds

    @staticmethod
    def _to_bytes(file_hash: str) -> bytes:
        return bytes.fromhex(file_hash)

    @staticmethod
    def _pack(stats: tuple[int, int, int, int]) -> bytes:
        return struct.pack(">4I", *stats)

    @staticmethod
    def _unpack(blob: bytes) -> tuple[int, int, int, int]:
        return struct.unpack(">4I", blob)

    def _memory_get(self, file_hash: str) -> tuple[int, int, int, int] | None:
        result = self._memory.get(file_hash)
        if result is not None:
            self._memory.move_to_end(file_hash)
        return result

    def _memory_set(self, file_hash: str, stats: tuple[int, int, int, int]) -> None:
        self._memory[file_hash] = stats
        self._memory.move_to_end(file_hash)
        if len(self._memory) > self._memory_max:
            self._memory.popitem(last=False)

    @staticmethod
    def _build_response(stats: tuple[int, int, int, int]) -> dict[str, Any]:
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
