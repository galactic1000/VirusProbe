from __future__ import annotations

import sqlite3
import time
from pathlib import Path

import pytest

from common.cache import ScanCache


def _row_count(db_path: Path) -> int:
    with sqlite3.connect(str(db_path)) as conn:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM scans")
        return int(cur.fetchone()[0])


def test_cache_roundtrip(tmp_path) -> None:
    db = tmp_path / "vt_cache.db"
    cache = ScanCache(cache_db=db)
    cache.init()
    try:
        cache.save("a" * 64, (1, 2, 3, 4))
        result = cache.get("a" * 64)
    finally:
        cache.close()

    assert result == (1, 2, 3, 4)


def test_cache_stale_row_deleted_on_read(tmp_path) -> None:
    db = tmp_path / "vt_cache.db"
    cache = ScanCache(cache_db=db)
    cache.init()
    try:
        file_hash = "b" * 64
        cache.save(file_hash, (0, 0, 0, 0))
        conn = cache._get_conn()  # noqa: SLF001
        conn.execute("UPDATE scans SET timestamp = 0 WHERE hash = ?", (bytes.fromhex(file_hash),))
        conn.commit()
        cache._memory.clear()  # noqa: SLF001

        assert cache.get(file_hash) is None

        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM scans WHERE hash = ?", (bytes.fromhex(file_hash),))
        remaining = int(cur.fetchone()[0])
    finally:
        cache.close()

    assert remaining == 0


def test_cache_enforces_row_cap_per_save(tmp_path) -> None:
    db = tmp_path / "vt_cache.db"
    cache = ScanCache(cache_db=db, cache_max_rows=2)
    cache.init()
    try:
        cache.save("0" * 64, (0, 0, 0, 0))
        cache.save("1" * 64, (1, 0, 0, 0))
        cache.save("2" * 64, (2, 0, 0, 0))
    finally:
        cache.close()

    assert _row_count(db) == 2


def test_cache_init_prunes_expired_rows(tmp_path) -> None:
    db = tmp_path / "vt_cache.db"
    cache = ScanCache(cache_db=db)
    cache.init()
    try:
        file_hash = "c" * 64
        cache.save(file_hash, (0, 0, 0, 0))
        conn = cache._get_conn()  # noqa: SLF001
        conn.execute("UPDATE scans SET timestamp = 0 WHERE hash = ?", (bytes.fromhex(file_hash),))
        conn.commit()
    finally:
        cache.close()

    cache2 = ScanCache(cache_db=db)
    cache2.init()
    try:
        assert _row_count(db) == 0
    finally:
        cache2.close()


def test_cache_init_enforces_row_cap_on_existing_db(tmp_path) -> None:
    db = tmp_path / "vt_cache.db"
    cache = ScanCache(cache_db=db, cache_max_rows=5)
    cache.init()
    try:
        for index in range(5):
            cache.save(f"{index:064x}", (index, 0, 0, 0))
    finally:
        cache.close()

    with sqlite3.connect(str(db)) as conn:
        conn.execute(
            "INSERT INTO scans (hash, stats, timestamp) VALUES (?, ?, ?)",
            (bytes.fromhex("f" * 64), sqlite3.Binary(b"\x00" * 16), int(time.time())),
        )
        conn.commit()

    cache2 = ScanCache(cache_db=db, cache_max_rows=5)
    cache2.init()
    try:
        assert _row_count(db) == 5
    finally:
        cache2.close()


def test_memory_cache_lru_eviction(tmp_path) -> None:
    db = tmp_path / "vt_cache.db"
    cache = ScanCache(cache_db=db, memory_cache_max_entries=2)
    cache.init()
    try:
        cache.save("1" * 64, (1, 0, 0, 0))
        cache.save("2" * 64, (2, 0, 0, 0))
        cache.save("3" * 64, (3, 0, 0, 0))
        memory_keys = list(cache._memory.keys())  # noqa: SLF001
    finally:
        cache.close()

    assert len(memory_keys) == 2
    assert "1" * 64 not in memory_keys


def test_memory_cache_entry_expires_without_restart(tmp_path) -> None:
    db = tmp_path / "vt_cache.db"
    cache = ScanCache(cache_db=db, cache_expiry_days=1)
    cache.init()
    try:
        file_hash = "d" * 64
        cache.save(file_hash, (4, 3, 2, 1))
        conn = cache._get_conn()  # noqa: SLF001
        conn.execute("UPDATE scans SET timestamp = 0 WHERE hash = ?", (bytes.fromhex(file_hash),))
        conn.commit()
        cache._memory[file_hash] = ((4, 3, 2, 1), 0)  # noqa: SLF001

        assert cache.get(file_hash) is None
        assert file_hash not in cache._memory  # noqa: SLF001
    finally:
        cache.close()


def test_cache_save_does_not_populate_memory_when_commit_fails(monkeypatch, tmp_path) -> None:
    class _FakeCursor:
        rowcount = 1

        def execute(self, _sql, _params=None) -> None:
            return None

        def fetchone(self):
            return None

    class _FakeConnection:
        def __init__(self) -> None:
            self._cursor = _FakeCursor()
            self.rollback_called = False

        def cursor(self) -> _FakeCursor:
            return self._cursor

        def commit(self) -> None:
            raise sqlite3.OperationalError("commit failed")

        def rollback(self) -> None:
            self.rollback_called = True

    db = tmp_path / "vt_cache.db"
    cache = ScanCache(cache_db=db)
    fake_conn = _FakeConnection()
    cache._row_count = 4  # noqa: SLF001
    cache._writes_since_trim = 7  # noqa: SLF001
    monkeypatch.setattr(cache, "_get_conn", lambda: fake_conn)

    with pytest.raises(sqlite3.OperationalError, match="commit failed"):
        cache.save("e" * 64, (1, 2, 3, 4))

    assert fake_conn.rollback_called is True
    assert cache._row_count == 4  # noqa: SLF001
    assert cache._writes_since_trim == 7  # noqa: SLF001
    assert "e" * 64 not in cache._memory  # noqa: SLF001


def test_cache_get_restores_row_count_when_stale_delete_commit_fails(monkeypatch, tmp_path) -> None:
    class _FakeCursor:
        def __init__(self) -> None:
            self.rowcount = 0

        def execute(self, sql, _params=None):
            if sql.startswith("SELECT stats, timestamp"):
                self.rowcount = 0
            elif sql.startswith("DELETE FROM scans WHERE hash"):
                self.rowcount = 1
            return None

        def fetchone(self):
            return (sqlite3.Binary(b"\x00" * 16), 0)

    class _FakeConnection:
        def __init__(self) -> None:
            self._cursor = _FakeCursor()
            self.rollback_called = False

        def cursor(self) -> _FakeCursor:
            return self._cursor

        def commit(self) -> None:
            raise sqlite3.OperationalError("commit failed")

        def rollback(self) -> None:
            self.rollback_called = True

    db = tmp_path / "vt_cache.db"
    cache = ScanCache(cache_db=db)
    fake_conn = _FakeConnection()
    cache._row_count = 9  # noqa: SLF001
    monkeypatch.setattr(cache, "_get_conn", lambda: fake_conn)

    with pytest.raises(sqlite3.OperationalError, match="commit failed"):
        cache.get("f" * 64)

    assert fake_conn.rollback_called is True
    assert cache._row_count == 9  # noqa: SLF001
