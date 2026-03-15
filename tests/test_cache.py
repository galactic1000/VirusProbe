from __future__ import annotations

import sqlite3
import threading
import time
from pathlib import Path

import pytest

from common.cache import ScanCache
from common.models import CacheEntry


def _row_count(db_path: Path) -> int:
    with sqlite3.connect(str(db_path)) as conn:
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM scans")
        return int(cur.fetchone()[0])


def test_roundtrip(cache_factory) -> None:
    cache = cache_factory()
    cache.save("a" * 64, (1, 2, 3, 4))
    result = cache.get("a" * 64)
    assert result == (1, 2, 3, 4)


def test_stale_row_deleted_on_read(cache_factory) -> None:
    cache = cache_factory()
    file_hash = "b" * 64
    cache.save(file_hash, (0, 0, 0, 0))
    conn = cache._get_conn()  # noqa: SLF001
    conn.execute("UPDATE scans SET timestamp = 0 WHERE hash = ?", (bytes.fromhex(file_hash),))
    conn.commit()
    cache._memory.clear()  # noqa: SLF001

    assert cache.get(file_hash) is None

    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM scans WHERE hash = ?", (bytes.fromhex(file_hash),))
    assert int(cur.fetchone()[0]) == 0


def test_row_cap_enforced_on_save(cache_factory, tmp_path) -> None:
    cache = cache_factory(cache_max_rows=2)
    cache.save("0" * 64, (0, 0, 0, 0))
    cache.save("1" * 64, (1, 0, 0, 0))
    cache.save("2" * 64, (2, 0, 0, 0))
    assert _row_count(tmp_path / "vt_cache.db") == 2


def test_init_prunes_expired(tmp_path) -> None:
    db = tmp_path / "vt_cache.db"
    cache = ScanCache(cache_db=db)
    cache.init()
    file_hash = "c" * 64
    cache.save(file_hash, (0, 0, 0, 0))
    conn = cache._get_conn()  # noqa: SLF001
    conn.execute("UPDATE scans SET timestamp = 0 WHERE hash = ?", (bytes.fromhex(file_hash),))
    conn.commit()
    cache.close()

    cache2 = ScanCache(cache_db=db)
    cache2.init()
    assert _row_count(db) == 0
    cache2.close()


def test_init_enforces_row_cap(tmp_path) -> None:
    db = tmp_path / "vt_cache.db"
    cache = ScanCache(cache_db=db, cache_max_rows=5)
    cache.init()
    for index in range(5):
        cache.save(f"{index:064x}", (index, 0, 0, 0))
    cache.close()

    with sqlite3.connect(str(db)) as conn:
        conn.execute(
            "INSERT INTO scans (hash, stats, timestamp) VALUES (?, ?, ?)",
            (bytes.fromhex("f" * 64), sqlite3.Binary(b"\x00" * 16), int(time.time())),
        )
        conn.commit()

    cache2 = ScanCache(cache_db=db, cache_max_rows=5)
    cache2.init()
    assert _row_count(db) == 5
    cache2.close()


def test_memory_lru_eviction(cache_factory) -> None:
    cache = cache_factory(memory_cache_max_entries=2)
    cache.save("1" * 64, (1, 0, 0, 0))
    cache.save("2" * 64, (2, 0, 0, 0))
    cache.save("3" * 64, (3, 0, 0, 0))
    memory_keys = list(cache._memory.keys())  # noqa: SLF001
    assert len(memory_keys) == 2
    assert "1" * 64 not in memory_keys


def test_memory_entry_expires(cache_factory) -> None:
    cache = cache_factory(cache_expiry_days=1)
    file_hash = "d" * 64
    cache.save(file_hash, (4, 3, 2, 1))
    conn = cache._get_conn()  # noqa: SLF001
    conn.execute("UPDATE scans SET timestamp = 0 WHERE hash = ?", (bytes.fromhex(file_hash),))
    conn.commit()
    cache._memory[file_hash] = ((4, 3, 2, 1), 0, ScanCache._RESULT_TYPE_STATS)  # noqa: SLF001

    assert cache.get(file_hash) is None
    assert file_hash not in cache._memory  # noqa: SLF001


def test_not_found_roundtrip(cache_factory) -> None:
    cache = cache_factory()
    file_hash = "9" * 64
    cache.save_not_found(file_hash)
    entry = cache.get_entry(file_hash)
    assert entry == CacheEntry(stats=(0, 0, 0, 0), is_not_found=True)

    conn = cache._get_conn()  # noqa: SLF001
    conn.execute("UPDATE scans SET timestamp = 0 WHERE hash = ?", (bytes.fromhex(file_hash),))
    conn.commit()
    cache._memory.clear()  # noqa: SLF001

    assert cache.get_entry(file_hash) is None


def test_save_skips_memory_on_commit_failure(monkeypatch, tmp_path) -> None:
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

    cache = ScanCache(cache_db=tmp_path / "vt_cache.db")
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


def test_get_restores_row_count_on_commit_failure(monkeypatch, tmp_path) -> None:
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
            return (sqlite3.Binary(b"\x00" * 16), 0, ScanCache._RESULT_TYPE_STATS)

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

    cache = ScanCache(cache_db=tmp_path / "vt_cache.db")
    fake_conn = _FakeConnection()
    cache._row_count = 9  # noqa: SLF001
    monkeypatch.setattr(cache, "_get_conn", lambda: fake_conn)

    with pytest.raises(sqlite3.OperationalError, match="commit failed"):
        cache.get("f" * 64)

    assert fake_conn.rollback_called is True
    assert cache._row_count == 9  # noqa: SLF001


def test_close_drains_executor(service_factory) -> None:
    service = service_factory()
    started = threading.Event()
    release = threading.Event()
    original_get = service._cache.get  # noqa: SLF001
    call_count = {"value": 0}

    def _blocking_get(file_hash: str):
        call_count["value"] += 1
        started.set()
        if call_count["value"] == 1:
            release.wait(timeout=1.0)
        return original_get(file_hash)

    service._cache.get = _blocking_get  # type: ignore[method-assign]  # noqa: SLF001
    future = service._cache_executor.submit(service._cache.get, "a" * 64)  # noqa: SLF001
    assert started.wait(timeout=1.0) is True
    service._cache_executor.submit(service._cache.get, "a" * 64)  # noqa: SLF001
    release.set()
    future.result(timeout=1.0)

    service.close()

    assert service._cache._conn is None  # noqa: SLF001
    assert call_count["value"] == 2
