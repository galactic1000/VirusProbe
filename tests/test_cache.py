from __future__ import annotations

import sqlite3
from pathlib import Path

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
