from __future__ import annotations

import asyncio
import sqlite3
from contextlib import asynccontextmanager
from unittest.mock import AsyncMock, patch

import vt

from common.service import ScannerService


def _service(tmp_path) -> ScannerService:
    service = ScannerService(api_key="test", cache_db=tmp_path / "vt_cache.db")
    service.init_cache()
    return service


class _FakeRateLimiter:
    async def acquire(self) -> None:
        return None


def test_scan_hash_invalid_format_returns_error(tmp_path) -> None:
    service = _service(tmp_path)
    try:
        result, unresolved = asyncio.run(service._prepare_hash_scan_async("not-a-hash"))
    finally:
        service.close()
    assert unresolved is None
    assert result is not None
    assert result["status"] == "error"
    assert result["type"] == "hash"
    assert "Invalid SHA-256" in result["message"]


def test_scan_hash_uses_mocked_vt_response(tmp_path) -> None:
    service = _service(tmp_path)
    try:
        with patch.object(
            service, "_query_virustotal_async", AsyncMock(return_value=((12, 1, 5, 7), False))
        ):
            result = asyncio.run(service._scan_hash_live_async(object(), _FakeRateLimiter(), "a" * 64))
    finally:
        service.close()
    assert result["status"] == "ok"
    assert result["threat_level"] == "Malicious"
    assert result["malicious"] == 12
    assert result["file_hash"] == "a" * 64


def test_scan_hash_not_found_apierror_maps_to_undetected(tmp_path) -> None:
    service = _service(tmp_path)
    try:
        with patch.object(
            service,
            "_query_virustotal_async",
            AsyncMock(side_effect=vt.APIError("NotFoundError", "not found")),
        ):
            result = asyncio.run(service._scan_hash_live_async(object(), _FakeRateLimiter(), "c" * 64))
    finally:
        service.close()
    assert result["status"] == "undetected"
    assert result["threat_level"] == "Undetected"


def test_scan_hash_other_apierror_maps_to_error(tmp_path) -> None:
    service = _service(tmp_path)
    try:
        with patch.object(
            service,
            "_query_virustotal_async",
            AsyncMock(side_effect=vt.APIError("InvalidArgumentError", "bad hash")),
        ):
            result = asyncio.run(service._scan_hash_live_async(object(), _FakeRateLimiter(), "d" * 64))
    finally:
        service.close()
    assert result["status"] == "error"
    assert result["threat_level"] == "Error"
    assert "bad hash" in result["message"]


def test_scan_hash_malformed_response_maps_to_undetected(tmp_path) -> None:
    service = _service(tmp_path)
    try:
        with patch.object(service, "_query_virustotal_async", AsyncMock(side_effect=ValueError("bad response"))):
            result = asyncio.run(service._scan_hash_live_async(object(), _FakeRateLimiter(), "e" * 64))
    finally:
        service.close()
    assert result["status"] == "undetected"
    assert result["threat_level"] == "Undetected"


def test_scan_directory_passes_file_list_to_scan_files(tmp_path) -> None:
    service = _service(tmp_path)
    sample_dir = tmp_path / "samples"
    sample_dir.mkdir()
    (sample_dir / "a.bin").write_bytes(b"a")
    (sample_dir / "b.bin").write_bytes(b"b")
    try:
        with patch.object(service, "scan_files", AsyncMock(return_value=[])) as scan_files_mock:
            asyncio.run(service.scan_directory(str(sample_dir), recursive=False))
            arg = scan_files_mock.call_args[0][0]
    finally:
        service.close()
    assert sorted(arg) == sorted([str(sample_dir / "a.bin"), str(sample_dir / "b.bin")])


def test_scan_directory_nonexistent_returns_error_dict(tmp_path) -> None:
    service = _service(tmp_path)
    try:
        results = asyncio.run(service.scan_directory(str(tmp_path / "nonexistent")))
    finally:
        service.close()
    assert len(results) == 1
    assert results[0]["status"] == "error"
    assert results[0]["type"] == "directory"


def test_scan_directory_not_a_directory_returns_error_dict(tmp_path) -> None:
    service = _service(tmp_path)
    not_a_dir = tmp_path / "file.txt"
    not_a_dir.write_text("data")
    try:
        results = asyncio.run(service.scan_directory(str(not_a_dir)))
    finally:
        service.close()
    assert len(results) == 1
    assert results[0]["status"] == "error"
    assert results[0]["type"] == "directory"


def test_scan_hashes_on_result_callback_fires_for_each_item(tmp_path) -> None:
    service = _service(tmp_path)
    fired: list[dict] = []
    try:
        with patch.object(
            service, "_query_virustotal_async", AsyncMock(return_value=((0, 0, 5, 0), False))
        ):
            asyncio.run(service.scan_hashes(["a" * 64, "b" * 64], on_result=fired.append))
    finally:
        service.close()
    assert len(fired) == 2
    assert all(r["status"] == "ok" for r in fired)


def test_scan_hash_returns_success_when_cache_save_fails(tmp_path) -> None:
    service = _service(tmp_path)

    class _FakeClient:
        async def get_json_async(self, path: str) -> dict:
            assert path == f"/files/{'a' * 64}"
            return {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 0,
                            "suspicious": 3,
                            "harmless": 10,
                            "undetected": 2,
                        }
                    }
                }
            }

    try:
        with (
            patch.object(service, "_cache_get_async", AsyncMock(return_value=None)),
            patch.object(
                service,
                "_cache_save_async",
                AsyncMock(side_effect=sqlite3.OperationalError("disk full")),
            ),
        ):
            result = asyncio.run(service._scan_hash_live_async(_FakeClient(), _FakeRateLimiter(), "a" * 64))
    finally:
        service.close()

    assert result["status"] == "ok"
    assert result["threat_level"] == "Suspicious"
    assert result["was_cached"] is False


def test_scan_files_starts_live_lookup_before_all_preparation_finishes(tmp_path) -> None:
    service = _service(tmp_path)
    live_started = asyncio.Event()

    @asynccontextmanager
    async def _fake_client_context():
        yield object(), _FakeRateLimiter(), asyncio.Semaphore(service.max_workers)

    async def _prepare(file_path: str, cancel_event) -> tuple[dict | None, tuple[str, str] | None]:
        if file_path == "first":
            return None, (file_path, "a" * 64)
        await live_started.wait()
        return service._error_result(file_path, "file", "prepared after live start"), None

    async def _query(client, rate_limiter, file_hash: str, *, check_cache: bool = True):
        live_started.set()
        return (0, 0, 1, 0), False

    try:
        with (
            patch.object(service, "_client_context", _fake_client_context),
            patch.object(service, "_prepare_file_scan_async", side_effect=_prepare),
            patch.object(service, "_query_virustotal_async", side_effect=_query),
        ):
            results = asyncio.run(asyncio.wait_for(service.scan_files(["first", "second"]), timeout=0.2))
    finally:
        service.close()

    assert len(results) == 2
    assert live_started.is_set()


def test_cache_init_failure_disables_cache_but_live_lookup_still_works(tmp_path) -> None:
    service = ScannerService(api_key="test", cache_db=tmp_path / "vt_cache.db")

    class _FakeClient:
        async def get_json_async(self, path: str) -> dict:
            assert path == f"/files/{'a' * 64}"
            return {
                "data": {
                    "attributes": {
                        "last_analysis_stats": {
                            "malicious": 1,
                            "suspicious": 0,
                            "harmless": 10,
                            "undetected": 0,
                        }
                    }
                }
            }

    try:
        with patch.object(service._cache, "init", side_effect=RuntimeError("cache broken")):
            service.init_cache()
        result = asyncio.run(service._scan_hash_live_async(_FakeClient(), _FakeRateLimiter(), "a" * 64))
    finally:
        service.close()

    assert service._cache_available is False
    assert result["status"] == "ok"
    assert result["was_cached"] is False
