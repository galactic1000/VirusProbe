from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest
import vt

from common.service import ScannerService
from common import service_upload


def _service(tmp_path) -> ScannerService:
    service = ScannerService(api_key="test", cache_db=tmp_path / "vt_cache.db")
    service.init_cache()
    return service


def _hash_file(service: ScannerService, path: str) -> str:
    return asyncio.run(service.hash_file_async(path))


class _FakeRateLimiter:
    def __init__(self) -> None:
        self.acquire = AsyncMock(return_value=None)


def test_scan_file_not_found_with_upload_enabled_triggers_upload(tmp_path) -> None:
    service = ScannerService(api_key="test", cache_db=tmp_path / "vt_cache.db", upload_undetected=True)
    service.init_cache()
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"content")
    expected_hash = _hash_file(service, str(sample))
    expected_result = {
        "item": str(sample),
        "type": "file",
        "file_hash": expected_hash,
        "malicious": 1,
        "suspicious": 0,
        "harmless": 10,
        "undetected": 0,
        "threat_level": "Suspicious",
        "status": "ok",
        "message": "Uploaded to VirusTotal and scanned",
        "was_cached": False,
        "was_uploaded": True,
    }
    fake_client = object()
    limiter = _FakeRateLimiter()
    try:
        with (
            patch.object(
                service,
                "_query_virustotal_async",
                AsyncMock(side_effect=vt.APIError("NotFoundError", "not found")),
            ),
            patch.object(service, "_upload_and_scan_async", AsyncMock(return_value=expected_result)) as upload_mock,
        ):
            result = asyncio.run(service._scan_file_live_async(fake_client, limiter, str(sample), expected_hash))
    finally:
        service.close()
    assert result["status"] == "ok"
    assert result["was_uploaded"] is True
    upload_mock.assert_awaited_once_with(fake_client, limiter, str(sample), expected_hash, None)


def test_upload_and_scan_success_sets_uploaded_and_caches(tmp_path) -> None:
    service = _service(tmp_path)
    sample = tmp_path / "upload.bin"
    sample.write_bytes(b"payload")
    file_hash = _hash_file(service, str(sample))
    try:
        result = asyncio.run(
            service_upload.upload_and_scan_async(
                upload_file_fn=AsyncMock(return_value="analysis-id"),
                poll_analysis_fn=AsyncMock(return_value=(2, 1, 30, 4)),
                cache_save=service._cache.save,
                classify_threat=service.classify_threat,
                error_result=service._error_result,
                cancelled_result=service._cancelled_result,
                file_path=str(sample),
                file_hash=file_hash,
            )
        )
        cached = service._cache.get(file_hash)
    finally:
        service.close()
    assert result["status"] == "ok"
    assert result["was_uploaded"] is True
    assert result["malicious"] == 2
    assert cached == (2, 1, 30, 4)


def test_upload_and_scan_failure_returns_error(tmp_path) -> None:
    service = _service(tmp_path)
    try:
        result = asyncio.run(
            service_upload.upload_and_scan_async(
                upload_file_fn=AsyncMock(side_effect=RuntimeError("boom")),
                poll_analysis_fn=AsyncMock(),
                cache_save=lambda *_: None,
                classify_threat=service.classify_threat,
                error_result=service._error_result,
                cancelled_result=service._cancelled_result,
                file_path="some_file.bin",
                file_hash="a" * 64,
            )
        )
    finally:
        service.close()
    assert result["status"] == "error"
    assert result["type"] == "file"
    assert "Upload failed: boom" in result["message"]


def test_upload_and_scan_cache_save_failure_still_returns_success(tmp_path) -> None:
    service = _service(tmp_path)
    sample = tmp_path / "cache_fail.bin"
    sample.write_bytes(b"x")
    file_hash = _hash_file(service, str(sample))
    try:
        result = asyncio.run(
            service_upload.upload_and_scan_async(
                upload_file_fn=AsyncMock(return_value="analysis-id"),
                poll_analysis_fn=AsyncMock(return_value=(1, 0, 10, 0)),
                cache_save=AsyncMock(side_effect=RuntimeError("cache write failed")),
                classify_threat=service.classify_threat,
                error_result=service._error_result,
                cancelled_result=service._cancelled_result,
                file_path=str(sample),
                file_hash=file_hash,
            )
        )
    finally:
        service.close()
    assert result["status"] == "ok"
    assert result["was_uploaded"] is True
    assert result["malicious"] == 1


def test_upload_and_scan_malformed_poll_response_returns_error(tmp_path) -> None:
    service = _service(tmp_path)
    sample = tmp_path / "malformed.bin"
    sample.write_bytes(b"m")
    file_hash = _hash_file(service, str(sample))
    try:
        result = asyncio.run(
            service_upload.upload_and_scan_async(
                upload_file_fn=AsyncMock(return_value="analysis-id"),
                poll_analysis_fn=AsyncMock(side_effect=KeyError("stats")),
                cache_save=lambda *_: None,
                classify_threat=service.classify_threat,
                error_result=service._error_result,
                cancelled_result=service._cancelled_result,
                file_path=str(sample),
                file_hash=file_hash,
            )
        )
    finally:
        service.close()
    assert result["status"] == "error"
    assert result["was_uploaded"] is False
    assert "Upload failed" in result["message"]


def test_poll_analysis_uses_rate_limiter_for_each_poll(tmp_path) -> None:
    _ = tmp_path

    class _FakeClient:
        def __init__(self) -> None:
            self.calls = 0

        async def get_json_async(self, path: str) -> dict:
            assert path == "/analyses/analysis-id"
            self.calls += 1
            if self.calls == 1:
                return {"data": {"attributes": {"status": "running"}}}
            return {
                "data": {
                    "attributes": {
                        "status": "completed",
                        "stats": {"malicious": 3, "suspicious": 0, "harmless": 12, "undetected": 1},
                    }
                }
            }

    fake_client = _FakeClient()
    limiter = _FakeRateLimiter()
    with patch("common.service_upload.sleep_with_cancel_async", AsyncMock(return_value=None)):
        stats = asyncio.run(service_upload.poll_analysis_async(fake_client, limiter, 4, 20, "analysis-id"))
    assert stats == (3, 0, 12, 1)
    assert limiter.acquire.await_count == 2


def test_poll_analysis_uses_configured_timeout(tmp_path) -> None:
    service = ScannerService(api_key="test", cache_db=tmp_path / "vt_cache.db", upload_timeout_minutes=42)
    service.init_cache()
    sample = tmp_path / "timeout.bin"
    sample.write_bytes(b"x")
    file_hash = _hash_file(service, str(sample))
    fake_client = object()
    limiter = _FakeRateLimiter()

    try:
        with (
            patch("common.service_upload.upload_file_async", AsyncMock(return_value="analysis-id")),
            patch("common.service_upload.poll_analysis_async", AsyncMock(return_value=(0, 0, 1, 2))) as poll_mock,
        ):
            asyncio.run(service._upload_and_scan_async(fake_client, limiter, str(sample), file_hash))
    finally:
        service.close()

    assert poll_mock.await_args.args[3] == 42


def test_poll_interval_is_tied_to_requests_per_minute(tmp_path) -> None:
    _ = tmp_path
    assert service_upload.poll_interval_seconds(4) == 30
    assert service_upload.poll_interval_seconds(2) == 60
    assert service_upload.poll_interval_seconds(0) == 15


def test_upload_filter_blocks_upload_and_returns_undetected(tmp_path) -> None:
    service = ScannerService(
        api_key="test", cache_db=tmp_path / "vt_cache.db", upload_undetected=True, upload_filter=lambda _: False
    )
    service.init_cache()
    sample = tmp_path / "blocked.bin"
    sample.write_bytes(b"x")
    fake_client = object()
    limiter = _FakeRateLimiter()
    try:
        with (
            patch.object(
                service,
                "_query_virustotal_async",
                AsyncMock(side_effect=vt.APIError("NotFoundError", "not found")),
            ),
            patch.object(service, "_upload_and_scan_async", AsyncMock()) as upload_mock,
        ):
            result = asyncio.run(service._scan_file_live_async(fake_client, limiter, str(sample), _hash_file(service, str(sample))))
    finally:
        service.close()
    assert result["status"] == "undetected"
    assert result["threat_level"] == "Undetected"
    assert result["was_uploaded"] is False
    upload_mock.assert_not_awaited()


def test_upload_filter_allows_upload_when_matched(tmp_path) -> None:
    service = ScannerService(
        api_key="test", cache_db=tmp_path / "vt_cache.db", upload_undetected=True, upload_filter=lambda _: True
    )
    service.init_cache()
    sample = tmp_path / "allowed.bin"
    sample.write_bytes(b"x")
    expected_hash = _hash_file(service, str(sample))
    expected_result = {
        "item": str(sample),
        "type": "file",
        "file_hash": expected_hash,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 5,
        "undetected": 10,
        "threat_level": "Clean",
        "status": "ok",
        "message": "Uploaded to VirusTotal and scanned",
        "was_cached": False,
        "was_uploaded": True,
    }
    fake_client = object()
    limiter = _FakeRateLimiter()
    try:
        with (
            patch.object(
                service,
                "_query_virustotal_async",
                AsyncMock(side_effect=vt.APIError("NotFoundError", "not found")),
            ),
            patch.object(service, "_upload_and_scan_async", AsyncMock(return_value=expected_result)) as upload_mock,
        ):
            result = asyncio.run(service._scan_file_live_async(fake_client, limiter, str(sample), expected_hash))
    finally:
        service.close()
    assert result["status"] == "ok"
    assert result["was_uploaded"] is True
    upload_mock.assert_awaited_once_with(fake_client, limiter, str(sample), expected_hash, None)


def test_upload_file_small_path_rate_limited_once(tmp_path) -> None:
    sample = tmp_path / "small.bin"
    sample.write_bytes(b"small")

    class _FakeResponse:
        async def json_async(self) -> dict:
            return {"data": {"id": "analysis-small"}}

    class _FakeClient:
        async def post_async(self, path: str, data=None):
            assert path == "/files"
            return _FakeResponse()

        async def get_error_async(self, response) -> None:
            return None

    limiter = _FakeRateLimiter()
    analysis_id = asyncio.run(service_upload.upload_file_async(_FakeClient(), limiter, str(sample)))
    assert analysis_id == "analysis-small"
    assert limiter.acquire.await_count == 1


def test_upload_file_large_path_rate_limited_for_both_calls(tmp_path) -> None:
    sample = tmp_path / "large.bin"
    sample.write_bytes(b"large")

    class _FakeResponse:
        async def json_async(self) -> dict:
            return {"data": {"id": "analysis-large"}}

    class _FakeClient:
        async def get_data_async(self, path: str) -> str:
            assert path == "/files/upload_url"
            return "https://upload.url"

        async def post_async(self, path: str, data=None):
            assert path == "https://upload.url"
            return _FakeResponse()

        async def get_error_async(self, response) -> None:
            return None

    limiter = _FakeRateLimiter()
    with patch("common.service_upload._UPLOAD_SIZE_THRESHOLD", 1):
        analysis_id = asyncio.run(service_upload.upload_file_async(_FakeClient(), limiter, str(sample)))
    assert analysis_id == "analysis-large"
    assert limiter.acquire.await_count == 2


def test_upload_file_rejects_over_650mb(tmp_path) -> None:
    sample = tmp_path / "too_big.bin"
    sample.write_bytes(b"x")
    with patch("common.service_upload._UPLOAD_MAX_SIZE", 0):
        with pytest.raises(ValueError, match="max 650 MB"):
            asyncio.run(service_upload.upload_file_async(object(), _FakeRateLimiter(), str(sample)))
