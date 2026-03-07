from __future__ import annotations

from unittest.mock import patch

import vt

from common.service import ScannerService
from common import service_upload


def _service(tmp_path) -> ScannerService:
    service = ScannerService(api_key="test", cache_db=tmp_path / "vt_cache.db")
    service.init_cache()
    return service


def test_scan_file_not_found_with_upload_enabled_triggers_upload(tmp_path) -> None:
    service = ScannerService(api_key="test", cache_db=tmp_path / "vt_cache.db", upload_undetected=True)
    service.init_cache()
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"content")
    expected_hash = service.hash_file(str(sample))
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
    try:
        with (
            patch.object(service, "_query_virustotal", side_effect=vt.APIError("NotFoundError", "not found")),
            patch.object(service, "_upload_and_scan", return_value=expected_result) as upload_mock,
        ):
            result = service.scan_file(str(sample))
    finally:
        service.close()
    assert result["status"] == "ok"
    assert result["was_uploaded"] is True
    upload_mock.assert_called_once_with(str(sample), expected_hash)


def test_upload_and_scan_success_sets_uploaded_and_caches(tmp_path) -> None:
    service = _service(tmp_path)
    sample = tmp_path / "upload.bin"
    sample.write_bytes(b"payload")
    file_hash = service.hash_file(str(sample))
    try:
        with (
            patch.object(service, "_upload_file", return_value="analysis-id"),
            patch.object(service, "_poll_analysis", return_value=(2, 1, 30, 4)),
        ):
            result = service._upload_and_scan(str(sample), file_hash)
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
        with patch.object(service, "_upload_file", side_effect=RuntimeError("boom")):
            result = service._upload_and_scan("some_file.bin", "a" * 64)
    finally:
        service.close()
    assert result["status"] == "error"
    assert result["type"] == "file"
    assert "Upload failed: boom" in result["message"]


def test_upload_and_scan_cache_save_failure_still_returns_success(tmp_path) -> None:
    service = _service(tmp_path)
    sample = tmp_path / "cache_fail.bin"
    sample.write_bytes(b"x")
    file_hash = service.hash_file(str(sample))
    try:
        with (
            patch.object(service, "_upload_file", return_value="analysis-id"),
            patch.object(service, "_poll_analysis", return_value=(1, 0, 10, 0)),
            patch.object(service._cache, "save", side_effect=RuntimeError("cache write failed")),
        ):
            result = service._upload_and_scan(str(sample), file_hash)
    finally:
        service.close()
    assert result["status"] == "ok"
    assert result["was_uploaded"] is True
    assert result["malicious"] == 1


def test_upload_and_scan_malformed_poll_response_returns_error(tmp_path) -> None:
    service = _service(tmp_path)
    sample = tmp_path / "malformed.bin"
    sample.write_bytes(b"m")
    file_hash = service.hash_file(str(sample))

    class _MalformedClient:
        def get_json(self, path: str) -> dict:
            assert path == "/analyses/analysis-id"
            return {"data": {"attributes": {"status": "completed"}}}

    try:
        with (
            patch.object(service, "_upload_file", return_value="analysis-id"),
            patch.object(service, "_get_client", return_value=_MalformedClient()),
        ):
            result = service._upload_and_scan(str(sample), file_hash)
    finally:
        service.close()
    assert result["status"] == "error"
    assert result["was_uploaded"] is False
    assert "Upload failed" in result["message"]


def test_poll_analysis_uses_rate_limiter_for_each_poll(tmp_path) -> None:
    service = _service(tmp_path)

    class _FakeClient:
        def __init__(self) -> None:
            self.calls = 0

        def get_json(self, path: str) -> dict:
            assert path == "/analyses/analysis-id"
            self.calls += 1
            if self.calls == 1:
                return {"data": {"attributes": {"status": "running"}}}
            return {"data": {"attributes": {"status": "completed", "stats": {"malicious": 3, "suspicious": 0, "harmless": 12, "undetected": 1}}}}

    fake_client = _FakeClient()
    try:
        with (
            patch.object(service, "_get_client", return_value=fake_client),
            patch.object(service._rate_limiter, "acquire") as acquire_mock,
            patch("common.service_upload.time.sleep", return_value=None),
        ):
            stats = service._poll_analysis("analysis-id")
    finally:
        service.close()
    assert stats == (3, 0, 12, 1)
    assert acquire_mock.call_count == 2


def test_poll_analysis_uses_configured_timeout(tmp_path) -> None:
    service = ScannerService(api_key="test", cache_db=tmp_path / "vt_cache.db", upload_timeout_minutes=42)
    service.init_cache()
    try:
        with patch("common.service_upload.poll_analysis", return_value=(0, 0, 1, 2)) as poll_mock:
            service._poll_analysis("analysis-id")
    finally:
        service.close()
    assert poll_mock.call_args.kwargs["timeout_minutes"] == 42


def test_poll_interval_is_tied_to_requests_per_minute(tmp_path) -> None:
    assert service_upload.poll_interval_seconds(4) == 15
    assert service_upload.poll_interval_seconds(2) == 30
    assert service_upload.poll_interval_seconds(0) == 15


def test_upload_filter_blocks_upload_and_returns_undetected(tmp_path) -> None:
    service = ScannerService(api_key="test", cache_db=tmp_path / "vt_cache.db", upload_undetected=True, upload_filter=lambda _: False)
    service.init_cache()
    sample = tmp_path / "blocked.bin"
    sample.write_bytes(b"x")
    try:
        with (
            patch.object(service, "_query_virustotal", side_effect=vt.APIError("NotFoundError", "not found")),
            patch.object(service, "_upload_and_scan") as upload_mock,
        ):
            result = service.scan_file(str(sample))
    finally:
        service.close()
    assert result["status"] == "undetected"
    assert result["threat_level"] == "Undetected"
    assert result["was_uploaded"] is False
    upload_mock.assert_not_called()


def test_upload_filter_allows_upload_when_matched(tmp_path) -> None:
    service = ScannerService(api_key="test", cache_db=tmp_path / "vt_cache.db", upload_undetected=True, upload_filter=lambda _: True)
    service.init_cache()
    sample = tmp_path / "allowed.bin"
    sample.write_bytes(b"x")
    expected_hash = service.hash_file(str(sample))
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
    try:
        with (
            patch.object(service, "_query_virustotal", side_effect=vt.APIError("NotFoundError", "not found")),
            patch.object(service, "_upload_and_scan", return_value=expected_result) as upload_mock,
        ):
            result = service.scan_file(str(sample))
    finally:
        service.close()
    assert result["status"] == "ok"
    assert result["was_uploaded"] is True
    upload_mock.assert_called_once_with(str(sample), expected_hash)


def test_upload_file_small_path_rate_limited_once(tmp_path) -> None:
    service = _service(tmp_path)
    sample = tmp_path / "small.bin"
    sample.write_bytes(b"small")

    class _FakeResponse:
        @staticmethod
        def json() -> dict:
            return {"data": {"id": "analysis-small"}}

    class _FakeClient:
        def post(self, path: str, data=None):
            assert path == "/files"
            return _FakeResponse()

    try:
        with (
            patch.object(service, "_get_client", return_value=_FakeClient()),
            patch.object(service._rate_limiter, "acquire") as acquire_mock,
        ):
            analysis_id = service._upload_file(str(sample))
    finally:
        service.close()
    assert analysis_id == "analysis-small"
    assert acquire_mock.call_count == 1


def test_upload_file_large_path_rate_limited_for_both_calls(tmp_path) -> None:
    service = _service(tmp_path)
    sample = tmp_path / "large.bin"
    sample.write_bytes(b"large")

    class _FakeResponse:
        @staticmethod
        def json() -> dict:
            return {"data": {"id": "analysis-large"}}

    class _FakeClient:
        def get_json(self, path: str) -> dict:
            assert path == "/files/upload_url"
            return {"data": "https://upload.url"}

        def post(self, path: str, data=None):
            assert path == "https://upload.url"
            return _FakeResponse()

    try:
        with (
            patch("common.service_upload._UPLOAD_SIZE_THRESHOLD", 1),
            patch.object(service, "_get_client", return_value=_FakeClient()),
            patch.object(service._rate_limiter, "acquire") as acquire_mock,
        ):
            analysis_id = service._upload_file(str(sample))
    finally:
        service.close()
    assert analysis_id == "analysis-large"
    assert acquire_mock.call_count == 2


def test_upload_file_rejects_over_650mb(tmp_path) -> None:
    service = _service(tmp_path)
    sample = tmp_path / "too_big.bin"
    sample.write_bytes(b"x")
    try:
        with patch("common.service_upload._UPLOAD_MAX_SIZE", 0):
            try:
                service._upload_file(str(sample))
                assert False, "Expected ValueError for oversized file"
            except ValueError as exc:
                assert "max 650 MB" in str(exc)
    finally:
        service.close()
