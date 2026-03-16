from __future__ import annotations

import sqlite3

import pytest
import vt

from common import service_results
from common import service_upload
from common.models import ResultStatus, ScanResult, ScanTarget, ScanTargetKind, ThreatLevel
from common.service import ScannerService


async def _hash_file(service: ScannerService, path: str) -> str:
    return await service.hash_file_async(path)


async def test_not_found_triggers_upload(service_factory, file_factory, mocker, limiter) -> None:
    service = service_factory(upload_undetected=True)
    sample = file_factory("sample.bin", b"content")
    expected_hash = await _hash_file(service, str(sample))
    expected_result = ScanResult(
        item=str(sample),
        kind=ScanTargetKind.FILE,
        file_hash=expected_hash,
        malicious=1,
        suspicious=0,
        harmless=10,
        undetected=0,
        threat_level=ThreatLevel.SUSPICIOUS,
        status=ResultStatus.OK,
        message="Uploaded to VirusTotal and scanned",
        was_cached=False,
        was_uploaded=True,
    )
    fake_client = object()
    mocker.patch.object(
        service,
        "_query_virustotal_async",
        side_effect=vt.APIError("NotFoundError", "not found"),
    )
    upload_mock = mocker.patch.object(service, "_upload_and_scan_async", return_value=expected_result)
    result = await service._scan_live_async(fake_client, limiter, ScanTarget.from_file(expected_hash, str(sample)))  # type: ignore[arg-type]
    assert result.status == ResultStatus.OK
    assert result.was_uploaded is True
    upload_mock.assert_awaited_once_with(fake_client, limiter, str(sample), expected_hash, None)


async def test_upload_success_caches_result(service_factory, file_factory, mocker) -> None:
    service = service_factory()
    sample = file_factory("upload.bin", b"payload")
    file_hash = await _hash_file(service, str(sample))

    async def async_cache_save(fh: str, stats: tuple) -> None:
        service._cache.save(fh, stats)

    result = await service_upload.upload_and_scan_async(
        upload_file_fn=mocker.AsyncMock(return_value="analysis-id"),
        poll_analysis_fn=mocker.AsyncMock(return_value=(2, 1, 30, 4)),
        cache_save=async_cache_save,
        classify_threat=service_results.classify_threat,
        error_result=service_results.error_result,
        cancelled_result=service_results.cancelled_result,
        file_path=str(sample),
        file_hash=file_hash,
    )
    cached = service._cache.get(file_hash)
    assert result.status == ResultStatus.OK
    assert result.was_uploaded is True
    assert result.malicious == 2
    assert cached == (2, 1, 30, 4)


async def test_upload_failure_returns_error(mocker) -> None:
    result = await service_upload.upload_and_scan_async(
        upload_file_fn=mocker.AsyncMock(side_effect=RuntimeError("boom")),
        poll_analysis_fn=mocker.AsyncMock(),
        cache_save=lambda *_: None,  # type: ignore[arg-type]
        classify_threat=service_results.classify_threat,
        error_result=service_results.error_result,
        cancelled_result=service_results.cancelled_result,
        file_path="some_file.bin",
        file_hash="a" * 64,
    )
    assert result.status == ResultStatus.ERROR
    assert result.type == "file"
    assert "Upload failed: boom" in result.message


async def test_upload_cache_failure_still_succeeds(service_factory, file_factory, mocker) -> None:
    service = service_factory()
    sample = file_factory("cache_fail.bin")
    file_hash = await _hash_file(service, str(sample))
    result = await service_upload.upload_and_scan_async(
        upload_file_fn=mocker.AsyncMock(return_value="analysis-id"),
        poll_analysis_fn=mocker.AsyncMock(return_value=(1, 0, 10, 0)),
        cache_save=mocker.AsyncMock(side_effect=sqlite3.Error("cache write failed")),
        classify_threat=service_results.classify_threat,
        error_result=service_results.error_result,
        cancelled_result=service_results.cancelled_result,
        file_path=str(sample),
        file_hash=file_hash,
    )
    assert result.status == ResultStatus.OK
    assert result.was_uploaded is True
    assert result.malicious == 1


async def test_upload_malformed_poll_returns_error(service_factory, file_factory, mocker) -> None:
    service = service_factory()
    sample = file_factory("malformed.bin", b"m")
    file_hash = await _hash_file(service, str(sample))
    result = await service_upload.upload_and_scan_async(
        upload_file_fn=mocker.AsyncMock(return_value="analysis-id"),
        poll_analysis_fn=mocker.AsyncMock(side_effect=KeyError("stats")),
        cache_save=lambda *_: None,  # pyright: ignore[reportArgumentType]
        classify_threat=service_results.classify_threat,
        error_result=service_results.error_result,
        cancelled_result=service_results.cancelled_result,
        file_path=str(sample),
        file_hash=file_hash,
    )
    assert result.status == ResultStatus.ERROR
    assert result.was_uploaded is False
    assert "Upload failed" in result.message


async def test_poll_uses_rate_limiter(mocker, limiter, polling_client_factory) -> None:
    fake_client = polling_client_factory("analysis-id", ["running", "completed"], (3, 0, 12, 1))
    mocker.patch("common.service_upload.sleep_with_cancel_async", return_value=None)
    stats = await service_upload.poll_analysis_async(fake_client, limiter, 4, 20, "analysis-id")  # type: ignore[arg-type]
    assert stats == (3, 0, 12, 1)
    assert limiter.acquire.await_count == 2


async def test_poll_uses_configured_timeout(service_factory, file_factory, mocker, limiter) -> None:
    service = service_factory(upload_timeout_minutes=42)
    sample = file_factory("timeout.bin")
    file_hash = await _hash_file(service, str(sample))
    fake_client = object()
    mocker.patch("common.service_upload.upload_file_async", return_value="analysis-id")
    poll_mock = mocker.patch("common.service_upload.poll_analysis_async", return_value=(0, 0, 1, 2))
    await service._upload_and_scan_async(fake_client, limiter, str(sample), file_hash)  # type: ignore[arg-type]
    assert poll_mock.await_args.args[3] == 42  # type: ignore[union-attr]


def test_poll_interval_is_tied_to_requests_per_minute() -> None:
    assert service_upload.poll_interval_seconds(4) == 30
    assert service_upload.poll_interval_seconds(2) == 60
    assert service_upload.poll_interval_seconds(0) == 15


async def test_upload_filter_blocks_returns_undetected(service_factory, file_factory, mocker, limiter) -> None:
    service = service_factory(upload_undetected=True, upload_filter=lambda _: False)
    sample = file_factory("blocked.bin")
    fake_client = object()
    mocker.patch.object(
        service,
        "_query_virustotal_async",
        side_effect=vt.APIError("NotFoundError", "not found"),
    )
    upload_mock = mocker.patch.object(service, "_upload_and_scan_async")
    result = await service._scan_live_async(
        fake_client, limiter, ScanTarget.from_file(await _hash_file(service, str(sample)), str(sample))
    )  # type: ignore[arg-type]
    assert result.status == ResultStatus.UNDETECTED
    assert result.threat_level == ThreatLevel.UNDETECTED
    assert result.was_uploaded is False
    upload_mock.assert_not_awaited()


async def test_upload_filter_allows_when_matched(service_factory, file_factory, mocker, limiter) -> None:
    service = service_factory(upload_undetected=True, upload_filter=lambda _: True)
    sample = file_factory("allowed.bin")
    expected_hash = await _hash_file(service, str(sample))
    expected_result = ScanResult(
        item=str(sample),
        kind=ScanTargetKind.FILE,
        file_hash=expected_hash,
        malicious=0,
        suspicious=0,
        harmless=5,
        undetected=10,
        threat_level=ThreatLevel.CLEAN,
        status=ResultStatus.OK,
        message="Uploaded to VirusTotal and scanned",
        was_cached=False,
        was_uploaded=True,
    )
    fake_client = object()
    mocker.patch.object(
        service,
        "_query_virustotal_async",
        side_effect=vt.APIError("NotFoundError", "not found"),
    )
    upload_mock = mocker.patch.object(service, "_upload_and_scan_async", return_value=expected_result)
    result = await service._scan_live_async(fake_client, limiter, ScanTarget.from_file(expected_hash, str(sample)))  # type: ignore[arg-type]
    assert result.status == ResultStatus.OK
    assert result.was_uploaded is True
    upload_mock.assert_awaited_once_with(fake_client, limiter, str(sample), expected_hash, None)


async def test_small_file_rate_limited_once(file_factory, limiter, upload_client_factory) -> None:
    sample = file_factory("small.bin", b"small")
    fake_client = upload_client_factory(analysis_id="analysis-small")
    analysis_id = await service_upload.upload_file_async(fake_client, limiter, str(sample))  # type: ignore[arg-type]
    assert analysis_id == "analysis-small"
    assert limiter.acquire.await_count == 1


async def test_large_file_rate_limited_twice(
    file_factory, monkeypatch, limiter, upload_client_factory
) -> None:
    sample = file_factory("large.bin", b"large")
    fake_client = upload_client_factory(analysis_id="analysis-large", large=True)
    monkeypatch.setattr("common.service_upload._UPLOAD_SIZE_THRESHOLD", 1)
    analysis_id = await service_upload.upload_file_async(fake_client, limiter, str(sample))  # type: ignore[arg-type]
    assert analysis_id == "analysis-large"
    assert limiter.acquire.await_count == 2


async def test_rejects_over_650mb(file_factory, monkeypatch, limiter) -> None:
    sample = file_factory("too_big.bin")
    monkeypatch.setattr("common.service_upload._UPLOAD_MAX_SIZE", 0)
    with pytest.raises(ValueError, match="max 650 MB"):
        await service_upload.upload_file_async(object(), limiter, str(sample))  # type: ignore[arg-type]


async def test_upload_file_error_response(file_factory, limiter) -> None:
    sample = file_factory("err.bin", b"x")
    error = vt.APIError("ForbiddenError", "forbidden")

    class _Client:
        async def post_async(self, _path, **_kwargs):
            return self

        async def get_error_async(self, _response):
            return error

    with pytest.raises(vt.APIError):
        await service_upload.upload_file_async(_Client(), limiter, str(sample))  # type: ignore[arg-type]


async def test_sleep_no_cancel_event() -> None:
    await service_upload.sleep_with_cancel_async(0.0)


async def test_sleep_cancel_raises() -> None:
    from threading import Event
    cancel = Event()
    cancel.set()
    with pytest.raises(service_upload.ScanCancelledError):
        await service_upload.sleep_with_cancel_async(10.0, cancel_event=cancel)


async def test_poll_analysis_times_out(mocker, limiter, polling_client_factory) -> None:
    fake_client = polling_client_factory("analysis-id", ["running"], (0, 0, 0, 0))
    call_count = 0

    def _fake_monotonic() -> float:
        nonlocal call_count
        call_count += 1
        return 0.0 if call_count == 1 else float("inf")

    mocker.patch("common.service_upload.time.monotonic", side_effect=_fake_monotonic)
    mocker.patch("common.service_upload.sleep_with_cancel_async", new_callable=mocker.AsyncMock)
    with pytest.raises(TimeoutError):
        await service_upload.poll_analysis_async(fake_client, limiter, 4, 1, "analysis-id")  # type: ignore[arg-type]


async def test_poll_analysis_pre_cancel_in_loop(limiter, polling_client_factory) -> None:
    from threading import Event
    cancel = Event()
    cancel.set()
    fake_client = polling_client_factory("analysis-id", ["running"], (0, 0, 0, 0))
    with pytest.raises(service_upload.ScanCancelledError):
        await service_upload.poll_analysis_async(fake_client, limiter, 4, 0, "analysis-id", cancel_event=cancel)


async def test_upload_and_scan_pre_cancel(mocker) -> None:
    from threading import Event
    cancel = Event()
    cancel.set()
    result = await service_upload.upload_and_scan_async(
        upload_file_fn=mocker.AsyncMock(),
        poll_analysis_fn=mocker.AsyncMock(),
        cache_save=mocker.AsyncMock(),
        classify_threat=service_results.classify_threat,
        error_result=service_results.error_result,
        cancelled_result=service_results.cancelled_result,
        file_path="file.bin",
        file_hash="a" * 64,
        cancel_event=cancel,
    )
    assert result.status == ResultStatus.CANCELLED


async def test_upload_and_scan_cancelled_during_poll(mocker) -> None:
    result = await service_upload.upload_and_scan_async(
        upload_file_fn=mocker.AsyncMock(return_value="analysis-id"),
        poll_analysis_fn=mocker.AsyncMock(side_effect=service_upload.ScanCancelledError()),
        cache_save=mocker.AsyncMock(),
        classify_threat=service_results.classify_threat,
        error_result=service_results.error_result,
        cancelled_result=service_results.cancelled_result,
        file_path="file.bin",
        file_hash="a" * 64,
    )
    assert result.status == ResultStatus.CANCELLED
