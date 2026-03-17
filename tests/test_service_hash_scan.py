from __future__ import annotations

import asyncio
import sqlite3
import threading

import pytest
import vt

from common import service_results
from common.models import ResultStatus, ScanResult, ScanTarget, ScanTargetKind, ThreatLevel
from common.service import ScannerService


@pytest.mark.parametrize("file_hash,expected_label", [
    ("a" * 32, "MD5"),
    ("a" * 40, "SHA-1"),
    ("a" * 64, "SHA-256"),
])
def test_format_hash_label(file_hash, expected_label) -> None:
    from common import service_results
    assert service_results.format_hash(file_hash) == f"{expected_label} hash: {file_hash}"


async def test_invalid_hash_returns_error(service_factory) -> None:
    service = service_factory()
    result, unresolved = await service._prepare_hash_scan_async(ScanTarget.from_hash("not-a-hash"))
    assert unresolved is None
    assert result is not None
    assert result.status == ResultStatus.ERROR
    assert result.type == "hash"
    assert "Invalid hash format" in result.message


async def test_hash_scan_uses_vt_response(service_factory, mocker, limiter) -> None:
    service = service_factory()
    mocker.patch.object(service, "_query_virustotal_async", return_value=((12, 1, 5, 7), False))
    result = await service._scan_live_async(object(), limiter, ScanTarget.from_hash("a" * 64))
    assert result.status == ResultStatus.OK
    assert result.threat_level == ThreatLevel.MALICIOUS
    assert result.malicious == 12
    assert result.file_hash == "a" * 64


@pytest.mark.parametrize("side_effect,expected_status,expected_threat,message_substr", [
    (vt.APIError("NotFoundError", "not found"), ResultStatus.UNDETECTED, ThreatLevel.UNDETECTED, None),
    (vt.APIError("InvalidArgumentError", "bad hash"), ResultStatus.ERROR, ThreatLevel.ERROR, "bad hash"),
    (ValueError("bad response"), ResultStatus.ERROR, None, None),
])
async def test_query_error_maps_to_result(
    service_factory, mocker, limiter, side_effect, expected_status, expected_threat, message_substr
) -> None:
    service = service_factory()
    mocker.patch.object(service, "_query_virustotal_async", side_effect=side_effect)
    result = await service._scan_live_async(object(), limiter, ScanTarget.from_hash("a" * 64))
    assert result.status == expected_status
    if expected_threat is not None:
        assert result.threat_level == expected_threat
    if message_substr is not None:
        assert message_substr in result.message


async def test_not_found_cached_short_expiry(service_factory, mocker) -> None:
    service = service_factory()
    query_mock = mocker.patch.object(
        service,
        "_query_virustotal_async",
        side_effect=vt.APIError("NotFoundError", "not found"),
    )
    async with service:
        first = await service.scan_targets([ScanTarget.from_hash("c" * 64)])
        second = await service.scan_targets([ScanTarget.from_hash("c" * 64)])
    assert query_mock.await_count == 1
    assert first[0].status == ResultStatus.UNDETECTED
    assert second[0].status == ResultStatus.UNDETECTED
    assert second[0].was_cached is True
    assert second[0].message == "Using cached result"



async def test_on_result_fires_per_item(service_factory, mocker) -> None:
    service = service_factory()
    fired: list[ScanResult] = []
    mocker.patch.object(service, "_query_virustotal_async", return_value=((0, 0, 5, 0), False))
    async with service:
        await service.scan_targets(
            [ScanTarget.from_hash("a" * 64), ScanTarget.from_hash("b" * 64)],
            on_result=fired.append,
        )
    assert len(fired) == 2
    assert all(r.status == ResultStatus.OK for r in fired)


async def test_deduplicates_before_pipeline(service_factory, mocker) -> None:
    service = service_factory()
    seen: list[str] = []

    async def _prepare_target(target: ScanTarget, cancel_event) -> tuple[ScanResult | None, ScanTarget | None]:
        seen.append(target.value)
        return None, ScanTarget.from_hash(target.value.strip().lower())

    async def _scan_hash_live_for_test(client, rate_limiter, unresolved, cancel_event=None) -> ScanResult:
        return service_results.stats_result(
            item=service_results.format_hash(unresolved.hash),
            kind=ScanTargetKind.HASH,
            file_hash=unresolved.hash,
            stats=(1, 0, 0, 0),
            was_cached=False,
        )

    mocker.patch.object(service, "_prepare_hash_scan_async", side_effect=_prepare_target)
    mocker.patch.object(service, "_scan_live_async", side_effect=_scan_hash_live_for_test)
    async with service:
        results = await service.scan_targets(
            [
                ScanTarget.from_hash("A" * 64),
                ScanTarget.from_hash("a" * 64),
                ScanTarget.from_hash("b" * 64),
                ScanTarget.from_hash("B" * 64),
            ]
        )
    assert seen == ["A" * 64, "b" * 64]
    assert len(results) == 2
    assert results[0].file_hash == "a" * 64
    assert results[1].file_hash == "b" * 64


async def test_preserves_duplicate_errors(service_factory) -> None:
    service = service_factory()
    async with service:
        results = await service.scan_targets(
            [ScanTarget.from_hash("not-a-hash"), ScanTarget.from_hash("not-a-hash")]
        )
    assert len(results) == 2
    assert all(result.status == ResultStatus.ERROR for result in results)


async def test_preserves_mixed_input_order(service_factory, file_factory, mocker) -> None:
    service = service_factory()
    sample_file = file_factory("sample.bin", b"sample")
    mocker.patch.object(service, "_query_virustotal_async", return_value=((1, 0, 0, 0), False))
    async with service:
        results = await service.scan_targets(
            [
                ScanTarget.from_hash("a" * 64),
                ScanTarget.from_file_path(str(sample_file)),
                ScanTarget.from_hash("b" * 64),
            ]
        )
    assert [result.kind for result in results] == [
        ScanTargetKind.HASH,
        ScanTargetKind.FILE,
        ScanTargetKind.HASH,
    ]
    assert results[0].file_hash == "a" * 64
    assert results[1].item == str(sample_file)
    assert results[2].file_hash == "b" * 64


async def test_preserves_hash_input_order(service_factory, mocker) -> None:
    service = service_factory()

    async def _query(client, rate_limiter, file_hash, *, check_cache=True):
        if file_hash.startswith("a"):
            await asyncio.sleep(0.05)
        return (1, 0, 0, 0), False

    mocker.patch.object(service, "_query_virustotal_async", side_effect=_query)
    async with service:
        results = await service.scan_targets(
            [
                ScanTarget.from_hash("a" * 64),
                ScanTarget.from_hash("b" * 64),
            ]
        )
    assert [result.file_hash for result in results] == ["a" * 64, "b" * 64]


async def test_emits_cancelled_when_pre_cancelled(service_factory) -> None:
    service = service_factory()
    seen: list[ScanResult] = []
    thread_cancel = threading.Event()
    thread_cancel.set()
    async with service:
        results = await service.scan_targets(
            [ScanTarget.from_hash("a" * 64), ScanTarget.from_hash("b" * 64), ScanTarget.from_hash("c" * 64)],
            on_result=seen.append,
            cancel_event=thread_cancel,
        )
    assert len(results) == 3
    assert len(seen) == 3
    assert all(result.status == ResultStatus.CANCELLED for result in results)


async def test_waits_for_late_unique_hash(service_factory, mocker) -> None:
    service = service_factory()
    late_prepare_started = asyncio.Event()
    release_late_prepare = asyncio.Event()
    seen: list[ScanResult] = []

    async def _prepare_target(target: ScanTarget, cancel_event) -> tuple[ScanResult | None, ScanTarget | None]:
        if target.value == "f" * 64:
            late_prepare_started.set()
            await release_late_prepare.wait()
        return None, ScanTarget.from_hash(target.value)

    async def _scan_hash_live(client, rate_limiter, normalized_hash: str) -> ScanResult:
        return service_results.stats_result(
            item=service_results.format_hash(normalized_hash),
            kind=ScanTargetKind.HASH,
            file_hash=normalized_hash,
            stats=(1, 0, 0, 0),
            was_cached=False,
        )

    async def _scan_hash_live_for_test(client, rate_limiter, unresolved, cancel_event=None) -> ScanResult:
        return await _scan_hash_live(client, rate_limiter, unresolved.hash)

    async def _run() -> list[ScanResult]:
        task = asyncio.create_task(
            service.scan_targets(
                [
                    ScanTarget.from_hash("a" * 64),
                    ScanTarget.from_hash("b" * 64),
                    ScanTarget.from_hash("c" * 64),
                    ScanTarget.from_hash("d" * 64),
                    ScanTarget.from_hash("e" * 64),
                    ScanTarget.from_hash("f" * 64),
                ],
                on_result=seen.append,
            )
        )
        await late_prepare_started.wait()
        await asyncio.sleep(0)
        release_late_prepare.set()
        return await asyncio.wait_for(task, timeout=0.5)

    mocker.patch.object(service, "_prepare_hash_scan_async", side_effect=_prepare_target)
    mocker.patch.object(service, "_scan_live_async", side_effect=_scan_hash_live_for_test)
    async with service:
        results = await _run()
    assert len(results) == 6
    assert len(seen) == 6
    assert results[-1].file_hash == "f" * 64


async def test_succeeds_when_cache_save_fails(
    service_factory, mocker, limiter, vt_stats_client_factory
) -> None:
    service = service_factory()
    mocker.patch.object(service, "_cache_get_async", return_value=None)
    mocker.patch.object(
        service,
        "_cache_save_async",
        side_effect=sqlite3.OperationalError("disk full"),
    )
    fake_client = vt_stats_client_factory("a" * 64, (0, 3, 10, 2))
    result = await service._scan_live_async(fake_client, limiter, ScanTarget.from_hash("a" * 64))
    assert result.status == ResultStatus.OK
    assert result.threat_level == ThreatLevel.SUSPICIOUS
    assert result.was_cached is False


async def test_cache_init_failure_allows_live_lookup(
    tmp_path, mocker, limiter, vt_stats_client_factory
) -> None:
    service = ScannerService(api_key="test", cache_db=tmp_path / "vt_cache.db")
    try:
        mocker.patch.object(service._cache, "init", side_effect=RuntimeError("cache broken"))
        service.init_cache()
        fake_client = vt_stats_client_factory("a" * 64, (1, 0, 10, 0))
        result = await service._scan_live_async(fake_client, limiter, ScanTarget.from_hash("a" * 64))
    finally:
        service.close()
    assert service._cache_available is False
    assert result.status == ResultStatus.OK
    assert result.was_cached is False


def test_init_cache_idempotent(service_factory, mocker) -> None:
    service = service_factory()
    init_spy = mocker.spy(service._cache, "init")
    service.init_cache()
    init_spy.assert_not_called()


async def test_init_cache_async(tmp_path) -> None:
    service = ScannerService(api_key="test", cache_db=tmp_path / "vt_cache.db")
    try:
        assert service._cache_available is False
        await service.init_cache_async()
        assert service._cache_available is True
    finally:
        service.close()


async def test_init_cache_async_exception(tmp_path, mocker) -> None:
    service = ScannerService(api_key="test", cache_db=tmp_path / "vt_cache.db")
    try:
        mocker.patch.object(service._cache, "init", side_effect=RuntimeError("broken"))
        await service.init_cache_async()
        assert service._cache_available is False
    finally:
        service.close()


def test_clear_cache_when_unavailable(tmp_path) -> None:
    service = ScannerService(api_key="test", cache_db=tmp_path / "vt_cache.db")
    try:
        assert service._cache_available is False
        assert service.clear_cache() == 0
    finally:
        service.close()


async def test_clear_cache_async(service_factory, mocker) -> None:
    service = service_factory()
    mocker.patch.object(service._cache, "clear", return_value=5)
    count = await service.clear_cache_async()
    assert count == 5


def test_close_with_session_client(tmp_path, mocker) -> None:
    service = ScannerService(api_key="test", cache_db=tmp_path / "vt_cache.db")
    fake_client = mocker.MagicMock()
    service._session_client = fake_client
    service.close()
    fake_client.close.assert_called_once()
    assert service._session_client is None


async def test_cache_get_unavailable_returns_none(tmp_path) -> None:
    service = ScannerService(api_key="test", cache_db=tmp_path / "vt_cache.db")
    try:
        result = await service._cache_get_async("a" * 64)
        assert result is None
    finally:
        service.close()


async def test_cache_get_not_found_returns_none(service_factory) -> None:
    service = service_factory()
    service._cache.save_not_found("b" * 64)
    result = await service._cache_get_async("b" * 64)
    assert result is None


async def test_cache_save_noop_when_unavailable(tmp_path) -> None:
    service = ScannerService(api_key="test", cache_db=tmp_path / "vt_cache.db")
    try:
        await service._cache_save_async("a" * 64, (0, 0, 1, 0))
    finally:
        service.close()


async def test_scan_targets_empty_returns_empty(service_factory) -> None:
    service = service_factory()
    async with service:
        results = await service.scan_targets([])
    assert results == []


def test_clear_cache_when_available(service_factory, mocker) -> None:
    service = service_factory()
    mocker.patch.object(service._cache, "clear", return_value=3)
    assert service.clear_cache() == 3


async def test_clear_cache_async_when_unavailable(tmp_path) -> None:
    service = ScannerService(api_key="test", cache_db=tmp_path / "vt_cache2.db")
    try:
        assert service._cache_available is False
        assert await service.clear_cache_async() == 0
    finally:
        service.close()
