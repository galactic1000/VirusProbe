from __future__ import annotations

import asyncio
from threading import Event

import pytest

from common import service_results
from common.models import ResultStatus, ScanResult, ScanTarget, ScanTargetKind, UploadTarget


async def test_small_batch_deduplicates_by_hash(service_factory, file_factory, mocker) -> None:
    service = service_factory(max_workers=4)
    same_a = file_factory("same_a.bin", b"same")
    same_b = file_factory("same_b.bin", b"same")
    uniq = file_factory("uniq.bin", b"uniq")
    query_mock = mocker.patch.object(service, "_query_virustotal_async", return_value=((0, 0, 5, 0), False))
    async with service:
        results = await service.scan_targets(
            [
                ScanTarget.from_file_path(str(same_a)),
                ScanTarget.from_file_path(str(same_b)),
                ScanTarget.from_file_path(str(uniq)),
            ]
        )
    assert len(results) == 3
    assert results[0].item == str(same_a)
    assert results[1].item == str(same_b)
    assert results[2].item == str(uniq)
    assert query_mock.await_count == 2


async def test_live_starts_before_all_prep(service_factory, mocker) -> None:
    service = service_factory()
    live_started = asyncio.Event()

    async def _prepare(target: ScanTarget, cancel_event) -> tuple[ScanResult | None, ScanTarget | None]:
        if target.value == "first":
            return None, ScanTarget.from_file("a" * 64, target.value)
        await live_started.wait()
        return service_results.error_result(target.value, ScanTargetKind.FILE, "prepared after live start"), None

    async def _query(client, rate_limiter, file_hash: str, *, check_cache: bool = True):
        live_started.set()
        return (0, 0, 1, 0), False

    mocker.patch.object(service, "_prepare_file_scan_async", side_effect=_prepare)
    mocker.patch.object(service, "_query_virustotal_async", side_effect=_query)
    async with service:
        results = await asyncio.wait_for(
            service.scan_targets([ScanTarget.from_file_path("first"), ScanTarget.from_file_path("second")]),
            timeout=0.2,
        )
    assert len(results) == 2
    assert live_started.is_set()


async def test_waits_for_late_prepared_file(service_factory, mocker) -> None:
    service = service_factory()
    late_prepare_started = asyncio.Event()
    release_late_prepare = asyncio.Event()
    seen: list[ScanResult] = []

    async def _prepare(target: ScanTarget, cancel_event) -> tuple[ScanResult | None, ScanTarget | None]:
        if target.value == "late.bin":
            late_prepare_started.set()
            await release_late_prepare.wait()
        return None, ScanTarget.from_file(f"{target.value}-hash", target.value)

    async def _scan_file_live(client, rate_limiter, file_path: str, file_hash: str, cancel_event) -> ScanResult:
        return ScanResult(item=file_path, kind=ScanTargetKind.FILE, file_hash=file_hash, status=ResultStatus.OK)

    async def _scan_file_live_for_test(client, rate_limiter, unresolved, cancel_event=None) -> ScanResult:
        return await _scan_file_live(client, rate_limiter, unresolved.file_path, unresolved.hash, cancel_event)

    async def _run() -> list[ScanResult]:
        task = asyncio.create_task(
            service.scan_targets(
                [
                    ScanTarget.from_file_path("a.bin"),
                    ScanTarget.from_file_path("b.bin"),
                    ScanTarget.from_file_path("c.bin"),
                    ScanTarget.from_file_path("d.bin"),
                    ScanTarget.from_file_path("e.bin"),
                    ScanTarget.from_file_path("late.bin"),
                ],
                on_result=seen.append,
            )
        )
        await late_prepare_started.wait()
        await asyncio.sleep(0)
        release_late_prepare.set()
        return await asyncio.wait_for(task, timeout=0.5)

    mocker.patch.object(service, "_prepare_file_scan_async", side_effect=_prepare)
    mocker.patch.object(service, "_scan_live_async", side_effect=_scan_file_live_for_test)
    async with service:
        results = await _run()
    assert len(results) == 6
    assert len(seen) == 6
    assert results[-1].item == "late.bin"


async def test_cached_result_not_found_file(service_factory, tmp_path) -> None:
    service = service_factory()
    file_path = str(tmp_path / "missing.bin")
    file_hash = "c" * 64
    service._cache.save_not_found(file_hash)
    result = await service._cached_result_async(item=file_path, kind=ScanTargetKind.FILE, file_hash=file_hash)
    assert result is not None
    assert result.status == ResultStatus.UNDETECTED


async def test_prepare_file_scan_not_found(service_factory) -> None:
    service = service_factory()
    result, unresolved = await service._prepare_file_scan_async(
        ScanTarget.from_file_path("/no/such/file.bin")
    )
    assert unresolved is None
    assert result is not None
    assert result.status == ResultStatus.ERROR
    assert "does not exist" in result.message


async def test_prepare_file_scan_not_a_file(service_factory, tmp_path) -> None:
    service = service_factory()
    result, unresolved = await service._prepare_file_scan_async(
        ScanTarget.from_file_path(str(tmp_path))
    )
    assert unresolved is None
    assert result is not None
    assert result.status == ResultStatus.ERROR
    assert "is not a file" in result.message


async def test_prepare_file_scan_hash_oserror(service_factory, file_factory, mocker) -> None:
    service = service_factory()
    sample = file_factory("oserr.bin", b"x")
    mocker.patch.object(service, "hash_file_async", side_effect=OSError("read error"))
    result, unresolved = await service._prepare_file_scan_async(
        ScanTarget.from_file_path(str(sample))
    )
    assert unresolved is None
    assert result is not None
    assert result.status == ResultStatus.ERROR


async def test_upload_file_direct_pre_cancel(service_factory, file_factory, limiter) -> None:
    service = service_factory()
    sample = file_factory("precancel.bin", b"x")
    cancel = Event()
    cancel.set()
    result = await service._upload_file_direct_async(
        object(), limiter, str(sample), "a" * 64, cancel  # type: ignore[arg-type]
    )
    assert result.status == ResultStatus.CANCELLED


@pytest.mark.parametrize("use_dir,expected_message", [
    (False, "File not found"),  # nonexistent path
    (True, "Not a file"),       # directory instead of file
])
async def test_upload_file_direct_path_error(service_factory, tmp_path, limiter, use_dir, expected_message) -> None:
    service = service_factory()
    path = str(tmp_path) if use_dir else str(tmp_path / "no_such.bin")
    result = await service._upload_file_direct_async(
        object(), limiter, path, "a" * 64  # type: ignore[arg-type]
    )
    assert result.status == ResultStatus.ERROR
    assert expected_message in result.message


async def test_upload_files_direct(service_factory, file_factory, mocker) -> None:
    service = service_factory()
    sample_a = file_factory("a.bin", b"a")
    sample_b = file_factory("b.bin", b"b")
    entries = [
        UploadTarget(file_path=str(sample_a), file_hash="a" * 64),
        UploadTarget(file_path=str(sample_b), file_hash="b" * 64),
    ]
    ok_result = ScanResult(item="x", kind=ScanTargetKind.FILE, file_hash="a" * 64, status=ResultStatus.OK)
    mocker.patch.object(service, "_upload_file_direct_async", return_value=ok_result)
    async with service:
        results = await service.upload_files_direct(entries)
    assert len(results) == 2


# ---------------------------------------------------------------------------
# Large-batch path (scan_deduped_large_batch_async, max_workers=1)
# ---------------------------------------------------------------------------


async def test_large_batch_pre_cancel(service_factory, file_factory) -> None:
    service = service_factory(max_workers=1)
    a = file_factory("la.bin", b"a")
    b = file_factory("lb.bin", b"b")
    cancel = Event()
    cancel.set()
    async with service:
        results = await service.scan_targets(
            [ScanTarget.from_file_path(str(a)), ScanTarget.from_file_path(str(b))],
            cancel_event=cancel,
        )
    assert all(r.status == ResultStatus.CANCELLED for r in results)


async def test_large_batch_immediate_result(service_factory, file_factory, mocker) -> None:
    service = service_factory(max_workers=1)
    a = file_factory("ia.bin", b"a")
    mocker.patch.object(service, "_query_virustotal_async", return_value=((0, 0, 1, 0), False))
    async with service:
        results = await service.scan_targets([
            ScanTarget.from_file_path(str(a)),
            ScanTarget.from_file_path("/no/such/file.bin"),
        ])
    statuses = {r.status for r in results}
    assert ResultStatus.OK in statuses
    assert ResultStatus.ERROR in statuses


async def test_large_batch_duplicate_hash_waiter(service_factory, file_factory, mocker) -> None:
    service = service_factory(max_workers=1)
    a = file_factory("da.bin", b"same")
    b = file_factory("db.bin", b"same")
    mocker.patch.object(service, "_query_virustotal_async", return_value=((2, 0, 0, 0), False))
    async with service:
        results = await service.scan_targets([
            ScanTarget.from_file_path(str(a)),
            ScanTarget.from_file_path(str(b)),
        ])
    assert len(results) == 2
    assert all(r.malicious == 2 for r in results)


async def test_large_batch_cancel_in_live_worker(service_factory, file_factory, mocker) -> None:
    service = service_factory(max_workers=1)
    a = file_factory("ca.bin", b"a")
    b = file_factory("cb.bin", b"b")
    cancel = Event()
    call_count = 0

    async def _mock_query(_client, _limiter, _hash, *, check_cache=True):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            cancel.set()
        return (0, 0, 1, 0), False

    mocker.patch.object(service, "_query_virustotal_async", side_effect=_mock_query)
    async with service:
        results = await service.scan_targets(
            [ScanTarget.from_file_path(str(a)), ScanTarget.from_file_path(str(b))],
            cancel_event=cancel,
        )
    assert any(r.status == ResultStatus.CANCELLED for r in results)
