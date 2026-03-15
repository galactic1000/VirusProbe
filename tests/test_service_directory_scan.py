from __future__ import annotations

import asyncio
from threading import Event

import pytest

from common import service_results
from common import service_scan
from common.models import ResultStatus, ScanResult, ScanTarget, ScanTargetKind


async def test_directory_passes_file_targets(tmp_path) -> None:
    sample_dir = tmp_path / "samples"
    sample_dir.mkdir()
    (sample_dir / "a.bin").write_bytes(b"a")
    (sample_dir / "b.bin").write_bytes(b"b")

    captured: list[ScanTarget] = []

    async def _scan_targets_fn(targets, on_result, cancel_event):
        captured.extend(targets)
        return []

    await service_scan.scan_directory_async(
        ScanTarget.from_directory(str(sample_dir)),
        scan_targets_fn=_scan_targets_fn,
        error_result=lambda target, message: service_results.error_result(target.value, target.kind, message),
    )
    assert sorted(target.value for target in captured) == sorted([str(sample_dir / "a.bin"), str(sample_dir / "b.bin")])
    assert all(target.kind is ScanTargetKind.FILE for target in captured)


@pytest.mark.parametrize("name,create_file", [
    ("nonexistent", False),  # path does not exist
    ("file.txt", True),      # path exists but is a file, not a directory
])
async def test_invalid_directory_target_returns_error(service_factory, tmp_path, name, create_file) -> None:
    path = tmp_path / name
    if create_file:
        path.write_text("data")
    service = service_factory()
    results = await service.scan_targets([ScanTarget.from_directory(str(path))])
    assert len(results) == 1
    assert results[0].status == ResultStatus.ERROR
    assert results[0].type == "directory"


async def test_directory_error_fires_on_result() -> None:
    seen: list[ScanResult] = []
    async def _scan_targets_fn(_targets, _on_r, _ce):
        return []

    await service_scan.scan_directory_async(
        ScanTarget.from_directory("/no/such/dir"),
        scan_targets_fn=_scan_targets_fn,
        error_result=lambda target, message: service_results.error_result(target.value, target.kind, message),
        on_result=seen.append,
    )
    assert len(seen) == 1
    assert seen[0].status == ResultStatus.ERROR


async def test_directory_enumeration_error_returns_error_result(mocker) -> None:
    seen: list[ScanResult] = []

    async def _scan_targets_fn(_targets, _on_r, _ce):
        return []

    mocker.patch("common.service_scan.Path.is_dir", return_value=True)
    mocker.patch("common.service_scan.Path.iterdir", side_effect=PermissionError("denied"))

    results = await service_scan.scan_directory_async(
        ScanTarget.from_directory("C:/restricted"),
        scan_targets_fn=_scan_targets_fn,
        error_result=lambda target, message: service_results.error_result(target.value, target.kind, message),
        on_result=seen.append,
    )

    assert len(results) == 1
    assert results[0].status == ResultStatus.ERROR
    assert "denied" in results[0].message
    assert seen == results


async def test_scan_many_empty_returns_empty() -> None:
    results = await service_scan.scan_many_async(
        asyncio.Semaphore(4),
        scan_func=lambda _: (_ for _ in ()).throw(AssertionError("should not be called")),
        items=[],
    )
    assert results == []


async def test_scan_many_pre_cancel_no_cancelled_result() -> None:
    cancel = Event()
    cancel.set()
    semaphore = asyncio.Semaphore(4)
    results = await service_scan.scan_many_async(
        semaphore,
        scan_func=lambda _: (_ for _ in ()).throw(AssertionError("should not be called")),
        items=["a", "b"],
        cancel_event=cancel,
    )
    assert results == []


async def test_scan_many_cancel_mid_scan() -> None:
    cancel = Event()
    semaphore = asyncio.Semaphore(4)
    fired: list[ScanResult] = []

    async def _scan(item: str) -> ScanResult:
        cancel.set()
        return ScanResult(item=item, kind=ScanTargetKind.FILE, file_hash="a" * 64, status=ResultStatus.OK)

    def _cancelled(item: str) -> ScanResult:
        return ScanResult(item=item, kind=ScanTargetKind.FILE, file_hash="a" * 64, status=ResultStatus.CANCELLED)

    results = await service_scan.scan_many_async(
        semaphore,
        scan_func=_scan,
        items=["first", "second"],
        on_result=fired.append,
        cancel_event=cancel,
        cancelled_result=_cancelled,
    )
    statuses = {r.status for r in results}
    assert ResultStatus.CANCELLED in statuses
