from __future__ import annotations

from threading import Event

import pytest

from common.models import ResultStatus, ScanResult, ScanTarget, ScanTargetKind, UploadTarget
from gui.workflows import (
    PendingScanEntry,
    PendingUploadEntry,
    ReportRequest,
    run_report_workflow_async,
    run_scan_workflow_async,
    run_upload_workflow_async,
    upload_completion_feedback,
)


class _FakeScanWorkflowScanner:
    def __init__(self, results: list[ScanResult]) -> None:
        self.results = results
        self.received_targets: list[ScanTarget] | None = None
        self.received_cancel_event = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def scan_targets(self, targets, on_result=None, cancel_event=None):
        self.received_targets = list(targets)
        self.received_cancel_event = cancel_event
        for result in self.results:
            if on_result is not None:
                on_result(result)
        return self.results


class _FakeUploadWorkflowScanner:
    def __init__(self, results: list[ScanResult]) -> None:
        self.results = results
        self.received_entries: list[UploadTarget] | None = None
        self.received_cancel_event = None

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return None

    async def upload_files_direct(self, entries, on_result=None, cancel_event=None):
        self.received_entries = list(entries)
        self.received_cancel_event = cancel_event
        for result in self.results:
            if on_result is not None:
                on_result(result)
        return self.results


async def test_scan_workflow_maps_results_to_iids() -> None:
    ordered_entries = [
        PendingScanEntry("row-file", ScanTargetKind.FILE, "C:/sample.bin"),
        PendingScanEntry("row-hash", ScanTargetKind.HASH, "A" * 64),
    ]
    results = [
        ScanResult(item="C:/sample.bin", kind=ScanTargetKind.FILE, file_hash="f" * 64, status=ResultStatus.OK),
        ScanResult(item="SHA-256 hash: " + ("a" * 64), kind=ScanTargetKind.HASH, file_hash="a" * 64, status=ResultStatus.OK),
    ]
    scanner = _FakeScanWorkflowScanner(results)
    seen = []

    def on_result(result: ScanResult, iid: str | None, completed: int, total: int) -> None:
        seen.append((iid, completed, total, result.type))

    run_result = await run_scan_workflow_async(
        scanner=scanner,  # type: ignore[arg-type]
        ordered_entries=ordered_entries,
        cancel_event=Event(),
        on_result=on_result,
    )

    assert scanner.received_targets is not None
    assert [target.kind for target in scanner.received_targets] == [ScanTargetKind.FILE, ScanTargetKind.HASH]
    assert [target.value for target in scanner.received_targets] == ["C:/sample.bin", "A" * 64]
    assert seen == [
        ("row-file", 1, 2, "file"),
        ("row-hash", 2, 2, "hash"),
    ]
    assert run_result.completed == 2
    assert run_result.total == 2
    assert run_result.cancelled is False
    assert run_result.entry_iids == ["row-file", "row-hash"]


async def test_scan_workflow_skips_when_pre_cancelled(mocker) -> None:
    ordered_entries = [PendingScanEntry("row-hash", ScanTargetKind.HASH, "A" * 64)]
    scanner = _FakeScanWorkflowScanner([])
    cancel_event = Event()
    cancel_event.set()
    scan_targets = mocker.spy(scanner, "scan_targets")

    run_result = await run_scan_workflow_async(
        scanner=scanner,  # type: ignore[arg-type]
        ordered_entries=ordered_entries,
        cancel_event=cancel_event,
        on_result=lambda *_args: None,
    )

    scan_targets.assert_not_called()
    assert run_result.completed == 0
    assert run_result.total == 1
    assert run_result.cancelled is True


async def test_upload_workflow_tracks_errors() -> None:
    entries = [
        PendingUploadEntry("row-a", "C:/a.bin", "a" * 64),
        PendingUploadEntry("row-b", "C:/b.bin", "b" * 64),
    ]
    results = [
        ScanResult(item="C:/a.bin", kind=ScanTargetKind.FILE, file_hash="a" * 64, status=ResultStatus.OK),
        ScanResult(item="C:/b.bin", kind=ScanTargetKind.FILE, file_hash="b" * 64, status=ResultStatus.ERROR),
    ]
    scanner = _FakeUploadWorkflowScanner(results)
    seen = []

    def on_result(result: ScanResult, iid: str | None) -> None:
        seen.append((iid, result.status))

    run_result = await run_upload_workflow_async(
        scanner=scanner,  # type: ignore[arg-type]
        entries=entries,
        cancel_event=Event(),
        on_result=on_result,
    )

    assert scanner.received_entries is not None
    assert [(entry.file_path, entry.file_hash) for entry in scanner.received_entries] == [
        ("C:/a.bin", "a" * 64),
        ("C:/b.bin", "b" * 64),
    ]
    assert seen == [("row-a", "ok"), ("row-b", "error")]
    assert run_result.total == 2
    assert run_result.error_count == 1
    assert run_result.cancelled is False
    assert run_result.entry_iids == ["row-a", "row-b"]


async def test_report_workflow_delegates_write(mocker, tmp_path) -> None:
    request = ReportRequest(
        new_dir=str(tmp_path),
        output_path=str(tmp_path / "report.json"),
        report_format="json",
    )
    results = [ScanResult(item="x", kind=ScanTargetKind.FILE, file_hash="a" * 64)]
    write_mock = mocker.patch("gui.workflows.write_report")

    returned = await run_report_workflow_async(results, request, 95)

    write_mock.assert_called_once_with(results, request.output_path, request.report_format, 95)
    assert returned is request


@pytest.mark.parametrize("total,errors,expected", [
    (3, 0, ("Upload complete", "Upload Complete", "Uploaded 3 file(s).", "success")),
    (3, 1, ("Upload finished with errors", "Upload Finished With Errors", "Uploaded 2/3 file(s); 1 failed.", "warning")),
])
def test_upload_completion_feedback(total: int, errors: int, expected: tuple) -> None:
    assert upload_completion_feedback(total, errors) == expected
