"""Scan and upload workflows."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from threading import Event
from collections.abc import Callable

from common import (
    ResultStatus,
    ScanResult,
    ScannerService,
    ScanTarget,
    ScanTargetKind,
    UploadTarget,
    write_report,
)


@dataclass
class ScanWorkflowResult:
    completed: int
    total: int
    cancelled: bool
    entry_iids: list[str]


@dataclass(frozen=True)
class PendingScanEntry:
    iid: str
    kind: ScanTargetKind
    value: str


async def run_scan_workflow_async(
    scanner: ScannerService,
    ordered_entries: list[PendingScanEntry],
    cancel_event: Event,
    on_result: Callable[[ScanResult, str | None, int, int], None],
) -> ScanWorkflowResult:
    total = len(ordered_entries)
    completed = 0
    entry_by_file = {}
    entry_by_hash = {}
    targets = []
    for entry in ordered_entries:
        if entry.kind is ScanTargetKind.FILE:
            entry_by_file[entry.value] = entry.iid
            targets.append(ScanTarget.from_file_path(entry.value))
        else:
            entry_by_hash[entry.value.strip().lower()] = entry.iid
            targets.append(ScanTarget.from_hash(entry.value))

    def _on_result(result: ScanResult) -> None:
        nonlocal completed
        if result.kind is ScanTargetKind.FILE:
            iid = entry_by_file.get(result.item)
        else:
            iid = entry_by_hash.get(result.file_hash.lower())
        completed += 1
        on_result(result, iid, completed, total)

    async with scanner:
        if targets and not cancel_event.is_set():
            await scanner.scan_targets(targets, on_result=_on_result, cancel_event=cancel_event)

    return ScanWorkflowResult(
        completed=completed,
        total=total,
        cancelled=cancel_event.is_set(),
        entry_iids=[entry.iid for entry in ordered_entries],
    )


@dataclass
class UploadWorkflowResult:
    total: int
    error_count: int
    cancelled: bool
    entry_iids: list[str]


@dataclass(frozen=True)
class PendingUploadEntry:
    iid: str
    file_path: str
    file_hash: str


def upload_completion_feedback(total: int, error_count: int) -> tuple[str, str, str, str]:
    if error_count > 0:
        success_count = max(0, total - error_count)
        return (
            "Upload finished with errors",
            "Upload Finished With Errors",
            f"Uploaded {success_count}/{total} file(s); {error_count} failed.",
            "warning",
        )
    return (
        "Upload complete",
        "Upload Complete",
        f"Uploaded {total} file(s).",
        "success",
    )


async def run_upload_workflow_async(
    scanner: ScannerService,
    entries: list[PendingUploadEntry],
    cancel_event: Event,
    on_result: Callable[[ScanResult, str | None], None],
) -> UploadWorkflowResult:
    entry_by_file = {entry.file_path: entry.iid for entry in entries}
    upload_entries = [UploadTarget(file_path=entry.file_path, file_hash=entry.file_hash) for entry in entries]
    total = len(entries)
    error_count = 0

    def _on_result(result: ScanResult) -> None:
        nonlocal error_count
        iid = entry_by_file.get(result.item)
        if result.status == ResultStatus.ERROR:
            error_count += 1
        on_result(result, iid)

    async with scanner:
        await scanner.upload_files_direct(upload_entries, on_result=_on_result, cancel_event=cancel_event)
    return UploadWorkflowResult(
        total=total,
        error_count=error_count,
        cancelled=cancel_event.is_set(),
        entry_iids=[entry.iid for entry in entries],
    )


@dataclass(frozen=True)
class ReportRequest:
    new_dir: str
    output_path: str
    report_format: str


async def run_report_workflow_async(
    results: list[ScanResult],
    request: ReportRequest,
    separator_width: int,
) -> ReportRequest:
    await asyncio.to_thread(
        write_report,
        results,
        request.output_path,
        request.report_format,
        separator_width,
    )
    return request
