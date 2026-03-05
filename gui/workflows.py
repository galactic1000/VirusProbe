"""Background scan and upload workflow logic for VirusProbe GUI."""

from __future__ import annotations

from dataclasses import dataclass
from threading import Event
from typing import Any, Callable

from common import ScannerService


@dataclass
class ScanWorkflowResult:
    results: list[dict[str, Any]]
    completed: int
    total: int
    cancelled: bool
    entry_iids: list[str]


def run_scan_workflow(
    scanner: ScannerService,
    ordered_entries: list[tuple[str, str, str]],
    cancel_event: Event,
    on_result: Callable[[dict[str, Any], str | None, int, int], None],
) -> ScanWorkflowResult:
    total = len(ordered_entries)
    completed = 0
    new_results: list[dict[str, Any]] = []
    entry_by_file: dict[str, str] = {}
    entry_by_hash: dict[str, str] = {}
    file_values: list[str] = []
    hash_values: list[str] = []
    for iid, item_type, value in ordered_entries:
        if item_type == "file":
            file_values.append(value)
            entry_by_file[value] = iid
        else:
            hash_values.append(value)
            entry_by_hash[value.strip().lower()] = iid

    def _on_result(result: dict[str, Any]) -> None:
        nonlocal completed
        new_results.append(result)
        if str(result.get("type", "")) == "file":
            iid = entry_by_file.get(str(result.get("item", "")))
        else:
            iid = entry_by_hash.get(str(result.get("file_hash", "")).lower())
        completed += 1
        on_result(result, iid, completed, total)

    if file_values and not cancel_event.is_set():
        scanner.scan_files(file_values, on_result=_on_result, cancel_event=cancel_event)
    if hash_values and not cancel_event.is_set():
        scanner.scan_hashes(hash_values, on_result=_on_result, cancel_event=cancel_event)

    return ScanWorkflowResult(
        results=new_results,
        completed=completed,
        total=total,
        cancelled=cancel_event.is_set(),
        entry_iids=[iid for iid, _, _ in ordered_entries],
    )


@dataclass
class UploadWorkflowResult:
    cancelled: bool
    entry_iids: list[str]


def run_upload_workflow(
    scanner: ScannerService,
    entries: list[tuple[str, str]],
    cancel_event: Event,
    on_result: Callable[[dict[str, Any], str | None], None],
) -> UploadWorkflowResult:
    entry_by_file = {file_path: iid for iid, file_path in entries}
    results = scanner.scan_files([file_path for _, file_path in entries], cancel_event=cancel_event)
    for result in results:
        file_path = str(result.get("item", ""))
        iid = entry_by_file.get(file_path)
        on_result(result, iid)
    return UploadWorkflowResult(cancelled=cancel_event.is_set(), entry_iids=[iid for iid, _ in entries])
