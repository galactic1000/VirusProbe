"""Workflow controllers for VirusProbe GUI."""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING, Any

from common import ScannerService, UPLOAD_AUTO, UPLOAD_MANUAL
from common.service import DEFAULT_REQUESTS_PER_MINUTE, DEFAULT_SCAN_WORKERS

if TYPE_CHECKING:
    from .app import VirusProbeGUI


class ScanController:
    def __init__(self, app: "VirusProbeGUI") -> None:
        self.app = app

    def start(self) -> None:
        app = self.app
        if app.is_scanning or app.is_uploading:
            return
        if not app.view.tree.get_children():
            app._show_info("No Items", "Add at least one file or SHA-256 hash to scan.")
            return
        if not app.api_key:
            app._show_error("Missing API Key", "Set an API key before scanning.")
            return
        app.pending_entries = app._collect_pending_entries()
        if not app.pending_entries:
            app._show_info("Nothing to Scan", "All items have already been scanned. Add new items to scan.")
            return
        app.scan_total = len(app.pending_entries)
        app.view.set_progress(0, app.scan_total)
        for iid, _, _ in app.pending_entries:
            app._set_row_status(iid, "Scanning...")
        app.current_rpm = app._parse_int(app.rpm_var.get(), DEFAULT_REQUESTS_PER_MINUTE, minimum=0)
        app.current_workers = app._parse_int(app.workers_var.get(), DEFAULT_SCAN_WORKERS, minimum=1)
        app.cancel_event.clear()
        app.is_scanning = True
        app.view.report_button.configure(state="disabled")
        app._set_scanning_ui(True)
        app.view.progress_var.set("Starting scan...")
        threading.Thread(target=self._worker, daemon=True).start()

    def cancel(self) -> None:
        app = self.app
        if not app.is_scanning:
            return
        app.cancel_event.set()
        app.view.scan_btn.configure(state="disabled")
        app.view.progress_var.set("Cancelling scan...")

    def _worker(self) -> None:
        app = self.app
        scanner: ScannerService | None = None
        try:
            scanner = ScannerService(
                api_key=app.api_key or "",
                cache_db=app.cache_db,
                requests_per_minute=app.current_rpm,
                max_workers=app.current_workers,
                upload_undetected=(app.upload_mode == UPLOAD_AUTO),
            )
            app.scanner = scanner
            scanner.init_cache()
            ordered_entries = app.pending_entries
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

            def on_result(result: dict[str, Any]) -> None:
                nonlocal completed
                new_results.append(result)
                iid: str | None
                if str(result.get("type", "")) == "file":
                    iid = entry_by_file.get(str(result.get("item", "")))
                else:
                    iid = entry_by_hash.get(str(result.get("file_hash", "")).lower())
                if iid is not None:
                    app._safe_after(app._set_row_status, iid, app._result_status(result))
                completed += 1
                app._safe_after(lambda c=completed: app.view.progress_var.set(f"Scanning {c}/{total}..."))
                app._safe_after(app.view.set_progress, completed, total)

            if file_values and not app.cancel_event.is_set():
                scanner.scan_files(file_values, on_result=on_result, cancel_event=app.cancel_event)
            if hash_values and not app.cancel_event.is_set():
                scanner.scan_hashes(hash_values, on_result=on_result, cancel_event=app.cancel_event)

            app._merge_results(new_results)
            if app.last_results:
                app._safe_after(lambda: app.view.report_button.configure(state="normal"))
            if app.cancel_event.is_set():
                app._safe_after(app._mark_scanning_cancelled, [iid for iid, _, _ in ordered_entries])
                app._safe_after(lambda c=completed, t=total: app.view.progress_var.set(f"Scan cancelled ({c}/{t})"))
                app._safe_after(app.view.set_progress, completed, total)
            else:
                app._safe_after(lambda: app.view.progress_var.set("Scan complete"))
                app._safe_after(app.view.set_progress, total, total)
        except Exception as exc:
            app._safe_after(lambda: app._show_error("Scan Error", str(exc)))
            app._safe_after(lambda: app.view.progress_var.set("Scan failed"))
        finally:
            if scanner is not None:
                scanner.close()
            app.scanner = None
            app.is_scanning = False
            app._safe_after(app._restore_scan_buttons)
            if app.is_closing:
                app._safe_after(app.root.destroy)


class UploadController:
    def __init__(self, app: "VirusProbeGUI") -> None:
        self.app = app

    def has_uploadable_undetected(self) -> bool:
        app = self.app
        if app.upload_mode != UPLOAD_MANUAL:
            return False
        for iid in app.view.tree.get_children():
            vals = app.view.tree.item(iid, "values")
            if vals and vals[0] == "file" and vals[2] == "Undetected":
                return True
        return False

    def start_selected(self) -> None:
        app = self.app
        if app.is_scanning or app.is_uploading:
            return
        if not app.api_key:
            app._show_error("Missing API Key", "Set an API key before uploading.")
            return
        selected = app.view.tree.selection()
        entries: list[tuple[str, str]] = []
        for iid in selected:
            vals = app.view.tree.item(iid, "values")
            if vals and vals[0] == "file" and vals[2] == "Undetected":
                entries.append((iid, vals[1]))
        if not entries:
            app._show_info("No Upload Selection", "Select one or more 'Undetected' file rows to upload.")
            return
        for iid, _ in entries:
            app._set_row_status(iid, "Uploading...")
        app.cancel_event.clear()
        app.is_uploading = True
        app.view.set_controls_enabled(False)
        app.view.set_scan_button_cancel(self.cancel)
        app._update_upload_action_visibility()
        app.view.progress_var.set(f"Uploading {len(entries)} selected file(s)...")
        threading.Thread(target=self._worker, args=(entries,), daemon=True).start()

    def cancel(self) -> None:
        app = self.app
        if not app.is_uploading:
            return
        app.cancel_event.set()
        app.view.scan_btn.configure(state="disabled")
        app.view.progress_var.set("Cancelling upload...")

    def _worker(self, entries: list[tuple[str, str]]) -> None:
        app = self.app
        scanner: ScannerService | None = None
        try:
            current_rpm = app._parse_int(app.rpm_var.get(), DEFAULT_REQUESTS_PER_MINUTE, minimum=0)
            current_workers = app._parse_int(app.workers_var.get(), DEFAULT_SCAN_WORKERS, minimum=1)
            entry_by_file = {file_path: iid for iid, file_path in entries}
            scanner = ScannerService(
                api_key=app.api_key or "",
                cache_db=app.cache_db,
                requests_per_minute=current_rpm,
                max_workers=max(1, min(current_workers, len(entries))),
                upload_undetected=True,
            )
            scanner.init_cache()
            results = scanner.scan_files([file_path for _, file_path in entries], cancel_event=app.cancel_event)
            for result in results:
                file_path = str(result.get("item", ""))
                iid = entry_by_file.get(file_path)
                if iid is not None:
                    app._safe_after(app._set_row_status, iid, app._result_status(result))
                app._upsert_last_result(result)
            if app.cancel_event.is_set():
                app._safe_after(app._mark_uploading_cancelled, [iid for iid, _ in entries])
                app._safe_after(lambda: app.view.progress_var.set("Upload cancelled"))
            else:
                app._safe_after(lambda: app.view.progress_var.set("Upload complete"))
        except Exception as exc:
            app._safe_after(lambda: app._show_error("Upload Error", str(exc)))
            app._safe_after(lambda: app.view.progress_var.set("Upload failed"))

            def _mark_errors() -> None:
                for iid, _ in entries:
                    vals = app.view.tree.item(iid, "values")
                    if vals and vals[2] == "Uploading...":
                        app._set_row_status(iid, "Error")

            app._safe_after(_mark_errors)
        finally:
            if scanner is not None:
                scanner.close()
            app.is_uploading = False
            app._safe_after(app._restore_scan_buttons)
            app._safe_after(app._update_upload_action_visibility)
            if app.is_closing:
                app._safe_after(app.root.destroy)

