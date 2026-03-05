"""Tkinter GUI app and controller for VirusProbe."""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox
from typing import Any

from tkinterdnd2 import TkinterDnD

from common import ScannerService, UPLOAD_AUTO
from common.service import DEFAULT_REQUESTS_PER_MINUTE, DEFAULT_SCAN_WORKERS

from .dialogs import (
    show_add_hash_dialog,
    show_add_hashes_dialog,
    show_advanced_dialog,
    show_clear_cache_dialog,
    show_generate_report_dialog,
    show_set_api_key_dialog,
)
from .model import AppModel
from .presenter import AppPresenter, masked_api_key_text, upload_indicator_text
from .view import MainWindow
from .workflows import run_scan_workflow, run_upload_workflow

CACHE_DB = Path(__file__).resolve().parents[1] / "cache" / "vt_cache.db"


class VirusProbeGUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("VirusProbe GUI")
        self.root.geometry("980x620")
        self.root.minsize(860, 520)

        self.model = AppModel(cache_db=CACHE_DB)
        self.view: Any = MainWindow(
            root=self.root,
            on_clear_cache=self.on_clear_cache,
            on_set_api_key=self.on_set_api_key,
            on_add_files=self.on_add_files,
            on_add_hash=self.on_add_hash,
            on_add_hashes=self.on_add_hashes,
            on_remove_selected=self.on_remove_selected,
            on_clear_items=self.on_clear_items,
            on_advanced=self.on_advanced,
            on_scan=self.on_scan,
            on_upload=self.on_upload,
            on_drop_files=self.on_drop_files,
            on_generate_report=self.on_generate_report,
        )
        self.presenter = AppPresenter(self.view)

        self.pending_entries: list[tuple[str, str, str]] = []
        self.current_rpm = DEFAULT_REQUESTS_PER_MINUTE
        self.current_workers = DEFAULT_SCAN_WORKERS
        self.cancel_event = threading.Event()
        self.is_scanning = False
        self.is_uploading = False
        self.is_closing = False
        self.scan_total = 0

        self.rpm_var = tk.StringVar(value=str(self.model.saved_rpm))
        self.workers_var = tk.StringVar(value=str(self.model.saved_workers))

        self.initialize_view()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def initialize_view(self) -> None:
        self._update_api_key_status()
        self._update_upload_indicator()
        self._update_upload_action_visibility()

    @property
    def api_key(self) -> str | None:
        return self.model.api_key

    def on_scan(self) -> None:
        if self.is_scanning:
            self._request_cancel("Cancelling scan...")
            return
        self._start_scan()

    def on_upload(self) -> None:
        self._start_upload_selected()

    def on_set_api_key(self) -> None:
        value = show_set_api_key_dialog(self.root, self.model.api_key)
        if value is None:
            return
        self.model.set_api_key(value)
        self._update_api_key_status()

    def on_clear_cache(self) -> None:
        deleted = show_clear_cache_dialog(self.root, self.model.clear_cache)
        if deleted is not None:
            label = f"{deleted} entr{'y' if deleted == 1 else 'ies'}"
            self.view.progress_var.set(f"Cache cleared ({label})")

    def on_add_files(self) -> None:
        for path in filedialog.askopenfilenames(parent=self.root, title="Select files to scan"):
            self._add_item("file", str(path))

    def on_add_hash(self) -> None:
        value = show_add_hash_dialog(self.root)
        if value is not None:
            self._add_item("hash", value)

    def on_add_hashes(self) -> None:
        show_add_hashes_dialog(self.root, self._add_item)

    def on_remove_selected(self) -> None:
        if self.view.remove_selected():
            self._set_queued_count_text()
            self._update_upload_action_visibility()

    def on_clear_items(self) -> None:
        self.view.clear_items()
        self.model.clear_results()
        self.scan_total = 0
        self.view.set_progress(0, 0)
        self.view.report_button.configure(state="disabled")
        self.view.progress_var.set("Ready")
        self._update_upload_action_visibility()

    def on_advanced(self) -> None:
        result = show_advanced_dialog(
            self.root,
            self._parse_int(self.rpm_var.get(), DEFAULT_REQUESTS_PER_MINUTE, minimum=0),
            self._parse_int(self.workers_var.get(), DEFAULT_SCAN_WORKERS, minimum=1),
            self.model.upload_mode,
        )
        if result is None:
            return
        rpm, workers, mode = result
        self.rpm_var.set(str(rpm))
        self.workers_var.set(str(workers))
        self.model.set_advanced(rpm, workers, mode)
        self._update_upload_indicator()
        self._update_upload_action_visibility()

    def on_drop_files(self, event: object) -> None:
        try:
            paths = self.root.tk.splitlist(getattr(event, "data"))
        except Exception:
            paths = [getattr(event, "data", "")]
        for raw in paths:
            path = str(raw).strip().strip("{}")
            if path and Path(path).is_file():
                self._add_item("file", path)

    def on_generate_report(self) -> None:
        results_snapshot = self.model.results_snapshot()
        if not results_snapshot:
            self._show_info("No Results", "Run a scan first to generate a report.")
            return
        new_dir = show_generate_report_dialog(
            self.root,
            self.model.default_report_dir,
            results_snapshot,
            self._open_path,
            self._open_folder,
        )
        if new_dir:
            self.model.default_report_dir = new_dir

    def on_close(self) -> None:
        if self.is_scanning:
            self.is_closing = True
            self._request_cancel("Cancelling scan before close...")
            return
        if self.is_uploading:
            self.is_closing = True
            self._request_cancel("Cancelling upload before close...")
            return
        self.model.close()
        self.root.destroy()

    def _start_scan(self) -> None:
        if self.is_scanning or self.is_uploading:
            return
        if not self.view.item_count():
            self._show_info("No Items", "Add at least one file or SHA-256 hash to scan.")
            return
        if not self.api_key:
            self._show_error("Missing API Key", "Set an API key before scanning.")
            return

        self.pending_entries = self.view.collect_pending_entries()
        if not self.pending_entries:
            self._show_info("Nothing to Scan", "All items have already been scanned. Add new items to scan.")
            return

        self.scan_total = len(self.pending_entries)
        self.view.set_progress(0, self.scan_total)
        for iid, _, _ in self.pending_entries:
            self.view.set_row_status(iid, "Scanning...")

        self.current_rpm, self.current_workers = self._current_limits()
        self._begin_busy_state(self.on_scan)
        self.is_scanning = True
        self.view.report_button.configure(state="disabled")
        self.view.progress_var.set("Starting scan...")
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self) -> None:
        try:
            scanner = self._acquire_scanner(
                requests_per_minute=self.current_rpm,
                workers=self.current_workers,
                upload_undetected=(self.model.upload_mode == UPLOAD_AUTO),
            )

            def on_result(result: dict[str, Any], iid: str | None, completed: int, total: int) -> None:
                if iid is not None:
                    self._safe_after(self.view.set_row_status, iid, self.model.result_status(result))
                self._safe_after(lambda c=completed, t=total: self.view.progress_var.set(f"Scanning {c}/{t}..."))
                self._safe_after(self.view.set_progress, completed, total)

            run_result = run_scan_workflow(
                scanner=scanner,
                ordered_entries=self.pending_entries,
                cancel_event=self.cancel_event,
                on_result=on_result,
            )

            self.model.merge_results(run_result.results)
            if self.model.has_results():
                self._safe_after(lambda: self.view.report_button.configure(state="normal"))

            if run_result.cancelled:
                self._safe_after(
                    self.view.mark_rows_status_if_current,
                    run_result.entry_iids,
                    "Scanning...",
                    "Cancelled",
                )
                self._safe_after(
                    lambda c=run_result.completed, t=run_result.total: self.view.progress_var.set(f"Scan cancelled ({c}/{t})")
                )
                self._safe_after(self.view.set_progress, run_result.completed, run_result.total)
            else:
                self._safe_after(lambda: self.view.progress_var.set("Scan complete"))
                self._safe_after(self.view.set_progress, run_result.total, run_result.total)
        except Exception as exc:
            self._safe_after(lambda err=str(exc): self._show_error("Scan Error", err))
            self._safe_after(lambda: self.view.progress_var.set("Scan failed"))
        finally:
            self.is_scanning = False
            self._safe_after(self._restore_buttons)
            if self.is_closing:
                self._safe_after(self.root.destroy)

    def _start_upload_selected(self) -> None:
        if self.is_scanning or self.is_uploading:
            return
        if not self.api_key:
            self._show_error("Missing API Key", "Set an API key before uploading.")
            return

        file_entries = self.view.selected_undetected_files()
        if not file_entries:
            self._show_info("No Upload Selection", "Select one or more 'Undetected' file rows to upload.")
            return

        entries = [(iid, fp, "") for iid, fp in file_entries]

        for iid, _, _ in entries:
            self.view.set_row_status(iid, "Uploading...")
        self._begin_busy_state(self._cancel_upload)
        self.is_uploading = True
        self.view.set_progress(0, len(entries))
        self.view.progress_var.set(f"Uploading 0/{len(entries)}...")
        threading.Thread(target=self._upload_worker, args=(entries,), daemon=True).start()

    def _cancel_upload(self) -> None:
        if not self.is_uploading:
            return
        self._request_cancel("Cancelling upload...")

    def _upload_worker(self, entries: list[tuple[str, str, str]]) -> None:
        try:
            current_rpm, current_workers = self._current_limits()
            scanner = self._acquire_scanner(
                requests_per_minute=current_rpm,
                workers=max(1, min(current_workers, len(entries))),
                upload_undetected=False,
            )

            total = len(entries)
            completed_ref = [0]

            def on_result(result: dict[str, Any], iid: str | None) -> None:
                completed_ref[0] += 1
                c = completed_ref[0]
                if iid is not None:
                    self._safe_after(self.view.set_row_status, iid, self.model.result_status(result))
                self.model.upsert_result(result)
                self._safe_after(self.view.set_progress, c, total)
                self._safe_after(lambda cc=c, t=total: self.view.progress_var.set(f"Uploading {cc}/{t}..."))

            run_result = run_upload_workflow(
                scanner=scanner,
                entries=entries,
                cancel_event=self.cancel_event,
                on_result=on_result,
            )
            if run_result.cancelled:
                self._safe_after(
                    self.view.mark_rows_status_if_current,
                    run_result.entry_iids,
                    "Uploading...",
                    "Cancelled",
                )
                self._safe_after(lambda: self.view.progress_var.set("Upload cancelled"))
            else:
                self._safe_after(lambda: self.view.progress_var.set("Upload complete"))
        except Exception as exc:
            self._safe_after(lambda err=str(exc): self._show_error("Upload Error", err))
            self._safe_after(lambda: self.view.progress_var.set("Upload failed"))
            self._safe_after(
                self.view.mark_rows_status_if_current,
                [iid for iid, _, _ in entries],
                "Uploading...",
                "Error",
            )
        finally:
            self.is_uploading = False
            self._safe_after(self._restore_buttons)
            if self.is_closing:
                self._safe_after(self.root.destroy)

    def _acquire_scanner(self, requests_per_minute: int, workers: int, upload_undetected: bool) -> ScannerService:
        return self.model.acquire_scanner(requests_per_minute, workers, upload_undetected)

    def _add_item(self, item_type: str, value: str) -> bool:
        added = self.view.add_item(item_type, value)
        if added:
            self._set_queued_count_text()
        return added

    def _update_api_key_status(self) -> None:
        self.presenter.set_api_key_text(masked_api_key_text(self.model.api_key))

    def _update_upload_indicator(self) -> None:
        self.presenter.set_upload_indicator_text(upload_indicator_text(self.model.upload_mode))

    def _update_upload_action_visibility(self) -> None:
        self.presenter.update_upload_action_visibility(
            upload_mode=self.model.upload_mode,
            has_uploadable=self.view.has_uploadable_undetected(),
            busy=(self.is_scanning or self.is_uploading),
        )

    def _show_info(self, title: str, text: str) -> None:
        messagebox.showinfo(title, text, parent=self.root)

    def _show_error(self, title: str, text: str) -> None:
        messagebox.showerror(title, text, parent=self.root)

    def _safe_after(self, callback, *args) -> None:
        try:
            if self.root.winfo_exists():
                self.root.after(0, callback, *args)
        except tk.TclError:
            pass

    def _parse_int(self, raw: str, default: int, minimum: int) -> int:
        return self.model.parse_int(raw, default, minimum)

    def _current_limits(self) -> tuple[int, int]:
        rpm = self._parse_int(self.rpm_var.get(), DEFAULT_REQUESTS_PER_MINUTE, minimum=0)
        workers = self._parse_int(self.workers_var.get(), DEFAULT_SCAN_WORKERS, minimum=1)
        return rpm, workers

    def _request_cancel(self, text: str) -> None:
        self.cancel_event.set()
        self.presenter.set_canceling(text)

    def _begin_busy_state(self, cancel_handler) -> None:
        self.cancel_event.clear()
        self.presenter.begin_busy(cancel_handler)
        self._update_upload_action_visibility()

    def _set_queued_count_text(self) -> None:
        self.presenter.set_queued_count(self.view.item_count())

    def _restore_buttons(self) -> None:
        if not self.is_closing:
            self.presenter.restore_idle(self.on_scan)
        self._update_upload_action_visibility()

    def _open_path(self, path: str) -> None:
        try:
            if os.name == "nt":
                os.startfile(path)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.run(["open", path], check=False)
            else:
                subprocess.run(["xdg-open", path], check=False)
        except Exception as exc:
            self._show_error("Open Error", str(exc))

    def _open_folder(self, path: str) -> None:
        self._open_path(str(Path(path).resolve().parent))


def main() -> None:
    root = TkinterDnD.Tk()
    VirusProbeGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
