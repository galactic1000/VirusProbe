"""Tkinter GUI app and controller for VirusProbe."""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog
from typing import Any

import ttkbootstrap as ttk
from tkinterdnd2 import TkinterDnD
from ttkbootstrap.dialogs.dialogs import Messagebox
from ttkbootstrap.widgets import ToastNotification

from common import CACHE_DB, THEME_AUTO, UPLOAD_AUTO, get_theme_mode
from common.service import DEFAULT_REQUESTS_PER_MINUTE, DEFAULT_SCAN_WORKERS, DEFAULT_UPLOAD_TIMEOUT_MINUTES

from .style import apply_theme, apply_titlebar_theme, theme_name
from .dialogs import (
    show_add_hashes_dialog,
    show_advanced_dialog,
    show_generate_report_dialog,
    show_set_api_key_dialog,
)
from .async_runner import BackgroundAsyncRunner
from .model import AppModel
from .presenter import AppPresenter, masked_api_key_text, upload_indicator_text
from .view import MainWindow
from .workflows import run_scan_workflow_async, run_upload_workflow_async, upload_completion_feedback


class VirusProbeGUI(ttk.Window):
    _ICON = Path(__file__).resolve().parent / "assets" / "icon.png"
    _BASE_DPI = 96.0  # standard DPI at 100% Windows scale
    _WINDOW_WIDTH = 980
    _WINDOW_HEIGHT = 620
    _MIN_WIDTH = 860
    _MIN_HEIGHT = 520
    _TOAST_DURATION = 3200
    _ERROR_TOAST_DURATION = 4500

    def __init__(self) -> None:
        super().__init__(
            title="VirusProbe GUI",
            themename=theme_name(get_theme_mode() or THEME_AUTO),
            iconphoto=str(self._ICON) if self._ICON.exists() else None,
        )
        self.withdraw()
        scale = self.winfo_fpixels("1i") / self._BASE_DPI
        self.geometry(f"{int(self._WINDOW_WIDTH * scale)}x{int(self._WINDOW_HEIGHT * scale)}")
        self.minsize(int(self._MIN_WIDTH * scale), int(self._MIN_HEIGHT * scale))
        TkinterDnD._require(self)
        self.place_window_center()
        self.bind_all("<Map>", self._on_toplevel_map, add=True)

        self.model = AppModel(cache_db=CACHE_DB)
        self._async_runner = BackgroundAsyncRunner()
        self.view = MainWindow(
            root=self,
            on_clear_cache=self.on_clear_cache,
            on_set_api_key=self.on_set_api_key,
            on_add_files=self.on_add_files,
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
        self.active_upload_entries: list[tuple[str, str, str]] = []
        self.cancel_event = threading.Event()
        self.is_scanning = False
        self.is_uploading = False
        self.is_clearing_cache = False
        self.is_closing = False
        self.scan_total = 0

        self.rpm_var = tk.StringVar(value=str(self.model.saved_rpm))
        self.workers_var = tk.StringVar(value=str(self.model.saved_workers))
        self.upload_timeout_var = tk.StringVar(value=str(self.model.saved_upload_timeout))

        self.initialize_view()
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        apply_titlebar_theme(self)
        self.deiconify()

    def _on_toplevel_map(self, event: tk.Event) -> None:
        if isinstance(event.widget, tk.Toplevel):
            if not getattr(event.widget, "_titlebar_styled", False):
                apply_titlebar_theme(event.widget)

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
        value = show_set_api_key_dialog(self, self.model.api_key)
        if value is None:
            return
        self.model.set_api_key(value)
        self._update_api_key_status()

    def on_clear_cache(self) -> None:
        if self.is_scanning or self.is_uploading or self.is_clearing_cache:
            return
        result = Messagebox.yesno(
            "Clear local SQLite cache now?",
            title="Clear Cache",
            parent=self,
            buttons=["No:secondary", "Yes:primary"],
            default="No",
        )
        if result != "Yes":
            return

        self.is_clearing_cache = True
        self._set_progress_text("Clearing cache...")
        self._update_upload_action_visibility()
        future = self._async_runner.submit(self.model.clear_cache_async())
        future.add_done_callback(self._on_clear_cache_done)

    def on_add_files(self) -> None:
        for path in filedialog.askopenfilenames(parent=self, title="Select files to scan"):
            self._add_item("file", str(path))

    def on_add_hashes(self) -> None:
        show_add_hashes_dialog(self, self._add_item)

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
            self,
            self._parse_int(self.rpm_var.get(), DEFAULT_REQUESTS_PER_MINUTE, minimum=0),
            self._parse_int(self.workers_var.get(), DEFAULT_SCAN_WORKERS, minimum=1),
            self._parse_int(self.upload_timeout_var.get(), DEFAULT_UPLOAD_TIMEOUT_MINUTES, minimum=0),
            self.model.upload_mode,
            self.model.theme_mode,
        )
        if result is None:
            return
        rpm, workers, upload_timeout, mode, theme_mode = result
        self.rpm_var.set(str(rpm))
        self.workers_var.set(str(workers))
        self.upload_timeout_var.set(str(upload_timeout))
        self.model.set_advanced(rpm, workers, upload_timeout, mode, theme_mode)
        apply_theme(self, theme_mode)
        self._update_upload_indicator()
        self._update_upload_action_visibility()

    def on_drop_files(self, event: object) -> None:
        try:
            paths = self.tk.splitlist(getattr(event, "data"))
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
            self,
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
        if self.is_clearing_cache:
            self.is_closing = True
            return
        self.model.close()
        self._async_runner.close()
        self.destroy()

    def _start_scan(self) -> None:
        if self.is_scanning or self.is_uploading or self.is_clearing_cache:
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
        self._set_entry_rows_status(self.pending_entries, "Scanning...")

        self.current_rpm, self.current_workers, self.current_upload_timeout = self._current_limits()
        self._begin_busy_state(self.on_scan)
        self.is_scanning = True
        self.view.report_button.configure(state="disabled")
        self._set_progress_text("Scanning...")
        future = self._async_runner.submit(self._run_scan_async())
        future.add_done_callback(self._on_scan_done)

    async def _run_scan_async(self) -> Any:
        def on_result(result: dict[str, Any], iid: str | None, completed: int, total: int) -> None:
            if iid is not None:
                self._safe_after(self.view.set_row_status, iid, self.model.result_status(result))
            self.model.upsert_result(result)
            self._safe_after(self._set_progress_text, "Scanning...")
            self._safe_after(self.view.set_progress, completed, total)

        scanner = await self.model.acquire_scanner_async(
            requests_per_minute=self.current_rpm,
            workers=self.current_workers,
            upload_timeout=self.current_upload_timeout,
            upload_undetected=(self.model.upload_mode == UPLOAD_AUTO),
        )
        return await run_scan_workflow_async(
            scanner=scanner,
            ordered_entries=self.pending_entries,
            cancel_event=self.cancel_event,
            on_result=on_result,
        )

    def _start_upload_selected(self) -> None:
        if self.is_scanning or self.is_uploading or self.is_clearing_cache:
            return
        if not self.api_key:
            self._show_error("Missing API Key", "Set an API key before uploading.")
            return

        file_entries = self.view.undetected_files(selected_only=True) or self.view.undetected_files()
        if not file_entries:
            return

        entries = [(iid, fp, self.model.get_file_hash(fp)) for iid, fp in file_entries]
        self.active_upload_entries = entries

        self._set_entry_rows_status(entries, "Uploading...")
        self._begin_busy_state(self._cancel_upload)
        self.is_uploading = True
        self.view.set_progress(0, len(entries))
        self._set_progress_text("Uploading...")
        future = self._async_runner.submit(self._run_upload_async(entries))
        future.add_done_callback(self._on_upload_done)

    def _cancel_upload(self) -> None:
        if not self.is_uploading:
            return
        self._request_cancel("Cancelling upload...")

    async def _run_upload_async(self, entries: list[tuple[str, str, str]]) -> tuple[Any, int, int]:
        current_rpm, current_workers, current_upload_timeout = self._current_limits()
        total = len(entries)
        completed_ref = [0]
        error_count_ref = [0]

        def on_result(result: dict[str, Any], iid: str | None) -> None:
            completed_ref[0] += 1
            c = completed_ref[0]
            if result.get("status") == "error":
                error_count_ref[0] += 1
            if iid is not None:
                self._safe_after(self.view.set_row_status, iid, self.model.result_status(result))
            self.model.upsert_result(result)
            self._safe_after(self.view.set_progress, c, total)
            self._safe_after(self._set_progress_text, "Uploading...")

        scanner = await self.model.acquire_scanner_async(
            requests_per_minute=current_rpm,
            workers=max(1, min(current_workers, len(entries))),
            upload_timeout=current_upload_timeout,
            upload_undetected=False,
        )
        run_result = await run_upload_workflow_async(
            scanner=scanner,
            entries=entries,
            cancel_event=self.cancel_event,
            on_result=on_result,
        )
        return run_result, total, error_count_ref[0]

    def _on_clear_cache_done(self, future) -> None:
        try:
            deleted = future.result()
        except Exception as exc:
            self._safe_after(lambda err=str(exc): self._show_error("Cache Error", err))
            self._safe_after(self._finish_clear_cache_error)
            return
        self._safe_after(self._finish_clear_cache, deleted)

    def _finish_clear_cache(self, deleted: int) -> None:
        try:
            label = f"{deleted} entr{'y' if deleted == 1 else 'ies'}"
            Messagebox.show_info(f"Cleared SQLite cache ({label}).", title="Cache Cleared", parent=self)
            self._set_progress_text(f"Cache cleared ({label})")
        finally:
            self.is_clearing_cache = False
            self._update_upload_action_visibility()
            if self.is_closing:
                self.model.close()
                self._async_runner.close()
                self.destroy()

    def _finish_clear_cache_error(self) -> None:
        self.is_clearing_cache = False
        self._set_progress_text("Cache clear failed")
        self._update_upload_action_visibility()
        if self.is_closing:
            self.model.close()
            self._async_runner.close()
            self.destroy()

    def _on_scan_done(self, future) -> None:
        try:
            run_result = future.result()
        except Exception as exc:
            self._safe_after(self._finish_scan, None, exc)
            return
        self._safe_after(self._finish_scan, run_result, None)

    def _finish_scan(self, run_result: Any, exc: Exception | None) -> None:
        try:
            if exc is None:
                self.model.merge_results(run_result.results)
                if self.model.has_results():
                    self.view.report_button.configure(state="normal")

                if run_result.cancelled:
                    self.view.mark_rows_status_if_current(run_result.entry_iids, "Scanning...", "Cancelled")
                    self._set_progress_text(
                        self._status_with_queued_suffix(f"Scan cancelled ({run_result.completed}/{run_result.total})")
                    )
                    self.view.set_progress(run_result.completed, run_result.total)
                else:
                    self._set_progress_text(self._status_with_queued_suffix("Scan complete"))
                    self.view.set_progress(run_result.total, run_result.total)
                    self._show_toast("Scan Complete", f"Processed {run_result.total} item(s).", "success")
                return

            if self.model.has_results():
                self.view.report_button.configure(state="normal")
            self._show_error("Scan Error", str(exc))
            self._set_progress_text(self._status_with_queued_suffix("Scan failed"))
            if not self.is_closing:
                self._show_toast("Scan Failed", str(exc), "danger", self._ERROR_TOAST_DURATION)
        finally:
            self.is_scanning = False
            self._restore_buttons()
            if self.is_closing:
                self.model.close()
                self._async_runner.close()
                self.destroy()

    def _on_upload_done(self, future) -> None:
        try:
            run_result, total, error_count = future.result()
        except Exception as exc:
            self._safe_after(self._finish_upload, None, None, None, exc)
            return
        self._safe_after(self._finish_upload, run_result, total, error_count, None)

    def _finish_upload(
        self,
        run_result: Any,
        total: int | None,
        error_count: int | None,
        exc: Exception | None,
    ) -> None:
        try:
            if exc is None:
                assert total is not None
                assert error_count is not None
                if run_result.cancelled:
                    self.view.mark_rows_status_if_current(run_result.entry_iids, "Uploading...", "Cancelled")
                    self._set_progress_text(self._status_with_queued_suffix("Upload cancelled"))
                else:
                    progress_text, toast_title, toast_message, toast_style = upload_completion_feedback(
                        total, error_count
                    )
                    self._set_progress_text(self._status_with_queued_suffix(progress_text))
                    self._show_toast(toast_title, toast_message, toast_style)
                return

            self._show_error("Upload Error", str(exc))
            self._set_progress_text(self._status_with_queued_suffix("Upload failed"))
            self.view.mark_rows_status_if_current(
                [iid for iid, _, _ in self.active_upload_entries],
                "Uploading...",
                "Error",
            )
            if not self.is_closing:
                self._show_toast("Upload Failed", str(exc), "danger", self._ERROR_TOAST_DURATION)
        finally:
            self.is_uploading = False
            self.active_upload_entries = []
            self._restore_buttons()
            if self.is_closing:
                self.model.close()
                self._async_runner.close()
                self.destroy()

    def _add_item(self, item_type: str, value: str) -> bool:
        added = self.view.add_item(item_type, value)
        if added and not (self.is_scanning or self.is_uploading or self.is_clearing_cache):
            self._set_queued_count_text()
        return added

    def _set_entry_rows_status(self, entries: list[tuple[str, ...]], status: str) -> None:
        for iid, *_ in entries:
            self.view.set_row_status(iid, status)

    def _update_api_key_status(self) -> None:
        self.presenter.set_api_key_text(masked_api_key_text(self.model.api_key))

    def _update_upload_indicator(self) -> None:
        self.presenter.set_upload_indicator_text(upload_indicator_text(self.model.upload_mode))

    def _update_upload_action_visibility(self) -> None:
        self.presenter.update_upload_action_visibility(
            upload_mode=self.model.upload_mode,
            has_uploadable=self.view.has_uploadable_undetected(),
            busy=(self.is_scanning or self.is_uploading or self.is_clearing_cache),
        )

    def _show_info(self, title: str, text: str) -> None:
        Messagebox.show_info(text, title=title, parent=self)

    def _show_error(self, title: str, text: str) -> None:
        Messagebox.show_error(text, title=title, parent=self)

    def _show_toast(
        self,
        title: str,
        message: str,
        bootstyle: str = "secondary",
        duration: int | None = None,
    ) -> None:
        duration = duration if duration is not None else self._TOAST_DURATION
        try:
            ToastNotification(
                title=title,
                message=message,
                duration=duration,
                bootstyle=bootstyle,
            ).show_toast()
        except Exception:
            pass

    def _safe_after(self, callback, *args) -> None:
        try:
            if self.winfo_exists():
                self.after(0, callback, *args)
        except tk.TclError:
            pass

    def _parse_int(self, raw: str, default: int, minimum: int) -> int:
        return self.model.parse_int(raw, default, minimum)

    def _current_limits(self) -> tuple[int, int, int]:
        rpm = self._parse_int(self.rpm_var.get(), DEFAULT_REQUESTS_PER_MINUTE, minimum=0)
        workers = self._parse_int(self.workers_var.get(), DEFAULT_SCAN_WORKERS, minimum=1)
        upload_timeout = self._parse_int(self.upload_timeout_var.get(), DEFAULT_UPLOAD_TIMEOUT_MINUTES, minimum=0)
        return rpm, workers, upload_timeout

    def _request_cancel(self, text: str) -> None:
        self.cancel_event.set()
        self.presenter.set_canceling(text)

    def _begin_busy_state(self, cancel_handler) -> None:
        self.cancel_event.clear()
        self.presenter.begin_busy(cancel_handler)
        self._update_upload_action_visibility()

    def _set_queued_count_text(self) -> None:
        self.presenter.set_queued_count(self._queued_count())

    def _queued_count(self) -> int:
        return len(self.view.collect_pending_entries())

    def _status_with_queued_suffix(self, text: str) -> str:
        queued = self._queued_count()
        if queued <= 0:
            return text
        return f"{text} ({queued} queued)"

    def _set_progress_text(self, text: str) -> None:
        if self.view.progress_var.get() != text:
            self.view.progress_var.set(text)

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
    VirusProbeGUI().mainloop()
