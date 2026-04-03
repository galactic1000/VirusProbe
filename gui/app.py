"""PySide6 GUI app and controller for VirusProbe."""

from __future__ import annotations

import asyncio
import sys
import threading
from collections.abc import Callable
from pathlib import Path
from typing import TypeVar

from PySide6.QtCore import QObject, QThread, Qt, Signal, Slot
from PySide6.QtGui import QCloseEvent, QDesktopServices, QIcon
from PySide6.QtWidgets import (
    QApplication,
    QFileDialog,
    QMainWindow,
    QMessageBox,
)
from PySide6.QtCore import QUrl

from common import (
    CACHE_DB,
    DEFAULT_REQUESTS_PER_MINUTE,
    DEFAULT_SCAN_WORKERS,
    DEFAULT_UPLOAD_TIMEOUT_MINUTES,
    ScannerConfig,
    ScanResult,
    THEME_AUTO,
    UPLOAD_AUTO,
    UPLOAD_MANUAL,
    is_valid_api_key,
)

from .dialogs import (
    show_add_hashes_dialog,
    show_advanced_dialog,
    show_generate_report_dialog,
    show_report_saved_dialog,
    show_set_api_key_dialog,
)
from .model import AppModel
from .presenter import masked_api_key_text, upload_indicator_text
from .results_model import UiState
from .style import apply_theme
from .view import MainWindow
from .workflows import (
    PendingUploadEntry,
    ReportRequest,
    ScanWorkflowResult,
    UploadWorkflowResult,
    run_report_workflow_async,
    run_scan_workflow_async,
    run_upload_workflow_async,
    upload_completion_feedback,
)

_TaskResult = TypeVar("_TaskResult")


class TaskWorker(QObject):
    """Runs a callable on a worker thread and emits Qt signals for lifecycle updates."""

    result = Signal(object)
    error = Signal(object)
    finished = Signal()
    progress = Signal(int, int)
    scan_result = Signal(object, object)
    upload_result = Signal(object, object)

    def __init__(self, fn: Callable[[TaskWorker], _TaskResult]) -> None:
        super().__init__()
        self._fn = fn

    @Slot()
    def run(self) -> None:
        try:
            result = self._fn(self)
        except Exception as exc:
            self.error.emit(exc)
        else:
            self.result.emit(result)
        finally:
            self.finished.emit()


class VirusProbeGUI(QMainWindow):
    _ICON = Path(__file__).resolve().parent / "assets" / "icon.png"
    _WINDOW_WIDTH = 980
    _WINDOW_HEIGHT = 620
    _MIN_WIDTH = 860
    _MIN_HEIGHT = 520

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle("VirusProbe GUI")
        self.resize(self._WINDOW_WIDTH, self._WINDOW_HEIGHT)
        self.setMinimumSize(self._MIN_WIDTH, self._MIN_HEIGHT)
        if self._ICON.exists():
            self.setWindowIcon(QIcon(str(self._ICON)))

        self.model = AppModel(cache_db=CACHE_DB)
        self.ui_state = UiState()
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
            on_copy_value=self.on_copy_value,
        )
        self.view.bind_state(self.ui_state)
        self.setCentralWidget(self.view.central_widget)

        self.pending_entries: list = []
        self.active_upload_entries: list = []
        self.cancel_event = threading.Event()
        self.is_scanning = False
        self.is_uploading = False
        self.is_clearing_cache = False
        self.is_generating_report = False
        self.is_closing = False
        self._rpm = str(self.model.saved_rpm)
        self._workers = str(self.model.saved_workers)
        self._upload_timeout = str(self.model.saved_upload_timeout)
        self._active_thread: QThread | None = None
        self._active_worker: TaskWorker | None = None

        apply_theme(self.model.theme_mode)
        app = QApplication.instance()
        if app is not None:
            app.styleHints().colorSchemeChanged.connect(self._on_color_scheme_changed)  # type: ignore
        self.initialize_view()

        self.show()

    def initialize_view(self) -> None:
        self._update_api_key_status()
        self._update_upload_indicator()
        self._update_upload_action_visibility()
        self._warn_if_invalid_loaded_api_key()

    @property
    def api_key(self) -> str | None:
        return self.model.api_key

    @property
    def _is_busy(self) -> bool:
        return self.is_scanning or self.is_uploading or self.is_clearing_cache or self.is_generating_report

    def _close_if_requested(self) -> None:
        if self.is_closing and not self._is_busy:
            self.model.close()
            app = QApplication.instance()
            if app is not None:
                app.quit()

    def closeEvent(self, event: QCloseEvent) -> None:
        if self.is_scanning:
            self.is_closing = True
            self._request_cancel("Cancelling scan before close...")
            event.ignore()
            return
        if self.is_uploading:
            self.is_closing = True
            self._request_cancel("Cancelling upload before close...")
            event.ignore()
            return
        if self.is_clearing_cache or self.is_generating_report:
            self.is_closing = True
            event.ignore()
            return
        self.model.close()
        event.accept()

    def on_scan(self) -> None:
        if self.is_scanning:
            self._request_cancel("Cancelling scan...")
            return
        self._start_scan()

    def on_upload(self) -> None:
        self._start_upload_selected()

    def on_set_api_key(self) -> None:
        if self._is_busy:
            return
        value = show_set_api_key_dialog(self, self.model.api_key)
        if value is None:
            return
        if value and not is_valid_api_key(value):
            self._show_error(
                "Invalid API Key",
                "VirusTotal API keys must be 64 hex characters. Please check your key and try again.",
            )
            return
        self.model.set_api_key(value)
        self._update_api_key_status()

    def on_clear_cache(self) -> None:
        if self._is_busy:
            return
        result = QMessageBox.question(
            self,
            "Clear Cache",
            "Clear local SQLite cache now?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if result != QMessageBox.StandardButton.Yes:
            return

        self.is_clearing_cache = True
        self.ui_state.controls_enabled_changed.emit(False)
        self.ui_state.scan_button_enabled_changed.emit(False)
        self._set_progress_text("Clearing cache...")
        self.ui_state.report_button_enabled_changed.emit(False)
        self._update_upload_action_visibility()
        self._start_worker(lambda _worker: self.model.clear_cache(), self._finish_clear_cache, self._handle_clear_cache_error)

    def on_add_files(self) -> None:
        if self._is_busy:
            return
        paths, _ = QFileDialog.getOpenFileNames(self, "Select files to scan")
        for path in paths:
            if Path(path).is_file():
                self._add_item("file", path)

    def on_add_hashes(self) -> None:
        if self._is_busy:
            return
        show_add_hashes_dialog(self, self._add_item)

    def on_remove_selected(self) -> None:
        if self._is_busy:
            return
        removed_keys = self.view.remove_selected()
        if removed_keys:
            self.model.remove_results(removed_keys)
            self._set_queued_count_text()
            self._update_upload_action_visibility()

    def on_clear_items(self) -> None:
        if self._is_busy:
            return
        self.view.clear_items()
        self.model.clear_results()
        self.ui_state.progress_changed.emit(0, 0)
        self.ui_state.report_button_enabled_changed.emit(False)
        self._set_progress_text("Ready")
        self._update_upload_action_visibility()

    def on_advanced(self) -> None:
        if self._is_busy:
            return
        result = show_advanced_dialog(
            self,
            self._parse_int(self._rpm, DEFAULT_REQUESTS_PER_MINUTE, minimum=0),
            self._parse_int(self._workers, DEFAULT_SCAN_WORKERS, minimum=1),
            self._parse_int(self._upload_timeout, DEFAULT_UPLOAD_TIMEOUT_MINUTES, minimum=0),
            self.model.upload_mode,
            self.model.theme_mode,
        )
        if result is None:
            return
        rpm, workers, upload_timeout, mode, theme_mode = result
        self._rpm = str(rpm)
        self._workers = str(workers)
        self._upload_timeout = str(upload_timeout)
        self.model.set_advanced(rpm, workers, upload_timeout, mode, theme_mode)
        apply_theme(theme_mode)
        self._update_upload_indicator()
        self._update_upload_action_visibility()

    def on_drop_files(self, paths: list[str]) -> None:
        if self._is_busy:
            return
        for path in paths:
            if path and Path(path).is_file():
                self._add_item("file", path)

    def on_generate_report(self) -> None:
        if self._is_busy:
            return
        results_snapshot = self._current_report_results()
        if not results_snapshot:
            self._show_info("No Results", "Run a scan first to generate a report.")
            return
        request = show_generate_report_dialog(self, self.model.default_report_dir)
        if request is None:
            return
        self.is_generating_report = True
        self.ui_state.controls_enabled_changed.emit(False)
        self.ui_state.scan_button_enabled_changed.emit(False)
        self._update_upload_action_visibility()
        self.ui_state.report_button_enabled_changed.emit(False)
        self._set_progress_text("Generating report...")
        self._start_worker(
            lambda _worker: asyncio.run(
                run_report_workflow_async(results_snapshot, request, self.view.separator_width)
            ),
            self._finish_report_success,
            self._finish_report_error,
        )

    def on_copy_value(self, value: str) -> None:
        clipboard = QApplication.clipboard()
        if clipboard is None:
            self._show_error("Clipboard Error", "System clipboard is unavailable.")
            return
        clipboard.setText(value)
        self._set_progress_text("Copied value to clipboard")

    def _start_scan(self) -> None:
        if self._is_busy:
            return
        if not self.view.item_count():
            self._show_info("No Items", "Add at least one file or hash to scan.")
            return
        if not self.api_key:
            self._show_error("Missing API Key", "Set an API key before scanning.")
            return

        self.pending_entries = self.view.collect_pending_entries()
        if not self.pending_entries:
            self._show_info("Nothing to Scan", "All items have already been scanned. Add new items to scan.")
            return

        self.ui_state.progress_changed.emit(0, len(self.pending_entries))
        for entry in self.pending_entries:
            self.view.set_row_status(entry.iid, "Scanning...")

        self.is_scanning = True
        self._begin_busy_state(self.on_scan)
        self.ui_state.report_button_enabled_changed.emit(False)
        self._set_progress_text("Scanning...")

        def task(worker: TaskWorker) -> ScanWorkflowResult:
            rpm, workers, upload_timeout = self._current_limits()
            scanner = self.model.build_scanner(
                ScannerConfig(
                    requests_per_minute=rpm,
                    max_workers=workers,
                    upload_timeout_minutes=upload_timeout,
                    upload_undetected=(self.model.upload_mode == UPLOAD_AUTO),
                )
            )

            async def run() -> ScanWorkflowResult:
                def on_result(result: ScanResult, iid: str | None, completed: int, total: int) -> None:
                    worker.scan_result.emit(result, iid)
                    worker.progress.emit(completed, total)

                return await run_scan_workflow_async(
                    scanner=scanner,
                    ordered_entries=self.pending_entries,
                    cancel_event=self.cancel_event,
                    on_result=on_result,
                )

            try:
                return asyncio.run(run())
            finally:
                scanner.close()

        self._start_worker(task, self._finish_scan_success, self._finish_scan_error, connect_scan=True)

    def _current_report_results(self) -> list[ScanResult]:
        return self.model.results_for_keys(self.view.result_keys_in_order())

    def _start_upload_selected(self) -> None:
        if self._is_busy:
            return
        if not self.api_key:
            self._show_error("Missing API Key", "Set an API key before uploading.")
            return

        has_selection = self.view.has_selection()
        file_entries = self.view.undetected_files(selected_only=has_selection)
        if not file_entries:
            return

        entries = [
            PendingUploadEntry(iid=iid, file_path=fp, file_hash=self.model.get_file_hash(fp))
            for iid, fp in file_entries
        ]
        self.active_upload_entries = entries
        for entry in entries:
            self.view.set_row_status(entry.iid, "Uploading...")

        self.is_uploading = True
        self._begin_busy_state(self._cancel_upload)
        self.ui_state.progress_changed.emit(0, len(entries))
        self._set_progress_text("Uploading...")

        def task(worker: TaskWorker) -> UploadWorkflowResult:
            current_rpm, current_workers, current_upload_timeout = self._current_limits()
            scanner = self.model.build_scanner(
                ScannerConfig(
                    requests_per_minute=current_rpm,
                    max_workers=max(1, min(current_workers, len(entries))),
                    upload_timeout_minutes=current_upload_timeout,
                )
            )

            async def run() -> UploadWorkflowResult:
                completed = 0
                total = len(entries)

                def on_result(result: ScanResult, iid: str | None) -> None:
                    nonlocal completed
                    completed += 1
                    worker.upload_result.emit(result, iid)
                    worker.progress.emit(completed, total)

                return await run_upload_workflow_async(
                    scanner=scanner,
                    entries=entries,
                    cancel_event=self.cancel_event,
                    on_result=on_result,
                )

            try:
                return asyncio.run(run())
            finally:
                scanner.close()

        self._start_worker(task, self._finish_upload_success, self._finish_upload_error, connect_upload=True)

    def _cancel_upload(self) -> None:
        if self.is_uploading:
            self._request_cancel("Cancelling upload...")

    def _start_worker(
        self,
        fn: Callable[[TaskWorker], _TaskResult],
        on_success: Callable[[_TaskResult], None],
        on_error: Callable[[Exception], None],
        *,
        connect_scan: bool = False,
        connect_upload: bool = False,
    ) -> None:
        thread = QThread(self)
        worker = TaskWorker(fn)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.result.connect(on_success)
        worker.error.connect(on_error)
        worker.finished.connect(thread.quit)
        worker.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)
        thread.finished.connect(self._clear_worker_refs)
        if connect_scan:
            worker.scan_result.connect(self._handle_scan_result)
        if connect_upload:
            worker.upload_result.connect(self._handle_upload_result)
        worker.progress.connect(self.ui_state.progress_changed.emit)

        self._active_thread = thread
        self._active_worker = worker
        thread.start()

    @Slot()
    def _clear_worker_refs(self) -> None:
        self._active_worker = None
        self._active_thread = None

    @Slot(object, object)
    def _handle_scan_result(self, result: object, iid: object) -> None:
        scan_result = result if isinstance(result, ScanResult) else None
        row_iid = iid if isinstance(iid, str) else None
        if scan_result is None:
            return
        if row_iid is not None:
            self.view.set_row_status(row_iid, self.model.result_status(scan_result))
        self.model.upsert_result(scan_result)
        self._set_progress_text("Scanning...")

    @Slot(object, object)
    def _handle_upload_result(self, result: object, iid: object) -> None:
        scan_result = result if isinstance(result, ScanResult) else None
        row_iid = iid if isinstance(iid, str) else None
        if scan_result is None:
            return
        if row_iid is not None:
            self.view.set_row_status(row_iid, self.model.result_status(scan_result))
        self.model.upsert_result(scan_result)
        self._set_progress_text("Uploading...")

    @Slot(object)
    def _finish_clear_cache(self, deleted: int) -> None:
        try:
            label = f"{deleted} entr{'y' if deleted == 1 else 'ies'}"
            QMessageBox.information(self, "Cache Cleared", f"Cleared SQLite cache ({label}).")
            self._set_progress_text(f"Cache cleared ({label})")
        finally:
            self.is_clearing_cache = False
            self._restore_buttons()
            self._update_upload_action_visibility()
            self._close_if_requested()

    @Slot(object)
    def _handle_clear_cache_error(self, exc: Exception) -> None:
        self._show_error("Cache Error", str(exc))
        self._finish_clear_cache_error()

    def _finish_clear_cache_error(self) -> None:
        self.is_clearing_cache = False
        self._set_progress_text("Cache clear failed")
        self._restore_buttons()
        self._update_upload_action_visibility()
        self._close_if_requested()

    @Slot(object)
    def _finish_scan_success(self, run_result: ScanWorkflowResult) -> None:
        try:
            if self.model.has_results():
                self.ui_state.report_button_enabled_changed.emit(True)
            if run_result.cancelled:
                self.view.mark_rows_status_if_current(run_result.entry_iids, "Scanning...", "Cancelled")
                self._set_progress_text(
                    self._status_with_queued_suffix(f"Scan cancelled ({run_result.completed}/{run_result.total})")
                )
                self.ui_state.progress_changed.emit(run_result.completed, run_result.total)
            else:
                self._set_progress_text(self._status_with_queued_suffix("Scan complete"))
                self.ui_state.progress_changed.emit(run_result.total, run_result.total)
        finally:
            self.is_scanning = False
            self._restore_buttons()
            self._close_if_requested()

    @Slot(object)
    def _finish_scan_error(self, exc: Exception) -> None:
        try:
            if self.model.has_results():
                self.ui_state.report_button_enabled_changed.emit(True)
            self._mark_entries_as_error(self.pending_entries, "Scanning...")
            self._show_error("Scan Error", str(exc))
            self._set_progress_text(self._status_with_queued_suffix("Scan failed"))
        finally:
            self.is_scanning = False
            self._restore_buttons()
            self._close_if_requested()

    @Slot(object)
    def _finish_report_success(self, request: ReportRequest) -> None:
        try:
            self.model.set_default_report_dir(request.new_dir)
            self._set_progress_text("Report saved")
            show_report_saved_dialog(self, request.output_path, self._open_path, self._open_folder)
        finally:
            self.is_generating_report = False
            self._restore_buttons()
            self._restore_report_button_if_ready()
            self._close_if_requested()

    @Slot(object)
    def _finish_report_error(self, exc: Exception) -> None:
        try:
            self._show_error("Report Error", str(exc))
            self._set_progress_text("Report generation failed")
        finally:
            self.is_generating_report = False
            self._restore_buttons()
            self._restore_report_button_if_ready()
            self._close_if_requested()

    @Slot(object)
    def _finish_upload_success(self, run_result: UploadWorkflowResult) -> None:
        try:
            if run_result.cancelled:
                self.view.mark_rows_status_if_current(run_result.entry_iids, "Uploading...", "Cancelled")
                self._set_progress_text(self._status_with_queued_suffix("Upload cancelled"))
            else:
                progress_text, toast_title, toast_message, toast_style = upload_completion_feedback(
                    run_result.total, run_result.error_count
                )
                del toast_title, toast_message, toast_style
                self._set_progress_text(self._status_with_queued_suffix(progress_text))
        finally:
            self.is_uploading = False
            self.active_upload_entries = []
            self._restore_buttons()
            self._close_if_requested()

    @Slot(object)
    def _finish_upload_error(self, exc: Exception) -> None:
        try:
            self._show_error("Upload Error", str(exc))
            self._set_progress_text(self._status_with_queued_suffix("Upload failed"))
            self._mark_entries_as_error(self.active_upload_entries, "Uploading...")
        finally:
            self.is_uploading = False
            self.active_upload_entries = []
            self._restore_buttons()
            self._close_if_requested()

    def _mark_entries_as_error(self, entries: list, from_status: str) -> None:
        self.view.mark_rows_status_if_current([e.iid for e in entries], from_status, "Error")

    def _restore_report_button_if_ready(self) -> None:
        if self.model.has_results() and not self.is_scanning and not self.is_uploading and not self.is_clearing_cache:
            self.ui_state.report_button_enabled_changed.emit(True)

    def _add_item(self, item_type: str, value: str) -> bool:
        added = self.view.add_item(item_type, value)
        if added and not (self.is_scanning or self.is_uploading or self.is_clearing_cache):
            self._set_queued_count_text()
        return added

    def _update_api_key_status(self) -> None:
        self.ui_state.api_status_changed.emit(masked_api_key_text(self.model.api_key))

    def _update_upload_indicator(self) -> None:
        self.ui_state.upload_indicator_changed.emit(upload_indicator_text(self.model.upload_mode))

    def _update_upload_action_visibility(self) -> None:
        should_show = self.model.upload_mode == UPLOAD_MANUAL
        can_upload = should_show and self.view.has_uploadable_undetected() and not self._is_busy
        self.ui_state.upload_button_visible_changed.emit(should_show)
        if should_show:
            self.ui_state.upload_button_enabled_changed.emit(can_upload)

    @Slot(Qt.ColorScheme)
    def _on_color_scheme_changed(self, _scheme: Qt.ColorScheme) -> None:
        if self.model.theme_mode == THEME_AUTO:
            apply_theme(THEME_AUTO)

    def _warn_if_invalid_loaded_api_key(self) -> None:
        if not self.model.had_invalid_loaded_api_key:
            return
        self._show_error(
            "Invalid Saved API Key",
            "The saved VirusTotal API key is invalid and was ignored. Set a valid API key to scan.",
        )
        self.model.had_invalid_loaded_api_key = False

    def _show_info(self, title: str, text: str) -> None:
        QMessageBox.information(self, title, text)

    def _show_error(self, title: str, text: str) -> None:
        QMessageBox.critical(self, title, text)

    def _parse_int(self, raw: str, default: int, minimum: int) -> int:
        return self.model.parse_int(raw, default, minimum)

    def _current_limits(self) -> tuple[int, int, int]:
        rpm = self._parse_int(self._rpm, DEFAULT_REQUESTS_PER_MINUTE, minimum=0)
        workers = self._parse_int(self._workers, DEFAULT_SCAN_WORKERS, minimum=1)
        upload_timeout = self._parse_int(self._upload_timeout, DEFAULT_UPLOAD_TIMEOUT_MINUTES, minimum=0)
        return rpm, workers, upload_timeout

    def _request_cancel(self, text: str) -> None:
        self.cancel_event.set()
        self.ui_state.scan_button_enabled_changed.emit(False)
        self._set_progress_text(text)

    def _begin_busy_state(self, cancel_handler: Callable[[], None]) -> None:
        self.cancel_event.clear()
        self.ui_state.controls_enabled_changed.emit(False)
        self.view.set_scan_button_cancel(cancel_handler)
        self._update_upload_action_visibility()

    def _set_queued_count_text(self) -> None:
        self._set_progress_text(f"Items queued: {len(self.view.collect_pending_entries())}")

    def _status_with_queued_suffix(self, text: str) -> str:
        queued = len(self.view.collect_pending_entries())
        if queued <= 0:
            return text
        return f"{text} ({queued} queued)"

    def _set_progress_text(self, text: str) -> None:
        if self.view.get_progress_text() != text:
            self.ui_state.progress_text_changed.emit(text)

    def _restore_buttons(self) -> None:
        if not self.is_closing:
            self.ui_state.controls_enabled_changed.emit(True)
            self.view.set_scan_button_scan(self.on_scan)
            self.ui_state.progress_changed.emit(0, 0)
        self._update_upload_action_visibility()

    def _open_path(self, path: str) -> None:
        try:
            if not QDesktopServices.openUrl(QUrl.fromLocalFile(path)):
                raise RuntimeError(f"Unable to open path: {path}")
        except Exception as exc:
            self._show_error("Open Error", str(exc))

    def _open_folder(self, path: str) -> None:
        self._open_path(str(Path(path).resolve().parent))


def main() -> None:
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    icon_path = Path(__file__).resolve().parent / "assets" / "icon.png"
    if icon_path.exists():
        app.setWindowIcon(QIcon(str(icon_path)))
    window = VirusProbeGUI()
    sys.exit(app.exec())
