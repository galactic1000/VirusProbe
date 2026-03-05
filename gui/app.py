"""Tkinter GUI entry and coordinator for VirusProbe."""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox

from tkinterdnd2 import TkinterDnD

from common import (
    ScannerService,
    UPLOAD_AUTO,
    UPLOAD_MANUAL,
    get_api_key,
    get_requests_per_minute,
    get_upload_mode,
    get_workers,
    remove_api_key_from_env,
    save_api_key_to_env,
    save_requests_per_minute_to_env,
    save_upload_mode_to_env,
    save_workers_to_env,
)
from common.service import DEFAULT_REQUESTS_PER_MINUTE, DEFAULT_SCAN_WORKERS
from .controllers import ScanController, UploadController
from .dialogs import (
    show_add_hash_dialog,
    show_add_hashes_dialog,
    show_advanced_dialog,
    show_clear_cache_dialog,
    show_generate_report_dialog,
    show_set_api_key_dialog,
)
from .view import MainWindow

CACHE_DB = Path(__file__).resolve().parents[1] / "cache" / "vt_cache.db"


class VirusProbeGUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("VirusProbe GUI")
        self.root.geometry("980x620")
        self.root.minsize(860, 520)

        self.cache_db = CACHE_DB
        self.api_key: str | None = get_api_key()
        self.scanner: ScannerService | None = None
        self.item_keys: set[tuple[str, str]] = set()
        self.last_results: list[dict] = []
        self.results_lock = threading.Lock()
        self.pending_entries: list[tuple[str, str, str]] = []
        self.current_rpm = DEFAULT_REQUESTS_PER_MINUTE
        self.current_workers = DEFAULT_SCAN_WORKERS
        self.cancel_event = threading.Event()
        self.upload_mode: str = get_upload_mode()
        self.is_scanning = False
        self.is_uploading = False
        self.is_closing = False
        self.default_report_dir = str(Path.home())
        self.scan_total = 0

        saved_rpm = get_requests_per_minute()
        initial_rpm = saved_rpm if saved_rpm is not None else DEFAULT_REQUESTS_PER_MINUTE
        self.rpm_var = tk.StringVar(value=str(initial_rpm))

        saved_workers = get_workers()
        initial_workers = saved_workers if saved_workers is not None else DEFAULT_SCAN_WORKERS
        self.workers_var = tk.StringVar(value=str(initial_workers))

        self.scan_controller = ScanController(self)
        self.upload_controller = UploadController(self)
        self.view = MainWindow(
            root=self.root,
            on_clear_cache=self._clear_cache_dialog,
            on_set_api_key=self._set_api_key_dialog,
            on_add_files=self._add_files_dialog,
            on_add_hash=self._add_hash_dialog,
            on_add_hashes=self._add_multiple_hashes_dialog,
            on_remove_selected=self._remove_selected,
            on_clear_items=self._clear_items,
            on_advanced=self._show_advanced_dialog,
            on_scan=self._scan_items,
            on_upload=self._upload_selected_undetected,
            on_drop_files=self._on_drop_files,
            on_generate_report=self._generate_report,
        )
        self._update_api_key_status()
        self._update_upload_indicator()
        self._update_upload_action_visibility()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _parse_int(self, raw: str, default: int, minimum: int) -> int:
        try:
            value = int(raw)
        except ValueError:
            return default
        return max(minimum, value)

    def _safe_after(self, callback, *args) -> None:
        try:
            if self.root.winfo_exists():
                self.root.after(0, callback, *args)
        except tk.TclError:
            pass

    def _show_info(self, title: str, text: str) -> None:
        messagebox.showinfo(title, text, parent=self.root)

    def _show_error(self, title: str, text: str) -> None:
        messagebox.showerror(title, text, parent=self.root)

    def _set_scanning_ui(self, scanning: bool) -> None:
        self.view.set_controls_enabled(not scanning)
        if scanning:
            self.view.set_scan_button_cancel(self._cancel_scan)
        else:
            self.view.set_scan_button_scan(self._scan_items)
        self._update_upload_action_visibility()

    def _scan_items(self) -> None:
        self.scan_controller.start()

    def _cancel_scan(self) -> None:
        self.scan_controller.cancel()

    def _upload_selected_undetected(self) -> None:
        self.upload_controller.start_selected()

    def _cancel_upload(self) -> None:
        self.upload_controller.cancel()

    def _collect_pending_entries(self) -> list[tuple[str, str, str]]:
        tree_entries: list[tuple[str, str, str]] = []
        for iid in self.view.tree.get_children():
            vals = self.view.tree.item(iid, "values")
            if not vals or vals[2] != "Queued":
                continue
            tree_entries.append((iid, vals[0], vals[1]))
        return [e for e in tree_entries if e[1] == "file"] + [e for e in tree_entries if e[1] == "hash"]

    def _merge_results(self, new_results: list[dict]) -> None:
        with self.results_lock:
            result_map = {(r.get("type"), r.get("item")): r for r in self.last_results}
            for result in new_results:
                result_map[(result.get("type"), result.get("item"))] = result
            self.last_results = list(result_map.values())

    def _upsert_last_result(self, result: dict) -> None:
        with self.results_lock:
            item = result.get("item")
            for i, existing in enumerate(self.last_results):
                if existing.get("type") == result.get("type") and existing.get("item") == item:
                    self.last_results[i] = result
                    return
            self.last_results.append(result)

    def _update_upload_action_visibility(self) -> None:
        should_show = self.upload_mode == UPLOAD_MANUAL
        can_upload = (
            should_show
            and self.upload_controller.has_uploadable_undetected()
            and not (self.is_scanning or self.is_uploading)
        )
        self.view.show_upload_button(should_show)
        if should_show:
            self.view.set_upload_button_enabled(can_upload)

    def _mark_scanning_cancelled(self, iids: list[str]) -> None:
        for iid in iids:
            vals = self.view.tree.item(iid, "values")
            if vals and vals[2] == "Scanning...":
                self.view.tree.item(iid, values=(vals[0], vals[1], "Cancelled"))

    def _mark_uploading_cancelled(self, iids: list[str]) -> None:
        for iid in iids:
            vals = self.view.tree.item(iid, "values")
            if vals and vals[2] == "Uploading...":
                self.view.tree.item(iid, values=(vals[0], vals[1], "Cancelled"))

    def _restore_scan_buttons(self) -> None:
        if not self.is_closing:
            self._set_scanning_ui(False)
        self._update_upload_action_visibility()

    def _set_row_status(self, iid: str, status: str) -> None:
        vals = self.view.tree.item(iid, "values")
        if vals:
            self.view.tree.item(iid, values=(vals[0], vals[1], status))
        self._update_upload_action_visibility()

    @staticmethod
    def _result_status(result: dict) -> str:
        if result.get("status") == "cancelled":
            return "Cancelled"
        if result.get("status") == "error":
            return "Error"
        if result.get("threat_level") == "Undetected":
            return "Undetected"
        prefix = "Uploaded - " if result.get("was_uploaded") else ""
        if result.get("malicious", 0) >= 10:
            return f"{prefix}Malicious"
        if result.get("malicious", 0) > 0 or result.get("suspicious", 0) >= 3:
            return f"{prefix}Suspicious"
        return f"{prefix}Clean"

    def _update_api_key_status(self) -> None:
        if self.api_key:
            masked = f"{self.api_key[:4]}...{self.api_key[-4:]}" if len(self.api_key) >= 8 else "set"
            self.view.api_status_var.set(f"API Key: {masked}")
        else:
            self.view.api_status_var.set("API Key: Not Set")

    def _update_upload_indicator(self) -> None:
        if self.upload_mode == UPLOAD_AUTO:
            self.view.upload_indicator_var.set("[Upload: auto]")
        elif self.upload_mode == UPLOAD_MANUAL:
            self.view.upload_indicator_var.set("[Upload: manual]")
        else:
            self.view.upload_indicator_var.set("")

    def _show_advanced_dialog(self) -> None:
        result = show_advanced_dialog(
            self.root,
            int(self.rpm_var.get()),
            int(self.workers_var.get()),
            self.upload_mode,
        )
        if result is None:
            return
        rpm, workers, mode = result
        self.rpm_var.set(str(rpm))
        self.workers_var.set(str(workers))
        self.upload_mode = mode
        save_requests_per_minute_to_env(rpm)
        save_workers_to_env(workers)
        save_upload_mode_to_env(mode)
        self._update_upload_indicator()
        self._update_upload_action_visibility()

    def _set_api_key_dialog(self) -> None:
        value = show_set_api_key_dialog(self.root, self.api_key)
        if value is None:
            return
        self.api_key = value.strip() or None
        if self.api_key:
            save_api_key_to_env(self.api_key)
        else:
            remove_api_key_from_env()
        self._update_api_key_status()

    def _clear_cache_dialog(self) -> None:
        def _do_clear() -> int:
            service = self.scanner or ScannerService(api_key=self.api_key or "", cache_db=self.cache_db)
            try:
                return service.clear_cache()
            finally:
                if self.scanner is None:
                    service.close()

        deleted = show_clear_cache_dialog(self.root, _do_clear)
        if deleted is not None:
            label = f"{deleted} entr{'y' if deleted == 1 else 'ies'}"
            self.view.progress_var.set(f"Cache cleared ({label})")

    def _add_files_dialog(self) -> None:
        for path in filedialog.askopenfilenames(parent=self.root, title="Select files to scan"):
            self._add_item("file", str(path))

    def _add_hash_dialog(self) -> None:
        value = show_add_hash_dialog(self.root)
        if value is not None:
            self._add_item("hash", value)

    def _add_multiple_hashes_dialog(self) -> None:
        show_add_hashes_dialog(self.root, self._add_item)

    def _add_item(self, item_type: str, value: str) -> bool:
        key = (item_type, value)
        if key in self.item_keys:
            return False
        self.item_keys.add(key)
        self.view.tree.insert("", tk.END, values=(item_type, value, "Queued"))
        self.view.progress_var.set(f"Items queued: {len(self.view.tree.get_children())}")
        return True

    def _remove_selected(self) -> None:
        selected = self.view.tree.selection()
        if not selected:
            return
        keys_to_remove: set[tuple[str, str]] = set()
        for iid in selected:
            vals = self.view.tree.item(iid, "values")
            if vals:
                keys_to_remove.add((vals[0], vals[1]))
            self.view.tree.delete(iid)
        self.item_keys = {
            (vals[0], vals[1])
            for iid in self.view.tree.get_children()
            for vals in [self.view.tree.item(iid, "values")]
            if vals
        }
        self.view.progress_var.set(f"Items queued: {len(self.view.tree.get_children())}")
        self._update_upload_action_visibility()

    def _clear_items(self) -> None:
        self.view.tree.delete(*self.view.tree.get_children())
        self.item_keys.clear()
        with self.results_lock:
            self.last_results = []
        self.scan_total = 0
        self.view.set_progress(0, 0)
        self.view.report_button.configure(state="disabled")
        self.view.progress_var.set("Ready")
        self._update_upload_action_visibility()

    def _on_drop_files(self, event) -> None:
        try:
            paths = self.root.tk.splitlist(event.data)
        except Exception:
            paths = [event.data]
        for raw in paths:
            path = str(raw).strip().strip("{}")
            if path and Path(path).is_file():
                self._add_item("file", path)

    def _generate_report(self) -> None:
        with self.results_lock:
            results_snapshot = list(self.last_results)
        if not results_snapshot:
            self._show_info("No Results", "Run a scan first to generate a report.")
            return
        new_dir = show_generate_report_dialog(
            self.root,
            self.default_report_dir,
            results_snapshot,
            self._open_path,
            self._open_folder,
        )
        if new_dir:
            self.default_report_dir = new_dir

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

    def _on_close(self) -> None:
        if self.is_scanning:
            self.is_closing = True
            self.cancel_event.set()
            self.view.scan_btn.configure(state="disabled")
            self.view.progress_var.set("Cancelling scan before close...")
            return
        if self.is_uploading:
            self.is_closing = True
            self.cancel_event.set()
            self.view.scan_btn.configure(state="disabled")
            self.view.progress_var.set("Cancelling upload before close...")
            return
        if self.scanner is not None:
            self.scanner.close()
            self.scanner = None
        self.root.destroy()


def main() -> None:
    root = TkinterDnD.Tk()
    VirusProbeGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

