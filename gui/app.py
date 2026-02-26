"""Tkinter GUI for VirusProbe."""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any

from tkinterdnd2 import DND_FILES, TkinterDnD

from common import (
    ScannerService,
    get_api_key,
    get_requests_per_minute,
    get_workers,
    remove_api_key_from_env,
    save_api_key_to_env,
    save_requests_per_minute_to_env,
    save_workers_to_env,
)
from common.service import DEFAULT_REQUESTS_PER_MINUTE, DEFAULT_SCAN_WORKERS
from .dialogs import (
    show_add_hash_dialog,
    show_add_hashes_dialog,
    show_advanced_dialog,
    show_clear_cache_dialog,
    show_generate_report_dialog,
    show_set_api_key_dialog,
)

CACHE_DB = Path(__file__).resolve().parents[1] / "cache" / "vt_cache.db"


def _title_font() -> tuple[str, int, str]:
    if sys.platform.startswith("win"):
        return ("Segoe UI", 16, "bold")
    if sys.platform == "darwin":
        return ("Helvetica Neue", 16, "bold")
    return ("Noto Sans", 16, "bold")


class VirusProbeGUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("VirusProbe GUI")
        self.root.geometry("980x620")
        self.root.minsize(860, 520)

        self.api_key: str | None = get_api_key()
        self.scanner: ScannerService | None = None
        self.items: list[dict[str, Any]] = []
        self.item_keys: set[tuple[str, str]] = set()
        self.last_results: list[dict[str, Any]] = []
        self._pending_entries: list[tuple[str, str, str]] = []
        self._current_rpm: int = DEFAULT_REQUESTS_PER_MINUTE
        self._current_workers: int = DEFAULT_SCAN_WORKERS
        self._cancel_requested = threading.Event()
        self.is_scanning = False
        self._is_closing = False
        self.default_report_dir = str(Path.home())
        self._scan_total = 0

        saved_rpm = get_requests_per_minute()
        initial_rpm = saved_rpm if saved_rpm is not None else DEFAULT_REQUESTS_PER_MINUTE
        self.rpm_var = tk.StringVar(value=str(initial_rpm))

        saved_workers = get_workers()
        initial_workers = saved_workers if saved_workers is not None else DEFAULT_SCAN_WORKERS
        self.workers_var = tk.StringVar(value=str(initial_workers))

        self._build_ui()
        self._update_api_key_status()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_ui(self) -> None:
        # Top bar
        top = ttk.Frame(self.root, padding=(12, 10, 12, 8))
        top.pack(fill=tk.X)

        ttk.Label(top, text="VirusProbe", font=_title_font()).pack(side=tk.LEFT)
        self.api_status_var = tk.StringVar(value="API Key: Not Set")
        ttk.Label(top, textvariable=self.api_status_var).pack(side=tk.LEFT, padx=(20, 0))

        ttk.Button(top, text="Clear Cache", command=self._clear_cache_dialog).pack(side=tk.RIGHT)
        ttk.Button(top, text="Set API Key", command=self._set_api_key_dialog).pack(side=tk.RIGHT, padx=(0, 8))

        ttk.Separator(self.root, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=12)
        # Controls bar
        controls = ttk.Frame(self.root, padding=(12, 8, 12, 8))
        controls.pack(fill=tk.X)

        # Left group: item management
        left = ttk.Frame(controls)
        left.pack(side=tk.LEFT, fill=tk.Y)

        self.add_menu_btn = ttk.Menubutton(left, text="Add Item")
        add_menu = tk.Menu(self.add_menu_btn, tearoff=False)
        add_menu.add_command(label="Add File(s)...", command=self._add_files_dialog)
        add_menu.add_command(label="Add SHA-256 hash...", command=self._add_hash_dialog)
        add_menu.add_command(label="Add multiple SHA-256 hashes...", command=self._add_multiple_hashes_dialog)
        self.add_menu_btn["menu"] = add_menu
        self.add_menu_btn.pack(side=tk.LEFT)

        self.remove_btn = ttk.Button(left, text="Remove Selected", command=self._remove_selected)
        self.remove_btn.pack(side=tk.LEFT, padx=(8, 0))
        self.clear_btn = ttk.Button(left, text="Clear List", command=self._clear_items)
        self.clear_btn.pack(side=tk.LEFT, padx=(8, 0))

        # Right group: advanced settings + scan button
        right = ttk.Frame(controls)
        right.pack(side=tk.RIGHT, fill=tk.Y)

        self.advanced_btn = ttk.Button(right, text="Advanced...", command=self._show_advanced_dialog)
        self.advanced_btn.pack(side=tk.LEFT)

        ttk.Separator(right, orient=tk.VERTICAL).pack(side=tk.LEFT, fill=tk.Y, padx=(12, 12), pady=2)

        self.scan_btn = ttk.Button(right, text="Scan", command=self._scan_items, width=8)
        self.scan_btn.pack(side=tk.LEFT)

        ttk.Separator(self.root, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=12)
        # List
        list_frame = ttk.Frame(self.root, padding=(12, 8, 12, 0))
        list_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("type", "value", "status")
        self.tree = ttk.Treeview(list_frame, columns=columns, show="headings", selectmode="extended")
        self.tree.heading("type", text="Type")
        self.tree.heading("value", text="Value")
        self.tree.heading("status", text="Status")
        self.tree.column("type", width=100, anchor=tk.CENTER, stretch=False)
        self.tree.column("value", width=650, anchor=tk.CENTER)
        self.tree.column("status", width=180, anchor=tk.CENTER, stretch=False)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.drop_target_register(DND_FILES)  # type: ignore[attr-defined]
        self.tree.dnd_bind("<<Drop>>", self._on_drop_files)  # type: ignore[attr-defined]

        ttk.Separator(self.root, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=12, pady=(8, 0))
        # Bottom bar
        bottom = ttk.Frame(self.root, padding=(12, 6, 12, 10))
        bottom.pack(fill=tk.X)

        self.report_button = ttk.Button(bottom, text="Generate Report...", command=self._generate_report)
        self.report_button.pack(side=tk.LEFT)
        self.report_button.configure(state=tk.DISABLED)

        self.progress_var = tk.StringVar(value="Ready")
        ttk.Label(bottom, textvariable=self.progress_var).pack(side=tk.RIGHT)

        self.progress_bar = ttk.Progressbar(bottom, orient=tk.HORIZONTAL, mode="determinate", length=260, maximum=1, value=0)
        self.progress_bar.pack(side=tk.RIGHT, padx=(0, 8))

    def _set_controls_enabled(self, enabled: bool) -> None:
        state = tk.NORMAL if enabled else tk.DISABLED
        self.remove_btn.configure(state=state)
        self.clear_btn.configure(state=state)
        self.add_menu_btn.configure(state=state)
        self.advanced_btn.configure(state=state)

    def _set_scanning_ui(self, scanning: bool) -> None:
        self._set_controls_enabled(not scanning)
        if scanning:
            self.scan_btn.configure(state=tk.NORMAL, text="Cancel", command=self._cancel_scan)
        else:
            self.scan_btn.configure(state=tk.NORMAL, text="Scan", command=self._scan_items)

    def _show_advanced_dialog(self) -> None:
        result = show_advanced_dialog(self.root, int(self.rpm_var.get()), int(self.workers_var.get()))
        if result is not None:
            rpm, workers = result
            self.rpm_var.set(str(rpm))
            self.workers_var.set(str(workers))
            save_requests_per_minute_to_env(rpm)
            save_workers_to_env(workers)

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
            service = self.scanner or ScannerService(api_key=self.api_key or "", cache_db=CACHE_DB)
            try:
                return service.clear_cache()
            finally:
                if self.scanner is None:
                    service.close()

        deleted = show_clear_cache_dialog(self.root, _do_clear)
        if deleted is not None:
            label = f"{deleted} entr{'y' if deleted == 1 else 'ies'}"
            self.progress_var.set(f"Cache cleared ({label})")

    def _update_api_key_status(self) -> None:
        if self.api_key:
            masked = f"{self.api_key[:4]}...{self.api_key[-4:]}" if len(self.api_key) >= 8 else "set"
            self.api_status_var.set(f"API Key: {masked}")
        else:
            self.api_status_var.set("API Key: Not Set")

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
        self.items.append({"type": item_type, "value": value, "status": "Queued"})
        self.item_keys.add(key)
        self.tree.insert("", tk.END, values=(item_type, value, "Queued"))
        self.progress_var.set(f"Items queued: {len(self.items)}")
        return True

    def _remove_selected(self) -> None:
        selected = self.tree.selection()
        if not selected:
            return
        keys_to_remove: set[tuple[str, str]] = set()
        for iid in selected:
            vals = self.tree.item(iid, "values")
            if vals:
                keys_to_remove.add((vals[0], vals[1]))
            self.tree.delete(iid)
        self.items = [i for i in self.items if (i["type"], i["value"]) not in keys_to_remove]
        self.item_keys = {(i["type"], i["value"]) for i in self.items}
        self.progress_var.set(f"Items queued: {len(self.items)}")

    def _clear_items(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self.items.clear()
        self.item_keys.clear()
        self.last_results = []
        self._scan_total = 0
        self._set_progress(0, 0)
        self.report_button.configure(state=tk.DISABLED)
        self.progress_var.set("Ready")

    def _on_drop_files(self, event: Any) -> None:
        try:
            paths = self.root.tk.splitlist(event.data)
        except Exception:
            paths = [event.data]
        for raw in paths:
            path = str(raw).strip().strip("{}")
            if path and Path(path).is_file():
                self._add_item("file", path)

    def _collect_pending_entries(self) -> list[tuple[str, str, str]]:
        tree_entries: list[tuple[str, str, str]] = []
        for iid in self.tree.get_children():
            vals = self.tree.item(iid, "values")
            if not vals or vals[2] != "Queued":
                continue
            item_type, value, _ = vals
            tree_entries.append((iid, item_type, value))
        return [e for e in tree_entries if e[1] == "file"] + [e for e in tree_entries if e[1] == "hash"]

    def _scan_items(self) -> None:
        if self.is_scanning:
            return
        if not self.items:
            messagebox.showinfo("No Items", "Add at least one file or SHA-256 hash to scan.", parent=self.root)
            return
        if not self.api_key:
            messagebox.showerror("Missing API Key", "Set an API key before scanning.", parent=self.root)
            return

        self._pending_entries = self._collect_pending_entries()
        if not self._pending_entries:
            messagebox.showinfo("Nothing to Scan", "All items have already been scanned. Add new items to scan.", parent=self.root)
            return
        self._scan_total = len(self._pending_entries)
        self._set_progress(0, self._scan_total)
        for iid, _, _ in self._pending_entries:
            self._set_row_status(iid, "Scanning...")

        try:
            self._current_rpm = max(0, int(self.rpm_var.get()))
        except ValueError:
            self._current_rpm = DEFAULT_REQUESTS_PER_MINUTE

        try:
            self._current_workers = max(1, int(self.workers_var.get()))
        except ValueError:
            self._current_workers = DEFAULT_SCAN_WORKERS

        self._cancel_requested.clear()
        self.is_scanning = True
        self.report_button.configure(state=tk.DISABLED)
        self._set_scanning_ui(True)
        self.progress_var.set("Starting scan...")
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _cancel_scan(self) -> None:
        if not self.is_scanning:
            return
        self._cancel_requested.set()
        self.scan_btn.configure(state=tk.DISABLED)
        self.progress_var.set("Cancelling scan...")

    def _safe_after(self, callback, *args) -> None:
        try:
            if self.root.winfo_exists():
                self.root.after(0, callback, *args)
        except tk.TclError:
            pass

    def _scan_worker(self) -> None:
        scanner: ScannerService | None = None
        try:
            scanner = ScannerService(api_key=self.api_key or "", cache_db=CACHE_DB, requests_per_minute=self._current_rpm, max_workers=self._current_workers)
            self.scanner = scanner
            scanner.init_cache()

            ordered_entries = self._pending_entries
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

            def handle_result(result: dict[str, Any]) -> None:
                nonlocal completed
                new_results.append(result)
                result_type = str(result.get("type", ""))
                if result_type == "file":
                    iid = entry_by_file.get(str(result.get("item", "")))
                else:
                    iid = entry_by_hash.get(str(result.get("file_hash", "")).lower())
                if iid is not None:
                    self._safe_after(self._set_row_status, iid, self._result_status(result))
                completed += 1
                self._safe_after(lambda c=completed: self.progress_var.set(f"Scanning {c}/{total}..."))
                self._safe_after(self._set_progress, completed, total)

            if file_values and not self._cancel_requested.is_set():
                scanner.scan_files(file_values, on_result=handle_result, cancel_event=self._cancel_requested)
            if hash_values and not self._cancel_requested.is_set():
                scanner.scan_hashes(hash_values, on_result=handle_result, cancel_event=self._cancel_requested)

            result_map = {(r.get("type"), r.get("item")): r for r in self.last_results}
            for r in new_results:
                result_map[(r.get("type"), r.get("item"))] = r
            self.last_results = list(result_map.values())
            if self.last_results:
                self._safe_after(lambda: self.report_button.configure(state=tk.NORMAL))
            if self._cancel_requested.is_set():
                pending_iids = [iid for iid, _, _ in ordered_entries]
                self._safe_after(self._mark_pending_cancelled, pending_iids)
                self._safe_after(lambda c=completed, t=total: self.progress_var.set(f"Scan cancelled ({c}/{t})"))
                self._safe_after(self._set_progress, completed, total)
            else:
                self._safe_after(lambda: self.progress_var.set("Scan complete"))
                self._safe_after(self._set_progress, total, total)
        except Exception as exc:
            self._safe_after(lambda: messagebox.showerror("Scan Error", str(exc), parent=self.root))
            self._safe_after(lambda: self.progress_var.set("Scan failed"))
        finally:
            if scanner is not None:
                scanner.close()
            self.scanner = None
            self.is_scanning = False
            self._safe_after(self._restore_scan_buttons)
            if self._is_closing:
                self._safe_after(self.root.destroy)

    def _restore_scan_buttons(self) -> None:
        if not self._is_closing:
            self._set_scanning_ui(False)

    def _mark_pending_cancelled(self, iids: list[str]) -> None:
        for iid in iids:
            vals = self.tree.item(iid, "values")
            if vals and vals[2] == "Scanning...":
                self.tree.item(iid, values=(vals[0], vals[1], "Cancelled"))

    def _set_progress(self, completed: int, total: int) -> None:
        if total <= 0:
            self.progress_bar.configure(maximum=1, value=0)
            return
        self.progress_bar.configure(maximum=total, value=min(completed, total))

    def _set_row_status(self, iid: str, status: str) -> None:
        vals = self.tree.item(iid, "values")
        if vals:
            self.tree.item(iid, values=(vals[0], vals[1], status))

    @staticmethod
    def _result_status(result: dict[str, Any]) -> str:
        if result.get("status") == "error":
            return "Error"
        if result.get("threat_level") == "Undetected":
            return "Undetected"
        if result.get("malicious", 0) >= 10:
            return "Malicious"
        if result.get("malicious", 0) > 0:
            return "Suspicious"
        return "Clean"

    def _generate_report(self) -> None:
        if not self.last_results:
            messagebox.showinfo("No Results", "Run a scan first to generate a report.", parent=self.root)
            return
        new_dir = show_generate_report_dialog(
            self.root,
            self.default_report_dir,
            self.last_results,
            self._open_path,
            self._open_folder,
        )
        if new_dir:
            self.default_report_dir = new_dir

    def _open_path(self, path: str) -> None:
        try:
            if sys.platform.startswith("win"):
                os.startfile(path)  # type: ignore[attr-defined]
            elif sys.platform == "darwin":
                subprocess.run(["open", path], check=False)
            else:
                subprocess.run(["xdg-open", path], check=False)
        except Exception as exc:
            messagebox.showerror("Open Error", str(exc), parent=self.root)

    def _open_folder(self, path: str) -> None:
        self._open_path(str(Path(path).resolve().parent))

    def _on_close(self) -> None:
        if self.is_scanning:
            self._is_closing = True
            self._cancel_requested.set()
            self.scan_btn.configure(state=tk.DISABLED)
            self.progress_var.set("Cancelling scan before close...")
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

