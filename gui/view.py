"""UI view layer for VirusProbe GUI."""

from __future__ import annotations

import sys
import tkinter as tk
from tkinter import ttk
from typing import Any, Callable

from tkinterdnd2 import DND_FILES


def _title_font() -> tuple[str, int, str]:
    if sys.platform.startswith("win"):
        return ("Segoe UI", 16, "bold")
    if sys.platform == "darwin":
        return ("Helvetica Neue", 16, "bold")
    return ("Noto Sans", 16, "bold")


class MainWindow:
    def __init__(
        self,
        root: tk.Tk,
        on_clear_cache: Callable[[], None],
        on_set_api_key: Callable[[], None],
        on_add_files: Callable[[], None],
        on_add_hash: Callable[[], None],
        on_add_hashes: Callable[[], None],
        on_remove_selected: Callable[[], None],
        on_clear_items: Callable[[], None],
        on_advanced: Callable[[], None],
        on_scan: Callable[[], None],
        on_upload: Callable[[], None],
        on_drop_files: Callable[[object], None],
        on_generate_report: Callable[[], None],
    ) -> None:
        self.root = root
        self._item_keys: set[tuple[str, str]] = set()
        self.api_status_var = tk.StringVar(value="API Key: Not Set")
        self.upload_indicator_var = tk.StringVar(value="")
        self.progress_var = tk.StringVar(value="Ready")
        self._build(
            on_clear_cache=on_clear_cache,
            on_set_api_key=on_set_api_key,
            on_add_files=on_add_files,
            on_add_hash=on_add_hash,
            on_add_hashes=on_add_hashes,
            on_remove_selected=on_remove_selected,
            on_clear_items=on_clear_items,
            on_advanced=on_advanced,
            on_scan=on_scan,
            on_upload=on_upload,
            on_drop_files=on_drop_files,
            on_generate_report=on_generate_report,
        )

    def _build(
        self,
        *,
        on_clear_cache: Callable[[], None],
        on_set_api_key: Callable[[], None],
        on_add_files: Callable[[], None],
        on_add_hash: Callable[[], None],
        on_add_hashes: Callable[[], None],
        on_remove_selected: Callable[[], None],
        on_clear_items: Callable[[], None],
        on_advanced: Callable[[], None],
        on_scan: Callable[[], None],
        on_upload: Callable[[], None],
        on_drop_files: Callable[[object], None],
        on_generate_report: Callable[[], None],
    ) -> None:
        top = ttk.Frame(self.root, padding=(12, 10, 12, 8))
        top.pack(fill=tk.X)
        ttk.Label(top, text="VirusProbe", font=_title_font()).pack(side=tk.LEFT)
        ttk.Label(top, textvariable=self.api_status_var).pack(side=tk.LEFT, padx=(20, 0), pady=(5, 0))
        top_actions = ttk.Frame(top)
        top_actions.pack(side=tk.RIGHT)
        self.set_api_key_btn = ttk.Button(top_actions, text="Set API Key", command=on_set_api_key)
        self.set_api_key_btn.pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(top_actions, text="Clear Cache", command=on_clear_cache).pack(side=tk.LEFT, padx=(0, 8))
        self.advanced_btn = ttk.Button(top_actions, text="Advanced...", command=on_advanced)
        self.advanced_btn.pack(side=tk.LEFT)

        ttk.Separator(self.root, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=12)
        controls = ttk.Frame(self.root, padding=(12, 8, 12, 8))
        controls.pack(fill=tk.X)

        left = ttk.Frame(controls)
        left.pack(side=tk.LEFT, fill=tk.Y)
        self.add_menu_btn = ttk.Menubutton(left, text="Add Item")
        add_menu = tk.Menu(self.add_menu_btn, tearoff=False)
        add_menu.add_command(label="Add File(s)...", command=on_add_files)
        add_menu.add_command(label="Add SHA-256 hash...", command=on_add_hash)
        add_menu.add_command(label="Add multiple SHA-256 hashes...", command=on_add_hashes)
        self.add_menu_btn["menu"] = add_menu
        self.add_menu_btn.pack(side=tk.LEFT)
        self.remove_btn = ttk.Button(left, text="Remove Selected", command=on_remove_selected)
        self.remove_btn.pack(side=tk.LEFT, padx=(8, 0))
        self.clear_btn = ttk.Button(left, text="Clear List", command=on_clear_items)
        self.clear_btn.pack(side=tk.LEFT, padx=(8, 0))

        right = ttk.Frame(controls)
        right.pack(side=tk.RIGHT, fill=tk.Y)
        self.upload_indicator_lbl = ttk.Label(right, textvariable=self.upload_indicator_var, foreground="orange")
        self.upload_indicator_lbl.pack(side=tk.LEFT)
        self.upload_action_btn = ttk.Button(right, text="Upload", command=on_upload)
        self.upload_action_btn.pack(side=tk.LEFT, padx=(8, 0))
        self.scan_btn = ttk.Button(right, text="Scan", command=on_scan, width=8)
        self.scan_btn.pack(side=tk.LEFT, padx=(8, 0))

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
        self.tree.dnd_bind("<<Drop>>", on_drop_files)  # type: ignore[attr-defined]
        self.tree.focus_set()

        bottom = ttk.Frame(self.root, padding=(12, 6, 12, 10))
        bottom.pack(fill=tk.X)
        self.report_button = ttk.Button(bottom, text="Generate Report...", command=on_generate_report)
        self.report_button.pack(side=tk.LEFT)
        self.report_button.configure(state=tk.DISABLED)
        ttk.Label(bottom, textvariable=self.progress_var).pack(side=tk.RIGHT)
        self.progress_bar = ttk.Progressbar(bottom, orient=tk.HORIZONTAL, mode="determinate", length=260, maximum=1, value=0)
        self.progress_bar.pack(side=tk.RIGHT, padx=(0, 8))

    def set_controls_enabled(self, enabled: bool) -> None:
        state = tk.NORMAL if enabled else tk.DISABLED
        self.remove_btn.configure(state=state)
        self.clear_btn.configure(state=state)
        self.add_menu_btn.configure(state=state)
        self.set_api_key_btn.configure(state=state)
        self.advanced_btn.configure(state=state)

    def set_scan_button_scan(self, on_scan: Callable[[], None]) -> None:
        self.scan_btn.configure(state=tk.NORMAL, text="Scan", command=on_scan)

    def set_scan_button_cancel(self, on_cancel: Callable[[], None]) -> None:
        self.scan_btn.configure(state=tk.NORMAL, text="Cancel", command=on_cancel)

    def show_upload_button(self, visible: bool) -> None:
        if visible and self.upload_action_btn.winfo_manager() != "pack":
            self.upload_action_btn.pack(side=tk.LEFT, padx=(8, 0), before=self.scan_btn)
        if not visible and self.upload_action_btn.winfo_manager() == "pack":
            self.upload_action_btn.pack_forget()

    def set_upload_button_enabled(self, enabled: bool) -> None:
        self.upload_action_btn.configure(state=tk.NORMAL if enabled else tk.DISABLED)

    def set_progress(self, completed: int, total: int) -> None:
        if total <= 0:
            self.progress_bar.configure(maximum=1, value=0)
            return
        self.progress_bar.configure(maximum=total, value=min(completed, total))

    def add_item(self, item_type: str, value: str) -> bool:
        key = (item_type, value)
        if key in self._item_keys:
            return False
        self._item_keys.add(key)
        self.tree.insert("", tk.END, values=(item_type, value, "Queued"))
        return True

    def remove_selected(self) -> bool:
        selected = self.tree.selection()
        if not selected:
            return False
        for iid in selected:
            self.tree.delete(iid)
        self._item_keys = {
            (vals[0], vals[1])
            for iid in self.tree.get_children()
            for vals in [self.tree.item(iid, "values")]
            if vals
        }
        return True

    def clear_items(self) -> None:
        self.tree.delete(*self.tree.get_children())
        self._item_keys.clear()

    def item_count(self) -> int:
        return len(self.tree.get_children())

    def collect_pending_entries(self) -> list[tuple[str, str, str]]:
        rows: list[tuple[str, str, str]] = []
        for iid in self.tree.get_children():
            vals = self.tree.item(iid, "values")
            if not vals or vals[2] != "Queued":
                continue
            rows.append((iid, vals[0], vals[1]))
        return [e for e in rows if e[1] == "file"] + [e for e in rows if e[1] == "hash"]

    def set_row_status(self, iid: str, status: str) -> None:
        vals = self.tree.item(iid, "values")
        if vals:
            self.tree.item(iid, values=(vals[0], vals[1], status))

    def mark_rows_status_if_current(self, iids: list[str], from_status: str, to_status: str) -> None:
        for iid in iids:
            vals = self.tree.item(iid, "values")
            if vals and vals[2] == from_status:
                self.tree.item(iid, values=(vals[0], vals[1], to_status))

    def has_uploadable_undetected(self) -> bool:
        for iid in self.tree.get_children():
            vals = self.tree.item(iid, "values")
            if vals and vals[0] == "file" and vals[2] == "Undetected":
                return True
        return False

    def selected_undetected_files(self) -> list[tuple[str, str]]:
        entries: list[tuple[str, str]] = []
        for iid in self.tree.selection():
            vals = self.tree.item(iid, "values")
            if vals and vals[0] == "file" and vals[2] == "Undetected":
                entries.append((iid, vals[1]))
        return entries

