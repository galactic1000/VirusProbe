"""UI view layer for VirusProbe GUI."""

from __future__ import annotations

import tkinter as tk
from collections.abc import Callable

import ttkbootstrap as ttk
from ttkbootstrap.widgets import ToolTip
from ttkbootstrap.widgets.tableview import Tableview
from tkinterdnd2 import DND_FILES

from common import ScanTargetKind
from .os_detect import IS_WINDOWS, IS_MACOS
from .workflows import PendingScanEntry


def _ui_font() -> str:
    if IS_WINDOWS:
        return "Segoe UI"
    elif IS_MACOS:
        return "Helvetica Neue"
    return "Noto Sans"


def _title_font() -> tuple[str, int, str]:
    return (_ui_font(), 16, "bold")


class MainWindow:
    _TYPE_COL_WIDTH = 90
    _TYPE_COL_MIN_WIDTH = 70
    _VALUE_COL_WIDTH = 650
    _STATUS_COL_WIDTH = 180
    _STATUS_COL_MIN_WIDTH = 120
    _VALUE_COL_MIN_WIDTH = 220
    _TOOLTIP_DELAY = 600

    def __init__(
        self,
        root: tk.Tk,
        on_clear_cache: Callable[[], None],
        on_set_api_key: Callable[[], None],
        on_add_files: Callable[[], None],
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
        self._item_keys = set()
        self._tooltips = []
        self.api_status_var = tk.StringVar(value="API Key: Not Set")
        self.upload_indicator_var = tk.StringVar(value="")
        self.progress_var = tk.StringVar(value="Ready")
        self.progress_gauge_var = tk.StringVar(value="")
        self._build(
            on_clear_cache=on_clear_cache,
            on_set_api_key=on_set_api_key,
            on_add_files=on_add_files,
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
        self.set_api_key_btn = ttk.Button(top_actions, text="Set API Key", command=on_set_api_key, bootstyle="secondary")
        self.set_api_key_btn.pack(side=tk.LEFT, padx=(0, 8))
        self.clear_cache_btn = ttk.Button(top_actions, text="Clear Cache", command=on_clear_cache, bootstyle="secondary")
        self.clear_cache_btn.pack(side=tk.LEFT, padx=(0, 8))
        self.advanced_btn = ttk.Button(top_actions, text="Advanced...", command=on_advanced, bootstyle="secondary")
        self.advanced_btn.pack(side=tk.LEFT)

        ttk.Separator(self.root, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=12)
        controls = ttk.Frame(self.root, padding=(12, 8, 12, 8))
        controls.pack(fill=tk.X)

        left = ttk.Frame(controls)
        left.pack(side=tk.LEFT, fill=tk.Y)
        self.add_menu_btn = ttk.Menubutton(left, text="Add Item", bootstyle="primary")
        add_menu = tk.Menu(
            self.add_menu_btn,
            tearoff=False,
            bd=0,
            relief=tk.FLAT,
            activeborderwidth=0,
        )
        add_menu.add_command(label="Add File(s)...", command=on_add_files)
        add_menu.add_command(label="Add SHA-256 hash(es)...", command=on_add_hashes)
        self.add_menu_btn["menu"] = add_menu
        self.add_menu_btn.pack(side=tk.LEFT)
        self.remove_btn = ttk.Button(left, text="Remove Selected", command=on_remove_selected, bootstyle="secondary")
        self.remove_btn.pack(side=tk.LEFT, padx=(8, 0))
        self.clear_btn = ttk.Button(left, text="Clear List", command=on_clear_items, bootstyle="secondary")
        self.clear_btn.pack(side=tk.LEFT, padx=(8, 0))

        right = ttk.Frame(controls)
        right.pack(side=tk.RIGHT, fill=tk.Y)
        self.upload_indicator_lbl = ttk.Label(right, textvariable=self.upload_indicator_var, foreground="orange")
        self.upload_indicator_lbl.pack(side=tk.LEFT)
        self.upload_action_btn = ttk.Button(right, text="Upload", command=on_upload, bootstyle="secondary")
        self.upload_action_btn.pack(side=tk.LEFT, padx=(8, 0))
        self.scan_btn = ttk.Button(right, text="Scan", command=on_scan, width=8, bootstyle="primary")
        self.scan_btn.pack(side=tk.LEFT, padx=(8, 0))

        self.list_frame = ttk.Frame(self.root, padding=(12, 8, 12, 0))
        self.list_frame.pack(fill=tk.BOTH, expand=True)
        self.table = Tableview(
            self.list_frame,
            coldata=[
                {"text": "Type", "stretch": True, "width": self._TYPE_COL_WIDTH, "minwidth": self._TYPE_COL_MIN_WIDTH},
                {"text": "Value", "stretch": True, "width": self._VALUE_COL_WIDTH, "minwidth": self._VALUE_COL_MIN_WIDTH},
                {"text": "Status", "stretch": True, "width": self._STATUS_COL_WIDTH, "minwidth": self._STATUS_COL_MIN_WIDTH},
            ],
            rowdata=[],
            paginated=False,
            searchable=True,
            yscrollbar=True,
            autofit=False,
            autoalign=False,
            stripecolor=None,
            disable_right_click=True,
            bootstyle="default",
        )
        self.table.pack(fill=tk.BOTH, expand=True)
        self.table.hbar.pack_forget()

        self.tree = self.table.view
        style = ttk.Style()
        tree_style = self.tree.cget("style") or "Treeview"
        table_bg = style.lookup(tree_style, "background") or self.root.cget("background")
        table_fg = style.lookup(tree_style, "foreground") or "#f5f5f5"
        hint_fg = style.lookup("secondary.TLabel", "foreground") or table_fg
        self.empty_state_overlay = tk.Frame(
            self.tree,
            bg=table_bg,
            bd=0,
            highlightthickness=0,
            padx=22,
            pady=12,
        )
        self.empty_state_title = tk.Label(
            self.empty_state_overlay,
            text="Drop Files Here",
            font=(_ui_font(), 17, "bold"),
            background=table_bg,
            foreground=table_fg,
            borderwidth=0,
            highlightthickness=0,
        )
        self.empty_state_hint = tk.Label(
            self.empty_state_overlay,
            text="or use Add Item",
            background=table_bg,
            foreground=hint_fg,
            font=(_ui_font(), 10),
            borderwidth=0,
            highlightthickness=0,
        )
        self.empty_state_title.pack()
        self.empty_state_hint.pack(pady=(4, 0))
        self._update_empty_state()
        self.tree.drop_target_register(DND_FILES)  # type: ignore[attr-defined]
        self.tree.dnd_bind("<<Drop>>", on_drop_files)  # type: ignore[attr-defined]
        bottom = ttk.Frame(self.root, padding=(12, 6, 12, 10))
        bottom.pack(fill=tk.X)
        self.report_button = ttk.Button(bottom, text="Generate Report...", command=on_generate_report, bootstyle="secondary")
        self.report_button.pack(side=tk.LEFT)
        self.report_button.configure(state=tk.DISABLED)
        self.progress_status_label = ttk.Label(bottom, textvariable=self.progress_var)
        self.progress_status_label.pack(side=tk.RIGHT)
        self.progress_bar = ttk.Floodgauge(
            bottom,
            orient=tk.HORIZONTAL,
            mode="determinate",
            length=260,
            thickness=18,
            maximum=1,
            value=0,
            bootstyle="secondary",
            textvariable=self.progress_gauge_var,
            font=(_ui_font(), 9),
        )
        self.progress_bar.pack(side=tk.RIGHT, padx=(0, 8))
        self.progress_bar.pack_forget()
        self._setup_tooltips()

    def set_controls_enabled(self, enabled: bool) -> None:
        state = tk.NORMAL if enabled else tk.DISABLED
        self.add_menu_btn.configure(state=state)
        self.remove_btn.configure(state=state)
        self.clear_btn.configure(state=state)
        self.set_api_key_btn.configure(state=state)
        self.clear_cache_btn.configure(state=state)
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
            if self.progress_bar.winfo_manager() == "pack":
                self.progress_bar.pack_forget()
            self.progress_bar.configure(maximum=1, value=0)
            self.progress_gauge_var.set("")
            return
        if self.progress_bar.winfo_manager() != "pack":
            self.progress_bar.pack(side=tk.RIGHT, padx=(0, 8), before=self.progress_status_label)
        self.progress_bar.configure(maximum=total, value=min(completed, total))
        self.progress_gauge_var.set(f"{min(completed, total)}/{total}")

    @staticmethod
    def _normalize_item_value(item_type: str, value: str) -> str:
        if item_type == ScanTargetKind.HASH:
            return value.strip().lower()
        return value

    @classmethod
    def _item_key(cls, item_type: str, value: str) -> tuple[str, str]:
        return item_type, cls._normalize_item_value(item_type, value)

    def add_item(self, item_type: str, value: str) -> bool:
        key = self._item_key(item_type, value)
        if key in self._item_keys:
            return False
        self._item_keys.add(key)
        self.table.insert_row("end", [item_type, key[1], "Pending"])
        self._update_empty_state()
        return True

    @property
    def separator_width(self) -> int:
        return max(72, int(self.root.winfo_width()))

    def remove_selected(self) -> list[tuple[str, str]]:
        selected_rows = self.table.get_rows(selected=True)
        if not selected_rows:
            return []
        removed_keys = []
        for row in selected_rows:
            values = row.values
            if len(values) >= 2:
                key = self._item_key(str(values[0]), str(values[1]))
                removed_keys.append(key)
                self._item_keys.discard(key)
        self.table.delete_rows(iids=[row.iid for row in selected_rows])
        self._update_empty_state()
        return removed_keys

    def clear_items(self) -> None:
        self.table.delete_rows()
        self._item_keys.clear()
        self._update_empty_state()

    def item_count(self) -> int:
        return len(self.table.tablerows)

    def collect_pending_entries(self) -> list[PendingScanEntry]:
        entries = []
        for row in self.table.get_rows():
            values = row.values
            if len(values) < 3 or str(values[2]) != "Pending":
                continue
            entries.append(
                PendingScanEntry(
                    iid=str(row.iid),
                    kind=ScanTargetKind(str(values[0])),
                    value=str(values[1]),
                )
            )
        return entries

    def result_keys_in_order(self) -> list[tuple[str, str]]:
        keys = []
        for row in self.table.get_rows():
            values = row.values
            if len(values) < 2:
                continue
            keys.append(self._item_key(str(values[0]), str(values[1])))
        return keys

    def set_row_status(self, iid: str, status: str) -> None:
        row = self.table.get_row(iid=iid)
        if row is None:
            return
        values = list(row.values)
        if len(values) < 3:
            return
        values[2] = status
        row.values = values

    def mark_rows_status_if_current(self, iids: list[str], from_status: str, to_status: str) -> None:
        for iid in iids:
            row = self.table.get_row(iid=iid)
            if row is None:
                continue
            values = list(row.values)
            if len(values) < 3:
                continue
            if str(values[2]) == from_status:
                values[2] = to_status
                row.values = values

    def has_uploadable_undetected(self) -> bool:
        return bool(self.undetected_files())

    def undetected_files(self, selected_only: bool = False) -> list[tuple[str, str]]:
        entries = []
        for row in self.table.get_rows(selected=selected_only):
            values = row.values
            if len(values) >= 3 and str(values[0]) == ScanTargetKind.FILE and str(values[2]) == "Undetected":
                entries.append((str(row.iid), str(values[1])))
        return entries

    def _update_empty_state(self) -> None:
        if self.item_count() == 0:
            self.empty_state_overlay.place(relx=0.5, rely=0.47, anchor=tk.CENTER)
            self.empty_state_overlay.lift()
        else:
            self.empty_state_overlay.place_forget()

    def _setup_tooltips(self) -> None:
        def add(widget: tk.Misc, text: str) -> None:
            self._tooltips.append(
                ToolTip(
                    widget,
                    text=text,
                    delay=self._TOOLTIP_DELAY,
                    position="left",
                    bootstyle="inverse",
                )
            )

        add(self.set_api_key_btn, "Set or replace the saved VirusTotal API key.")
        add(self.advanced_btn, "Adjust theme, concurrency, rate limit, and upload behavior.")
        add(
            self.upload_action_btn,
            "Upload selected undetected files to VirusTotal. If none are selected, all undetected files are uploaded. (Uses extra API quota.)",
        )

