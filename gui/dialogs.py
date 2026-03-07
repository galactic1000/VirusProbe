"""Toplevel dialog windows for the VirusProbe GUI."""

from __future__ import annotations

import textwrap
from datetime import datetime
from pathlib import Path
from typing import Any, Callable
import tkinter as tk
from tkinter import filedialog

import ttkbootstrap as ttk
from ttkbootstrap.dialogs.dialogs import Messagebox
from ttkbootstrap.dialogs.base import Dialog
from ttkbootstrap.dialogs.query import QueryDialog

from common import ScannerService, UPLOAD_AUTO, UPLOAD_MANUAL, UPLOAD_NEVER, THEME_AUTO, THEME_DARK, THEME_LIGHT, write_report
from .style import apply_titlebar_theme


class AppDialog(Dialog):
    """Project-local dialog base with configurable sizing."""

    resizable = (False, False)
    minsize = (250, 15)

    def build(self) -> None:
        self._toplevel = ttk.Toplevel(
            transient=self.master,
            title=self._title,
            resizable=self.resizable,
            minsize=self.minsize,
            windowtype="dialog",
            iconify=True,
        )

        self._toplevel.withdraw()
        self._toplevel.bind("<Escape>", lambda _: self._toplevel.destroy())

        self.create_body(self._toplevel)
        self.create_buttonbox(self._toplevel)
        self._toplevel.update_idletasks()

        width = self._toplevel.winfo_reqwidth()
        height = self._toplevel.winfo_reqheight()
        if width > 0 and height > 0:
            self._toplevel.geometry(f"{width}x{height}")

        apply_titlebar_theme(self._toplevel)
        self._toplevel._titlebar_styled = True  # type: ignore[attr-defined]


class MaskedDialog(QueryDialog):
    """Query dialog variant that masks entry input."""

    def create_body(self, master: tk.Misc) -> None:
        frame = ttk.Frame(master, padding=self._padding)
        if self._prompt:
            for part in self._prompt.split("\n"):
                prompt = "\n".join(textwrap.wrap(part, width=self._width))
                ttk.Label(frame, text=prompt).pack(pady=(0, 5), fill=tk.X, anchor=tk.N)

        entry = ttk.Entry(master=frame, show="*")
        entry.insert(tk.END, self._initialvalue)
        entry.pack(pady=(0, 5), fill=tk.X)
        entry.bind("<Return>", self.on_submit)
        entry.bind("<KP_Enter>", self.on_submit)
        entry.bind("<Escape>", self.on_cancel)

        frame.pack(fill=tk.X, expand=True)
        self._initial_focus = entry


class AddHashesDialog(AppDialog):
    """Modal dialog for adding multiple hashes."""

    resizable = (True, True)
    minsize = (560, 360)
    _AUTO_CLOSE_DELAY = 500

    def __init__(self, parent: tk.Tk, add_item: Callable[[str, str], bool]) -> None:
        super().__init__(parent, "Add SHA-256 Hashes")
        self._add_item = add_item
        self._status_var = tk.StringVar(value="")
        self._text: tk.Text | None = None

    def create_body(self, master: tk.Misc) -> None:
        frame = ttk.Frame(master, padding=12)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Enter one or more SHA-256 hashes.", font=("-size 11 -weight bold")).pack(anchor=tk.W)
        ttk.Label(
            frame,
            text="Enter one hash per line. A single hash is supported too.",
        ).pack(anchor=tk.W, pady=(2, 8))

        self._text = tk.Text(frame, height=10, wrap=tk.WORD)
        self._text.pack(fill=tk.BOTH, expand=True)
        ttk.Label(
            frame,
            text="Example: 275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            foreground="#8f949b",
        ).pack(anchor=tk.W, pady=(8, 0))
        ttk.Label(frame, textvariable=self._status_var).pack(anchor=tk.W, pady=(6, 0))
        self._initial_focus = self._text

    def create_buttonbox(self, master: tk.Misc) -> None:
        buttons = ttk.Frame(master, padding=(12, 0, 12, 12))
        buttons.pack(fill=tk.X)
        ttk.Button(buttons, text="Add", command=self._add_hashes, bootstyle="primary").pack(side=tk.RIGHT)
        ttk.Button(buttons, text="Cancel", command=self._toplevel.destroy, bootstyle="secondary").pack(side=tk.RIGHT, padx=(0, 8))

    def _add_hashes(self) -> None:
        if self._text is None:
            return
        raw = self._text.get("1.0", tk.END).strip()
        if not raw:
            self._status_var.set("No hashes provided.")
            return

        tokens = [line.strip() for line in raw.splitlines() if line.strip()]
        if not tokens:
            self._status_var.set("No hashes provided.")
            return

        added = 0
        invalid: list[str] = []
        duplicates = 0
        seen: set[str] = set()
        for token in tokens:
            value = token.lower()
            if value in seen:
                duplicates += 1
                continue
            seen.add(value)
            if not ScannerService.is_sha256(value):
                invalid.append(token)
                continue
            if self._add_item("hash", value):
                added += 1

        parts: list[str] = [f"Added {added} hash{'es' if added != 1 else ''}."]
        if invalid:
            parts.append(f"Skipped {len(invalid)} invalid.")
        if duplicates:
            parts.append(f"Ignored {duplicates} duplicate{'s' if duplicates != 1 else ''}.")
        self._status_var.set(" ".join(parts))
        if added > 0:
            self._toplevel.after(self._AUTO_CLOSE_DELAY, self._toplevel.destroy)


class ReportSavedDialog(AppDialog):
    """Dialog shown after report generation succeeds."""

    def __init__(
        self,
        parent: tk.Tk,
        output_path: str,
        open_path: Callable[[str], None],
        open_folder: Callable[[str], None],
    ) -> None:
        super().__init__(parent, "Report Saved")
        self._output_path = output_path
        self._open_path = open_path
        self._open_folder = open_folder

    def create_body(self, master: tk.Misc) -> None:
        frame = ttk.Frame(master, padding=12)
        frame.pack(fill=tk.BOTH, expand=True)
        ttk.Label(frame, text="Report saved successfully.").pack(anchor=tk.W)
        ttk.Label(frame, text=self._output_path, wraplength=540).pack(anchor=tk.W, pady=(4, 10))

    def create_buttonbox(self, master: tk.Misc) -> None:
        buttons = ttk.Frame(master, padding=(12, 0, 12, 12))
        buttons.pack(fill=tk.X)
        ttk.Button(buttons, text="Open Report", command=self._on_open_report, bootstyle="primary").pack(side=tk.LEFT)
        ttk.Button(buttons, text="Open Folder", command=self._on_open_folder, bootstyle="secondary").pack(side=tk.LEFT, padx=8)
        ttk.Button(buttons, text="Close", command=self._toplevel.destroy, bootstyle="secondary").pack(side=tk.RIGHT)

    def _on_open_report(self) -> None:
        self._open_path(self._output_path)
        self._toplevel.destroy()

    def _on_open_folder(self) -> None:
        self._open_folder(self._output_path)
        self._toplevel.destroy()


class GenerateReportDialog(AppDialog):
    """Dialog for configuring and generating a report."""

    _PORTABLE_INVALID_CHARS = set('/\\:*?"<>|')

    def __init__(self, parent: tk.Tk, default_dir: str, results: list[dict]) -> None:
        super().__init__(parent, "Generate Report")
        default_name = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        self._default_dir = default_dir
        self._results = results
        self._name_var = tk.StringVar(value=default_name)
        self._fmt_var = tk.StringVar(value="json")
        self._folder_var = tk.StringVar(value=default_dir)
        self._result: dict[str, str] | None = None

    def create_body(self, master: tk.Misc) -> None:
        frame = ttk.Frame(master, padding=12)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Report Name").grid(row=0, column=0, sticky=tk.W, pady=(0, 6))
        name_entry = ttk.Entry(frame, textvariable=self._name_var, width=36)
        name_entry.grid(row=0, column=1, columnspan=2, sticky=tk.EW, pady=(0, 6))

        ttk.Label(frame, text="Report Type").grid(row=1, column=0, sticky=tk.W, pady=(0, 6))
        fmt_combo = ttk.Combobox(frame, textvariable=self._fmt_var, values=["json", "csv", "txt", "md"], state="readonly", width=10)
        fmt_combo.grid(row=1, column=1, sticky=tk.W, pady=(0, 6))

        ttk.Label(frame, text="Folder").grid(row=2, column=0, sticky=tk.W)
        folder_entry = ttk.Entry(frame, textvariable=self._folder_var, width=36)
        folder_entry.grid(row=2, column=1, sticky=tk.EW)
        ttk.Button(frame, text="Browse...", command=self._browse_folder, bootstyle="secondary").grid(row=2, column=2, padx=(6, 0))

        frame.columnconfigure(1, weight=1)
        self._initial_focus = name_entry

    def create_buttonbox(self, master: tk.Misc) -> None:
        buttons = ttk.Frame(master, padding=(12, 0, 12, 12))
        buttons.pack(fill=tk.X)
        ttk.Button(buttons, text="Generate", command=self._confirm, bootstyle="primary").pack(side=tk.RIGHT)
        ttk.Button(buttons, text="Cancel", command=self._toplevel.destroy, bootstyle="secondary").pack(side=tk.RIGHT, padx=(0, 8))

    def _browse_folder(self) -> None:
        selected = filedialog.askdirectory(
            parent=self._toplevel,
            title="Select Report Folder",
            initialdir=self._folder_var.get() or self._default_dir,
        )
        if selected:
            self._folder_var.set(selected)

    @staticmethod
    def _is_portable_filename(name: str) -> bool:
        if not name or name in {".", ".."}:
            return False
        if name[-1] in {" ", "."}:
            return False
        for ch in name:
            if ch in GenerateReportDialog._PORTABLE_INVALID_CHARS or ord(ch) < 32:
                return False
        return True

    def _confirm(self) -> None:
        name = self._name_var.get().strip()
        folder = self._folder_var.get().strip()
        fmt = self._fmt_var.get().strip().lower() or "json"
        if not name:
            Messagebox.show_error("Report name is required.", title="Invalid Name", parent=self._toplevel)
            return
        if not folder:
            Messagebox.show_error("Select a folder for the report.", title="Invalid Folder", parent=self._toplevel)
            return

        folder_path = Path(folder)
        if not folder_path.exists() or not folder_path.is_dir():
            Messagebox.show_error("Selected folder does not exist.", title="Invalid Folder", parent=self._toplevel)
            return

        safe_name = Path(name).stem if "." in Path(name).name else name
        safe_name = Path(safe_name).name.strip()
        if not self._is_portable_filename(safe_name):
            Messagebox.show_error(
                "Use a portable filename (no / \\ : * ? \" < > |, control chars, trailing space/period).",
                title="Invalid Name",
                parent=self._toplevel,
            )
            return

        output_path = str(folder_path / f"{safe_name}.{fmt}")
        try:
            write_report(self._results, output_path, fmt)
        except Exception as exc:
            Messagebox.show_error(str(exc), title="Report Error", parent=self._toplevel)
            return

        self._result = {"new_dir": str(folder_path), "output_path": output_path}
        self._toplevel.destroy()


class AdvancedDialog(AppDialog):
    """Dialog for advanced scan settings."""

    _MAX_WORKERS = 50
    _MAX_RPM = 500
    _MAX_UPLOAD_TIMEOUT = 7200
    _THEME_VALUES = (THEME_AUTO, THEME_DARK, THEME_LIGHT)

    def __init__(
        self,
        parent: tk.Tk,
        current_rpm: int,
        current_workers: int,
        current_upload_timeout: int,
        current_upload_mode: str,
        current_theme_mode: str,
    ) -> None:
        super().__init__(parent, "Advanced Scan Settings")
        theme_mode = current_theme_mode if current_theme_mode in self._THEME_VALUES else THEME_AUTO
        self._current_rpm = current_rpm
        self._current_workers = current_workers
        self._current_upload_timeout = current_upload_timeout
        self._rpm_var = tk.StringVar(value=str(current_rpm))
        self._workers_var = tk.StringVar(value=str(current_workers))
        self._upload_timeout_var = tk.StringVar(value=str(current_upload_timeout))
        self._theme_var = tk.StringVar(value=theme_mode.title())
        self._upload_enabled_var = tk.BooleanVar(value=current_upload_mode in (UPLOAD_MANUAL, UPLOAD_AUTO))
        self._auto_upload_var = tk.BooleanVar(value=current_upload_mode == UPLOAD_AUTO)

    def create_body(self, master: tk.Misc) -> None:
        body = ttk.Frame(master, padding=(20, 16, 20, 12))
        body.pack(fill=tk.BOTH, expand=True)
        body.columnconfigure(0, weight=1)
        body.columnconfigure(1, weight=1)

        ttk.Label(body, text="Theme:").grid(row=0, column=0, sticky=tk.W, pady=(0, 10))
        theme_combo = ttk.Combobox(body, textvariable=self._theme_var, values=[v.title() for v in self._THEME_VALUES], state="readonly", width=12)
        theme_combo.grid(row=0, column=1, sticky=tk.W, padx=(16, 0), pady=(0, 10))
        theme_combo.set(self._theme_var.get())

        ttk.Label(body, text="Workers:").grid(row=1, column=0, sticky=tk.W, pady=(0, 10))
        ttk.Spinbox(body, from_=1, to=self._MAX_WORKERS, textvariable=self._workers_var, width=6).grid(row=1, column=1, sticky=tk.W, padx=(16, 0), pady=(0, 10))

        ttk.Label(body, text="Req/min (0 = unlimited):").grid(row=2, column=0, sticky=tk.W, pady=(0, 10))
        ttk.Spinbox(body, from_=0, to=self._MAX_RPM, textvariable=self._rpm_var, width=6).grid(row=2, column=1, sticky=tk.W, padx=(16, 0), pady=(0, 10))

        ttk.Label(body, text="Upload timeout (min, 0 = none):").grid(row=3, column=0, sticky=tk.W, pady=(0, 10))
        ttk.Spinbox(
            body,
            from_=0,
            to=self._MAX_UPLOAD_TIMEOUT,
            textvariable=self._upload_timeout_var,
            width=6,
        ).grid(row=3, column=1, sticky=tk.W, padx=(16, 0), pady=(0, 10))

        ttk.Separator(body, orient=tk.HORIZONTAL).grid(row=4, column=0, columnspan=2, sticky=tk.EW, pady=(4, 10))

        ttk.Checkbutton(
            body,
            text="Enable upload to VirusTotal for undetected files",
            variable=self._upload_enabled_var,
        ).grid(row=5, column=0, columnspan=2, sticky=tk.W, pady=(0, 4))

        sub_frame = ttk.Frame(body)
        sub_frame.grid(row=6, column=0, columnspan=2, sticky=tk.W, padx=(20, 0), pady=(2, 2))

        auto_chk = ttk.Checkbutton(sub_frame, text="Auto-upload all undetected items (uses extra API quota)", variable=self._auto_upload_var)
        auto_chk.pack(anchor=tk.W)

        def toggle_sub(*_: object) -> None:
            enabled = self._upload_enabled_var.get()
            auto_chk.configure(state=tk.NORMAL if enabled else tk.DISABLED)
            if not enabled:
                self._auto_upload_var.set(False)

        self._upload_enabled_var.trace_add("write", toggle_sub)
        toggle_sub()
        self._initial_focus = theme_combo

    def create_buttonbox(self, master: tk.Misc) -> None:
        ttk.Separator(master, orient=tk.HORIZONTAL).pack(fill=tk.X)
        btns = ttk.Frame(master, padding=(12, 8))
        btns.pack(fill=tk.X)
        ttk.Button(btns, text="Cancel", command=self._toplevel.destroy, bootstyle="secondary").pack(side=tk.RIGHT)
        ttk.Button(btns, text="Apply", command=self._apply, bootstyle="primary").pack(side=tk.RIGHT, padx=(0, 8))

    def _apply(self) -> None:
        try:
            workers = max(1, int(self._workers_var.get()))
        except ValueError:
            workers = self._current_workers
        try:
            rpm = max(0, int(self._rpm_var.get()))
        except ValueError:
            rpm = self._current_rpm
        try:
            upload_timeout = max(0, int(self._upload_timeout_var.get()))
        except ValueError:
            upload_timeout = self._current_upload_timeout

        if not self._upload_enabled_var.get():
            mode = UPLOAD_NEVER
        elif self._auto_upload_var.get():
            mode = UPLOAD_AUTO
        else:
            mode = UPLOAD_MANUAL

        selected_theme = self._theme_var.get().lower()
        self._result = (rpm, workers, upload_timeout, mode, selected_theme)
        self._toplevel.destroy()


def show_add_hashes_dialog(parent: tk.Tk, add_item: Callable[[str, str], bool]) -> None:
    AddHashesDialog(parent, add_item).show()


def show_generate_report_dialog(
    parent: tk.Tk,
    default_dir: str,
    results: list[dict],
    open_path: Callable[[str], None],
    open_folder: Callable[[str], None],
) -> str | None:
    dialog = GenerateReportDialog(parent, default_dir, results)
    dialog.show()
    result = dialog._result
    if not result:
        return None
    show_report_saved_dialog(parent, result["output_path"], open_path, open_folder)
    return result["new_dir"]


def show_report_saved_dialog(
    parent: tk.Tk,
    output_path: str,
    open_path: Callable[[str], None],
    open_folder: Callable[[str], None],
) -> None:
    ReportSavedDialog(parent, output_path, open_path, open_folder).show()


def show_set_api_key_dialog(parent: tk.Tk, current_key: str | None) -> str | None:
    """Prompts for an API key. Returns the entered string, or None if cancelled."""
    dialog = MaskedDialog(
        prompt="Enter API key:",
        title="VirusTotal API Key",
        initialvalue=current_key or "",
        parent=parent,
    )
    dialog.show()
    return dialog._result


def show_clear_cache_dialog(parent: tk.Tk, clear_fn: Callable[[], int]) -> int | None:
    """Confirms then calls clear_fn(). Returns deleted count, or None if cancelled/failed."""
    result = Messagebox.yesno(
        "Clear local SQLite cache now?",
        title="Clear Cache",
        parent=parent,
        buttons=["No:secondary", "Yes:primary"],
        default="Yes",
    )
    if result != "Yes":
        return None
    try:
        deleted = clear_fn()
        label = f"{deleted} entr{'y' if deleted == 1 else 'ies'}"
        Messagebox.show_info(f"Cleared SQLite cache ({label}).", title="Cache Cleared", parent=parent)
        return deleted
    except Exception as exc:
        Messagebox.show_error(str(exc), title="Cache Error", parent=parent)
        return None


def show_advanced_dialog(
    parent: tk.Tk,
    current_rpm: int,
    current_workers: int,
    current_upload_timeout: int,
    current_upload_mode: str = "never",
    current_theme_mode: str = "auto",
) -> tuple[int, int, int, str, str] | None:
    """Shows Advanced Scan Settings.

    Returns (rpm, workers, upload_timeout_minutes, upload_mode, theme_mode) on Apply, None on Cancel.
    upload_mode is one of 'never', 'manual', 'auto'.
    Checkbox mapping:
      main OFF              -> 'never'
      main ON, auto OFF     -> 'manual'  (toolbar Upload button; enabled when undetected files are selectable)
      main ON, auto ON      -> 'auto'    (upload happens automatically)
    """
    dialog = AdvancedDialog(parent, current_rpm, current_workers, current_upload_timeout, current_upload_mode, current_theme_mode)
    dialog.show()
    return dialog._result
