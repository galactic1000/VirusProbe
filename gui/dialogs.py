"""Toplevel dialog windows for the VirusProbe GUI."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Callable
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from common import ScannerService, UPLOAD_AUTO, UPLOAD_MANUAL, UPLOAD_NEVER, write_report

PORTABLE_INVALID_CHARS = set('/\\:*?"<>|')


def _is_portable_filename(name: str) -> bool:
    """Returns True when `name` is portable across common filesystems."""
    if not name or name in {".", ".."}:
        return False
    if name[-1] in {" ", "."}:
        return False
    for ch in name:
        if ch in PORTABLE_INVALID_CHARS or ord(ch) < 32:
            return False
    return True


def show_add_hashes_dialog(parent: tk.Tk, add_item: Callable[[str, str], bool]) -> None:
    """Prompts the user to paste multiple SHA-256 hashes.

    `add_item(type, value)` should return True if the item was newly added.
    """
    dialog = tk.Toplevel(parent)
    dialog.title("Add multiple SHA-256 hashes")
    dialog.transient(parent)
    dialog.grab_set()
    dialog.resizable(True, True)
    dialog.minsize(560, 360)

    frame = ttk.Frame(dialog, padding=12)
    frame.pack(fill=tk.BOTH, expand=True)

    ttk.Label(frame, text="Add SHA-256 hashes (one per line):").pack(anchor=tk.W, pady=(0, 6))

    text = tk.Text(frame, height=12, wrap=tk.WORD)
    text.pack(fill=tk.BOTH, expand=True)

    status_var = tk.StringVar(value="")
    ttk.Label(frame, textvariable=status_var).pack(anchor=tk.W, pady=(6, 0))

    buttons = ttk.Frame(frame)
    buttons.pack(fill=tk.X, pady=(8, 0))

    def cancel() -> None:
        dialog.destroy()

    def add_hashes() -> None:
        raw = text.get("1.0", tk.END).strip()
        if not raw:
            status_var.set("No hashes provided.")
            return
        tokens = [line.strip() for line in raw.splitlines() if line.strip()]
        if not tokens:
            status_var.set("No hashes provided.")
            return
        added = 0
        invalid: list[str] = []
        seen: set[str] = set()
        for token in tokens:
            value = token.lower()
            if value in seen:
                continue
            seen.add(value)
            if not ScannerService.is_sha256(value):
                invalid.append(token)
                continue
            if add_item("hash", value):
                added += 1
        if invalid:
            status_var.set(f"Added {added}. Skipped invalid: {len(invalid)}")
        else:
            status_var.set(f"Added {added} hash(es).")
        if added > 0:
            dialog.after(500, dialog.destroy)

    ttk.Button(buttons, text="Add", command=add_hashes).pack(side=tk.RIGHT)
    ttk.Button(buttons, text="Cancel", command=cancel).pack(side=tk.RIGHT, padx=(0, 8))

    text.focus_set()
    dialog.update_idletasks()
    x = parent.winfo_rootx() + (parent.winfo_width() - dialog.winfo_width()) // 2
    y = parent.winfo_rooty() + (parent.winfo_height() - dialog.winfo_height()) // 2
    dialog.geometry(f"+{max(x, 0)}+{max(y, 0)}")


def show_generate_report_dialog(
    parent: tk.Tk,
    default_dir: str,
    results: list[dict],
    open_path: Callable[[str], None],
    open_folder: Callable[[str], None],
) -> str | None:
    """Shows the Generate Report dialog. Writes the report on confirm.

    Returns the new default directory on success, or None if cancelled.
    Stays open if the write fails, showing the error inline.
    """
    dialog = tk.Toplevel(parent)
    dialog.title("Generate Report")
    dialog.transient(parent)
    dialog.grab_set()
    dialog.resizable(False, False)

    result: dict[str, str] = {}

    frame = ttk.Frame(dialog, padding=12)
    frame.pack(fill=tk.BOTH, expand=True)

    ttk.Label(frame, text="Report Name").grid(row=0, column=0, sticky=tk.W, pady=(0, 6))
    default_name = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    name_var = tk.StringVar(value=default_name)
    name_entry = ttk.Entry(frame, textvariable=name_var, width=36)
    name_entry.grid(row=0, column=1, columnspan=2, sticky=tk.EW, pady=(0, 6))

    ttk.Label(frame, text="Report Type").grid(row=1, column=0, sticky=tk.W, pady=(0, 6))
    fmt_var = tk.StringVar(value="json")
    fmt_combo = ttk.Combobox(frame, textvariable=fmt_var, values=["json", "csv", "txt", "md"], state="readonly", width=10)
    fmt_combo.grid(row=1, column=1, sticky=tk.W, pady=(0, 6))

    ttk.Label(frame, text="Folder").grid(row=2, column=0, sticky=tk.W)
    folder_var = tk.StringVar(value=default_dir)
    folder_entry = ttk.Entry(frame, textvariable=folder_var, width=36)
    folder_entry.grid(row=2, column=1, sticky=tk.EW)

    def browse_folder() -> None:
        selected = filedialog.askdirectory(parent=dialog, title="Select Report Folder", initialdir=folder_var.get() or default_dir)
        if selected:
            folder_var.set(selected)

    ttk.Button(frame, text="Browse...", command=browse_folder).grid(row=2, column=2, padx=(6, 0))
    frame.columnconfigure(1, weight=1)

    buttons = ttk.Frame(frame)
    buttons.grid(row=3, column=0, columnspan=3, sticky=tk.EW, pady=(12, 0))

    def confirm() -> None:
        name = name_var.get().strip()
        folder = folder_var.get().strip()
        fmt = fmt_var.get().strip().lower() or "json"
        if not name:
            messagebox.showerror("Invalid Name", "Report name is required.", parent=dialog)
            return
        if not folder:
            messagebox.showerror("Invalid Folder", "Select a folder for the report.", parent=dialog)
            return
        folder_path = Path(folder)
        if not folder_path.exists() or not folder_path.is_dir():
            messagebox.showerror("Invalid Folder", "Selected folder does not exist.", parent=dialog)
            return

        safe_name = Path(name).stem if "." in Path(name).name else name
        safe_name = Path(safe_name).name.strip()
        if not _is_portable_filename(safe_name):
            messagebox.showerror(
                "Invalid Name",
                "Use a portable filename (no / \\ : * ? \" < > |, control chars, trailing space/period).",
                parent=dialog,
            )
            return

        output_path = str(folder_path / f"{safe_name}.{fmt}")
        try:
            write_report(results, output_path, fmt)
        except Exception as exc:
            messagebox.showerror("Report Error", str(exc), parent=dialog)
            return
        result["new_dir"] = str(folder_path)
        dialog.destroy()
        show_report_saved_dialog(parent, output_path, open_path, open_folder)

    def cancel() -> None:
        dialog.destroy()

    ttk.Button(buttons, text="Generate", command=confirm).pack(side=tk.RIGHT)
    ttk.Button(buttons, text="Cancel", command=cancel).pack(side=tk.RIGHT, padx=(0, 8))

    name_entry.focus_set()
    dialog.update_idletasks()
    x = parent.winfo_rootx() + (parent.winfo_width() - dialog.winfo_width()) // 2
    y = parent.winfo_rooty() + (parent.winfo_height() - dialog.winfo_height()) // 2
    dialog.geometry(f"+{max(x, 0)}+{max(y, 0)}")
    parent.wait_window(dialog)

    return result.get("new_dir")


def show_report_saved_dialog(
    parent: tk.Tk,
    output_path: str,
    open_path: Callable[[str], None],
    open_folder: Callable[[str], None],
) -> None:
    """Shows the Report Saved confirmation dialog."""
    dialog = tk.Toplevel(parent)
    dialog.title("Report Saved")
    dialog.transient(parent)
    dialog.grab_set()
    dialog.resizable(False, False)

    frame = ttk.Frame(dialog, padding=12)
    frame.pack(fill=tk.BOTH, expand=True)

    ttk.Label(frame, text="Report saved successfully.").pack(anchor=tk.W)
    ttk.Label(frame, text=output_path, wraplength=540).pack(anchor=tk.W, pady=(4, 10))

    buttons = ttk.Frame(frame)
    buttons.pack(fill=tk.X)

    def close_dialog() -> None:
        dialog.destroy()

    def on_open_report() -> None:
        open_path(output_path)
        close_dialog()

    def on_open_folder() -> None:
        open_folder(output_path)
        close_dialog()

    ttk.Button(buttons, text="Open Report", command=on_open_report).pack(side=tk.LEFT)
    ttk.Button(buttons, text="Open Folder", command=on_open_folder).pack(side=tk.LEFT, padx=8)
    ttk.Button(buttons, text="Close", command=close_dialog).pack(side=tk.RIGHT)

    dialog.update_idletasks()
    x = parent.winfo_rootx() + (parent.winfo_width() - dialog.winfo_width()) // 2
    y = parent.winfo_rooty() + (parent.winfo_height() - dialog.winfo_height()) // 2
    dialog.geometry(f"+{max(x, 0)}+{max(y, 0)}")


def show_set_api_key_dialog(parent: tk.Tk, current_key: str | None) -> str | None:
    """Prompts for an API key. Returns the entered string, or None if cancelled."""
    return simpledialog.askstring(
        "VirusTotal API Key",
        "Enter API key:",
        initialvalue=current_key or "",
        show="*",
        parent=parent,
    )


def show_clear_cache_dialog(parent: tk.Tk, clear_fn: Callable[[], int]) -> int | None:
    """Confirms then calls clear_fn(). Returns deleted count, or None if cancelled/failed."""
    if not messagebox.askyesno("Clear Cache", "Clear local SQLite cache now?", parent=parent):
        return None
    try:
        deleted = clear_fn()
        label = f"{deleted} entr{'y' if deleted == 1 else 'ies'}"
        messagebox.showinfo("Cache Cleared", f"Cleared SQLite cache ({label}).", parent=parent)
        return deleted
    except Exception as exc:
        messagebox.showerror("Cache Error", str(exc), parent=parent)
        return None


def show_add_hash_dialog(parent: tk.Tk) -> str | None:
    """Prompts for a single SHA-256 hash. Returns validated lowercase hash, or None."""
    raw = simpledialog.askstring("Add SHA-256 hash", "Enter SHA-256 hash (64 hex chars):", parent=parent)
    if raw is None:
        return None
    value = raw.strip()
    if not ScannerService.is_sha256(value):
        messagebox.showerror("Invalid hash", "Hash must be exactly 64 hexadecimal characters.", parent=parent)
        return None
    return value.lower()


def show_advanced_dialog(parent: tk.Tk, current_rpm: int, current_workers: int, current_upload_mode: str = "never") -> tuple[int, int, str] | None:
    """Shows Advanced Scan Settings.

    Returns (rpm, workers, upload_mode) on Apply, None on Cancel.
    upload_mode is one of 'never', 'manual', 'auto'.
    Checkbox mapping:
      main OFF              -> 'never'
      main ON, auto OFF     -> 'manual'  (Upload button appears after scan)
      main ON, auto ON      -> 'auto'    (upload happens automatically)
    """
    dlg = tk.Toplevel(parent)
    dlg.title("Advanced Scan Settings")
    dlg.resizable(False, False)
    dlg.transient(parent)
    dlg.grab_set()

    rpm_var = tk.StringVar(value=str(current_rpm))
    workers_var = tk.StringVar(value=str(current_workers))
    upload_enabled_var = tk.BooleanVar(value=current_upload_mode in (UPLOAD_MANUAL, UPLOAD_AUTO))
    auto_upload_var = tk.BooleanVar(value=current_upload_mode == UPLOAD_AUTO)
    result: dict[str, tuple[int, int, str]] = {}

    body = ttk.Frame(dlg, padding=(20, 16, 20, 12))
    body.pack(fill=tk.BOTH, expand=True)

    ttk.Label(body, text="Workers:").grid(row=0, column=0, sticky=tk.W, pady=(0, 10))
    ttk.Spinbox(body, from_=1, to=50, textvariable=workers_var, width=6).grid(row=0, column=1, sticky=tk.W, padx=(16, 0), pady=(0, 10))

    ttk.Label(body, text="Req/min (0 = unlimited):").grid(row=1, column=0, sticky=tk.W, pady=(0, 10))
    ttk.Spinbox(body, from_=0, to=500, textvariable=rpm_var, width=6).grid(row=1, column=1, sticky=tk.W, padx=(16, 0), pady=(0, 10))

    ttk.Separator(body, orient=tk.HORIZONTAL).grid(row=2, column=0, columnspan=2, sticky=tk.EW, pady=(4, 10))

    # Main upload checkbox
    upload_chk = ttk.Checkbutton(body, text="Enable upload to VirusTotal for undetected files (uses extra API quota)", variable=upload_enabled_var)
    upload_chk.grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=(0, 4))

    # Sub-option (indented, disabled when main is off)
    sub_frame = ttk.Frame(body)
    sub_frame.grid(row=4, column=0, columnspan=2, sticky=tk.W, padx=(20, 0), pady=(0, 4))

    auto_chk = ttk.Checkbutton(sub_frame, text="Auto-upload all undetected items", variable=auto_upload_var)
    auto_chk.pack(anchor=tk.W)
    desc_lbl = ttk.Label(
        sub_frame,
        text="When checked: files are uploaded automatically (auto).\nWhen unchecked: an Upload button appears after the scan (manual).\nResults are always cached locally.",
        foreground="gray",
    )
    desc_lbl.pack(anchor=tk.W, pady=(2, 0))

    def _toggle_sub(*_: object) -> None:
        enabled = upload_enabled_var.get()
        auto_chk.configure(state=tk.NORMAL if enabled else tk.DISABLED)
        desc_lbl.configure(foreground="black" if enabled else "gray")
        if not enabled:
            auto_upload_var.set(False)

    upload_enabled_var.trace_add("write", _toggle_sub)
    _toggle_sub()  # apply initial state

    ttk.Separator(dlg, orient=tk.HORIZONTAL).pack(fill=tk.X)

    btns = ttk.Frame(dlg, padding=(12, 8))
    btns.pack(fill=tk.X)

    def _apply() -> None:
        try:
            workers = max(1, int(workers_var.get()))
        except ValueError:
            workers = current_workers
        try:
            rpm = max(0, int(rpm_var.get()))
        except ValueError:
            rpm = current_rpm
        if not upload_enabled_var.get():
            mode = UPLOAD_NEVER
        elif auto_upload_var.get():
            mode = UPLOAD_AUTO
        else:
            mode = UPLOAD_MANUAL
        result["values"] = (rpm, workers, mode)
        dlg.destroy()

    ttk.Button(btns, text="Cancel", command=dlg.destroy).pack(side=tk.RIGHT)
    ttk.Button(btns, text="Apply", command=_apply).pack(side=tk.RIGHT, padx=(0, 8))

    dlg.update_idletasks()
    x = parent.winfo_rootx() + (parent.winfo_width() - dlg.winfo_width()) // 2
    y = parent.winfo_rooty() + (parent.winfo_height() - dlg.winfo_height()) // 2
    dlg.geometry(f"+{max(x, 0)}+{max(y, 0)}")

    dlg.wait_window()
    return result.get("values")

