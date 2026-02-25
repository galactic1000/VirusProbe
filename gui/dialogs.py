"""Toplevel dialog windows for the VirusProbe GUI."""

from __future__ import annotations

import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Callable

from common import ScannerService, write_report

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
