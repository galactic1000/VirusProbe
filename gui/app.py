"""Tkinter GUI for VirusProbe."""

from __future__ import annotations

import os
import subprocess
import sys
import threading
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk
from typing import Any

from common import ScannerService, write_report

TOOL_NAME = "VirusProbe"
CACHE_DB = Path(__file__).resolve().parents[1] / "cache" / "vt_cache.db"
DOTENV_PATH = Path(__file__).resolve().parents[1] / ".env"
API_KEY_ENV_VARS = ("VT_API_KEY", "VIRUSTOTAL_API_KEY")
INVALID_FILENAME_CHARS = set('<>:"/\\|?*')
_HEX_CHARS: frozenset[str] = frozenset("0123456789abcdefABCDEF")
WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "COM1",
    "COM2",
    "COM3",
    "COM4",
    "COM5",
    "COM6",
    "COM7",
    "COM8",
    "COM9",
    "LPT1",
    "LPT2",
    "LPT3",
    "LPT4",
    "LPT5",
    "LPT6",
    "LPT7",
    "LPT8",
    "LPT9",
}

from tkinterdnd2 import DND_FILES, TkinterDnD


def _load_dotenv(dotenv_path: Path) -> None:
    if not dotenv_path.exists():
        return
    for raw_line in dotenv_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _get_api_key() -> str | None:
    _load_dotenv(DOTENV_PATH)
    for var_name in API_KEY_ENV_VARS:
        value = os.environ.get(var_name, "").strip()
        if value:
            return value
    return None


def _is_sha256(value: str) -> bool:
    return len(value) == 64 and all(c in _HEX_CHARS for c in value)


class VirusProbeGUI:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("VirusProbe GUI")
        self.root.geometry("980x620")
        self.root.minsize(860, 520)

        self.api_key: str | None = _get_api_key()
        self.scanner: ScannerService | None = None
        self.items: list[dict[str, Any]] = []
        self.item_keys: set[tuple[str, str]] = set()
        self.last_results: list[dict[str, Any]] = []
        self._pending_entries: list[tuple[str, str, str]] = []
        self.is_scanning = False
        self.default_report_dir = str(Path.home())

        self._build_ui()
        self._update_api_key_status()

    def _build_ui(self) -> None:
        top = ttk.Frame(self.root, padding=10)
        top.pack(fill=tk.X)

        title = ttk.Label(top, text="VirusProbe", font=("Segoe UI", 16, "bold"))
        title.pack(side=tk.LEFT)

        self.api_status_var = tk.StringVar(value="API Key: Not Set")
        api_status = ttk.Label(top, textvariable=self.api_status_var)
        api_status.pack(side=tk.LEFT, padx=20)

        ttk.Button(top, text="Clear Cache", command=self._clear_cache_dialog).pack(side=tk.RIGHT, padx=(0, 8))
        ttk.Button(top, text="Set API Key", command=self._set_api_key_dialog).pack(side=tk.RIGHT)

        controls = ttk.Frame(self.root, padding=(10, 0, 10, 10))
        controls.pack(fill=tk.X)

        self.add_menu_btn = ttk.Menubutton(controls, text="Add Item")
        add_menu = tk.Menu(self.add_menu_btn, tearoff=False)
        add_menu.add_command(label="Add File(s)...", command=self._add_files_dialog)
        add_menu.add_command(label="Add SHA-256 Hash...", command=self._add_hash_dialog)
        add_menu.add_command(label="Add Multiple SHA-256 Hashes...", command=self._add_multiple_hashes_dialog)
        self.add_menu_btn["menu"] = add_menu
        self.add_menu_btn.pack(side=tk.LEFT)

        self.remove_btn = ttk.Button(controls, text="Remove Selected", command=self._remove_selected)
        self.remove_btn.pack(side=tk.LEFT, padx=8)
        self.clear_btn = ttk.Button(controls, text="Clear List", command=self._clear_items)
        self.clear_btn.pack(side=tk.LEFT)
        self.scan_btn = ttk.Button(controls, text="Scan", command=self._scan_items)
        self.scan_btn.pack(side=tk.RIGHT)

        helper_text = "Drag files into the list or use Add Item."
        ttk.Label(controls, text=helper_text).pack(side=tk.RIGHT, padx=12)

        list_frame = ttk.Frame(self.root, padding=(10, 0, 10, 10))
        list_frame.pack(fill=tk.BOTH, expand=True)

        columns = ("type", "value", "status")
        self.tree = ttk.Treeview(list_frame, columns=columns, show="headings", selectmode="extended")
        self.tree.heading("type", text="Type")
        self.tree.heading("value", text="Value")
        self.tree.heading("status", text="Status")
        self.tree.column("type", width=100, anchor=tk.CENTER, stretch=False)
        self.tree.column("value", width=650, anchor=tk.CENTER)
        self.tree.column("status", width=180, anchor=tk.CENTER)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.tree.drop_target_register(DND_FILES)  # type: ignore[attr-defined]
        self.tree.dnd_bind("<<Drop>>", self._on_drop_files)  # type: ignore[attr-defined]

        bottom = ttk.Frame(self.root, padding=(10, 0, 10, 10))
        bottom.pack(fill=tk.X)
        self.report_button = ttk.Button(bottom, text="Generate Report...", command=self._generate_report)
        self.report_button.pack(side=tk.LEFT)
        self.report_button.configure(state=tk.DISABLED)

        self.progress_var = tk.StringVar(value="Ready")
        ttk.Label(bottom, textvariable=self.progress_var).pack(side=tk.RIGHT)

    def _set_api_key_dialog(self) -> None:
        value = simpledialog.askstring(
            "VirusTotal API Key",
            "Enter API key:",
            initialvalue=self.api_key or "",
            show="*",
            parent=self.root,
        )
        if value is None:
            return
        value = value.strip()
        self.api_key = value or None
        if self.api_key:
            self._save_api_key_to_env(self.api_key)
        else:
            self._remove_api_key_from_env()
        self._update_api_key_status()

    def _clear_cache_dialog(self) -> None:
        confirmed = messagebox.askyesno(
            "Clear Cache",
            "Clear local SQLite cache now?",
            parent=self.root,
        )
        if not confirmed:
            return
        try:
            service = self.scanner or ScannerService(api_key=self.api_key or "", cache_db=CACHE_DB)
            deleted = service.clear_cache()
            self.progress_var.set(f"Cache cleared ({deleted} entr{'y' if deleted == 1 else 'ies'})")
            messagebox.showinfo(
                "Cache Cleared",
                f"Cleared SQLite cache ({deleted} entr{'y' if deleted == 1 else 'ies'}).",
                parent=self.root,
            )
        except Exception as exc:
            messagebox.showerror("Cache Error", str(exc), parent=self.root)

    def _update_api_key_status(self) -> None:
        if self.api_key:
            masked = f"{self.api_key[:4]}...{self.api_key[-4:]}" if len(self.api_key) >= 8 else "set"
            self.api_status_var.set(f"API Key: {masked}")
        else:
            self.api_status_var.set("API Key: Not Set")

    def _add_files_dialog(self) -> None:
        paths = filedialog.askopenfilenames(parent=self.root, title="Select files to scan")
        for path in paths:
            self._add_item("file", str(path))

    def _add_hash_dialog(self) -> None:
        raw = simpledialog.askstring("Add SHA-256 Hash", "Enter SHA-256 Hash (64 hex chars):", parent=self.root)
        if raw is None:
            return
        value = raw.strip()
        if not _is_sha256(value):
            messagebox.showerror("Invalid Hash", "Hash must be exactly 64 hexadecimal characters.", parent=self.root)
            return
        self._add_item("hash", value.lower())

    def _add_multiple_hashes_dialog(self) -> None:
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Multiple SHA-256 Hashes")
        dialog.transient(self.root)
        dialog.grab_set()
        dialog.resizable(True, True)
        dialog.minsize(560, 360)

        frame = ttk.Frame(dialog, padding=12)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(
            frame,
            text="Add SHA-256 hashes (one per line):",
        ).pack(anchor=tk.W, pady=(0, 6))

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
                if not _is_sha256(value):
                    invalid.append(token)
                    continue
                before_count = len(self.items)
                self._add_item("hash", value)
                if len(self.items) > before_count:
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
        x = self.root.winfo_rootx() + (self.root.winfo_width() - dialog.winfo_width()) // 2
        y = self.root.winfo_rooty() + (self.root.winfo_height() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{max(x, 0)}+{max(y, 0)}")

    def _add_item(self, item_type: str, value: str) -> None:
        key = (item_type, value)
        if key in self.item_keys:
            return
        entry = {"type": item_type, "value": value, "status": "Queued"}
        self.items.append(entry)
        self.item_keys.add(key)
        self.tree.insert("", tk.END, values=(item_type, value, "Queued"))
        self.progress_var.set(f"Items queued: {len(self.items)}")

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
        self.report_button.configure(state=tk.DISABLED)
        self.progress_var.set("Ready")

    def _on_drop_files(self, event: Any) -> None:
        data = event.data
        try:
            paths = self.root.tk.splitlist(data)
        except Exception:
            paths = [data]
        for raw in paths:
            path = str(raw).strip().strip("{}")
            if path and Path(path).is_file():
                self._add_item("file", path)

    def _scan_items(self) -> None:
        if self.is_scanning:
            return
        if not self.items:
            messagebox.showinfo("No Items", "Add at least one file or SHA-256 Hash to scan.", parent=self.root)
            return
        if not self.api_key:
            messagebox.showerror("Missing API Key", "Set an API key before scanning.", parent=self.root)
            return

        tree_entries: list[tuple[str, str, str]] = []
        for iid in self.tree.get_children():
            vals = self.tree.item(iid, "values")
            if not vals:
                continue
            item_type, value, _ = vals
            tree_entries.append((iid, item_type, value))
        self._pending_entries = (
            [e for e in tree_entries if e[1] == "file"]
            + [e for e in tree_entries if e[1] == "hash"]
        )

        self.is_scanning = True
        self.last_results = []
        self.report_button.configure(state=tk.DISABLED)
        self.remove_btn.configure(state=tk.DISABLED)
        self.clear_btn.configure(state=tk.DISABLED)
        self.scan_btn.configure(state=tk.DISABLED)
        self.add_menu_btn.configure(state=tk.DISABLED)
        self.progress_var.set("Starting scan...")
        thread = threading.Thread(target=self._scan_worker, daemon=True)
        thread.start()

    def _scan_worker(self) -> None:
        try:
            self.scanner = ScannerService(api_key=self.api_key or "", cache_db=CACHE_DB)
            self.scanner.init_cache()
            results: list[dict[str, Any]] = []
            # Use entries captured on the main thread — avoids touching Tkinter from background thread.
            ordered_entries = self._pending_entries
            total = len(ordered_entries)
            for idx, (iid, item_type, value) in enumerate(ordered_entries, start=1):
                self.root.after(0, self._set_row_status, iid, f"Scanning ({idx}/{total})...")
                if item_type == "hash":
                    result = self.scanner.scan_hash(value)
                else:
                    result = self.scanner.scan_file(value)
                results.append(result)
                status = self._result_status(result)
                self.root.after(0, self._set_row_status, iid, status)
            self.last_results = results
            if results:
                self.root.after(0, lambda: self.report_button.configure(state=tk.NORMAL))
            self.root.after(0, lambda: self.progress_var.set("Scan complete"))
        except Exception as exc:
            self.root.after(0, lambda: messagebox.showerror("Scan Error", str(exc), parent=self.root))
            self.root.after(0, lambda: self.progress_var.set("Scan failed"))
        finally:
            self.is_scanning = False
            self.root.after(0, self._restore_scan_buttons)

    def _restore_scan_buttons(self) -> None:
        self.remove_btn.configure(state=tk.NORMAL)
        self.clear_btn.configure(state=tk.NORMAL)
        self.scan_btn.configure(state=tk.NORMAL)
        self.add_menu_btn.configure(state=tk.NORMAL)

    def _set_row_status(self, iid: str, status: str) -> None:
        vals = self.tree.item(iid, "values")
        if not vals:
            return
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
        selection = self._show_generate_report_dialog()
        if not selection:
            return
        output_path, fmt = selection
        try:
            write_report(self.last_results, output_path, fmt)
            self._show_report_saved_dialog(output_path)
        except Exception as exc:
            messagebox.showerror("Report Error", str(exc), parent=self.root)

    def _show_generate_report_dialog(self) -> tuple[str, str] | None:
        dialog = tk.Toplevel(self.root)
        dialog.title("Generate Report")
        dialog.transient(self.root)
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
        folder_var = tk.StringVar(value=self.default_report_dir)
        folder_entry = ttk.Entry(frame, textvariable=folder_var, width=36)
        folder_entry.grid(row=2, column=1, sticky=tk.EW)

        def browse_folder() -> None:
            selected = filedialog.askdirectory(parent=dialog, title="Select Report Folder", initialdir=folder_var.get() or self.default_report_dir)
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
            if any(ch in INVALID_FILENAME_CHARS for ch in name):
                messagebox.showerror(
                    "Invalid Name",
                    'Report name contains invalid characters: <>:"/\\|?*',
                    parent=dialog,
                )
                return
            if name[-1] in {" ", "."}:
                messagebox.showerror(
                    "Invalid Name",
                    "Report name cannot end with a space or period.",
                    parent=dialog,
                )
                return
            stem_upper = Path(name).stem.upper()
            if stem_upper in WINDOWS_RESERVED_NAMES:
                messagebox.showerror(
                    "Invalid Name",
                    "Report name uses a reserved system filename.",
                    parent=dialog,
                )
                return
            if not folder:
                messagebox.showerror("Invalid Folder", "Select a folder for the report.", parent=dialog)
                return
            folder_path = Path(folder)
            if not folder_path.exists() or not folder_path.is_dir():
                messagebox.showerror("Invalid Folder", "Selected folder does not exist.", parent=dialog)
                return
            safe_name = name if "." not in Path(name).name else Path(name).stem
            output_path = str(folder_path / f"{safe_name}.{fmt}")
            result["path"] = output_path
            result["fmt"] = fmt
            self.default_report_dir = str(folder_path)
            dialog.destroy()

        def cancel() -> None:
            dialog.destroy()

        ttk.Button(buttons, text="Generate", command=confirm).pack(side=tk.RIGHT)
        ttk.Button(buttons, text="Cancel", command=cancel).pack(side=tk.RIGHT, padx=(0, 8))

        name_entry.focus_set()
        dialog.update_idletasks()
        x = self.root.winfo_rootx() + (self.root.winfo_width() - dialog.winfo_width()) // 2
        y = self.root.winfo_rooty() + (self.root.winfo_height() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{max(x, 0)}+{max(y, 0)}")
        self.root.wait_window(dialog)

        if "path" not in result or "fmt" not in result:
            return None
        return result["path"], result["fmt"]

    def _show_report_saved_dialog(self, output_path: str) -> None:
        dialog = tk.Toplevel(self.root)
        dialog.title("Report Saved")
        dialog.transient(self.root)
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

        def open_report() -> None:
            self._open_path(output_path)
            close_dialog()

        def open_folder() -> None:
            self._open_folder(output_path)
            close_dialog()

        ttk.Button(buttons, text="Open Report", command=open_report).pack(side=tk.LEFT)
        ttk.Button(buttons, text="Open Folder", command=open_folder).pack(side=tk.LEFT, padx=8)
        ttk.Button(buttons, text="Close", command=close_dialog).pack(side=tk.RIGHT)

        dialog.update_idletasks()
        x = self.root.winfo_rootx() + (self.root.winfo_width() - dialog.winfo_width()) // 2
        y = self.root.winfo_rooty() + (self.root.winfo_height() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{max(x, 0)}+{max(y, 0)}")

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
        folder = str(Path(path).resolve().parent)
        self._open_path(folder)

    def _save_api_key_to_env(self, api_key: str) -> None:
        lines: list[str] = []
        if DOTENV_PATH.exists():
            lines = DOTENV_PATH.read_text(encoding="utf-8").splitlines()
        updated = False
        out: list[str] = []
        for line in lines:
            stripped = line.strip()
            if any(stripped.startswith(f"{name}=") for name in API_KEY_ENV_VARS):
                if not updated:
                    out.append(f"VT_API_KEY={api_key}")
                    updated = True
                continue
            out.append(line)
        if not updated:
            out.append(f"VT_API_KEY={api_key}")
        DOTENV_PATH.write_text("\n".join(out).rstrip() + "\n", encoding="utf-8")
        os.environ["VT_API_KEY"] = api_key

    def _remove_api_key_from_env(self) -> None:
        if not DOTENV_PATH.exists():
            return
        lines = DOTENV_PATH.read_text(encoding="utf-8").splitlines()
        out = [
            line
            for line in lines
            if not any(line.strip().startswith(f"{name}=") for name in API_KEY_ENV_VARS)
        ]
        if out:
            DOTENV_PATH.write_text("\n".join(out).rstrip() + "\n", encoding="utf-8")
        else:
            DOTENV_PATH.unlink(missing_ok=True)
        for name in API_KEY_ENV_VARS:
            os.environ.pop(name, None)


def main() -> None:
    root = TkinterDnD.Tk()
    app = VirusProbeGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
