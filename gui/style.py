"""Theme and dark-mode helpers for the GUI."""

from __future__ import annotations

import re
import subprocess
import sys
import tkinter as tk

from ttkbootstrap import Style

if sys.platform.startswith("win"):
    import ctypes
    import winreg


_LIGHT_THEME = "flatly"
_DARK_THEME = "darkly"
_DWMWA_USE_IMMERSIVE_DARK_MODE = 20
_system_dark: bool | None = None


def theme_name(theme_mode: str) -> str:
    global _system_dark
    mode = (theme_mode or "auto").strip().lower()
    if mode == "dark":
        return _DARK_THEME
    if mode == "light":
        return _LIGHT_THEME
    if _system_dark is None:
        _system_dark = _system_prefers_dark_mode()
    return _DARK_THEME if _system_dark else _LIGHT_THEME


def apply_theme(root: tk.Tk, theme_mode: str = "auto") -> None:
    dark_mode = _apply_bootstrap_theme(theme_mode)
    _apply_windows_titlebar_mode(root, dark_mode)


def apply_titlebar_theme(widget: tk.Misc) -> None:
    """Apply the current ttkbootstrap theme's dark/light mode to a dialog's title bar."""
    style = Style.get_instance()
    if style is None:
        return
    theme = getattr(style, "theme", None)
    dark_mode = getattr(theme, "name", "") == _DARK_THEME
    _apply_windows_titlebar_mode(widget, dark_mode)


def _apply_bootstrap_theme(theme_mode: str) -> bool:
    theme = theme_name(theme_mode)
    try:
        Style.get_instance().theme_use(theme) # type: ignore[union-attr]
    except Exception:
        return False
    return theme == _DARK_THEME


def _system_prefers_dark_mode() -> bool:
    if sys.platform.startswith("win"):
        return _windows_prefers_dark_mode()
    if sys.platform == "darwin":
        return _macos_prefers_dark_mode()
    if sys.platform.startswith("linux"):
        return _linux_prefers_dark_mode()
    return False


def _windows_prefers_dark_mode() -> bool:
    try:
        with winreg.OpenKey( # type: ignore[attr-defined]
            winreg.HKEY_CURRENT_USER, # type: ignore[attr-defined]
            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize",
        ) as key:
            apps_value, _ = winreg.QueryValueEx(key, "AppsUseLightTheme") # type: ignore[attr-defined]
            return int(apps_value) == 0
    except Exception:
        return False


def _macos_prefers_dark_mode() -> bool:
    try:
        proc = subprocess.run(
            ["defaults", "read", "-g", "AppleInterfaceStyle"],
            capture_output=True,
            text=True,
            check=False,
        )
        return proc.returncode == 0 and proc.stdout.strip().lower() == "dark"
    except Exception:
        return False


def _linux_prefers_dark_mode() -> bool:
    try:
        proc = subprocess.run(
            [
                "gdbus",
                "call",
                "--session",
                "--dest",
                "org.freedesktop.portal.Desktop",
                "--object-path",
                "/org/freedesktop/portal/desktop",
                "--method",
                "org.freedesktop.portal.Settings.Read",
                "org.freedesktop.appearance",
                "color-scheme",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if proc.returncode != 0:
            return False
        m = re.search(r"uint32\s+(\d+)", proc.stdout)
        if not m:
            return False
        return int(m.group(1)) == 1
    except Exception:
        return False


def _apply_windows_titlebar_mode(root: tk.Misc, dark_mode: bool) -> None:
    if not sys.platform.startswith("win"):
        return
    try:
        root.update_idletasks()
        hwnd = root.winfo_id()
        top_hwnd = ctypes.windll.user32.GetParent(hwnd) or hwnd  # type: ignore[possibly-undefined]
        value = ctypes.c_int(1 if dark_mode else 0)  # type: ignore[possibly-undefined]
        ctypes.windll.dwmapi.DwmSetWindowAttribute(  # type: ignore[possibly-undefined]
            ctypes.c_void_p(top_hwnd), _DWMWA_USE_IMMERSIVE_DARK_MODE, ctypes.byref(value), ctypes.sizeof(value)  # type: ignore[possibly-undefined]
        )
    except Exception:
        pass
