"""Qt-native theme helpers for the GUI."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

_DARK_THEME = "dark"
_LIGHT_THEME = "light"
_ASSETS_DIR = Path(__file__).resolve().parent / "assets"


def _read_asset(name: str) -> str:
    return (_ASSETS_DIR / name).read_text(encoding="utf-8")


def is_dark_mode(theme_mode: str = "auto") -> bool:
    mode = (theme_mode or "").strip().lower()
    if mode == _DARK_THEME:
        return True
    if mode == _LIGHT_THEME:
        return False
    app = QApplication.instance()
    if app is None:
        return False
    return app.styleHints().colorScheme() == Qt.ColorScheme.Dark # type: ignore


def theme_name(theme_mode: str = "auto") -> str:
    return _DARK_THEME if is_dark_mode(theme_mode) else _LIGHT_THEME


def apply_theme(theme_mode: str = "auto") -> None:
    """Apply a restrained application stylesheet on top of Qt/Fusion."""
    mode = (theme_mode or "").strip().lower()
    app = QApplication.instance()
    if app is None:
        return
    hints = app.styleHints() # type: ignore
    if mode == _DARK_THEME:
        hints.setColorScheme(Qt.ColorScheme.Dark)
    elif mode == _LIGHT_THEME:
        hints.setColorScheme(Qt.ColorScheme.Light)
    else:
        hints.unsetColorScheme()
    app.setStyleSheet(_read_asset("dark.qss") # type: ignore
                      if is_dark_mode(theme_mode) 
                      else _read_asset("light.qss"))
