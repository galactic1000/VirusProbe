from __future__ import annotations

import pytest

from gui.style import (
    _DARK_THEME,
    _LIGHT_THEME,
    _apply_windows_titlebar_mode,
    _linux_prefers_dark_mode,
    _macos_prefers_dark_mode,
    _system_prefers_dark_mode,
    _windows_prefers_dark_mode,
    apply_theme,
    apply_titlebar_theme,
    theme_name,
)


@pytest.mark.parametrize(("mode", "expected"), [
    ("dark", _DARK_THEME),
    ("light", _LIGHT_THEME),
])
def test_theme_name_explicit(mode, expected) -> None:
    assert theme_name(mode) == expected


@pytest.mark.parametrize(("dark_returns", "expected"), [
    (True, _DARK_THEME),
    (False, _LIGHT_THEME),
])
def test_theme_name_auto(mocker, dark_returns, expected) -> None:
    mocker.patch("gui.style._system_prefers_dark_mode", return_value=dark_returns)
    assert theme_name("auto") == expected


def test_system_dark_windows(monkeypatch, mocker) -> None:
    monkeypatch.setattr("gui.style.IS_WINDOWS", True)
    monkeypatch.setattr("gui.style.IS_MACOS", False)
    monkeypatch.setattr("gui.style.IS_LINUX", False)
    mocker.patch("gui.style._windows_prefers_dark_mode", return_value=True)
    assert _system_prefers_dark_mode() is True


def test_system_dark_macos(monkeypatch, mocker) -> None:
    monkeypatch.setattr("gui.style.IS_WINDOWS", False)
    monkeypatch.setattr("gui.style.IS_MACOS", True)
    monkeypatch.setattr("gui.style.IS_LINUX", False)
    mocker.patch("gui.style._macos_prefers_dark_mode", return_value=True)
    assert _system_prefers_dark_mode() is True


def test_system_dark_linux(monkeypatch, mocker) -> None:
    monkeypatch.setattr("gui.style.IS_WINDOWS", False)
    monkeypatch.setattr("gui.style.IS_MACOS", False)
    monkeypatch.setattr("gui.style.IS_LINUX", True)
    mocker.patch("gui.style._linux_prefers_dark_mode", return_value=False)
    assert _system_prefers_dark_mode() is False


def test_system_dark_unknown_platform(monkeypatch) -> None:
    monkeypatch.setattr("gui.style.IS_WINDOWS", False)
    monkeypatch.setattr("gui.style.IS_MACOS", False)
    monkeypatch.setattr("gui.style.IS_LINUX", False)
    assert _system_prefers_dark_mode() is False


@pytest.mark.parametrize(("registry_value", "expected"), [
    (0, True),
    (1, False),
])
def test_windows_dark_mode(mocker, registry_value, expected) -> None:
    mocker.patch("winreg.OpenKey", return_value=mocker.MagicMock())
    mocker.patch("winreg.QueryValueEx", return_value=(registry_value, None))
    assert _windows_prefers_dark_mode() is expected


def test_windows_dark_mode_exception(mocker) -> None:
    mocker.patch("winreg.OpenKey", side_effect=OSError("no key"))
    assert _windows_prefers_dark_mode() is False


def test_macos_dark_mode_true(mocker) -> None:
    mocker.patch("gui.style.subprocess.run", return_value=mocker.MagicMock(returncode=0, stdout="Dark\n"))
    assert _macos_prefers_dark_mode() is True


def test_macos_dark_mode_false_returncode(mocker) -> None:
    mocker.patch("gui.style.subprocess.run", return_value=mocker.MagicMock(returncode=1))
    assert _macos_prefers_dark_mode() is False


def test_macos_dark_mode_exception(mocker) -> None:
    mocker.patch("gui.style.subprocess.run", side_effect=FileNotFoundError)
    assert _macos_prefers_dark_mode() is False


@pytest.mark.parametrize(("stdout", "expected"), [
    ("({'': ('(uint32 1)',)},)", True),
    ("({'': ('(uint32 2)',)},)", False),
    ("nothing useful", False),
])
def test_linux_dark_mode_stdout(mocker, stdout, expected) -> None:
    mocker.patch("gui.style.subprocess.run", return_value=mocker.MagicMock(returncode=0, stdout=stdout))
    assert _linux_prefers_dark_mode() is expected


def test_linux_dark_mode_bad_returncode(mocker) -> None:
    mocker.patch("gui.style.subprocess.run", return_value=mocker.MagicMock(returncode=1))
    assert _linux_prefers_dark_mode() is False


def test_linux_dark_mode_exception(mocker) -> None:
    mocker.patch("gui.style.subprocess.run", side_effect=FileNotFoundError)
    assert _linux_prefers_dark_mode() is False


def test_apply_titlebar_theme_no_instance(mocker) -> None:
    mocker.patch("gui.style.QApplication.instance", return_value=None)
    apply_titlebar_theme(mocker.MagicMock())


def test_apply_titlebar_theme_uses_mode(mocker) -> None:
    mocker.patch("gui.style.QApplication.instance", return_value=mocker.MagicMock())
    apply_impl = mocker.patch("gui.style._apply_windows_titlebar_mode")
    mocker.patch("gui.style.is_dark_mode", return_value=True)
    apply_titlebar_theme(mocker.MagicMock(), "dark")
    apply_impl.assert_called_once()


def test_apply_windows_titlebar_mode_noop_non_windows(monkeypatch, mocker) -> None:
    monkeypatch.setattr("gui.style.IS_WINDOWS", False)
    _apply_windows_titlebar_mode(mocker.MagicMock(), True)


def test_apply_windows_titlebar_mode_on_windows(monkeypatch, mocker) -> None:
    monkeypatch.setattr("gui.style.IS_WINDOWS", True)
    widget = mocker.MagicMock()
    widget.winId.return_value = 99999
    _apply_windows_titlebar_mode(widget, True)


def test_apply_theme_resets_stylesheet(mocker) -> None:
    app = mocker.MagicMock()
    style = mocker.MagicMock()
    app.style.return_value = style
    mocker.patch("gui.style.QApplication.instance", return_value=app)
    titlebar = mocker.patch("gui.style.apply_titlebar_theme")
    root = mocker.MagicMock()

    apply_theme(root, "dark")

    app.setPalette.assert_called_once_with(style.standardPalette())
    app.setStyleSheet.assert_called_once_with("")
    titlebar.assert_called_once_with(root, "dark")
