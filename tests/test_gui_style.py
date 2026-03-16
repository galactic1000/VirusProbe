from __future__ import annotations

import pytest

from gui.style import (
    _DARK_THEME,
    _LIGHT_THEME,
    _apply_bootstrap_theme,
    _linux_prefers_dark_mode,
    _macos_prefers_dark_mode,
    _system_prefers_dark_mode,
    _windows_prefers_dark_mode,
    _apply_windows_titlebar_mode,
    apply_theme,
    apply_titlebar_theme,
    theme_name,
)


# ---------------------------------------------------------------------------
# theme_name
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode,expected", [
    ("dark", _DARK_THEME),
    ("light", _LIGHT_THEME),
])
def test_theme_name_explicit(mode, expected) -> None:
    assert theme_name(mode) == expected


@pytest.mark.parametrize("dark_returns,expected", [
    (True, _DARK_THEME),
    (False, _LIGHT_THEME),
])
def test_theme_name_auto(mocker, dark_returns, expected) -> None:
    mocker.patch("gui.style._system_prefers_dark_mode", return_value=dark_returns)
    assert theme_name("auto") == expected


# ---------------------------------------------------------------------------
# _system_prefers_dark_mode
# ---------------------------------------------------------------------------


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


# ---------------------------------------------------------------------------
# _windows_prefers_dark_mode
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("registry_value,expected", [
    (0, True),   # 0 = dark
    (1, False),  # 1 = light
])
def test_windows_dark_mode(mocker, registry_value, expected) -> None:
    mocker.patch("winreg.OpenKey", return_value=mocker.MagicMock())
    mocker.patch("winreg.QueryValueEx", return_value=(registry_value, None))
    assert _windows_prefers_dark_mode() is expected


def test_windows_dark_mode_exception(mocker) -> None:
    mocker.patch("winreg.OpenKey", side_effect=OSError("no key"))
    assert _windows_prefers_dark_mode() is False


# ---------------------------------------------------------------------------
# _macos_prefers_dark_mode
# ---------------------------------------------------------------------------


def test_macos_dark_mode_true(mocker) -> None:
    mocker.patch("gui.style.subprocess.run", return_value=mocker.MagicMock(returncode=0, stdout="Dark\n"))
    assert _macos_prefers_dark_mode() is True


def test_macos_dark_mode_false_returncode(mocker) -> None:
    mocker.patch("gui.style.subprocess.run", return_value=mocker.MagicMock(returncode=1))
    assert _macos_prefers_dark_mode() is False


def test_macos_dark_mode_exception(mocker) -> None:
    mocker.patch("gui.style.subprocess.run", side_effect=FileNotFoundError)
    assert _macos_prefers_dark_mode() is False


# ---------------------------------------------------------------------------
# _linux_prefers_dark_mode
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("stdout,expected", [
    ("({'': ('(uint32 1)',)},)", True),   # value 1 = dark
    ("({'': ('(uint32 2)',)},)", False),  # value 2 = light
    ("nothing useful", False),           # no regex match
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


# ---------------------------------------------------------------------------
# _apply_bootstrap_theme
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("mode,expected", [
    ("dark", True),
    ("light", False),
])
def test_apply_bootstrap_theme(mocker, mode, expected) -> None:
    mocker.patch("gui.style.Style.get_instance", return_value=mocker.MagicMock())
    assert _apply_bootstrap_theme(mode) is expected


def test_apply_bootstrap_theme_exception(mocker) -> None:
    mocker.patch("gui.style.Style.get_instance", return_value=mocker.MagicMock(**{"theme_use.side_effect": Exception("no style")}))
    assert _apply_bootstrap_theme("dark") is False


# ---------------------------------------------------------------------------
# apply_titlebar_theme
# ---------------------------------------------------------------------------


def test_apply_titlebar_theme_no_instance(mocker) -> None:
    mocker.patch("gui.style.Style.get_instance", return_value=None)
    apply_titlebar_theme(mocker.MagicMock())  # early return, no error


def test_apply_titlebar_theme_with_dark_theme(monkeypatch, mocker) -> None:
    monkeypatch.setattr("gui.style.IS_WINDOWS", False)
    mock_theme = mocker.MagicMock()
    mock_theme.name = _DARK_THEME
    mocker.patch("gui.style.Style.get_instance", return_value=mocker.MagicMock(theme=mock_theme))
    apply_titlebar_theme(mocker.MagicMock())  # should not raise


# ---------------------------------------------------------------------------
# _apply_windows_titlebar_mode
# ---------------------------------------------------------------------------


def test_apply_windows_titlebar_mode_noop_non_windows(monkeypatch, mocker) -> None:
    monkeypatch.setattr("gui.style.IS_WINDOWS", False)
    root = mocker.MagicMock()
    _apply_windows_titlebar_mode(root, True)
    root.update_idletasks.assert_not_called()


def test_apply_windows_titlebar_mode_on_windows(monkeypatch, mocker) -> None:
    monkeypatch.setattr("gui.style.IS_WINDOWS", True)
    root = mocker.MagicMock()
    root.winfo_id.return_value = 99999
    _apply_windows_titlebar_mode(root, True)  # ctypes may fail, all wrapped in try/except


def test_apply_windows_titlebar_mode_exception_swallowed(monkeypatch, mocker) -> None:
    monkeypatch.setattr("gui.style.IS_WINDOWS", True)
    root = mocker.MagicMock()
    root.update_idletasks.side_effect = RuntimeError("no display")
    _apply_windows_titlebar_mode(root, True)  # must not raise


# ---------------------------------------------------------------------------
# apply_theme
# ---------------------------------------------------------------------------


def test_apply_theme_calls_bootstrap_and_titlebar(mocker) -> None:
    mock_bootstrap = mocker.patch("gui.style._apply_bootstrap_theme", return_value=True)
    mock_titlebar = mocker.patch("gui.style._apply_windows_titlebar_mode")
    root = mocker.MagicMock()
    apply_theme(root, "dark")
    mock_bootstrap.assert_called_once_with("dark")
    mock_titlebar.assert_called_once_with(root, True)
