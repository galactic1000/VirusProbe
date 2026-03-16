from __future__ import annotations

import os

import pytest

from common.env import (
    API_KEY_ENV_VAR,
    RPM_ENV_VAR,
    THEME_MODE_ENV_VAR,
    UPLOAD_MODE_ENV_VAR,
    UPLOAD_TIMEOUT_ENV_VAR,
    WORKERS_ENV_VAR,
    get_requests_per_minute,
    get_theme_mode,
    get_upload_mode,
    get_upload_timeout_minutes,
    get_workers,
    remove_api_key_from_env,
    save_requests_per_minute_to_env,
    save_theme_mode_to_env,
    save_upload_mode_to_env,
    save_upload_timeout_minutes_to_env,
    save_workers_to_env,
)


# ---------------------------------------------------------------------------
# get_requests_per_minute
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value,expected", [
    ("-5", None),
    ("0", 0),
    ("60", 60),
    ("abc", None),
])
def test_rpm(monkeypatch, value: str, expected: int | None) -> None:
    monkeypatch.setenv(RPM_ENV_VAR, value)
    assert get_requests_per_minute() == expected


# ---------------------------------------------------------------------------
# get_workers
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value,expected", [
    ("4", 4),
    ("0", None),
    ("-1", None),
    ("abc", None),
])
def test_workers(monkeypatch, value: str, expected: int | None) -> None:
    monkeypatch.setenv(WORKERS_ENV_VAR, value)
    assert get_workers() == expected


# ---------------------------------------------------------------------------
# get_upload_timeout_minutes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value,expected", [
    ("0", 0),
    ("20", 20),
    ("-1", None),
    ("abc", None),
])
def test_upload_timeout(monkeypatch, value: str, expected: int | None) -> None:
    monkeypatch.setenv(UPLOAD_TIMEOUT_ENV_VAR, value)
    assert get_upload_timeout_minutes() == expected


# ---------------------------------------------------------------------------
# get_upload_mode / get_theme_mode
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("value,expected", [
    ("manual", "manual"),
    ("auto", "auto"),
    ("never", "never"),
    ("invalid", "never"),
    ("", "never"),
])
def test_get_upload_mode(monkeypatch, value: str, expected: str) -> None:
    monkeypatch.setenv(UPLOAD_MODE_ENV_VAR, value)
    assert get_upload_mode() == expected


@pytest.mark.parametrize("value,expected", [
    ("dark", "dark"),
    ("light", "light"),
    ("auto", "auto"),
    ("invalid", "auto"),
    ("", "auto"),
])
def test_get_theme_mode(monkeypatch, value: str, expected: str) -> None:
    monkeypatch.setenv(THEME_MODE_ENV_VAR, value)
    assert get_theme_mode() == expected


# ---------------------------------------------------------------------------
# save_* functions
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fn,var,value,expected", [
    (save_requests_per_minute_to_env, RPM_ENV_VAR, 60, "60"),
    (save_workers_to_env, WORKERS_ENV_VAR, 4, "4"),
    (save_upload_timeout_minutes_to_env, UPLOAD_TIMEOUT_ENV_VAR, 20, "20"),
])
def test_save_numeric_env(mocker, monkeypatch, fn, var: str, value: int, expected: str) -> None:
    mocker.patch("common.env.dotenv.set_key")
    monkeypatch.delenv(var, raising=False)
    fn(value)
    assert os.environ.get(var) == expected


@pytest.mark.parametrize("mode,expected", [
    ("never", "never"),
    ("manual", "manual"),
    ("auto", "auto"),
    ("invalid", "never"),
])
def test_save_upload_mode(mocker, monkeypatch, mode: str, expected: str) -> None:
    mocker.patch("common.env.dotenv.set_key")
    monkeypatch.delenv(UPLOAD_MODE_ENV_VAR, raising=False)
    save_upload_mode_to_env(mode)
    assert os.environ.get(UPLOAD_MODE_ENV_VAR) == expected


@pytest.mark.parametrize("mode,expected", [
    ("auto", "auto"),
    ("dark", "dark"),
    ("light", "light"),
    ("invalid", "auto"),
])
def test_save_theme_mode(mocker, monkeypatch, mode: str, expected: str) -> None:
    mocker.patch("common.env.dotenv.set_key")
    monkeypatch.delenv(THEME_MODE_ENV_VAR, raising=False)
    save_theme_mode_to_env(mode)
    assert os.environ.get(THEME_MODE_ENV_VAR) == expected


# ---------------------------------------------------------------------------
# remove_api_key_from_env
# ---------------------------------------------------------------------------


def test_remove_api_key_no_file(monkeypatch, tmp_path) -> None:
    monkeypatch.setattr("common.env.DOTENV_PATH", tmp_path / ".env")
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    assert remove_api_key_from_env() is False


def test_remove_api_key_absent_from_file(monkeypatch, tmp_path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("VT_OTHER=value\n", encoding="utf-8")
    monkeypatch.setattr("common.env.DOTENV_PATH", env_file)
    monkeypatch.delenv(API_KEY_ENV_VAR, raising=False)
    assert remove_api_key_from_env() is False


def test_remove_api_key_success(monkeypatch, tmp_path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(f"{API_KEY_ENV_VAR}={'a' * 64}\nVT_OTHER=value\n", encoding="utf-8")
    monkeypatch.setattr("common.env.DOTENV_PATH", env_file)
    monkeypatch.setenv(API_KEY_ENV_VAR, "a" * 64)
    assert remove_api_key_from_env() is True
    assert API_KEY_ENV_VAR not in os.environ


def test_remove_api_key_deletes_empty_file(monkeypatch, tmp_path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(f"{API_KEY_ENV_VAR}={'a' * 64}\n", encoding="utf-8")
    monkeypatch.setattr("common.env.DOTENV_PATH", env_file)
    monkeypatch.setenv(API_KEY_ENV_VAR, "a" * 64)
    remove_api_key_from_env()
    assert not env_file.exists()
