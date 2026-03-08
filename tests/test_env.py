from __future__ import annotations

import pytest

from common.env import (
    RPM_ENV_VAR,
    UPLOAD_TIMEOUT_ENV_VAR,
    WORKERS_ENV_VAR,
    get_requests_per_minute,
    get_upload_timeout_minutes,
    get_workers,
)


# ---------------------------------------------------------------------------
# get_requests_per_minute
# ---------------------------------------------------------------------------


def test_get_requests_per_minute_rejects_negative_env(monkeypatch) -> None:
    monkeypatch.setenv(RPM_ENV_VAR, "-5")
    assert get_requests_per_minute() is None


def test_get_requests_per_minute_accepts_zero_env(monkeypatch) -> None:
    monkeypatch.setenv(RPM_ENV_VAR, "0")
    assert get_requests_per_minute() == 0


def test_get_requests_per_minute_accepts_positive_env(monkeypatch) -> None:
    monkeypatch.setenv(RPM_ENV_VAR, "60")
    assert get_requests_per_minute() == 60


def test_get_requests_per_minute_rejects_non_numeric_env(monkeypatch) -> None:
    monkeypatch.setenv(RPM_ENV_VAR, "abc")
    assert get_requests_per_minute() is None


# ---------------------------------------------------------------------------
# get_workers
# ---------------------------------------------------------------------------


def test_get_workers_accepts_valid_env(monkeypatch) -> None:
    monkeypatch.setenv(WORKERS_ENV_VAR, "4")
    assert get_workers() == 4


def test_get_workers_rejects_zero_env(monkeypatch) -> None:
    monkeypatch.setenv(WORKERS_ENV_VAR, "0")
    assert get_workers() is None


def test_get_workers_rejects_negative_env(monkeypatch) -> None:
    monkeypatch.setenv(WORKERS_ENV_VAR, "-1")
    assert get_workers() is None


def test_get_workers_rejects_non_numeric_env(monkeypatch) -> None:
    monkeypatch.setenv(WORKERS_ENV_VAR, "abc")
    assert get_workers() is None


# ---------------------------------------------------------------------------
# get_upload_timeout_minutes
# ---------------------------------------------------------------------------


def test_get_upload_timeout_minutes_accepts_zero_env(monkeypatch) -> None:
    monkeypatch.setenv(UPLOAD_TIMEOUT_ENV_VAR, "0")
    assert get_upload_timeout_minutes() == 0


def test_get_upload_timeout_minutes_accepts_positive_env(monkeypatch) -> None:
    monkeypatch.setenv(UPLOAD_TIMEOUT_ENV_VAR, "20")
    assert get_upload_timeout_minutes() == 20


def test_get_upload_timeout_minutes_rejects_negative_env(monkeypatch) -> None:
    monkeypatch.setenv(UPLOAD_TIMEOUT_ENV_VAR, "-1")
    assert get_upload_timeout_minutes() is None


def test_get_upload_timeout_minutes_rejects_non_numeric_env(monkeypatch) -> None:
    monkeypatch.setenv(UPLOAD_TIMEOUT_ENV_VAR, "abc")
    assert get_upload_timeout_minutes() is None
