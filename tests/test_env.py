from __future__ import annotations

from common.env import RPM_ENV_VAR, get_requests_per_minute


def test_get_requests_per_minute_rejects_negative_env(monkeypatch) -> None:
    monkeypatch.setenv(RPM_ENV_VAR, "-5")
    assert get_requests_per_minute() is None


def test_get_requests_per_minute_accepts_zero_env(monkeypatch) -> None:
    monkeypatch.setenv(RPM_ENV_VAR, "0")
    assert get_requests_per_minute() == 0
