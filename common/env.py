"""Shared .env and API key helpers used by both CLI and GUI."""

from __future__ import annotations

import os
from pathlib import Path

import dotenv

DOTENV_PATH: Path = Path(__file__).resolve().parents[1] / ".env"

API_KEY_ENV_VARS: tuple[str, ...] = ("VT_API_KEY", "VIRUSTOTAL_API_KEY")

RPM_ENV_VAR = "VT_REQUESTS_PER_MINUTE"

WORKERS_ENV_VAR = "VT_WORKERS"

dotenv.load_dotenv(DOTENV_PATH, override=False)


def get_api_key() -> str | None:
    for var_name in API_KEY_ENV_VARS:
        value = os.environ.get(var_name, "").strip()
        if value:
            return value
    return None


def save_api_key_to_env(api_key: str) -> None:
    for name in API_KEY_ENV_VARS:
        dotenv.unset_key(DOTENV_PATH, name)
    dotenv.set_key(DOTENV_PATH, "VT_API_KEY", api_key, quote_mode="auto")
    os.environ["VT_API_KEY"] = api_key


def get_requests_per_minute() -> int | None:
    raw = os.environ.get(RPM_ENV_VAR, "").strip()
    if raw.isdigit() or (raw.startswith("-") and raw[1:].isdigit()):
        return max(0, int(raw))
    return None


def save_requests_per_minute_to_env(rpm: int) -> None:
    dotenv.set_key(DOTENV_PATH, RPM_ENV_VAR, str(rpm), quote_mode="never")
    os.environ[RPM_ENV_VAR] = str(rpm)


def get_workers() -> int | None:
    raw = os.environ.get(WORKERS_ENV_VAR, "").strip()
    if raw.isdigit() and int(raw) >= 1:
        return int(raw)
    return None


def save_workers_to_env(workers: int) -> None:
    dotenv.set_key(DOTENV_PATH, WORKERS_ENV_VAR, str(workers), quote_mode="never")
    os.environ[WORKERS_ENV_VAR] = str(workers)


def remove_api_key_from_env() -> bool:
    """Removes the API key from .env and os.environ. Returns True if .env was modified."""
    removed = False
    for name in API_KEY_ENV_VARS:
        success, _ = dotenv.unset_key(DOTENV_PATH, name)
        if success:
            removed = True
    for name in API_KEY_ENV_VARS:
        os.environ.pop(name, None)
    if DOTENV_PATH.exists() and not DOTENV_PATH.read_text(encoding="utf-8").strip():
        DOTENV_PATH.unlink()
    return removed
