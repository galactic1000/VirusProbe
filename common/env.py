"""Shared .env and API key helpers used by both CLI and GUI."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import dotenv

if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys.executable).resolve().parent
else:
    BASE_DIR = Path(__file__).resolve().parents[1]

DOTENV_PATH: Path = BASE_DIR / ".env"

API_KEY_ENV_VAR = "VT_API_KEY"

RPM_ENV_VAR = "VT_REQUESTS_PER_MINUTE"

WORKERS_ENV_VAR = "VT_WORKERS"

UPLOAD_TIMEOUT_ENV_VAR = "VT_UPLOAD_TIMEOUT"

UPLOAD_MODE_ENV_VAR = "VT_GUI_UPLOAD_MODE"
# Valid values for UPLOAD_MODE_ENV_VAR:
UPLOAD_NEVER = "never"
UPLOAD_MANUAL = "manual"
UPLOAD_AUTO = "auto"

THEME_MODE_ENV_VAR = "VT_GUI_THEME_MODE"
THEME_AUTO = "auto"
THEME_DARK = "dark"
THEME_LIGHT = "light"

dotenv.load_dotenv(DOTENV_PATH, override=False)


def get_api_key() -> str | None:
    value = os.environ.get(API_KEY_ENV_VAR, "").strip()
    return value or None


def save_api_key_to_env(api_key: str) -> None:
    dotenv.set_key(DOTENV_PATH, API_KEY_ENV_VAR, api_key, quote_mode="auto")
    os.environ[API_KEY_ENV_VAR] = api_key


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


def get_upload_timeout_minutes() -> int | None:
    raw = os.environ.get(UPLOAD_TIMEOUT_ENV_VAR, "").strip()
    if raw.isdigit() and int(raw) >= 0:
        return int(raw)
    return None


def save_upload_timeout_minutes_to_env(timeout_minutes: int) -> None:
    dotenv.set_key(DOTENV_PATH, UPLOAD_TIMEOUT_ENV_VAR, str(timeout_minutes), quote_mode="never")
    os.environ[UPLOAD_TIMEOUT_ENV_VAR] = str(timeout_minutes)


def get_upload_mode() -> str:
    raw = os.environ.get(UPLOAD_MODE_ENV_VAR, "").strip().lower()
    if raw in (UPLOAD_MANUAL, UPLOAD_AUTO):
        return raw
    return UPLOAD_NEVER


def save_upload_mode_to_env(mode: str) -> None:
    if mode not in (UPLOAD_NEVER, UPLOAD_MANUAL, UPLOAD_AUTO):
        mode = UPLOAD_NEVER
    dotenv.set_key(DOTENV_PATH, UPLOAD_MODE_ENV_VAR, mode, quote_mode="never")
    os.environ[UPLOAD_MODE_ENV_VAR] = mode


def get_theme_mode() -> str:
    raw = os.environ.get(THEME_MODE_ENV_VAR, "").strip().lower()
    if raw in (THEME_DARK, THEME_LIGHT):
        return raw
    return THEME_AUTO


def save_theme_mode_to_env(mode: str) -> None:
    if mode not in (THEME_AUTO, THEME_DARK, THEME_LIGHT):
        mode = THEME_AUTO
    dotenv.set_key(DOTENV_PATH, THEME_MODE_ENV_VAR, mode, quote_mode="never")
    os.environ[THEME_MODE_ENV_VAR] = mode


def remove_api_key_from_env() -> bool:
    removed = False
    if DOTENV_PATH.exists():
        existing = dotenv.dotenv_values(DOTENV_PATH)
        if API_KEY_ENV_VAR in existing:
            success, _ = dotenv.unset_key(DOTENV_PATH, API_KEY_ENV_VAR)
            if success:
                removed = True
    os.environ.pop(API_KEY_ENV_VAR, None)
    if DOTENV_PATH.exists() and not DOTENV_PATH.read_text(encoding="utf-8").strip():
        DOTENV_PATH.unlink()
    return removed
