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
UPLOAD_NEVER = "never"
UPLOAD_MANUAL = "manual"
UPLOAD_AUTO = "auto"

THEME_MODE_ENV_VAR = "VT_GUI_THEME_MODE"
THEME_AUTO = "auto"
THEME_DARK = "dark"
THEME_LIGHT = "light"

dotenv.load_dotenv(DOTENV_PATH, override=False)


_VT_API_KEY_LENGTH = 64
HEX_CHARS: frozenset[str] = frozenset("0123456789abcdefABCDEF")


def is_valid_api_key(key: str) -> bool:
    return len(key) == _VT_API_KEY_LENGTH and all(c in HEX_CHARS for c in key)


def _get_int_env(var: str, minimum: int = 0) -> int | None:
    raw = os.environ.get(var, "").strip()
    if raw.isdecimal() and (n := int(raw)) >= minimum:
        return n
    return None


def _get_enum_env(var: str, valid: tuple[str, ...], default: str) -> str:
    raw = os.environ.get(var, "").strip().lower()
    return raw if raw in valid else default


def _save_env(var: str, value: str, *, quote_mode: str = "never") -> None:
    dotenv.set_key(DOTENV_PATH, var, value, quote_mode=quote_mode)
    os.environ[var] = value


def get_api_key() -> str | None:
    value = os.environ.get(API_KEY_ENV_VAR, "").strip()
    return value or None


def save_api_key_to_env(api_key: str) -> None:
    _save_env(API_KEY_ENV_VAR, api_key, quote_mode="auto")


def get_requests_per_minute() -> int | None:
    return _get_int_env(RPM_ENV_VAR)


def save_requests_per_minute_to_env(rpm: int) -> None:
    _save_env(RPM_ENV_VAR, str(rpm))


def get_workers() -> int | None:
    return _get_int_env(WORKERS_ENV_VAR, minimum=1)


def save_workers_to_env(workers: int) -> None:
    _save_env(WORKERS_ENV_VAR, str(workers))


def get_upload_timeout_minutes() -> int | None:
    return _get_int_env(UPLOAD_TIMEOUT_ENV_VAR)


def save_upload_timeout_minutes_to_env(timeout_minutes: int) -> None:
    _save_env(UPLOAD_TIMEOUT_ENV_VAR, str(timeout_minutes))


def get_upload_mode() -> str:
    return _get_enum_env(UPLOAD_MODE_ENV_VAR, (UPLOAD_MANUAL, UPLOAD_AUTO), UPLOAD_NEVER)


def save_upload_mode_to_env(mode: str) -> None:
    if mode not in (UPLOAD_NEVER, UPLOAD_MANUAL, UPLOAD_AUTO):
        mode = UPLOAD_NEVER
    _save_env(UPLOAD_MODE_ENV_VAR, mode)


def get_theme_mode() -> str:
    return _get_enum_env(THEME_MODE_ENV_VAR, (THEME_DARK, THEME_LIGHT), THEME_AUTO)


def save_theme_mode_to_env(mode: str) -> None:
    if mode not in (THEME_AUTO, THEME_DARK, THEME_LIGHT):
        mode = THEME_AUTO
    _save_env(THEME_MODE_ENV_VAR, mode)


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
