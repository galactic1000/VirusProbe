"""Shared .env and API key helpers used by both CLI and GUI."""

from __future__ import annotations

import os
from pathlib import Path

import dotenv

DOTENV_PATH: Path = Path(__file__).resolve().parents[1] / ".env"
API_KEY_ENV_VARS: tuple[str, ...] = ("VT_API_KEY", "VIRUSTOTAL_API_KEY")


def get_api_key() -> str | None:
    dotenv.load_dotenv(DOTENV_PATH, override=False)
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
