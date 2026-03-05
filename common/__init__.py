"""Shared scanning backend for CLI and GUI."""

from .env import (
    UPLOAD_AUTO,
    UPLOAD_MANUAL,
    UPLOAD_NEVER,
    get_api_key,
    get_requests_per_minute,
    get_upload_mode,
    get_workers,
    remove_api_key_from_env,
    save_api_key_to_env,
    save_requests_per_minute_to_env,
    save_upload_mode_to_env,
    save_workers_to_env,
)
from .reporting import build_summary, write_report
from .service import ScannerService

__all__ = [
    "ScannerService",
    "build_summary",
    "write_report",
    "get_api_key",
    "save_api_key_to_env",
    "remove_api_key_from_env",
    "get_requests_per_minute",
    "save_requests_per_minute_to_env",
    "get_workers",
    "save_workers_to_env",
    "get_upload_mode",
    "save_upload_mode_to_env",
    "UPLOAD_NEVER",
    "UPLOAD_MANUAL",
    "UPLOAD_AUTO",
]
