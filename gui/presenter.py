"""Small text-formatting helpers for the GUI."""

from __future__ import annotations

from common import UPLOAD_AUTO, UPLOAD_MANUAL


def masked_api_key_text(api_key: str | None) -> str:
    if not api_key:
        return "API Key: Not Set"
    masked = f"{api_key[:4]}...{api_key[-4:]}" if len(api_key) >= 8 else "set"
    return f"API Key: {masked}"


def upload_indicator_text(upload_mode: str) -> str:
    if upload_mode == UPLOAD_AUTO:
        return "[Upload: auto]"
    if upload_mode == UPLOAD_MANUAL:
        return "[Upload: manual]"
    return ""
