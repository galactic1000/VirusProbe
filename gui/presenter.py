"""Presenter layer for VirusProbe GUI."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from common import UPLOAD_AUTO, UPLOAD_MANUAL


def masked_api_key_text(api_key: str | None) -> str:
    if not api_key:
        return "API Key: Not Set"
    masked = f"{api_key[:4]}...{api_key[-4:]}" if len(api_key) >= 8 else "set"
    return f"API Key: {masked}"


def upload_indicator_text(upload_mode: str) -> str:
    if upload_mode == UPLOAD_AUTO:
        return "[Upload: auto]"
    elif upload_mode == UPLOAD_MANUAL:
        return "[Upload: manual]"
    return ""


class AppPresenter:
    def __init__(self, view: Any) -> None:
        self.view = view

    def set_api_key_text(self, text: str) -> None:
        self.view.api_status_var.set(text)

    def set_upload_indicator_text(self, text: str) -> None:
        self.view.upload_indicator_var.set(text)

    def set_queued_count(self, count: int) -> None:
        self.view.progress_var.set(f"Items queued: {count}")

    def set_canceling(self, text: str) -> None:
        self.view.scan_btn.configure(state="disabled")
        self.view.progress_var.set(text)

    def begin_busy(self, cancel_handler: Callable[[], None]) -> None:
        self.view.set_controls_enabled(False)
        self.view.set_scan_button_cancel(cancel_handler)

    def restore_idle(self, on_scan: Callable[[], None]) -> None:
        self.view.set_controls_enabled(True)
        self.view.set_scan_button_scan(on_scan)
        self.view.set_progress(0, 0)

    def update_upload_action_visibility(self, upload_mode: str, has_uploadable: bool, busy: bool) -> None:
        should_show = upload_mode == UPLOAD_MANUAL
        can_upload = should_show and has_uploadable and not busy
        self.view.show_upload_button(should_show)
        if should_show:
            self.view.set_upload_button_enabled(can_upload)
