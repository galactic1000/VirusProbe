"""Upload and analysis-polling helpers for ScannerService."""

from __future__ import annotations

import threading
import time
from pathlib import Path

import aiohttp

_UPLOAD_SIZE_THRESHOLD = 32 * 1024 * 1024  # 32 MB
_UPLOAD_MAX_SIZE = 650 * 1024 * 1024  # 650 MB hard cap
_MIN_POLL_INTERVAL = 15  # seconds between analysis status polls


class ScanCancelledError(Exception):
    """Internal control-flow exception used for cooperative cancellation."""


class UploadFlowMixin:
    def _passes_upload_filter(self, file_path: str) -> bool:
        if self.upload_filter is None:  # type: ignore[attr-defined]
            return True
        return self.upload_filter(file_path)  # type: ignore[attr-defined]

    def _upload_file(self, file_path: str) -> str:
        client = self._get_client()  # type: ignore[attr-defined]
        file_size = Path(file_path).stat().st_size
        if file_size > _UPLOAD_MAX_SIZE:
            raise ValueError("File exceeds VirusTotal upload limit (max 650 MB)")

        with open(file_path, "rb") as f:
            form = aiohttp.FormData()
            form.add_field("file", f, filename=Path(file_path).name)
            if file_size >= _UPLOAD_SIZE_THRESHOLD:
                self._rate_limiter.acquire()  # type: ignore[attr-defined]
                url_response = client.get_json("/files/upload_url")
                upload_url: str = url_response["data"]
                self._rate_limiter.acquire()  # type: ignore[attr-defined]
                response = client.post(upload_url, data=form)  # type: ignore[arg-type]
            else:
                self._rate_limiter.acquire()  # type: ignore[attr-defined]
                response = client.post("/files", data=form)  # type: ignore[arg-type]

        raw = response.json()
        return raw["data"]["id"]

    @staticmethod
    def _sleep_with_cancel(seconds: float, cancel_event: threading.Event | None = None) -> None:
        if cancel_event is None:
            time.sleep(max(0.0, seconds))
            return
        end = time.monotonic() + max(0.0, seconds)
        while True:
            if cancel_event.is_set():
                raise ScanCancelledError()
            remaining = end - time.monotonic()
            if remaining <= 0:
                return
            time.sleep(min(0.25, remaining))

    def _poll_interval_seconds(self) -> int:
        if self._requests_per_minute <= 0:  # type: ignore[attr-defined]
            return _MIN_POLL_INTERVAL
        return max(_MIN_POLL_INTERVAL, int(__import__("math").ceil(60 / self._requests_per_minute)))  # type: ignore[attr-defined]

    def _poll_analysis(self, analysis_id: str, cancel_event: threading.Event | None = None) -> tuple[int, int, int, int]:
        client = self._get_client()  # type: ignore[attr-defined]
        poll_interval = self._poll_interval_seconds()
        while True:
            if cancel_event is not None and cancel_event.is_set():
                raise ScanCancelledError()
            self._rate_limiter.acquire()  # type: ignore[attr-defined]
            raw = client.get_json(f"/analyses/{analysis_id}")
            status = raw.get("data", {}).get("attributes", {}).get("status", "")
            if status == "completed":
                stats = raw["data"]["attributes"]["stats"]
                return (
                    int(stats.get("malicious", 0)),
                    int(stats.get("suspicious", 0)),
                    int(stats.get("harmless", 0)),
                    int(stats.get("undetected", 0)),
                )
            self._sleep_with_cancel(poll_interval, cancel_event=cancel_event)

    def _upload_and_scan(self, file_path: str, file_hash: str, cancel_event: threading.Event | None = None) -> dict:
        try:
            if cancel_event is not None and cancel_event.is_set():
                raise ScanCancelledError()
            analysis_id = self._upload_file(file_path)
            malicious, suspicious, harmless, undetected = self._poll_analysis(analysis_id, cancel_event=cancel_event)
        except ScanCancelledError:
            return self._cancelled_result(file_path, "file", file_hash)  # type: ignore[attr-defined]
        except Exception as exc:
            return self._error_result(file_path, "file", f"Upload failed: {exc}", file_hash)  # type: ignore[attr-defined]

        self._cache.save(file_hash, (malicious, suspicious, harmless, undetected))  # type: ignore[attr-defined]
        return {
            "item": file_path,
            "type": "file",
            "file_hash": file_hash,
            "malicious": malicious,
            "suspicious": suspicious,
            "harmless": harmless,
            "undetected": undetected,
            "threat_level": self.classify_threat(malicious, suspicious),  # type: ignore[attr-defined]
            "status": "ok",
            "message": "Uploaded to VirusTotal and scanned",
            "was_cached": False,
            "was_uploaded": True,
        }
