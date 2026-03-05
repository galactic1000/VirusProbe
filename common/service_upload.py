"""Upload and analysis-polling helpers used by ScannerService."""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import aiohttp

_UPLOAD_SIZE_THRESHOLD = 32 * 1024 * 1024  # 32 MB
_UPLOAD_MAX_SIZE = 650 * 1024 * 1024  # 650 MB hard cap
_MIN_POLL_INTERVAL = 15  # seconds between analysis status polls


class ScanCancelledError(Exception):
    """Internal control-flow exception used for cooperative cancellation."""


def upload_file(
    get_client: Callable[[], Any],
    rate_limit_acquire: Callable[[], None],
    file_path: str,
) -> str:
    client = get_client()
    file_size = Path(file_path).stat().st_size
    if file_size > _UPLOAD_MAX_SIZE:
        raise ValueError("File exceeds VirusTotal upload limit (max 650 MB)")

    with open(file_path, "rb") as f:
        form = aiohttp.FormData()
        form.add_field("file", f, filename=Path(file_path).name)
        if file_size >= _UPLOAD_SIZE_THRESHOLD:
            rate_limit_acquire()
            url_response = client.get_json("/files/upload_url")
            upload_url: str = url_response["data"]
            rate_limit_acquire()
            response = client.post(upload_url, data=form)  # type: ignore[arg-type]
        else:
            rate_limit_acquire()
            response = client.post("/files", data=form)  # type: ignore[arg-type]

    raw = response.json()
    return raw["data"]["id"]


def sleep_with_cancel(seconds: float, cancel_event: threading.Event | None = None) -> None:
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


def poll_interval_seconds(requests_per_minute: int) -> int:
    if requests_per_minute <= 0:
        return _MIN_POLL_INTERVAL
    return max(_MIN_POLL_INTERVAL, int(math.ceil(60 / requests_per_minute)))


def poll_analysis(
    get_client: Callable[[], Any],
    rate_limit_acquire: Callable[[], None],
    requests_per_minute: int,
    analysis_id: str,
    cancel_event: threading.Event | None = None,
) -> tuple[int, int, int, int]:
    client = get_client()
    poll_interval = poll_interval_seconds(requests_per_minute)
    while True:
        if cancel_event is not None and cancel_event.is_set():
            raise ScanCancelledError()
        rate_limit_acquire()
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
        sleep_with_cancel(poll_interval, cancel_event=cancel_event)


def upload_and_scan(
    upload_file_fn: Callable[[str], str],
    poll_analysis_fn: Callable[[str, threading.Event | None], tuple[int, int, int, int]],
    cache_save: Callable[[str, tuple[int, int, int, int]], None],
    classify_threat: Callable[[int, int], str],
    error_result: Callable[[str, str, str, str], dict[str, Any]],
    cancelled_result: Callable[[str, str, str], dict[str, Any]],
    file_path: str,
    file_hash: str,
    cancel_event: threading.Event | None = None,
) -> dict[str, Any]:
    try:
        if cancel_event is not None and cancel_event.is_set():
            raise ScanCancelledError()
        analysis_id = upload_file_fn(file_path)
        malicious, suspicious, harmless, undetected = poll_analysis_fn(analysis_id, cancel_event)
    except ScanCancelledError:
        return cancelled_result(file_path, "file", file_hash)
    except Exception as exc:
        return error_result(file_path, "file", f"Upload failed: {exc}", file_hash)

    cache_save(file_hash, (malicious, suspicious, harmless, undetected))
    return {
        "item": file_path,
        "type": "file",
        "file_hash": file_hash,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "threat_level": classify_threat(malicious, suspicious),
        "status": "ok",
        "message": "Uploaded to VirusTotal and scanned",
        "was_cached": False,
        "was_uploaded": True,
    }
