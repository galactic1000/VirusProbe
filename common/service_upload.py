"""Upload and analysis-polling helpers used by ScannerService."""

from __future__ import annotations

import asyncio
import inspect
import math
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import aiohttp
import vt

from .api_errors import BATCH_FATAL_API_ERROR_CODES
from .rate_limit import AsyncRateLimiter

_UPLOAD_SIZE_THRESHOLD = 32 * 1024 * 1024  # 32 MB
_UPLOAD_MAX_SIZE = 650 * 1024 * 1024  # 650 MB hard cap
_MIN_POLL_INTERVAL = 15  # seconds between analysis status polls

class ScanCancelledError(Exception):
    """Internal control-flow exception used for cooperative cancellation."""


def _is_batch_fatal_upload_error(exc: Exception) -> bool:
    return isinstance(exc, vt.APIError) and exc.code in BATCH_FATAL_API_ERROR_CODES


async def upload_file_async(
    client: Any,
    rate_limiter: AsyncRateLimiter,
    file_path: str,
) -> str:
    file_size = await asyncio.to_thread(lambda: Path(file_path).stat().st_size)
    if file_size > _UPLOAD_MAX_SIZE:
        raise ValueError("File exceeds VirusTotal upload limit (max 650 MB)")

    f = await asyncio.to_thread(open, file_path, "rb")
    try:
        form = aiohttp.FormData()
        form.add_field("file", f, filename=Path(file_path).name)
        if file_size >= _UPLOAD_SIZE_THRESHOLD:
            await rate_limiter.acquire()
            upload_url: str = await client.get_data_async("/files/upload_url")
            await rate_limiter.acquire()
            response = await client.post_async(upload_url, data=form)
        else:
            await rate_limiter.acquire()
            response = await client.post_async("/files", data=form)
        error = await client.get_error_async(response)
        if error:
            raise error
        raw = await response.json_async()
    finally:
        f.close()

    return raw["data"]["id"]


async def sleep_with_cancel_async(seconds: float, cancel_event: threading.Event | None = None) -> None:
    if cancel_event is None:
        await asyncio.sleep(max(0.0, seconds))
        return
    end = time.monotonic() + max(0.0, seconds)
    while True:
        if cancel_event.is_set():
            raise ScanCancelledError()
        remaining = end - time.monotonic()
        if remaining <= 0:
            return
        await asyncio.sleep(min(0.25, remaining))


def poll_interval_seconds(requests_per_minute: int) -> int:
    if requests_per_minute <= 0:
        return _MIN_POLL_INTERVAL
    return max(_MIN_POLL_INTERVAL, int(math.ceil(60 / requests_per_minute)))


async def poll_analysis_async(
    client: Any,
    rate_limiter: AsyncRateLimiter,
    requests_per_minute: int,
    timeout_minutes: int,
    analysis_id: str,
    cancel_event: threading.Event | None = None,
) -> tuple[int, int, int, int]:
    poll_interval = poll_interval_seconds(requests_per_minute)
    deadline = None if timeout_minutes <= 0 else (time.monotonic() + (timeout_minutes * 60))
    while True:
        if cancel_event is not None and cancel_event.is_set():
            raise ScanCancelledError()
        if deadline is not None and time.monotonic() > deadline:
            raise TimeoutError(f"VirusTotal analysis timed out after {timeout_minutes} minute(s)")
        await rate_limiter.acquire()
        raw = await client.get_json_async(f"/analyses/{analysis_id}")
        status = raw.get("data", {}).get("attributes", {}).get("status", "")
        if status == "completed":
            stats = raw["data"]["attributes"]["stats"]
            return (
                int(stats.get("malicious", 0)),
                int(stats.get("suspicious", 0)),
                int(stats.get("harmless", 0)),
                int(stats.get("undetected", 0)),
            )
        await sleep_with_cancel_async(poll_interval, cancel_event=cancel_event)


async def upload_and_scan_async(
    upload_file_fn: Callable[[str], Any],
    poll_analysis_fn: Callable[[str, threading.Event | None], Any],
    cache_save: Callable[[str, tuple[int, int, int, int]], Any],
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
        analysis_id = await upload_file_fn(file_path)
        malicious, suspicious, harmless, undetected = await poll_analysis_fn(analysis_id, cancel_event)
    except ScanCancelledError:
        return cancelled_result(file_path, "file", file_hash)
    except Exception as exc:
        if _is_batch_fatal_upload_error(exc):
            raise
        return error_result(file_path, "file", f"Upload failed: {exc}", file_hash)

    try:
        maybe_awaitable = cache_save(file_hash, (malicious, suspicious, harmless, undetected))
        if inspect.isawaitable(maybe_awaitable):
            await maybe_awaitable
    except Exception:
        pass

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
