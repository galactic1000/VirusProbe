"""Model layer for VirusProbe GUI."""

from __future__ import annotations

import threading
from contextlib import suppress
from pathlib import Path
from typing import Any

import vt

from common import (
    ScannerService,
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
from common.service import DEFAULT_REQUESTS_PER_MINUTE, DEFAULT_SCAN_WORKERS


class AppModel:
    def __init__(self, cache_db: Path) -> None:
        self.cache_db = cache_db
        self.api_key: str | None = get_api_key()
        self.upload_mode: str = get_upload_mode()
        self.saved_rpm = get_requests_per_minute() or DEFAULT_REQUESTS_PER_MINUTE
        self.saved_workers = get_workers() or DEFAULT_SCAN_WORKERS
        self.default_report_dir = str(Path.home())

        self._scanner: ScannerService | None = None
        self._scanner_lock = threading.Lock()
        self._scanner_config: tuple[str, int, int, bool] | None = None
        self._results_lock = threading.Lock()
        self._last_results_by_key: dict[tuple[str, str], dict[str, Any]] = {}

    def close(self) -> None:
        self.reset_scanner()

    def set_api_key(self, value: str | None) -> None:
        self.api_key = value.strip() if value else None
        if self.api_key:
            save_api_key_to_env(self.api_key)
        else:
            remove_api_key_from_env()
        self.reset_scanner()

    def set_advanced(self, rpm: int, workers: int, upload_mode: str) -> None:
        self.saved_rpm = max(0, int(rpm))
        self.saved_workers = max(1, int(workers))
        self.upload_mode = upload_mode
        save_requests_per_minute_to_env(self.saved_rpm)
        save_workers_to_env(self.saved_workers)
        save_upload_mode_to_env(upload_mode)
        self.reset_scanner()

    def reset_scanner(self) -> None:
        with self._scanner_lock:
            if self._scanner is not None:
                with suppress(Exception):
                    self._scanner.close()
            self._scanner = None
            self._scanner_config = None

    def acquire_scanner(self, requests_per_minute: int, workers: int, upload_undetected: bool) -> ScannerService:
        desired = (self.api_key or "", requests_per_minute, workers, upload_undetected)
        with self._scanner_lock:
            if self._scanner is not None and self._scanner_config == desired:
                return self._scanner
            if self._scanner is not None:
                with suppress(Exception):
                    self._scanner.close()
            scanner = ScannerService(
                api_key=self.api_key or "",
                cache_db=self.cache_db,
                requests_per_minute=requests_per_minute,
                max_workers=workers,
                upload_undetected=upload_undetected,
            )
            scanner.init_cache()
            self._scanner = scanner
            self._scanner_config = desired
            return scanner

    def clear_cache(self) -> int:
        if self._scanner is not None:
            return self._scanner.clear_cache()
        service = ScannerService(api_key=self.api_key or "", cache_db=self.cache_db)
        try:
            return service.clear_cache()
        finally:
            with suppress(Exception):
                service.close()

    def merge_results(self, new_results: list[dict[str, Any]]) -> None:
        with self._results_lock:
            for result in new_results:
                key = (str(result.get("type", "")), str(result.get("item", "")))
                self._last_results_by_key[key] = result

    def upsert_result(self, result: dict[str, Any]) -> None:
        with self._results_lock:
            key = (str(result.get("type", "")), str(result.get("item", "")))
            self._last_results_by_key[key] = result

    def has_results(self) -> bool:
        with self._results_lock:
            return bool(self._last_results_by_key)

    def results_snapshot(self) -> list[dict[str, Any]]:
        with self._results_lock:
            return list(self._last_results_by_key.values())

    def clear_results(self) -> None:
        with self._results_lock:
            self._last_results_by_key = {}

    @staticmethod
    def parse_int(raw: str, default: int, minimum: int) -> int:
        try:
            value = int(raw)
        except ValueError:
            return default
        return max(minimum, value)

    @staticmethod
    def result_status(result: dict[str, Any]) -> str:
        if result.get("status") == "cancelled":
            return "Cancelled"
        if result.get("status") == "error":
            return "Error"
        if result.get("threat_level") == "Undetected":
            return "Undetected"
        prefix = "Uploaded - " if result.get("was_uploaded") else ""
        if result.get("malicious", 0) >= 10:
            return f"{prefix}Malicious"
        if result.get("malicious", 0) > 0 or result.get("suspicious", 0) >= 3:
            return f"{prefix}Suspicious"
        return f"{prefix}Clean"

