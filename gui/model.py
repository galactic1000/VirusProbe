"""Model layer for VirusProbe GUI."""

from __future__ import annotations

import asyncio
import threading
from contextlib import suppress
from pathlib import Path

from common import (
    DEFAULT_REQUESTS_PER_MINUTE,
    DEFAULT_SCAN_WORKERS,
    DEFAULT_UPLOAD_TIMEOUT_MINUTES,
    ResultStatus,
    ScannerConfig,
    ScanResult,
    ScanTargetKind,
    ScannerService,
    ThreatLevel,
    THEME_AUTO,
    THEME_DARK,
    THEME_LIGHT,
    get_api_key,
    get_requests_per_minute,
    get_theme_mode,
    get_upload_timeout_minutes,
    get_upload_mode,
    get_workers,
    is_valid_api_key,
    remove_api_key_from_env,
    save_api_key_to_env,
    save_requests_per_minute_to_env,
    save_theme_mode_to_env,
    save_upload_timeout_minutes_to_env,
    save_upload_mode_to_env,
    save_workers_to_env,
)


class AppModel:
    def __init__(self, cache_db: Path) -> None:
        self.cache_db = cache_db
        loaded_api_key = get_api_key()
        self.had_invalid_loaded_api_key = bool(loaded_api_key) and not is_valid_api_key(loaded_api_key)
        self.api_key = loaded_api_key if (loaded_api_key and is_valid_api_key(loaded_api_key)) else None
        self.upload_mode = get_upload_mode()
        self.theme_mode = get_theme_mode() or THEME_AUTO
        self.saved_rpm = v if (v := get_requests_per_minute()) is not None else DEFAULT_REQUESTS_PER_MINUTE
        self.saved_workers = v if (v := get_workers()) is not None else DEFAULT_SCAN_WORKERS
        self.saved_upload_timeout = v if (v := get_upload_timeout_minutes()) is not None else DEFAULT_UPLOAD_TIMEOUT_MINUTES
        self.default_report_dir = str(Path.home())

        self._scanner: ScannerService | None = None
        self._scanner_lock = threading.Lock()
        self._scanner_init_lock = asyncio.Lock()
        self._scanner_config: tuple[str, ScannerConfig] | None = None
        self._results_lock = threading.Lock()
        self._last_results_by_key: dict[tuple[str, str], ScanResult] = {}

    @staticmethod
    def _result_key(result: ScanResult) -> tuple[str, str]:
        value = result.file_hash if result.kind is ScanTargetKind.HASH else result.item
        return result.type, value

    def close(self) -> None:
        self.reset_scanner()

    def set_api_key(self, value: str | None) -> None:
        self.api_key = value.strip() if value else None
        if self.api_key:
            save_api_key_to_env(self.api_key)
        else:
            remove_api_key_from_env()
        self.reset_scanner()

    def set_advanced(self, rpm: int, workers: int, upload_timeout: int, upload_mode: str, theme_mode: str) -> None:
        self.saved_rpm = max(0, int(rpm))
        self.saved_workers = max(1, int(workers))
        self.saved_upload_timeout = max(0, int(upload_timeout))
        self.upload_mode = upload_mode
        self.theme_mode = theme_mode if theme_mode in (THEME_AUTO, THEME_DARK, THEME_LIGHT) else THEME_AUTO
        save_requests_per_minute_to_env(self.saved_rpm)
        save_workers_to_env(self.saved_workers)
        save_upload_timeout_minutes_to_env(self.saved_upload_timeout)
        save_upload_mode_to_env(upload_mode)
        save_theme_mode_to_env(self.theme_mode)
        self.invalidate_scanner_config()

    def reset_scanner(self) -> None:
        with self._scanner_lock:
            if self._scanner is not None:
                with suppress(Exception):
                    self._scanner.close()
            self._scanner = None
            self._scanner_config = None

    def invalidate_scanner_config(self) -> None:
        with self._scanner_lock:
            self._scanner_config = None

    async def acquire_scanner_async(self, config: ScannerConfig) -> ScannerService:
        desired = (self.api_key or "", config)
        with self._scanner_lock:
            if self._scanner is not None and self._scanner_config == desired:
                return self._scanner
        async with self._scanner_init_lock:
            with self._scanner_lock:
                if self._scanner is not None and self._scanner_config == desired:
                    return self._scanner
                if self._scanner is not None:
                    with suppress(Exception):
                        self._scanner.close()
                    self._scanner = None
                    self._scanner_config = None
                scanner = ScannerService(
                    api_key=self.api_key or "",
                    cache_db=self.cache_db,
                    config=config,
                )
            try:
                await scanner.init_cache_async()
            except Exception:
                with suppress(Exception):
                    scanner.close()
                raise
            with self._scanner_lock:
                self._scanner = scanner
                self._scanner_config = desired
                return scanner

    async def clear_cache_async(self) -> int:
        with self._scanner_lock:
            scanner = self._scanner
        if scanner is not None:
            return await scanner.clear_cache_async()
        service = ScannerService(api_key=self.api_key or "", cache_db=self.cache_db)
        try:
            await service.init_cache_async()
            return await service.clear_cache_async()
        finally:
            with suppress(Exception):
                await asyncio.get_running_loop().run_in_executor(None, service.close)

    def upsert_result(self, result: ScanResult) -> None:
        with self._results_lock:
            self._last_results_by_key[self._result_key(result)] = result

    def get_file_hash(self, file_path: str) -> str:
        with self._results_lock:
            result = self._last_results_by_key.get(("file", file_path))
            return result.file_hash if result else ""

    def has_results(self) -> bool:
        with self._results_lock:
            return bool(self._last_results_by_key)

    def results_snapshot(self) -> list[ScanResult]:
        with self._results_lock:
            return list(self._last_results_by_key.values())

    def results_for_keys(self, keys: list[tuple[str, str]]) -> list[ScanResult]:
        with self._results_lock:
            return [result for key in keys if (result := self._last_results_by_key.get(key)) is not None]

    def clear_results(self) -> None:
        with self._results_lock:
            self._last_results_by_key = {}

    def remove_results(self, keys: list[tuple[str, str]]) -> None:
        with self._results_lock:
            for key in keys:
                self._last_results_by_key.pop(key, None)

    @staticmethod
    def parse_int(raw: str, default: int, minimum: int) -> int:
        try:
            value = int(raw)
        except ValueError:
            return default
        return max(minimum, value)

    @staticmethod
    def result_status(result: ScanResult) -> str:
        if result.status == ResultStatus.CANCELLED:
            return "Cancelled"
        if result.status == ResultStatus.ERROR:
            return "Error"
        if result.threat_level == ThreatLevel.UNDETECTED:
            return "Undetected"
        prefix = "Uploaded - " if result.was_uploaded else ""
        return f"{prefix}{result.threat_level}"
