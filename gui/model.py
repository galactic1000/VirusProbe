"""Model layer for VirusProbe GUI."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QSettings

from common import (
    DEFAULT_REQUESTS_PER_MINUTE,
    DEFAULT_SCAN_WORKERS,
    DEFAULT_UPLOAD_TIMEOUT_MINUTES,
    ResultStatus,
    ScannerConfig,
    ScanResult,
    ScanTargetKind,
    ScannerService,
    THEME_AUTO,
    THEME_DARK,
    THEME_LIGHT,
    UPLOAD_AUTO,
    UPLOAD_MANUAL,
    UPLOAD_NEVER,
    is_valid_api_key,
)


class AppModel:
    _SETTINGS_GROUP = "gui"
    _API_KEY_KEY = "api_key"

    def __init__(self, cache_db: Path) -> None:
        self.cache_db = cache_db
        self.settings = QSettings("VirusProbe", "VirusProbeGUI")
        self.settings.beginGroup(self._SETTINGS_GROUP)

        loaded_api_key = self._api_key_setting()
        self.had_invalid_loaded_api_key = bool(loaded_api_key) and not is_valid_api_key(loaded_api_key)
        self.api_key = loaded_api_key if (loaded_api_key and is_valid_api_key(loaded_api_key)) else None

        self.upload_mode = self._setting("upload_mode", UPLOAD_NEVER, valid=(UPLOAD_NEVER, UPLOAD_MANUAL, UPLOAD_AUTO))
        self.theme_mode = self._setting("theme_mode", THEME_AUTO, valid=(THEME_AUTO, THEME_DARK, THEME_LIGHT))
        self.saved_rpm = self._setting_int("rpm", DEFAULT_REQUESTS_PER_MINUTE, minimum=0)
        self.saved_workers = self._setting_int("workers", DEFAULT_SCAN_WORKERS, minimum=1)
        self.saved_upload_timeout = self._setting_int("upload_timeout", DEFAULT_UPLOAD_TIMEOUT_MINUTES, minimum=0)
        self.default_report_dir = self._setting("default_report_dir", str(Path.home()))

        self._last_results_by_key: dict[tuple[str, str], ScanResult] = {}

    def _setting(self, key: str, default: str, *, valid: tuple[str, ...] | None = None) -> str:
        value = self.settings.value(key, default, str).strip() # type: ignore
        if valid is not None and value not in valid:
            return default
        return value

    def _setting_int(self, key: str, default: int, *, minimum: int) -> int:
        value = self.settings.value(key, default, int)
        return max(minimum, value) # type: ignore

    def _api_key_setting(self) -> str | None:
        value = self.settings.value(self._API_KEY_KEY, "", str).strip()  # type: ignore
        return value or None

    @staticmethod
    def _result_key(result: ScanResult) -> tuple[str, str]:
        value = result.file_hash if result.kind is ScanTargetKind.HASH else result.item
        return result.type, value

    def close(self) -> None:
        self.settings.sync()

    def set_api_key(self, value: str | None) -> None:
        self.api_key = value.strip() if value else None
        if self.api_key:
            self.settings.setValue(self._API_KEY_KEY, self.api_key)
        else:
            self.settings.remove(self._API_KEY_KEY)
        self.settings.sync()

    def set_advanced(self, rpm: int, workers: int, upload_timeout: int, upload_mode: str, theme_mode: str) -> None:
        self.saved_rpm = max(0, int(rpm))
        self.saved_workers = max(1, int(workers))
        self.saved_upload_timeout = max(0, int(upload_timeout))
        self.upload_mode = upload_mode if upload_mode in (UPLOAD_NEVER, UPLOAD_MANUAL, UPLOAD_AUTO) else UPLOAD_NEVER
        self.theme_mode = theme_mode if theme_mode in (THEME_AUTO, THEME_DARK, THEME_LIGHT) else THEME_AUTO

        self.settings.setValue("rpm", self.saved_rpm)
        self.settings.setValue("workers", self.saved_workers)
        self.settings.setValue("upload_timeout", self.saved_upload_timeout)
        self.settings.setValue("upload_mode", self.upload_mode)
        self.settings.setValue("theme_mode", self.theme_mode)
        self.settings.sync()

    def set_default_report_dir(self, path: str) -> None:
        self.default_report_dir = path
        self.settings.setValue("default_report_dir", path)
        self.settings.sync()

    def build_scanner(self, config: ScannerConfig) -> ScannerService:
        return ScannerService(api_key=self.api_key or "", cache_db=self.cache_db, config=config)

    def clear_cache(self) -> int:
        service = ScannerService(api_key=self.api_key or "", cache_db=self.cache_db)
        try:
            service.init_cache()
            return service.clear_cache()
        finally:
            service.close()

    def upsert_result(self, result: ScanResult) -> None:
        self._last_results_by_key[self._result_key(result)] = result

    def get_file_hash(self, file_path: str) -> str:
        result = self._last_results_by_key.get(("file", file_path))
        return result.file_hash if result else ""

    def has_results(self) -> bool:
        return bool(self._last_results_by_key)

    def results_for_keys(self, keys: list[tuple[str, str]]) -> list[ScanResult]:
        return [result for key in keys if (result := self._last_results_by_key.get(key)) is not None]

    def clear_results(self) -> None:
        self._last_results_by_key = {}

    def remove_results(self, keys: list[tuple[str, str]]) -> None:
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
        match result.status:
            case ResultStatus.CANCELLED:
                return "Cancelled"
            case ResultStatus.ERROR:
                return "Error"
            case ResultStatus.UNDETECTED:
                return "Undetected"
        prefix = "Uploaded - " if result.was_uploaded else ""
        return f"{prefix}{result.threat_level}"
