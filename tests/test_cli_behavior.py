from __future__ import annotations

import sys
from types import SimpleNamespace

import pytest

import cli.app as cli_app


class FakeService:
    clear_cache_called = 0

    def __init__(self, *args, **kwargs) -> None:
        self.closed = False

    def init_cache(self) -> None:
        return None

    def clear_cache(self) -> int:
        type(self).clear_cache_called += 1
        return 3

    def scan_directory(self, *args, **kwargs):
        return []

    def scan_files(self, *args, **kwargs):
        return []

    def scan_hashes(self, *args, **kwargs):
        return []

    def close(self) -> None:
        self.closed = True


def _run_main(monkeypatch, argv: list[str]) -> None:
    monkeypatch.setattr(sys, "argv", argv)
    cli_app.main()


def test_main_errors_when_recursive_without_directory(monkeypatch) -> None:
    monkeypatch.setattr(cli_app, "get_api_key", lambda: "k")
    with pytest.raises(SystemExit):
        _run_main(monkeypatch, ["cli.py", "-r", "-s", "a" * 64])


def test_main_errors_when_directory_and_files_used_together(monkeypatch) -> None:
    monkeypatch.setattr(cli_app, "get_api_key", lambda: "k")
    with pytest.raises(SystemExit):
        _run_main(monkeypatch, ["cli.py", "-d", ".", "-f", "a.bin"])


def test_main_errors_when_api_key_missing(monkeypatch) -> None:
    monkeypatch.setattr(cli_app, "get_api_key", lambda: None)
    with pytest.raises(SystemExit):
        _run_main(monkeypatch, ["cli.py", "-s", "a" * 64])


def test_save_api_key_action_only(monkeypatch) -> None:
    calls: dict[str, str | None] = {"saved": None}

    def fake_save(value: str) -> None:
        calls["saved"] = value

    monkeypatch.setattr(cli_app, "save_api_key_to_env", fake_save)
    monkeypatch.setattr(cli_app, "remove_api_key_from_env", lambda: False)
    monkeypatch.setattr(cli_app, "get_api_key", lambda: "k")

    _run_main(monkeypatch, ["cli.py", "--api-key", "abc", "--save-api-key"])
    assert calls["saved"] == "abc"


def test_clear_cache_action_only(monkeypatch) -> None:
    FakeService.clear_cache_called = 0
    monkeypatch.setattr(cli_app, "ScannerService", FakeService)
    monkeypatch.setattr(cli_app, "get_api_key", lambda: "k")

    _run_main(monkeypatch, ["cli.py", "--clear-cache"])
    assert FakeService.clear_cache_called == 1


def test_invalid_recursive_input_does_not_run_admin_actions(monkeypatch) -> None:
    calls: dict[str, str | None] = {"saved": None}

    monkeypatch.setattr(cli_app, "get_api_key", lambda: "k")
    monkeypatch.setattr(cli_app, "save_api_key_to_env", lambda value: calls.__setitem__("saved", value))

    with pytest.raises(SystemExit):
        _run_main(monkeypatch, ["cli.py", "--api-key", "abc", "--save-api-key", "-r", "-s", "a" * 64])

    assert calls["saved"] is None


def test_invalid_upload_filter_input_does_not_clear_cache(monkeypatch) -> None:
    FakeService.clear_cache_called = 0
    monkeypatch.setattr(cli_app, "ScannerService", FakeService)
    monkeypatch.setattr(cli_app, "get_api_key", lambda: "k")

    with pytest.raises(SystemExit):
        _run_main(monkeypatch, ["cli.py", "--clear-cache", "--upload-filter", "*.exe", "-s", "a" * 64])

    assert FakeService.clear_cache_called == 0


def test_filter_existing_files_returns_only_real_files(tmp_path) -> None:
    good = tmp_path / "good.bin"
    good.write_bytes(b"x")
    missing = tmp_path / "missing.bin"
    folder = tmp_path / "folder"
    folder.mkdir()

    valid, warnings = cli_app._filter_existing_files([str(good), str(missing), str(folder)])
    assert valid == [str(good)]
    assert warnings == [
        f"Skipping missing file: {missing}",
        f"Skipping non-file path: {folder}",
    ]


def test_upload_filter_path_glob_matches_resolved_absolute_path(tmp_path, monkeypatch) -> None:
    root = tmp_path / "root"
    target_dir = root / "samples"
    target_dir.mkdir(parents=True)
    file_path = target_dir / "x.dll"
    file_path.write_bytes(b"x")
    monkeypatch.chdir(root)

    # Path globs are matched against resolved absolute path values.
    matcher = cli_app._build_upload_filter(["*/samples/*.dll"])
    assert matcher(str(file_path)) is True


def test_upload_filter_absolute_path_glob_matches_absolute_path(tmp_path) -> None:
    target_dir = tmp_path / "absdir"
    target_dir.mkdir(parents=True)
    file_path = target_dir / "y.dll"
    file_path.write_bytes(b"x")

    pattern = str(target_dir).replace("\\", "/") + "/*.dll"
    matcher = cli_app._build_upload_filter([pattern])
    assert matcher(str(file_path)) is True


def test_main_exits_1_when_error_results(monkeypatch) -> None:
    class ErrorService(FakeService):
        def scan_hashes(self, *args, **kwargs):
            return [{"threat_level": "Error", "status": "error", "message": "API failure"}]

    monkeypatch.setattr(cli_app, "ScannerService", ErrorService)
    monkeypatch.setattr(cli_app, "get_api_key", lambda: "k")
    monkeypatch.setattr(cli_app, "print_banner", lambda: None)
    monkeypatch.setattr(cli_app, "print_result", lambda *a, **kw: None)
    monkeypatch.setattr(cli_app, "print_scan_summary", lambda *a: None)

    with pytest.raises(SystemExit) as exc_info:
        _run_main(monkeypatch, ["cli.py", "-s", "a" * 64])
    assert exc_info.value.code == 1


def test_main_exits_0_when_malicious_results(monkeypatch) -> None:
    class MaliciousService(FakeService):
        def scan_hashes(self, *args, **kwargs):
            return [{"threat_level": "Malicious", "status": "ok"}]

    monkeypatch.setattr(cli_app, "ScannerService", MaliciousService)
    monkeypatch.setattr(cli_app, "get_api_key", lambda: "k")
    monkeypatch.setattr(cli_app, "print_banner", lambda: None)
    monkeypatch.setattr(cli_app, "print_result", lambda *a, **kw: None)
    monkeypatch.setattr(cli_app, "print_scan_summary", lambda *a: None)

    _run_main(monkeypatch, ["cli.py", "-s", "a" * 64])  # should not raise


def test_output_toggle_auto_generates_report_name(monkeypatch) -> None:
    class FakeDateTime:
        @staticmethod
        def now():
            class _Now:
                @staticmethod
                def strftime(fmt: str) -> str:
                    return '20260225_120000'
            return _Now()

    monkeypatch.setattr(cli_app, 'datetime', FakeDateTime)
    monkeypatch.setattr(cli_app, 'get_api_key', lambda: 'k')
    monkeypatch.setattr(cli_app, 'ScannerService', FakeService)

    _run_main(monkeypatch, ['cli.py', '-s', 'a' * 64, '-o', '--format', 'md'])


def test_main_uses_env_upload_timeout_when_flag_missing(monkeypatch) -> None:
    captured: dict[str, int | None] = {"upload_timeout_minutes": None}

    class CaptureService(FakeService):
        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, **kwargs)
            captured["upload_timeout_minutes"] = kwargs.get("upload_timeout_minutes")

    monkeypatch.setattr(cli_app, "ScannerService", CaptureService)
    monkeypatch.setattr(cli_app, "get_api_key", lambda: "k")
    monkeypatch.setattr(cli_app, "get_upload_timeout_minutes", lambda: 30)
    monkeypatch.setattr(cli_app, "print_banner", lambda: None)
    monkeypatch.setattr(cli_app, "print_result", lambda *a, **kw: None)
    monkeypatch.setattr(cli_app, "print_scan_summary", lambda *a: None)

    _run_main(monkeypatch, ["cli.py", "-s", "a" * 64])
    assert captured["upload_timeout_minutes"] == 30


def test_main_uses_zero_env_upload_timeout_when_flag_missing(monkeypatch) -> None:
    captured: dict[str, int | None] = {"upload_timeout_minutes": None}

    class CaptureService(FakeService):
        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, **kwargs)
            captured["upload_timeout_minutes"] = kwargs.get("upload_timeout_minutes")

    monkeypatch.setattr(cli_app, "ScannerService", CaptureService)
    monkeypatch.setattr(cli_app, "get_api_key", lambda: "k")
    monkeypatch.setattr(cli_app, "get_requests_per_minute", lambda: 4)
    monkeypatch.setattr(cli_app, "get_workers", lambda: None)
    monkeypatch.setattr(cli_app, "get_upload_timeout_minutes", lambda: 0)
    monkeypatch.setattr(cli_app, "print_banner", lambda: None)
    monkeypatch.setattr(cli_app, "print_result", lambda *a, **kw: None)
    monkeypatch.setattr(cli_app, "print_scan_summary", lambda *a: None)

    _run_main(monkeypatch, ["cli.py", "-s", "a" * 64])
    assert captured["upload_timeout_minutes"] == 0


def test_main_accepts_zero_upload_timeout(monkeypatch) -> None:
    captured: dict[str, int | None] = {"upload_timeout_minutes": None}

    class CaptureService(FakeService):
        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, **kwargs)
            captured["upload_timeout_minutes"] = kwargs.get("upload_timeout_minutes")

    monkeypatch.setattr(cli_app, "ScannerService", CaptureService)
    monkeypatch.setattr(cli_app, "get_api_key", lambda: "k")
    monkeypatch.setattr(cli_app, "print_banner", lambda: None)
    monkeypatch.setattr(cli_app, "print_result", lambda *a, **kw: None)
    monkeypatch.setattr(cli_app, "print_scan_summary", lambda *a: None)

    _run_main(monkeypatch, ["cli.py", "-s", "a" * 64, "--upload-timeout", "0"])
    assert captured["upload_timeout_minutes"] == 0


def test_main_uses_env_rpm_and_workers_when_flags_missing(monkeypatch) -> None:
    captured: dict[str, int | None] = {"requests_per_minute": None, "max_workers": None}

    class CaptureService(FakeService):
        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, **kwargs)
            captured["requests_per_minute"] = kwargs.get("requests_per_minute")
            captured["max_workers"] = kwargs.get("max_workers")

    monkeypatch.setattr(cli_app, "ScannerService", CaptureService)
    monkeypatch.setattr(cli_app, "get_api_key", lambda: "k")
    monkeypatch.setattr(cli_app, "get_requests_per_minute", lambda: 0)
    monkeypatch.setattr(cli_app, "get_workers", lambda: 7)
    monkeypatch.setattr(cli_app, "get_upload_timeout_minutes", lambda: 20)
    monkeypatch.setattr(cli_app, "print_banner", lambda: None)
    monkeypatch.setattr(cli_app, "print_result", lambda *a, **kw: None)
    monkeypatch.setattr(cli_app, "print_scan_summary", lambda *a: None)

    _run_main(monkeypatch, ["cli.py", "-s", "a" * 64])
    assert captured["requests_per_minute"] == 0
    assert captured["max_workers"] == 7
