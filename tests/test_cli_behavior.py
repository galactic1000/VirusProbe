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


def test_filter_existing_files_returns_only_real_files(tmp_path) -> None:
    good = tmp_path / "good.bin"
    good.write_bytes(b"x")
    missing = tmp_path / "missing.bin"
    folder = tmp_path / "folder"
    folder.mkdir()

    result = cli_app._filter_existing_files([str(good), str(missing), str(folder)])
    assert result == [str(good)]


def test_main_exits_1_when_error_results(monkeypatch) -> None:
    class ErrorService(FakeService):
        def scan_hashes(self, *args, **kwargs):
            return [{"threat_level": "Error", "status": "error", "message": "API failure"}]

    monkeypatch.setattr(cli_app, "ScannerService", ErrorService)
    monkeypatch.setattr(cli_app, "get_api_key", lambda: "k")
    monkeypatch.setattr(cli_app, "print_banner", lambda: None)
    monkeypatch.setattr(cli_app, "print_run_context", lambda *a, **kw: None)
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
    monkeypatch.setattr(cli_app, "print_run_context", lambda *a, **kw: None)
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

