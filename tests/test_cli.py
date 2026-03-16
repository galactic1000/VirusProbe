from __future__ import annotations

import json
import sys

import pytest

import cli.app as cli_app
from cli.app import _build_parser
from cli.display import print_scan_summary
from common.models import ResultStatus, ScanResult, ScanTargetKind, ThreatLevel


class FakeService:
    clear_cache_called = 0
    init_cache_called = 0

    def __init__(self, *args, **kwargs) -> None:
        self.closed = False

    def init_cache(self) -> None:
        type(self).init_cache_called += 1

    async def init_cache_async(self) -> None:
        type(self).init_cache_called += 1

    def clear_cache(self) -> int:
        type(self).clear_cache_called += 1
        return 3

    async def __aenter__(self):
        await self.init_cache_async()
        return self

    async def __aexit__(self, exc_type, exc, tb) -> None:
        self.close()

    async def scan_targets(self, *args, **kwargs):
        return []

    def close(self) -> None:
        self.closed = True


def _run_main(monkeypatch, argv: list[str]) -> None:
    monkeypatch.setattr(sys, "argv", argv)
    cli_app.main()


def _make_capture_service(*keys: str) -> tuple[type, dict]:
    captured = {k: None for k in keys}

    class _CaptureService(FakeService):
        def __init__(self, *args, **kwargs) -> None:
            super().__init__(*args, **kwargs)
            config = kwargs.get("config")
            for k in keys:
                captured[k] = getattr(config, k, None) if config is not None else kwargs.get(k)

    return _CaptureService, captured



def test_s_flag_maps_to_hashes() -> None:
    parser = _build_parser()
    args = parser.parse_args(["-s", "a" * 64])
    assert args.hashes == ["a" * 64]


@pytest.mark.parametrize("argv,expected", [
    (["-o"], "__AUTO_OUTPUT__"),
    (["-o", "my_report.json"], "my_report.json"),
])
def test_output_flag_parsing(argv, expected) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)
    assert args.output == expected


@pytest.mark.parametrize("rpm_flags,expected", [
    ([], None),
    (["--requests-per-minute", "0"], 0),
    (["--requests-per-minute", "60"], 60),
])
def test_requests_per_minute_parsing(rpm_flags, expected) -> None:
    parser = _build_parser()
    args = parser.parse_args(["-s", "a" * 64] + rpm_flags)
    assert args.requests_per_minute == expected


def test_upload_timeout_parsing() -> None:
    parser = _build_parser()
    args = parser.parse_args(["-s", "a" * 64, "--upload-timeout", "30"])
    assert args.upload_timeout == 30


def test_summary_counts_suspicious_detections(capsys) -> None:
    print_scan_summary(
        [
            ScanResult(
                item="SHA-256 hash: " + ("a" * 64),
                kind=ScanTargetKind.HASH,
                file_hash="a" * 64,
                malicious=0,
                suspicious=3,
                harmless=12,
                undetected=1,
                threat_level=ThreatLevel.SUSPICIOUS ,
                status=ResultStatus.OK,
                message="",
            )
        ]
    )
    output = capsys.readouterr().out
    assert "SUSPICIOUS ITEMS" in output
    assert "(3 detections)" in output


def test_error_recursive_without_directory(mocker, monkeypatch) -> None:
    mocker.patch.object(cli_app, "get_api_key", return_value="a" * 64)
    with pytest.raises(SystemExit):
        _run_main(monkeypatch, ["cli.py", "-r", "-s", "a" * 64])


def test_error_directory_and_files_mixed(mocker, monkeypatch) -> None:
    mocker.patch.object(cli_app, "get_api_key", return_value="a" * 64)
    with pytest.raises(SystemExit):
        _run_main(monkeypatch, ["cli.py", "-d", ".", "-f", "a.bin"])


def test_error_api_key_missing(mocker, monkeypatch) -> None:
    mocker.patch.object(cli_app, "get_api_key", return_value=None)
    with pytest.raises(SystemExit):
        _run_main(monkeypatch, ["cli.py", "-s", "a" * 64])


def test_error_upload_timeout_without_upload(mocker, monkeypatch) -> None:
    mocker.patch.object(cli_app, "get_api_key", return_value="a" * 64)
    with pytest.raises(SystemExit) as exc_info:
        _run_main(monkeypatch, ["cli.py", "-s", "a" * 64, "--upload-timeout", "10"])
    assert exc_info.value.code == 2


def test_save_api_key_action_only(mocker, monkeypatch) -> None:
    mock_save = mocker.patch.object(cli_app, "save_api_key_to_env")
    mocker.patch.object(cli_app, "remove_api_key_from_env", return_value=False)
    mocker.patch.object(cli_app, "get_api_key", return_value="a" * 64)

    valid_key = "b" * 64
    _run_main(monkeypatch, ["cli.py", "--api-key", valid_key, "--save-api-key"])
    mock_save.assert_called_once_with(valid_key)


def test_save_api_key_rejects_invalid_key(mocker, monkeypatch) -> None:
    mock_save = mocker.patch.object(cli_app, "save_api_key_to_env")
    mocker.patch.object(cli_app, "remove_api_key_from_env", return_value=False)
    mocker.patch.object(cli_app, "get_api_key", return_value="a" * 64)

    with pytest.raises(SystemExit) as exc_info:
        _run_main(monkeypatch, ["cli.py", "--api-key", "abc", "--save-api-key"])

    assert exc_info.value.code == 2
    mock_save.assert_not_called()


def test_clear_cache_action_only(mocker, monkeypatch) -> None:
    FakeService.clear_cache_called = 0
    FakeService.init_cache_called = 0
    mocker.patch.object(cli_app, "ScannerService", FakeService)
    mocker.patch.object(cli_app, "get_api_key", return_value="a" * 64)

    _run_main(monkeypatch, ["cli.py", "--clear-cache"])
    assert FakeService.init_cache_called == 1
    assert FakeService.clear_cache_called == 1


def test_invalid_recursive_skips_admin_actions(mocker, monkeypatch) -> None:
    mocker.patch.object(cli_app, "get_api_key", return_value="a" * 64)
    mock_save = mocker.patch.object(cli_app, "save_api_key_to_env")

    with pytest.raises(SystemExit):
        _run_main(monkeypatch, ["cli.py", "--api-key", "abc", "--save-api-key", "-r", "-s", "a" * 64])

    mock_save.assert_not_called()


def test_invalid_upload_filter_skips_clear_cache(mocker, monkeypatch) -> None:
    FakeService.clear_cache_called = 0
    mocker.patch.object(cli_app, "ScannerService", FakeService)
    mocker.patch.object(cli_app, "get_api_key", return_value="a" * 64)

    with pytest.raises(SystemExit):
        _run_main(monkeypatch, ["cli.py", "--clear-cache", "--upload-filter", "*.exe", "-s", "a" * 64])

    assert FakeService.clear_cache_called == 0


def test_filter_existing_files(tmp_path) -> None:
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


def test_upload_filter_glob_matches_resolved_path(tmp_path, monkeypatch) -> None:
    root = tmp_path / "root"
    target_dir = root / "samples"
    target_dir.mkdir(parents=True)
    file_path = target_dir / "x.dll"
    file_path.write_bytes(b"x")
    monkeypatch.chdir(root)

    matcher = cli_app._build_upload_filter(["*/samples/*.dll"])
    assert matcher(str(file_path)) is True


def test_upload_filter_absolute_glob(tmp_path) -> None:
    target_dir = tmp_path / "absdir"
    target_dir.mkdir(parents=True)
    file_path = target_dir / "y.dll"
    file_path.write_bytes(b"x")

    pattern = str(target_dir).replace("\\", "/") + "/*.dll"
    matcher = cli_app._build_upload_filter([pattern])
    assert matcher(str(file_path)) is True


def test_exits_1_on_errors(mocker, monkeypatch) -> None:
    class ErrorService(FakeService):
        async def scan_targets(self, *args, **kwargs):
            result = ScanResult(
                item="SHA-256 hash: " + ("a" * 64),
                kind=ScanTargetKind.HASH,
                file_hash="a" * 64,
                threat_level=ThreatLevel.ERROR,
                status=ResultStatus.ERROR,
                message="API failure",
            )
            on_result = kwargs.get("on_result")
            if on_result is not None:
                on_result(result)
            return [result]

    mocker.patch.object(cli_app, "ScannerService", ErrorService)
    mocker.patch.object(cli_app, "get_api_key", return_value="a" * 64)
    mocker.patch.object(cli_app, "print_banner")
    mocker.patch.object(cli_app, "print_result")
    mocker.patch.object(cli_app, "print_scan_summary")

    with pytest.raises(SystemExit) as exc_info:
        _run_main(monkeypatch, ["cli.py", "-s", "a" * 64])
    assert exc_info.value.code == 1


def test_exits_0_on_malicious(mocker, monkeypatch) -> None:
    class MaliciousService(FakeService):
        async def scan_targets(self, *args, **kwargs):
            result = ScanResult(
                item="SHA-256 hash: " + ("a" * 64),
                kind=ScanTargetKind.HASH,
                file_hash="a" * 64,
                threat_level=ThreatLevel.MALICIOUS,
                status=ResultStatus.OK,
            )
            on_result = kwargs.get("on_result")
            if on_result is not None:
                on_result(result)
            return [result]

    mocker.patch.object(cli_app, "ScannerService", MaliciousService)
    mocker.patch.object(cli_app, "get_api_key", return_value="a" * 64)
    mocker.patch.object(cli_app, "print_banner")
    mocker.patch.object(cli_app, "print_result")
    mocker.patch.object(cli_app, "print_scan_summary")

    _run_main(monkeypatch, ["cli.py", "-s", "a" * 64])


def test_output_toggle_auto_generates_report_name(mocker, monkeypatch) -> None:
    class FakeDateTime:
        @staticmethod
        def now():
            class _Now:
                @staticmethod
                def strftime(fmt: str) -> str:
                    return "20260225_120000"
            return _Now()

    mocker.patch.object(cli_app, "datetime", FakeDateTime)
    mocker.patch.object(cli_app, "get_api_key", return_value="a" * 64)
    mocker.patch.object(cli_app, "ScannerService", FakeService)

    _run_main(monkeypatch, ["cli.py", "-s", "a" * 64, "-o", "--format", "md"])


@pytest.mark.parametrize("env_timeout", [30, 0])
def test_env_upload_timeout_fallback(mocker, monkeypatch, env_timeout) -> None:
    CaptureService, captured = _make_capture_service("upload_timeout_minutes")
    mocker.patch.object(cli_app, "ScannerService", CaptureService)
    mocker.patch.object(cli_app, "get_api_key", return_value="a" * 64)
    mocker.patch.object(cli_app, "get_upload_timeout_minutes", return_value=env_timeout)
    mocker.patch.object(cli_app, "print_banner")
    mocker.patch.object(cli_app, "print_result")
    mocker.patch.object(cli_app, "print_scan_summary")

    _run_main(monkeypatch, ["cli.py", "-s", "a" * 64])
    assert captured["upload_timeout_minutes"] == env_timeout


def test_accepts_zero_upload_timeout(mocker, monkeypatch) -> None:
    CaptureService, captured = _make_capture_service("upload_timeout_minutes")
    mocker.patch.object(cli_app, "ScannerService", CaptureService)
    mocker.patch.object(cli_app, "get_api_key", return_value="a" * 64)
    mocker.patch.object(cli_app, "print_banner")
    mocker.patch.object(cli_app, "print_result")
    mocker.patch.object(cli_app, "print_scan_summary")

    _run_main(monkeypatch, ["cli.py", "-s", "a" * 64, "--upload", "--upload-timeout", "0"])
    assert captured["upload_timeout_minutes"] == 0


def test_env_rpm_and_workers_fallback(mocker, monkeypatch) -> None:
    CaptureService, captured = _make_capture_service("requests_per_minute", "max_workers")
    mocker.patch.object(cli_app, "ScannerService", CaptureService)
    mocker.patch.object(cli_app, "get_api_key", return_value="a" * 64)
    mocker.patch.object(cli_app, "get_requests_per_minute", return_value=0)
    mocker.patch.object(cli_app, "get_workers", return_value=7)
    mocker.patch.object(cli_app, "get_upload_timeout_minutes", return_value=20)
    mocker.patch.object(cli_app, "print_banner")
    mocker.patch.object(cli_app, "print_result")
    mocker.patch.object(cli_app, "print_scan_summary")

    _run_main(monkeypatch, ["cli.py", "-s", "a" * 64])
    assert captured["requests_per_minute"] == 0
    assert captured["max_workers"] == 7


def test_writes_report_from_scan(monkeypatch, tmp_path, mocker) -> None:
    output_path = tmp_path / "report.json"

    class ReportService(FakeService):
        async def scan_targets(self, *args, **kwargs):
            result = ScanResult(
                item="SHA-256 hash: " + ("a" * 64),
                kind=ScanTargetKind.HASH,
                file_hash="a" * 64,
                malicious=10,
                suspicious=0,
                harmless=1,
                undetected=0,
                threat_level=ThreatLevel.MALICIOUS,
                status=ResultStatus.OK,
                message="Queried VirusTotal API",
            )
            on_result = kwargs.get("on_result")
            if on_result is not None:
                on_result(result)
            return [result]

    mocker.patch.object(cli_app, "ScannerService", ReportService)
    mocker.patch.object(cli_app, "get_api_key", return_value="a" * 64)
    mocker.patch.object(cli_app, "print_banner")
    mocker.patch.object(cli_app, "print_result")
    mocker.patch.object(cli_app, "print_scan_summary")

    _run_main(monkeypatch, ["cli.py", "-s", "a" * 64, "-o", str(output_path), "--format", "json"])

    data = json.loads(output_path.read_text(encoding="utf-8"))
    assert data["summary"]["total"] == 1
    assert data["summary"]["malicious"] == 1
    assert data["results"][0]["file_hash"] == "a" * 64


# ---------------------------------------------------------------------------
# _handle_admin_actions edge cases
# ---------------------------------------------------------------------------


def test_error_save_and_clear_api_key_together(monkeypatch, mocker) -> None:
    mocker.patch.object(cli_app, "get_api_key", return_value="a" * 64)
    with pytest.raises(SystemExit):
        _run_main(monkeypatch, ["cli.py", "--api-key", "abc", "--save-api-key", "--clear-api-key"])


def test_error_save_api_key_without_key(monkeypatch, mocker) -> None:
    mocker.patch.object(cli_app, "get_api_key", return_value="a" * 64)
    with pytest.raises(SystemExit):
        _run_main(monkeypatch, ["cli.py", "--save-api-key"])


def test_clear_api_key_action(monkeypatch, mocker) -> None:
    mock_remove = mocker.patch.object(cli_app, "remove_api_key_from_env", return_value=True)
    mocker.patch.object(cli_app, "get_api_key", return_value="a" * 64)
    _run_main(monkeypatch, ["cli.py", "--clear-api-key"])
    mock_remove.assert_called_once()


def test_clear_api_key_not_found(monkeypatch, mocker, capsys) -> None:
    mocker.patch.object(cli_app, "remove_api_key_from_env", return_value=False)
    mocker.patch.object(cli_app, "get_api_key", return_value="a" * 64)
    _run_main(monkeypatch, ["cli.py", "--clear-api-key"])
    assert "No saved API key found" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Argument validation edge cases
# ---------------------------------------------------------------------------


def test_error_negative_rpm(monkeypatch, mocker) -> None:
    mocker.patch.object(cli_app, "get_api_key", return_value="a" * 64)
    with pytest.raises(SystemExit):
        _run_main(monkeypatch, ["cli.py", "-s", "a" * 64, "--rpm", "-1"])


def test_error_negative_upload_timeout(monkeypatch, mocker) -> None:
    mocker.patch.object(cli_app, "get_api_key", return_value="a" * 64)
    with pytest.raises(SystemExit):
        _run_main(monkeypatch, ["cli.py", "-s", "a" * 64, "--upload", "--upload-timeout", "-1"])


def test_error_workers_less_than_one(monkeypatch, mocker) -> None:
    mocker.patch.object(cli_app, "get_api_key", return_value="a" * 64)
    with pytest.raises(SystemExit):
        _run_main(monkeypatch, ["cli.py", "-s", "a" * 64, "--workers", "0"])


def test_error_no_scan_input(monkeypatch, mocker) -> None:
    mocker.patch.object(cli_app, "get_api_key", return_value="a" * 64)
    with pytest.raises(SystemExit):
        _run_main(monkeypatch, ["cli.py"])


def test_error_invalid_api_key_format(monkeypatch, mocker) -> None:
    mocker.patch.object(cli_app, "get_api_key", return_value="short-key")
    with pytest.raises(SystemExit):
        _run_main(monkeypatch, ["cli.py", "-s", "a" * 64])


# ---------------------------------------------------------------------------
# Runtime display paths
# ---------------------------------------------------------------------------


def test_workers_greater_than_rpm_prints_warning(monkeypatch, mocker, capsys) -> None:
    mocker.patch.object(cli_app, "ScannerService", FakeService)
    mocker.patch.object(cli_app, "get_api_key", return_value="a" * 64)
    mocker.patch.object(cli_app, "print_result")
    mocker.patch.object(cli_app, "print_scan_summary")
    _run_main(monkeypatch, ["cli.py", "-s", "a" * 64, "--rpm", "1", "--workers", "8"])
    assert "workers" in capsys.readouterr().out.lower()


def test_upload_mode_message_no_filter(monkeypatch, mocker, capsys) -> None:
    mocker.patch.object(cli_app, "ScannerService", FakeService)
    mocker.patch.object(cli_app, "get_api_key", return_value="a" * 64)
    mocker.patch.object(cli_app, "print_banner")
    mocker.patch.object(cli_app, "print_result")
    mocker.patch.object(cli_app, "print_scan_summary")
    _run_main(monkeypatch, ["cli.py", "-s", "a" * 64, "--upload"])
    assert "undetected files will be submitted" in capsys.readouterr().out


def test_upload_mode_message_with_filter(monkeypatch, mocker, capsys) -> None:
    mocker.patch.object(cli_app, "ScannerService", FakeService)
    mocker.patch.object(cli_app, "get_api_key", return_value="a" * 64)
    mocker.patch.object(cli_app, "print_banner")
    mocker.patch.object(cli_app, "print_result")
    mocker.patch.object(cli_app, "print_scan_summary")
    _run_main(monkeypatch, ["cli.py", "-s", "a" * 64, "--upload", "--upload-filter", "*.exe"])
    assert "*.exe" in capsys.readouterr().out


def test_file_input_warnings_printed(monkeypatch, tmp_path, mocker, capsys) -> None:
    good = tmp_path / "good.bin"
    good.write_bytes(b"x")
    mocker.patch.object(cli_app, "ScannerService", FakeService)
    mocker.patch.object(cli_app, "get_api_key", return_value="a" * 64)
    mocker.patch.object(cli_app, "print_banner")
    mocker.patch.object(cli_app, "print_result")
    mocker.patch.object(cli_app, "print_scan_summary")
    _run_main(monkeypatch, ["cli.py", "-f", str(good), "/no/such/file.bin"])
    assert "Skipping missing file" in capsys.readouterr().out


def test_directory_scan_target(monkeypatch, tmp_path, mocker) -> None:
    mocker.patch.object(cli_app, "ScannerService", FakeService)
    mocker.patch.object(cli_app, "get_api_key", return_value="a" * 64)
    mocker.patch.object(cli_app, "print_banner")
    mocker.patch.object(cli_app, "print_result")
    mocker.patch.object(cli_app, "print_scan_summary")
    _run_main(monkeypatch, ["cli.py", "-d", str(tmp_path)])


def test_exits_130_on_keyboard_interrupt(monkeypatch, mocker) -> None:
    class CancelService(FakeService):
        async def scan_targets(self, *args, **kwargs):
            raise KeyboardInterrupt

    mocker.patch.object(cli_app, "ScannerService", CancelService)
    mocker.patch.object(cli_app, "get_api_key", return_value="a" * 64)
    mocker.patch.object(cli_app, "print_banner")
    with pytest.raises(SystemExit) as exc_info:
        _run_main(monkeypatch, ["cli.py", "-s", "a" * 64])
    assert exc_info.value.code == 130


def test_raises_on_unexpected_exception_no_results(monkeypatch, mocker) -> None:
    class BoomService(FakeService):
        async def scan_targets(self, *args, **kwargs):
            raise RuntimeError("network down")

    mocker.patch.object(cli_app, "ScannerService", BoomService)
    mocker.patch.object(cli_app, "get_api_key", return_value="a" * 64)
    mocker.patch.object(cli_app, "print_banner")
    with pytest.raises(RuntimeError, match="network down"):
        _run_main(monkeypatch, ["cli.py", "-s", "a" * 64])


def test_prints_run_error_when_results_exist(monkeypatch, mocker, capsys) -> None:
    class PartialService(FakeService):
        async def scan_targets(self, *args, **kwargs):
            result = ScanResult(
                item="SHA-256 hash: " + ("a" * 64),
                kind=ScanTargetKind.HASH,
                file_hash="a" * 64,
                threat_level=ThreatLevel.CLEAN,
                status=ResultStatus.OK,
            )
            on_result = kwargs.get("on_result")
            if on_result:
                on_result(result)
            raise RuntimeError("partial failure")

    mocker.patch.object(cli_app, "ScannerService", PartialService)
    mocker.patch.object(cli_app, "get_api_key", return_value="a" * 64)
    mocker.patch.object(cli_app, "print_banner")
    mocker.patch.object(cli_app, "print_result")
    mocker.patch.object(cli_app, "print_scan_summary")
    _run_main(monkeypatch, ["cli.py", "-s", "a" * 64])
    assert "partial failure" in capsys.readouterr().out
