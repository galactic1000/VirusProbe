from __future__ import annotations

from pathlib import Path

import pytest

from common.models import ResultStatus, ScannerConfig, ScanResult, ScanTargetKind
from gui.app import VirusProbeGUI
from gui.model import AppModel
from gui.presenter import AppPresenter
from gui.style import _DARK_THEME, _LIGHT_THEME, theme_name
from gui.view import MainWindow
from gui.workflows import PendingScanEntry, ReportRequest


class _RecorderButton:
    def __init__(self) -> None:
        self.calls = []

    def configure(self, **kwargs: object) -> None:
        self.calls.append(kwargs)


class _FakeScanner:
    def __init__(self) -> None:
        self.close_called = False

    def close(self) -> None:
        self.close_called = True


class _RecorderView:
    def __init__(self) -> None:
        self.controls_enabled = []
        self.scan_button_states = []
        self.upload_button_visible = []
        self.upload_button_enabled = []
        self.api_status_var = type("Var", (), {"set": lambda self, value: None})()
        self.upload_indicator_var = type("Var", (), {"set": lambda self, value: None})()
        self.progress_var = type("Var", (), {"set": lambda self, value: None})()

    def set_controls_enabled(self, enabled: bool) -> None:
        self.controls_enabled.append(enabled)

    def set_scan_button_cancel(self, on_cancel) -> None:
        self.scan_button_states.append(("cancel", on_cancel))

    def set_scan_button_scan(self, on_scan) -> None:
        self.scan_button_states.append(("scan", on_scan))

    def set_progress(self, completed: int, total: int) -> None:
        self.last_progress = (completed, total)

    def show_upload_button(self, visible: bool) -> None:
        self.upload_button_visible.append(visible)

    def set_upload_button_enabled(self, enabled: bool) -> None:
        self.upload_button_enabled.append(enabled)


class _ReportView:
    def __init__(self) -> None:
        self.controls_enabled = []
        self.scan_btn = _RecorderButton()
        self.report_button = _RecorderButton()
        self.separator_width = 95
        self._result_keys = []

    def set_controls_enabled(self, enabled: bool) -> None:
        self.controls_enabled.append(enabled)

    def result_keys_in_order(self) -> list[tuple[str, str]]:
        return list(self._result_keys)


class _ReportModel:
    def __init__(self, results: list[ScanResult], default_report_dir: str) -> None:
        self._results = results
        self.default_report_dir = default_report_dir

    def results_snapshot(self) -> list[ScanResult]:
        return list(self._results)

    def results_for_keys(self, keys: list[tuple[str, str]]) -> list[ScanResult]:
        index = {
            ("hash" if result.kind is ScanTargetKind.HASH else "file", result.file_hash if result.kind is ScanTargetKind.HASH else result.item): result
            for result in self._results
        }
        return [index[key] for key in keys if key in index]


class _ScanModel:
    def __init__(self, api_key: str) -> None:
        self.api_key = api_key
        self.had_invalid_loaded_api_key = False


class _UploadModel:
    def __init__(self, api_key: str) -> None:
        self.api_key = api_key
        self.had_invalid_loaded_api_key = False

    def get_file_hash(self, file_path: str) -> str:
        return f"hash-for-{Path(file_path).name}"


class _ScanStartView:
    def __init__(self, entries: list[PendingScanEntry]) -> None:
        self._entries = entries
        self.progress_calls = []
        self.status_updates = []
        self.report_button = _RecorderButton()

    def item_count(self) -> int:
        return len(self._entries)

    def collect_pending_entries(self) -> list[PendingScanEntry]:
        return list(self._entries)

    def set_progress(self, completed: int, total: int) -> None:
        self.progress_calls.append((completed, total))

    def set_row_status(self, iid: str, status: str) -> None:
        self.status_updates.append((iid, status))


class _UploadSelectionTable:
    def __init__(self, selected: bool) -> None:
        self._selected = selected

    def get_rows(self, selected: bool = False):
        if selected and self._selected:
            return [object()]
        return []


class _UploadStartView:
    def __init__(self, file_entries: list[tuple[str, str]], selected: bool = False) -> None:
        self.table = _UploadSelectionTable(selected)
        self._file_entries = file_entries
        self.status_updates = []
        self.progress_calls = []

    def undetected_files(self, selected_only: bool = False) -> list[tuple[str, str]]:
        return list(self._file_entries)

    def set_row_status(self, iid: str, status: str) -> None:
        self.status_updates.append((iid, status))

    def set_progress(self, completed: int, total: int) -> None:
        self.progress_calls.append((completed, total))


class _RemoveSelectedView:
    def __init__(self, removed_keys: list[tuple[str, str]]) -> None:
        self._removed_keys = removed_keys
        self.remove_selected_calls = 0

    def remove_selected(self) -> list[tuple[str, str]]:
        self.remove_selected_calls += 1
        return list(self._removed_keys)


class _RemoveSelectedModel:
    def __init__(self, remove_results) -> None:
        self.remove_results = remove_results


class _BusyGuardView:
    def __init__(self) -> None:
        self.remove_selected_calls = 0

    def remove_selected(self) -> list[tuple[str, str]]:
        self.remove_selected_calls += 1
        return []


def test_advanced_invalidates_scanner(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("gui.model.save_requests_per_minute_to_env", lambda _value: None)
    monkeypatch.setattr("gui.model.save_workers_to_env", lambda _value: None)
    monkeypatch.setattr("gui.model.save_upload_timeout_minutes_to_env", lambda _value: None)
    monkeypatch.setattr("gui.model.save_upload_mode_to_env", lambda _value: None)
    monkeypatch.setattr("gui.model.save_theme_mode_to_env", lambda _value: None)

    model = AppModel(cache_db=tmp_path / "vt_cache.db")
    fake_scanner = _FakeScanner()
    model._scanner = fake_scanner  # type: ignore[attr-defined]
    model._scanner_config = ("key", ScannerConfig(requests_per_minute=4, max_workers=4, upload_timeout_minutes=20))

    model.set_advanced(10, 2, 30, model.upload_mode, model.theme_mode)

    assert model._scanner is fake_scanner  # noqa: SLF001
    assert model._scanner_config is None  # noqa: SLF001
    assert fake_scanner.close_called is False


async def test_clear_cache_uses_temp_service(tmp_path, mocker) -> None:
    monkeypatches = {
        "gui.model.get_api_key": lambda: None,
        "gui.model.get_upload_mode": lambda: "never",
        "gui.model.get_theme_mode": lambda: "auto",
        "gui.model.get_requests_per_minute": lambda: None,
        "gui.model.get_workers": lambda: None,
        "gui.model.get_upload_timeout_minutes": lambda: None,
    }
    for path, value in monkeypatches.items():
        mocker.patch(path, side_effect=value if callable(value) else None)

    calls = []

    class _FakeService:
        def __init__(self, api_key: str, cache_db: Path) -> None:
            calls.append("init_service")

        async def init_cache_async(self) -> None:
            calls.append("init_cache_async")

        async def clear_cache_async(self) -> int:
            calls.append("clear_cache_async")
            return 7

        def close(self) -> None:
            calls.append("close")

    mocker.patch("gui.model.ScannerService", _FakeService)
    model = AppModel(cache_db=tmp_path / "vt_cache.db")

    deleted = await model.clear_cache_async()

    assert deleted == 7
    assert calls == ["init_service", "init_cache_async", "clear_cache_async", "close"]


def test_hash_result_key_is_file_hash(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("gui.model.get_api_key", lambda: None)
    monkeypatch.setattr("gui.model.get_upload_mode", lambda: "never")
    monkeypatch.setattr("gui.model.get_theme_mode", lambda: "auto")
    monkeypatch.setattr("gui.model.get_requests_per_minute", lambda: None)
    monkeypatch.setattr("gui.model.get_workers", lambda: None)
    monkeypatch.setattr("gui.model.get_upload_timeout_minutes", lambda: None)
    model = AppModel(cache_db=tmp_path / "vt_cache.db")

    result = ScanResult(
        item="SHA-256 hash: " + ("a" * 64),
        kind=ScanTargetKind.HASH,
        file_hash="a" * 64,
        status=ResultStatus.OK,
    )

    model.upsert_result(result)
    snapshot = model.results_snapshot()

    assert snapshot == [result]
    assert model._last_results_by_key == {("hash", "a" * 64): result}  # noqa: SLF001


def test_presenter_busy_then_idle() -> None:
    view = _RecorderView()
    presenter = AppPresenter(view)

    def on_scan() -> None:
        return None

    def on_cancel() -> None:
        return None

    presenter.begin_busy(on_cancel)
    presenter.restore_idle(on_scan)

    assert view.controls_enabled == [False, True]
    assert view.scan_button_states == [("cancel", on_cancel), ("scan", on_scan)]
    assert view.last_progress == (0, 0)


def test_report_submits_workflow(mocker, tmp_path, app_stub, runner_factory) -> None:
    app = app_stub
    app.model = _ReportModel(
        [ScanResult(item="x", kind=ScanTargetKind.FILE, file_hash="a" * 64)],
        str(tmp_path),
    )
    app.view = _ReportView()
    app.view._result_keys = [("file", "x")]
    app._update_upload_action_visibility = mocker.Mock()
    app._set_progress_text = mocker.Mock()
    future, submit = runner_factory(app, "_on_report_done")

    request = ReportRequest(str(tmp_path), str(tmp_path / "report.json"), "json")
    mocker.patch("gui.app.show_generate_report_dialog", return_value=request)
    workflow = mocker.patch("gui.app.run_report_workflow_async", new=mocker.Mock(return_value="workflow"))

    VirusProbeGUI.on_generate_report(app)

    assert app.is_generating_report is True
    assert app.view.controls_enabled == [False]
    assert app.view.scan_btn.calls[-1] == {"state": "disabled"}
    assert app.view.report_button.calls[-1] == {"state": "disabled"}
    app._update_upload_action_visibility.assert_called_once()
    app._set_progress_text.assert_called_once_with("Generating report...")
    workflow.assert_called_once_with(app.model.results_for_keys([("file", "x")]), request, 95)
    submit.assert_called_once_with("workflow")
    assert future.callbacks == [app._on_report_done]


def test_report_uses_visible_order(mocker, tmp_path, app_stub, runner_factory) -> None:
    file_result = ScanResult(item="C:/sample.bin", kind=ScanTargetKind.FILE, file_hash="f" * 64)
    hash_result = ScanResult(item="SHA-256 hash: " + ("a" * 64), kind=ScanTargetKind.HASH, file_hash="a" * 64)
    app = app_stub
    app.model = _ReportModel([hash_result, file_result], str(tmp_path))
    app.view = _ReportView()
    app.view._result_keys = [("file", "C:/sample.bin"), ("hash", "a" * 64)]
    app._update_upload_action_visibility = mocker.Mock()
    app._set_progress_text = mocker.Mock()
    runner_factory(app, "_on_report_done")

    request = ReportRequest(str(tmp_path), str(tmp_path / "report.json"), "json")
    mocker.patch("gui.app.show_generate_report_dialog", return_value=request)
    workflow = mocker.patch("gui.app.run_report_workflow_async", new=mocker.Mock(return_value="workflow"))

    VirusProbeGUI.on_generate_report(app)

    workflow.assert_called_once()
    ordered_results = workflow.call_args.args[0]
    assert ordered_results == [file_result, hash_result]


def test_scan_starts_pending_entries(mocker, app_stub, runner_factory) -> None:
    entries = [
        PendingScanEntry("row-file", ScanTargetKind.FILE, "C:/sample.bin"),
        PendingScanEntry("row-hash", ScanTargetKind.HASH, "A" * 64),
    ]
    app = app_stub
    app.model = _ScanModel("a" * 64)
    app.view = _ScanStartView(entries)
    app._show_info = mocker.Mock()
    app._show_error = mocker.Mock()
    app._current_limits = mocker.Mock(return_value=(15, 3, 20))
    app._begin_busy_state = mocker.Mock()
    app._set_progress_text = mocker.Mock()
    future, submit = runner_factory(app, "_on_scan_done")
    app._run_scan_async = mocker.Mock(return_value="scan-workflow")

    VirusProbeGUI._start_scan(app)

    assert app.pending_entries == entries
    assert app.view.progress_calls == [(0, 2)]
    assert app.view.status_updates == [("row-file", "Scanning..."), ("row-hash", "Scanning...")]
    app._run_scan_async.assert_called_once_with(15, 3, 20)
    app._begin_busy_state.assert_called_once_with(app.on_scan)
    assert app.is_scanning is True
    assert app.view.report_button.calls[-1] == {"state": "disabled"}
    app._set_progress_text.assert_called_once_with("Scanning...")
    submit.assert_called_once_with("scan-workflow")
    assert future.callbacks == [app._on_scan_done]
    app._show_info.assert_not_called()
    app._show_error.assert_not_called()


def test_upload_starts_pending_entries(mocker, app_stub, runner_factory) -> None:
    file_entries = [("row-a", "C:/a.bin"), ("row-b", "C:/b.bin")]
    app = app_stub
    app.model = _UploadModel("a" * 64)
    app.view = _UploadStartView(file_entries, selected=True)
    app._show_error = mocker.Mock()
    app._begin_busy_state = mocker.Mock()
    app._set_progress_text = mocker.Mock()
    future, submit = runner_factory(app, "_on_upload_done")
    app._run_upload_async = mocker.Mock(return_value="upload-workflow")

    VirusProbeGUI._start_upload_selected(app)

    assert [(entry.iid, entry.file_path, entry.file_hash) for entry in app.active_upload_entries] == [
        ("row-a", "C:/a.bin", "hash-for-a.bin"),
        ("row-b", "C:/b.bin", "hash-for-b.bin"),
    ]
    assert app.view.status_updates == [("row-a", "Uploading..."), ("row-b", "Uploading...")]
    app._begin_busy_state.assert_called_once_with(app._cancel_upload)
    assert app.is_uploading is True
    assert app.view.progress_calls == [(0, 2)]
    app._set_progress_text.assert_called_once_with("Uploading...")
    submit.assert_called_once_with("upload-workflow")
    assert future.callbacks == [app._on_upload_done]
    app._show_error.assert_not_called()


def test_remove_selected_clears_model(mocker, app_stub) -> None:
    removed_keys = [("hash", "a" * 64), ("file", "C:/sample.bin")]
    app = app_stub
    remove_results = mocker.Mock()
    app.view = _RemoveSelectedView(removed_keys)
    app.model = _RemoveSelectedModel(remove_results)
    app._set_queued_count_text = mocker.Mock()
    app._update_upload_action_visibility = mocker.Mock()

    VirusProbeGUI.on_remove_selected(app)

    assert app.view.remove_selected_calls == 1
    app.model.remove_results.assert_called_once_with(removed_keys)
    app._set_queued_count_text.assert_called_once_with()
    app._update_upload_action_visibility.assert_called_once_with()


def test_mutating_noop_during_clear_cache(mocker, app_stub) -> None:
    app = app_stub
    app.is_clearing_cache = True
    app.model = _ScanModel("a" * 64)
    app.view = _BusyGuardView()
    app._show_info = mocker.Mock()
    app._show_error = mocker.Mock()
    app._set_queued_count_text = mocker.Mock()
    app._update_upload_action_visibility = mocker.Mock()

    VirusProbeGUI.on_remove_selected(app)

    assert app.view.remove_selected_calls == 0


def test_drop_files_noop_while_busy(mocker, app_stub) -> None:
    app = app_stub
    app.is_scanning = True
    app.tk = mocker.Mock()
    app._add_item = mocker.Mock()

    VirusProbeGUI.on_drop_files(app, object())

    app.tk.splitlist.assert_not_called()
    app._add_item.assert_not_called()


def test_hash_keys_canonicalized() -> None:
    assert MainWindow._item_key("hash", "AA" * 32) == ("hash", "aa" * 32)
    assert MainWindow._item_key("file", "C:/Sample.bin") == ("file", "C:/Sample.bin")


def test_theme_name_auto_rechecks_system_preference(mocker) -> None:
    prefers_dark = mocker.patch("gui.style._system_prefers_dark_mode", side_effect=[False, True])

    first = theme_name("auto")
    second = theme_name("auto")

    assert first == _LIGHT_THEME
    assert second == _DARK_THEME
    assert prefers_dark.call_count == 2


def test_initialize_view_warns_once_for_invalid_loaded_key(mocker, app_stub) -> None:
    app = app_stub
    app.model = type(
        "Model",
        (),
        {
            "api_key": None,
            "upload_mode": "never",
            "had_invalid_loaded_api_key": True,
        },
    )()
    app._update_api_key_status = mocker.Mock()
    app._update_upload_indicator = mocker.Mock()
    app._update_upload_action_visibility = mocker.Mock()
    app._show_error = mocker.Mock()

    VirusProbeGUI.initialize_view(app)

    app._update_api_key_status.assert_called_once_with()
    app._update_upload_indicator.assert_called_once_with()
    app._update_upload_action_visibility.assert_called_once_with()
    app._show_error.assert_called_once_with(
        "Invalid Saved API Key",
        "The saved VirusTotal API key is invalid and was ignored. Set a valid API key to scan.",
    )
    assert app.model.had_invalid_loaded_api_key is False # type: ignore
