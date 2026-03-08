from __future__ import annotations

from gui.model import AppModel
from gui.workflows import upload_completion_feedback


class _FakeScanner:
    def __init__(self) -> None:
        self.close_called = False

    def close(self) -> None:
        self.close_called = True


def test_set_advanced_invalidates_scanner_without_closing_active_instance(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr("gui.model.save_requests_per_minute_to_env", lambda _value: None)
    monkeypatch.setattr("gui.model.save_workers_to_env", lambda _value: None)
    monkeypatch.setattr("gui.model.save_upload_timeout_minutes_to_env", lambda _value: None)
    monkeypatch.setattr("gui.model.save_upload_mode_to_env", lambda _value: None)
    monkeypatch.setattr("gui.model.save_theme_mode_to_env", lambda _value: None)

    model = AppModel(cache_db=tmp_path / "vt_cache.db")
    fake_scanner = _FakeScanner()
    model._scanner = fake_scanner  # type: ignore[attr-defined]
    model._scanner_config = ("key", 4, 4, 20, False)  # noqa: SLF001

    model.set_advanced(10, 2, 30, model.upload_mode, model.theme_mode)

    assert model._scanner is fake_scanner  # noqa: SLF001
    assert model._scanner_config is None  # noqa: SLF001
    assert fake_scanner.close_called is False


def test_upload_completion_feedback_success() -> None:
    progress, title, message, style = upload_completion_feedback(3, 0)
    assert progress == "Upload complete"
    assert title == "Upload Complete"
    assert message == "Uploaded 3 file(s)."
    assert style == "success"


def test_upload_completion_feedback_errors() -> None:
    progress, title, message, style = upload_completion_feedback(3, 1)
    assert progress == "Upload finished with errors"
    assert title == "Upload Finished With Errors"
    assert message == "Uploaded 2/3 file(s); 1 failed."
    assert style == "warning"
