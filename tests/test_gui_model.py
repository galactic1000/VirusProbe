from __future__ import annotations

import pytest

from common.models import ResultStatus, ScannerConfig, ScanResult, ScanTargetKind, ThreatLevel
from gui.model import AppModel
from gui.presenter import AppPresenter, masked_api_key_text, upload_indicator_text


# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------


@pytest.fixture
def model(mocker, tmp_path):
    mocker.patch("gui.model.get_api_key", return_value="a" * 64)
    mocker.patch("gui.model.get_upload_mode", return_value="never")
    mocker.patch("gui.model.get_requests_per_minute", return_value=None)
    mocker.patch("gui.model.get_workers", return_value=None)
    mocker.patch("gui.model.get_upload_timeout_minutes", return_value=None)
    return AppModel(tmp_path / "test.db")


def _make_result(**kwargs) -> ScanResult:
    defaults = dict(item="item", kind=ScanTargetKind.HASH, file_hash="a" * 64, status=ResultStatus.OK)
    defaults.update(kwargs)
    return ScanResult(**defaults) # type: ignore


# ---------------------------------------------------------------------------
# presenter standalone functions
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("key,expected", [
    (None, "API Key: Not Set"),
    ("", "API Key: Not Set"),
    ("abcdefgh", "API Key: abcd...efgh"),
    ("ab", "API Key: set"),
])
def test_masked_api_key_text(key, expected) -> None:
    assert masked_api_key_text(key) == expected


@pytest.mark.parametrize("mode,expected", [
    ("auto", "[Upload: auto]"),
    ("manual", "[Upload: manual]"),
    ("never", ""),
])
def test_upload_indicator_text(mode, expected) -> None:
    assert upload_indicator_text(mode) == expected


# ---------------------------------------------------------------------------
# AppPresenter methods (mock view)
# ---------------------------------------------------------------------------


@pytest.fixture
def presenter(mocker):
    view = mocker.MagicMock()
    return AppPresenter(view)


def test_presenter_set_api_key_text(presenter) -> None:
    presenter.set_api_key_text("API Key: abcd...efgh")
    presenter.view.set_api_status_text.assert_called_once_with("API Key: abcd...efgh")


def test_presenter_set_upload_indicator_text(presenter) -> None:
    presenter.set_upload_indicator_text("[Upload: auto]")
    presenter.view.set_upload_indicator_text.assert_called_once_with("[Upload: auto]")


def test_presenter_set_queued_count(presenter) -> None:
    presenter.set_queued_count(5)
    presenter.view.set_progress_text.assert_called_once_with("Items queued: 5")


def test_presenter_set_canceling(presenter) -> None:
    presenter.set_canceling("Cancelling...")
    presenter.view.set_scan_button_enabled.assert_called_once_with(False)
    presenter.view.set_progress_text.assert_called_once_with("Cancelling...")


@pytest.mark.parametrize("mode,has_uploadable,busy,expect_show,expect_enabled", [
    ("manual", True, False, True, True),
    ("manual", False, False, True, False),
    ("manual", True, True, True, False),
    ("never", True, False, False, False),
])
def test_presenter_upload_action_visibility(presenter, mode, has_uploadable, busy, expect_show, expect_enabled) -> None:
    presenter.update_upload_action_visibility(mode, has_uploadable, busy)
    presenter.view.show_upload_button.assert_called_once_with(expect_show)
    if expect_show:
        presenter.view.set_upload_button_enabled.assert_called_once_with(expect_enabled)
    else:
        presenter.view.set_upload_button_enabled.assert_not_called()


# ---------------------------------------------------------------------------
# AppModel.parse_int
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("raw,default,minimum,expected", [
    ("10", 5, 1, 10),
    ("0", 5, 1, 1),
    ("abc", 5, 1, 5),
    ("-1", 5, 0, 0),
])
def test_parse_int(raw, default, minimum, expected) -> None:
    assert AppModel.parse_int(raw, default, minimum) == expected


# ---------------------------------------------------------------------------
# AppModel.result_status
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("kwargs,expected", [
    (dict(status=ResultStatus.CANCELLED, threat_level=ThreatLevel.CANCELLED), "Cancelled"),
    (dict(status=ResultStatus.ERROR, threat_level=ThreatLevel.ERROR), "Error"),
    (dict(status=ResultStatus.UNDETECTED, threat_level=ThreatLevel.UNDETECTED), "Undetected"),
    (dict(status=ResultStatus.OK, threat_level=ThreatLevel.MALICIOUS, was_uploaded=False), "Malicious"),
    (dict(status=ResultStatus.OK, threat_level=ThreatLevel.CLEAN, was_uploaded=True), "Uploaded - Clean"),
])
def test_result_status(kwargs, expected) -> None:
    result = _make_result(**kwargs)
    assert AppModel.result_status(result) == expected


# ---------------------------------------------------------------------------
# AppModel result store methods
# ---------------------------------------------------------------------------


def test_get_file_hash_found(model) -> None:
    r = _make_result(item="C:/x.bin", kind=ScanTargetKind.FILE, file_hash="b" * 64)
    model.upsert_result(r)
    assert model.get_file_hash("C:/x.bin") == "b" * 64


def test_get_file_hash_missing(model) -> None:
    assert model.get_file_hash("no/such.bin") == ""


def test_has_results_empty(model) -> None:
    assert model.has_results() is False


def test_has_results_after_upsert(model) -> None:
    model.upsert_result(_make_result())
    assert model.has_results() is True


def test_results_for_keys(model) -> None:
    r = _make_result(file_hash="c" * 64)
    model.upsert_result(r)
    found = model.results_for_keys([("hash", "c" * 64)])
    assert len(found) == 1
    assert found[0].file_hash == "c" * 64


def test_results_for_keys_missing(model) -> None:
    assert model.results_for_keys([("hash", "z" * 64)]) == []


def test_clear_results(model) -> None:
    model.upsert_result(_make_result())
    model.clear_results()
    assert model.has_results() is False


def test_remove_results(model) -> None:
    r = _make_result(file_hash="d" * 64)
    model.upsert_result(r)
    model.remove_results([("hash", "d" * 64)])
    assert model.results_for_keys([("hash", "d" * 64)]) == []


def test_invalid_loaded_api_key_treated_as_unset(mocker, tmp_path) -> None:
    mocker.patch("gui.model.get_api_key", return_value="invalid-key")
    mocker.patch("gui.model.get_upload_mode", return_value="never")
    mocker.patch("gui.model.get_requests_per_minute", return_value=None)
    mocker.patch("gui.model.get_workers", return_value=None)
    mocker.patch("gui.model.get_upload_timeout_minutes", return_value=None)

    model = AppModel(tmp_path / "test.db")

    assert model.api_key is None
    assert model.had_invalid_loaded_api_key is True


# ---------------------------------------------------------------------------
# AppModel scanner lifecycle
# ---------------------------------------------------------------------------


def test_reset_scanner_closes_existing(model, mocker) -> None:
    fake = mocker.MagicMock()
    model._scanner = fake
    model.reset_scanner()
    fake.close.assert_called_once()
    assert model._scanner is None


def test_close_resets_scanner(model, mocker) -> None:
    fake = mocker.MagicMock()
    model._scanner = fake
    model.close()
    fake.close.assert_called_once()


def test_set_api_key_saves_and_resets(model, mocker) -> None:
    mock_save = mocker.patch("gui.model.save_api_key_to_env")
    reset_spy = mocker.spy(model, "reset_scanner")
    model.set_api_key("b" * 64)
    mock_save.assert_called_once_with("b" * 64)
    reset_spy.assert_called_once()


def test_set_api_key_empty_removes(model, mocker) -> None:
    mock_remove = mocker.patch("gui.model.remove_api_key_from_env", return_value=False)
    model.set_api_key("")
    mock_remove.assert_called_once()
    assert model.api_key is None


async def test_acquire_scanner_creates_and_caches(model, mocker) -> None:
    mock_svc = mocker.patch("gui.model.ScannerService", return_value=mocker.AsyncMock())
    config = ScannerConfig()
    s1 = await model.acquire_scanner_async(config)
    s2 = await model.acquire_scanner_async(config)
    assert s1 is s2
    mock_svc.assert_called_once()


async def test_acquire_scanner_replaces_on_config_change(model, mocker) -> None:
    mocker.patch("gui.model.ScannerService", side_effect=lambda **_: mocker.AsyncMock())
    s1 = await model.acquire_scanner_async(ScannerConfig(requests_per_minute=4))
    s2 = await model.acquire_scanner_async(ScannerConfig(requests_per_minute=8))
    assert s1 is not s2


async def test_clear_cache_uses_existing_scanner(model, mocker) -> None:
    fake = mocker.AsyncMock()
    fake.clear_cache_async.return_value = 7
    model._scanner = fake
    result = await model.clear_cache_async()
    assert result == 7


async def test_acquire_scanner_init_failure_raises(model, mocker) -> None:
    failing = mocker.AsyncMock()
    failing.init_cache_async.side_effect = RuntimeError("db error")
    failing.close = mocker.MagicMock()
    mocker.patch("gui.model.ScannerService", return_value=failing)
    with pytest.raises(RuntimeError, match="db error"):
        await model.acquire_scanner_async(ScannerConfig())
    assert model._scanner is None


async def test_acquire_scanner_concurrent_returns_same(model, mocker) -> None:
    import asyncio

    mocker.patch("gui.model.ScannerService", return_value=mocker.AsyncMock())
    config = ScannerConfig()
    s1, s2 = await asyncio.gather(
        model.acquire_scanner_async(config),
        model.acquire_scanner_async(config),
    )
    assert s1 is s2


async def test_acquire_scanner_reused_after_context_exit(model, tmp_path) -> None:
    config = ScannerConfig(max_workers=1)
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sample")

    scanner = await model.acquire_scanner_async(config)
    async with scanner:
        pass

    reused = await model.acquire_scanner_async(config)
    assert reused is scanner

    async with reused:
        file_hash = await reused.hash_file_async(str(sample))
    assert len(file_hash) == 64
