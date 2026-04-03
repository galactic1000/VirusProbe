"""Shared pytest fixtures and helpers for VirusProbe tests."""

from __future__ import annotations

from collections.abc import Iterable
from threading import Event

import pytest

from common.cache import ScanCache
from common.models import ScannerConfig
from common.service import ScannerService
from gui.app import VirusProbeGUI
from tests.helpers import (
    FakePollingClient,
    FakeRateLimiter,
    FakeUploadClient,
    FakeVTStatsClient,
)


@pytest.fixture
def service_factory(tmp_path):
    """Fixture that creates ScannerService instances and closes them after the test."""
    services = []

    def _make(**kwargs) -> ScannerService:
        s = ScannerService(api_key="test", cache_db=tmp_path / "vt_cache.db", config=ScannerConfig(**kwargs))
        s.init_cache()
        services.append(s)
        return s

    yield _make
    for s in services:
        s.close()


@pytest.fixture
def cache_factory(tmp_path):
    """Fixture that creates ScanCache instances and closes them after the test."""
    caches = []

    def _make(**kwargs) -> ScanCache:
        kwargs.setdefault("cache_db", tmp_path / "vt_cache.db")
        c = ScanCache(**kwargs)
        c.init()
        caches.append(c)
        return c

    yield _make
    for c in caches:
        c.close()


@pytest.fixture
def limiter(mocker):
    """Fixture that provides a FakeRateLimiter."""
    return FakeRateLimiter(mocker)


@pytest.fixture
def file_factory(tmp_path):
    """Fixture that creates a temp file with optional contents and returns its path."""

    def _make(name: str, contents: bytes = b"x"):
        path = tmp_path / name
        path.write_bytes(contents)
        return path

    return _make


@pytest.fixture
def vt_stats_client_factory():
    """Fixture that builds a fake VT client returning fixed analysis stats."""

    def _make(file_hash: str, stats: tuple[int, int, int, int]):
        return FakeVTStatsClient(file_hash, stats)

    return _make


@pytest.fixture
def polling_client_factory():
    """Fixture that builds a fake VT analysis polling client."""

    def _make(analysis_id: str, statuses: Iterable[str], stats: tuple[int, int, int, int]):
        return FakePollingClient(analysis_id, list(statuses), stats)

    return _make


@pytest.fixture
def upload_client_factory():
    """Fixture that builds fake VT upload clients for small or large uploads."""

    def _make(*, analysis_id: str, large: bool = False, upload_url: str = "https://upload.url"):
        return FakeUploadClient(analysis_id=analysis_id, large=large, upload_url=upload_url)

    return _make


@pytest.fixture
def app_stub():
    """Fixture that returns a minimally initialized VirusProbeGUI stub."""

    app = VirusProbeGUI.__new__(VirusProbeGUI)
    app.is_scanning = False
    app.is_uploading = False
    app.is_clearing_cache = False
    app.is_generating_report = False
    app.cancel_event = Event()
    app.active_upload_entries = []
    return app


@pytest.fixture
def runner_factory(mocker):
    """Fixture that intercepts QtAsyncio task startup."""

    def _attach(app: VirusProbeGUI, callback_name: str):
        start_task = mocker.Mock()
        app._start_task = start_task  # type: ignore[method-assign]
        callback = mocker.Mock()
        setattr(app, callback_name, callback)
        return start_task, callback

    return _attach
