"""Shared non-fixture test helpers."""

from __future__ import annotations

from dataclasses import dataclass, field


class FakeRateLimiter:
    def __init__(self, mocker) -> None:
        self.acquire = mocker.AsyncMock(return_value=None)


class ImmediateFuture:
    def __init__(self) -> None:
        self.callbacks = []

    def add_done_callback(self, callback) -> None:
        self.callbacks.append(callback)


class FakeRunner:
    def __init__(self, submit) -> None:
        self.submit = submit


def stats_dict(stats: tuple[int, int, int, int]) -> dict[str, int]:
    return {
        "malicious": stats[0],
        "suspicious": stats[1],
        "harmless": stats[2],
        "undetected": stats[3],
    }


@dataclass
class ScanObject:
    status: str | None = None
    stats: dict[str, int] = field(default_factory=dict)
    last_analysis_stats: dict[str, int] = field(default_factory=dict)

    @classmethod
    def from_stats(
        cls,
        *,
        status: str | None = None,
        stats: tuple[int, int, int, int] | None = None,
    ) -> ScanObject:
        if stats is None:
            return cls(status=status)
        result_stats = stats_dict(stats)
        return cls(status=status, stats=result_stats, last_analysis_stats=result_stats)


@dataclass
class FakeVTStatsClient:
    file_hash: str
    stats: tuple[int, int, int, int]

    async def get_object_async(self, path: str):
        assert path == f"/files/{self.file_hash}"
        return ScanObject.from_stats(stats=self.stats)


@dataclass
class FakePollingClient:
    analysis_id: str
    statuses: list[str]
    stats: tuple[int, int, int, int]
    calls: int = 0

    async def get_object_async(self, path: str):
        assert path == f"/analyses/{self.analysis_id}"
        status = self.statuses[min(self.calls, len(self.statuses) - 1)]
        self.calls += 1
        if status == "completed":
            return ScanObject.from_stats(status=status, stats=self.stats)
        return ScanObject.from_stats(status=status)


@dataclass
class FakeUploadResponse:
    analysis_id: str

    async def json_async(self) -> dict:
        return {"data": {"id": self.analysis_id}}


@dataclass
class FakeUploadClient:
    analysis_id: str
    large: bool = False
    upload_url: str = "https://upload.url"

    async def get_data_async(self, path: str) -> str:
        assert self.large is True
        assert path == "/files/upload_url"
        return self.upload_url

    async def post_async(self, path: str, data=None):
        expected_path = self.upload_url if self.large else "/files"
        assert path == expected_path
        return FakeUploadResponse(self.analysis_id)

    async def get_error_async(self, response) -> None:
        return None
