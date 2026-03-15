"""Shared dataclasses used across VirusProbe internals."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, NamedTuple

from .defaults import DEFAULT_REQUESTS_PER_MINUTE, DEFAULT_UPLOAD_TIMEOUT_MINUTES


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ScanTargetKind(StrEnum):
    HASH = "hash"
    FILE = "file"
    DIRECTORY = "directory"


class ResultStatus(StrEnum):
    OK = "ok"
    ERROR = "error"
    CANCELLED = "cancelled"
    UNDETECTED = "undetected"


class ThreatLevel(StrEnum):
    CLEAN = "Clean"
    MALICIOUS = "Malicious"
    SUSPICIOUS = "Suspicious"
    UNDETECTED = "Undetected"
    ERROR = "Error"
    CANCELLED = "Cancelled"


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ScanTarget:
    kind: ScanTargetKind
    value: str
    file_hash: str | None = None
    recursive: bool = False

    @property
    def hash(self) -> str:
        if self.kind is ScanTargetKind.HASH:
            return self.value
        return self.file_hash or ""

    @property
    def file_path(self) -> str | None:
        if self.kind is ScanTargetKind.FILE:
            return self.value
        return None

    @property
    def directory_path(self) -> str | None:
        if self.kind is ScanTargetKind.DIRECTORY:
            return self.value
        return None

    @classmethod
    def from_hash(cls, hash_value: str) -> ScanTarget:
        return cls(kind=ScanTargetKind.HASH, value=hash_value)

    @classmethod
    def from_file(cls, hash_value: str, file_path: str) -> ScanTarget:
        return cls(kind=ScanTargetKind.FILE, value=file_path, file_hash=hash_value)

    @classmethod
    def from_file_path(cls, file_path: str) -> ScanTarget:
        return cls(kind=ScanTargetKind.FILE, value=file_path)

    @classmethod
    def from_directory(cls, directory: str, recursive: bool = False) -> ScanTarget:
        return cls(kind=ScanTargetKind.DIRECTORY, value=directory, recursive=recursive)


@dataclass(frozen=True)
class ScanResult:
    item: str
    kind: ScanTargetKind
    file_hash: str
    malicious: int = 0
    suspicious: int = 0
    harmless: int = 0
    undetected: int = 0
    threat_level: ThreatLevel = ThreatLevel.CLEAN
    status: ResultStatus = ResultStatus.OK
    message: str = ""
    was_cached: bool = False
    was_uploaded: bool = False

    @property
    def type(self) -> str:
        return self.kind.value

    def to_dict(self) -> dict[str, Any]:
        return {
            "item": self.item,
            "type": self.kind.value,
            "file_hash": self.file_hash,
            "malicious": self.malicious,
            "suspicious": self.suspicious,
            "harmless": self.harmless,
            "undetected": self.undetected,
            "threat_level": self.threat_level,
            "status": self.status,
            "message": self.message,
            "was_cached": self.was_cached,
            "was_uploaded": self.was_uploaded,
        }


@dataclass(frozen=True)
class UploadTarget:
    file_path: str
    file_hash: str


@dataclass(frozen=True)
class ScannerConfig:
    requests_per_minute: int = DEFAULT_REQUESTS_PER_MINUTE
    max_workers: int | None = None
    upload_timeout_minutes: int = DEFAULT_UPLOAD_TIMEOUT_MINUTES
    upload_undetected: bool = False
    upload_filter: Callable[[str], bool] | None = field(default=None, hash=False, compare=False)
    cache_expiry_days: int = 7
    cache_max_rows: int = 10000
    memory_cache_max_entries: int = 512


# ---------------------------------------------------------------------------
# Internal
# ---------------------------------------------------------------------------

class CacheEntry(NamedTuple):
    stats: tuple[int, int, int, int]
    is_not_found: bool
