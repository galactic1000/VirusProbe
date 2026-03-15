"""Result builders and threat classification."""

from __future__ import annotations

import vt

from .models import ResultStatus, ScanResult, ScanTargetKind, ThreatLevel
from .env import HEX_CHARS


def format_hash(value: object) -> str:
    return f"SHA-256 hash: {value}"


def base_result(
    item: str,
    kind: ScanTargetKind,
    file_hash: str,
    threat_level: ThreatLevel,
    status: ResultStatus,
    message: str,
) -> ScanResult:
    return ScanResult(
        item=item,
        kind=kind,
        file_hash=file_hash,
        threat_level=threat_level,
        status=status,
        message=message,
    )


def error_result(item: str, kind: ScanTargetKind, message: str, file_hash: str = "") -> ScanResult:
    return base_result(item, kind, file_hash, ThreatLevel.ERROR, ResultStatus.ERROR, message)


def cancelled_result(item: str, kind: ScanTargetKind, file_hash: str = "") -> ScanResult:
    return base_result(item, kind, file_hash, ThreatLevel.CANCELLED, ResultStatus.CANCELLED, "Cancelled by user")



def hash_error(value: object, message: str, file_hash: str = "") -> ScanResult:
    return error_result(format_hash(value), ScanTargetKind.HASH, message, file_hash)


def not_found_result(normalized_hash: str) -> ScanResult:
    return base_result(
        format_hash(normalized_hash),
        ScanTargetKind.HASH,
        normalized_hash,
        ThreatLevel.UNDETECTED,
        ResultStatus.UNDETECTED,
        "No VirusTotal record found",
    )


def not_found_file_result(file_path: str, file_hash: str) -> ScanResult:
    return base_result(
        file_path,
        ScanTargetKind.FILE,
        file_hash,
        ThreatLevel.UNDETECTED,
        ResultStatus.UNDETECTED,
        "No VirusTotal record found",
    )


def is_sha256(value: str) -> bool:
    return len(value) == 64 and all(c in HEX_CHARS for c in value)


def classify_threat(malicious: int, suspicious: int = 0) -> ThreatLevel:
    if malicious >= 10:
        return ThreatLevel.MALICIOUS
    elif malicious > 0 or suspicious >= 3:
        return ThreatLevel.SUSPICIOUS
    return ThreatLevel.CLEAN


def extract_stats(obj: vt.Object) -> tuple[int, int, int, int]:
    stats = obj.last_analysis_stats
    return (
        int(stats["malicious"]),
        int(stats["suspicious"]),
        int(stats["harmless"]),
        int(stats["undetected"]),
    )


def stats_result(
    *,
    item: str,
    kind: ScanTargetKind,
    file_hash: str,
    stats: tuple[int, int, int, int],
    was_cached: bool,
) -> ScanResult:
    malicious, suspicious, harmless, undetected = stats
    return ScanResult(
        item=item,
        kind=kind,
        file_hash=file_hash,
        malicious=malicious,
        suspicious=suspicious,
        harmless=harmless,
        undetected=undetected,
        threat_level=classify_threat(malicious, suspicious),
        status=ResultStatus.OK,
        message="Using cached result" if was_cached else "Queried VirusTotal API",
        was_cached=was_cached,
    )
