"""Result-building helpers and classification utilities for the scanner service."""

from __future__ import annotations

from typing import Any

import vt

_HEX_CHARS: frozenset[str] = frozenset("0123456789abcdefABCDEF")


def hash_item(value: object) -> str:
    return f"SHA-256 hash: {value}"


def base_result(item: str, item_type: str, file_hash: str, threat_level: str, status: str, message: str) -> dict[str, Any]:
    return {
        "item": item,
        "type": item_type,
        "file_hash": file_hash,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "threat_level": threat_level,
        "status": status,
        "message": message,
        "was_cached": False,
        "was_uploaded": False,
    }


def error_result(item: str, item_type: str, message: str, file_hash: str = "") -> dict[str, Any]:
    return base_result(item, item_type, file_hash, "Error", "error", message)


def cancelled_result(item: str, item_type: str, file_hash: str = "") -> dict[str, Any]:
    return base_result(item, item_type, file_hash, "Cancelled", "cancelled", "Cancelled by user")


def hash_error(value: object, message: str, file_hash: str = "") -> dict[str, Any]:
    return error_result(hash_item(value), "hash", message, file_hash)


def not_found_result(normalized_hash: str) -> dict[str, Any]:
    return base_result(hash_item(normalized_hash), "hash", normalized_hash, "Undetected", "undetected", "No VirusTotal record found")


def is_sha256(value: str) -> bool:
    return len(value) == 64 and all(c in _HEX_CHARS for c in value)


def classify_threat(malicious: int, suspicious: int = 0) -> str:
    if malicious >= 10:
        return "Malicious"
    if malicious > 0 or suspicious >= 3:
        return "Suspicious"
    return "Clean"


def extract_stats(obj: vt.Object) -> tuple[int, int, int, int]:
    stats = obj.last_analysis_stats
    if not isinstance(stats, dict):
        raise ValueError("VirusTotal response missing analysis stats")
    return (
        int(stats["malicious"]),
        int(stats["suspicious"]),
        int(stats["harmless"]),
        int(stats["undetected"]),
    )


def stats_result(
    *,
    item: str,
    item_type: str,
    file_hash: str,
    stats: tuple[int, int, int, int],
    was_cached: bool,
) -> dict[str, Any]:
    malicious, suspicious, harmless, undetected = stats
    return {
        "item": item,
        "type": item_type,
        "file_hash": file_hash,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "threat_level": classify_threat(malicious, suspicious),
        "status": "ok",
        "message": "Using cached result" if was_cached else "Queried VirusTotal API",
        "was_cached": was_cached,
        "was_uploaded": False,
    }
