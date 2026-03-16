from __future__ import annotations

import pytest

from colorama import Fore

from cli.display import (
    _center_text,
    _item_label,
    _verdict_color,
    format_colored,
    print_banner,
    print_header,
    print_input_warnings,
    print_result,
    print_scan_summary,
    print_subsection,
)
from common.models import ResultStatus, ScanResult, ScanTargetKind, ThreatLevel


# ---------------------------------------------------------------------------
# _center_text
# ---------------------------------------------------------------------------


def test_center_text_pads() -> None:
    result = _center_text("hi", 10)
    assert "hi" in result
    assert len(result) == 10


def test_center_text_text_too_wide() -> None:
    long_text = "x" * 200
    assert _center_text(long_text, 10) == long_text


# ---------------------------------------------------------------------------
# format_colored / _verdict_color
# ---------------------------------------------------------------------------


def test_format_colored_wraps_text() -> None:
    out = format_colored("hello", Fore.RED)
    assert "hello" in out


@pytest.mark.parametrize("threat,expected_color", [
    (ThreatLevel.CANCELLED, Fore.MAGENTA),
    (ThreatLevel.MALICIOUS, Fore.RED),
    (ThreatLevel.SUSPICIOUS, Fore.YELLOW),
    (ThreatLevel.UNDETECTED, Fore.CYAN),
    (ThreatLevel.CLEAN, Fore.GREEN),
])
def test_verdict_color(threat: ThreatLevel, expected_color: str) -> None:
    assert _verdict_color(threat) == expected_color


# ---------------------------------------------------------------------------
# print_header / print_subsection
# ---------------------------------------------------------------------------


def test_print_header(capsys) -> None:
    print_header("TEST TITLE")
    out = capsys.readouterr().out
    assert "TEST TITLE" in out


def test_print_subsection_with_newline(capsys) -> None:
    print_subsection("SECTION", leading_newline=True)
    out = capsys.readouterr().out
    assert "SECTION" in out


def test_print_subsection_no_newline(capsys) -> None:
    print_subsection("SECTION", leading_newline=False)
    out = capsys.readouterr().out
    assert "SECTION" in out


# ---------------------------------------------------------------------------
# print_input_warnings
# ---------------------------------------------------------------------------


def test_print_input_warnings_empty(capsys) -> None:
    print_input_warnings([])
    assert capsys.readouterr().out == ""


def test_print_input_warnings_shows_each(capsys) -> None:
    print_input_warnings(["missing.bin", "bad.bin"])
    out = capsys.readouterr().out
    assert "missing.bin" in out
    assert "bad.bin" in out


# ---------------------------------------------------------------------------
# print_banner
# ---------------------------------------------------------------------------


def test_print_banner(capsys) -> None:
    print_banner()
    out = capsys.readouterr().out
    assert "VirusProbe" in out


# ---------------------------------------------------------------------------
# _item_label
# ---------------------------------------------------------------------------


def _make_result(**kwargs) -> ScanResult:
    defaults: dict = dict(
        item="item",
        kind=ScanTargetKind.HASH,
        file_hash="a" * 64,
        status=ResultStatus.OK,
    )
    defaults.update(kwargs)
    return ScanResult(**defaults)  # type: ignore[arg-type]


def test_item_label_file() -> None:
    r = _make_result(item="C:/file.bin", kind=ScanTargetKind.FILE)
    assert _item_label(r) == "File path: C:/file.bin"


def test_item_label_hash() -> None:
    r = _make_result(kind=ScanTargetKind.HASH, file_hash="b" * 64)
    assert _item_label(r) == f"SHA-256 hash: {'b' * 64}"


def test_item_label_fallback() -> None:
    r = _make_result(item="misc", kind=ScanTargetKind.DIRECTORY)
    assert _item_label(r) == "misc"


# ---------------------------------------------------------------------------
# print_result
# ---------------------------------------------------------------------------


def test_print_result_hash_no_index(capsys) -> None:
    r = _make_result(kind=ScanTargetKind.HASH, file_hash="a" * 64, malicious=5, suspicious=0, harmless=10, undetected=0, threat_level=ThreatLevel.MALICIOUS, message="Queried")
    print_result(r)
    out = capsys.readouterr().out
    assert "SHA-256 HASH SCAN" in out
    assert "a" * 64 in out


def test_print_result_with_index_and_total(capsys) -> None:
    r = _make_result(kind=ScanTargetKind.HASH, file_hash="a" * 64, malicious=1, message="Queried")
    print_result(r, index=2, total=5)
    out = capsys.readouterr().out
    assert "ITEM 2/5" in out


def test_print_result_index_only(capsys) -> None:
    r = _make_result(kind=ScanTargetKind.HASH, file_hash="a" * 64, malicious=1, message="Queried")
    print_result(r, index=3)
    out = capsys.readouterr().out
    assert "ITEM 3 -" in out
    assert "/5" not in out


def test_print_result_file_with_hash(capsys) -> None:
    r = _make_result(item="C:/x.bin", kind=ScanTargetKind.FILE, file_hash="c" * 64, malicious=2, message="Queried")
    print_result(r)
    out = capsys.readouterr().out
    assert "FILE SCAN" in out
    assert "C:/x.bin" in out
    assert "c" * 64 in out


def test_print_result_undetected_not_cached(capsys) -> None:
    r = _make_result(status=ResultStatus.UNDETECTED, threat_level=ThreatLevel.UNDETECTED, was_cached=False)
    print_result(r)
    out = capsys.readouterr().out
    assert "Undetected" in out


def test_print_result_undetected_cached(capsys) -> None:
    r = _make_result(status=ResultStatus.UNDETECTED, threat_level=ThreatLevel.UNDETECTED, was_cached=True, message="Using cached result")
    print_result(r)
    out = capsys.readouterr().out
    assert "Using cached result" in out


def test_print_result_cancelled(capsys) -> None:
    r = _make_result(status=ResultStatus.CANCELLED, threat_level=ThreatLevel.CANCELLED)
    print_result(r)
    assert "Cancelled" in capsys.readouterr().out


def test_print_result_error(capsys) -> None:
    r = _make_result(status=ResultStatus.ERROR, threat_level=ThreatLevel.ERROR, message="API failure")
    print_result(r)
    assert "API failure" in capsys.readouterr().out


def test_print_result_uploaded(capsys) -> None:
    r = _make_result(malicious=1, was_uploaded=True, message="Uploaded", threat_level=ThreatLevel.MALICIOUS)
    print_result(r)
    out = capsys.readouterr().out
    assert "Uploaded" in out


def test_print_result_cached(capsys) -> None:
    r = _make_result(malicious=0, harmless=5, was_cached=True, message="Cached", threat_level=ThreatLevel.CLEAN)
    print_result(r)
    assert "Cached" in capsys.readouterr().out


def test_print_result_live(capsys) -> None:
    r = _make_result(malicious=0, harmless=5, was_uploaded=False, was_cached=False, message="Queried", threat_level=ThreatLevel.CLEAN)
    print_result(r)
    assert "Queried" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# print_scan_summary
# ---------------------------------------------------------------------------


def test_scan_summary_empty(capsys) -> None:
    print_scan_summary([])
    assert capsys.readouterr().out == ""


def test_scan_summary_malicious_items(capsys) -> None:
    r = _make_result(malicious=3, suspicious=0, harmless=0, undetected=0, threat_level=ThreatLevel.MALICIOUS, status=ResultStatus.OK)
    print_scan_summary([r])
    out = capsys.readouterr().out
    assert "MALICIOUS ITEMS" in out


def test_scan_summary_undetected_items(capsys) -> None:
    r = _make_result(status=ResultStatus.UNDETECTED, threat_level=ThreatLevel.UNDETECTED)
    print_scan_summary([r])
    out = capsys.readouterr().out
    assert "UNDETECTED ITEMS" in out


def test_scan_summary_cancelled_items(capsys) -> None:
    r = _make_result(status=ResultStatus.CANCELLED, threat_level=ThreatLevel.CANCELLED)
    print_scan_summary([r])
    out = capsys.readouterr().out
    assert "CANCELLED ITEMS" in out
    assert "Cancelled:" in out


def test_scan_summary_error_items(capsys) -> None:
    r = _make_result(status=ResultStatus.ERROR, threat_level=ThreatLevel.ERROR, message="boom")
    print_scan_summary([r])
    out = capsys.readouterr().out
    assert "ERRORS" in out
    assert "Errors:" in out
    assert "boom" in out
