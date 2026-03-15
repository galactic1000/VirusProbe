from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from common.models import ResultStatus, ScanResult, ScanTargetKind, ThreatLevel
from common.reporting import write_report


SAMPLE_RESULTS = [
    ScanResult(
        item="SHA-256 hash: " + "a" * 64,
        kind=ScanTargetKind.HASH,
        file_hash="a" * 64,
        malicious=12,
        suspicious=1,
        harmless=0,
        undetected=0,
        threat_level=ThreatLevel.MALICIOUS,
        status=ResultStatus.OK,
        message="Queried VirusTotal API",
    ),
    ScanResult(
        item="SHA-256 hash: " + "b" * 64,
        kind=ScanTargetKind.HASH,
        file_hash="b" * 64,
        malicious=0,
        suspicious=0,
        harmless=0,
        undetected=0,
        threat_level=ThreatLevel.UNDETECTED,
        status=ResultStatus.UNDETECTED,
        message="No VirusTotal record found",
    ),
]


def test_write_report_json(tmp_path) -> None:
    out = tmp_path / "out" / "report.json"
    write_report(SAMPLE_RESULTS, str(out), "json")
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["summary"]["total"] == 2
    assert data["summary"]["malicious"] == 1


def test_write_report_csv(tmp_path) -> None:
    out = tmp_path / "report.csv"
    write_report(SAMPLE_RESULTS, str(out), "csv")
    with out.open("r", encoding="utf-8", newline="") as f:
        rows = list(csv.DictReader(f))
    assert len(rows) == 2
    assert rows[0]["threat_level"] == "Malicious"


@pytest.mark.parametrize("fmt,expected", [
    ("txt", ["VIRUS SCAN REPORT", "Total: 2"]),
    ("md", ["# Virus Scan Report", "| Item | Type |"]),
])
def test_write_report_text_formats(tmp_path, fmt: str, expected: list[str]) -> None:
    out = tmp_path / f"report.{fmt}"
    write_report(SAMPLE_RESULTS, str(out), fmt)
    text = out.read_text(encoding="utf-8")
    for s in expected:
        assert s in text


def test_write_report_creates_parent_dirs(tmp_path) -> None:
    out = tmp_path / "nested" / "deep" / "report.json"
    write_report(SAMPLE_RESULTS, str(out), "json")
    assert out.exists()
    assert Path(out).parent.exists()


_ERROR_RESULT = ScanResult(
    item="bad.exe",
    kind=ScanTargetKind.FILE,
    file_hash="",
    malicious=0,
    suspicious=0,
    harmless=0,
    undetected=0,
    threat_level=ThreatLevel.ERROR,
    status=ResultStatus.ERROR,
    message="File not found",
)


@pytest.mark.parametrize("fmt", ["md", "txt"])
def test_write_report_includes_errors_in_summary(tmp_path, fmt) -> None:
    out = tmp_path / f"report.{fmt}"
    write_report([_ERROR_RESULT], str(out), fmt)
    assert "Errors: 1" in out.read_text(encoding="utf-8")


def test_write_report_md_escapes_pipe_in_item(tmp_path) -> None:
    result = ScanResult(
        item="path|with|pipes.exe",
        kind=ScanTargetKind.FILE,
        file_hash="c" * 64,
        malicious=0,
        suspicious=0,
        harmless=10,
        undetected=0,
        threat_level=ThreatLevel.CLEAN,
        status=ResultStatus.OK,
        message="",
    )
    out = tmp_path / "report.md"
    write_report([result], str(out), "md")
    assert r"path\|with\|pipes.exe" in out.read_text(encoding="utf-8")


def test_write_report_rejects_unknown_format(tmp_path) -> None:
    out = tmp_path / "report.bad"
    with pytest.raises(ValueError, match="Unsupported report format"):
        write_report(SAMPLE_RESULTS, str(out), "bad")
