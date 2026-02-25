from __future__ import annotations

import csv
import json
from pathlib import Path

import pytest

from common.reporting import write_report


SAMPLE_RESULTS = [
    {
        "item": "SHA-256 Hash: " + "a" * 64,
        "type": "hash",
        "file_hash": "a" * 64,
        "malicious": 12,
        "suspicious": 1,
        "harmless": 0,
        "undetected": 0,
        "threat_level": "Malicious",
        "status": "ok",
        "message": "Queried VirusTotal API",
    },
    {
        "item": "SHA-256 Hash: " + "b" * 64,
        "type": "hash",
        "file_hash": "b" * 64,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 0,
        "undetected": 0,
        "threat_level": "Undetected",
        "status": "undetected",
        "message": "No VirusTotal record found",
    },
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


def test_write_report_txt(tmp_path) -> None:
    out = tmp_path / "report.txt"
    write_report(SAMPLE_RESULTS, str(out), "txt")
    text = out.read_text(encoding="utf-8")
    assert "VIRUS SCAN REPORT" in text
    assert "Total: 2" in text


def test_write_report_md(tmp_path) -> None:
    out = tmp_path / "report.md"
    write_report(SAMPLE_RESULTS, str(out), "md")
    text = out.read_text(encoding="utf-8")
    assert "# Virus Scan Report" in text
    assert "| Item | Type |" in text


def test_write_report_creates_parent_dirs(tmp_path) -> None:
    out = tmp_path / "nested" / "deep" / "report.json"
    write_report(SAMPLE_RESULTS, str(out), "json")
    assert out.exists()
    assert Path(out).parent.exists()


_ERROR_RESULT = {
    "item": "bad.exe",
    "type": "file",
    "file_hash": "",
    "malicious": 0,
    "suspicious": 0,
    "harmless": 0,
    "undetected": 0,
    "threat_level": "Error",
    "status": "error",
    "message": "File not found",
}


@pytest.mark.parametrize("fmt", ["md", "txt"])
def test_write_report_includes_errors_in_summary(tmp_path, fmt) -> None:
    out = tmp_path / f"report.{fmt}"
    write_report([_ERROR_RESULT], str(out), fmt)
    assert "Errors: 1" in out.read_text(encoding="utf-8")


def test_write_report_md_escapes_pipe_in_item(tmp_path) -> None:
    result = {
        "item": "path|with|pipes.exe",
        "type": "file",
        "file_hash": "c" * 64,
        "malicious": 0,
        "suspicious": 0,
        "harmless": 10,
        "undetected": 0,
        "threat_level": "Clean",
        "status": "ok",
        "message": "",
    }
    out = tmp_path / "report.md"
    write_report([result], str(out), "md")
    assert r"path\|with\|pipes.exe" in out.read_text(encoding="utf-8")
