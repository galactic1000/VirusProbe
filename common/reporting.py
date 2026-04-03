"""Report generation."""

from __future__ import annotations

import csv
import io
import json
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path

from .models import ScanResult, ThreatLevel


def build_summary(results: Sequence[ScanResult]) -> dict[str, int]:
    clean = suspicious = malicious = undetected = errors = cancelled = 0
    for result in results:
        match result.threat_level:
            case ThreatLevel.ERROR:
                errors += 1
            case ThreatLevel.CANCELLED:
                cancelled += 1
            case ThreatLevel.UNDETECTED:
                undetected += 1
            case ThreatLevel.MALICIOUS:
                malicious += 1
            case ThreatLevel.SUSPICIOUS:
                suspicious += 1
            case _:
                clean += 1
    return {
        "total": len(results),
        "clean": clean,
        "suspicious": suspicious,
        "malicious": malicious,
        "undetected": undetected,
        "errors": errors,
        "cancelled": cancelled,
    }


def _md_cell(value: object) -> str:
    return str(value).replace("|", "\\|")


def render_report_text(
    results: Sequence[ScanResult],
    report_format: str,
    separator_width: int = 72,
) -> str:
    if report_format not in {"csv", "json", "md", "txt"}:
        raise ValueError(f"Unsupported report format: {report_format}")
    if report_format == "csv":
        fieldnames = ["item", "type", "file_hash", "malicious", "suspicious", "harmless", "undetected", "threat_level", "status", "message"]
        with io.StringIO(newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(result.to_dict() for result in results)
            return f.getvalue()
    generated_at = datetime.now().isoformat(timespec="seconds")
    summary = build_summary(results)
    if report_format == "json":
        return json.dumps(
            {
                "generated_at": generated_at,
                "summary": summary,
                "results": [result.to_dict() for result in results],
            },
            indent=2,
        )
    if report_format == "md":
        lines = [
            "# Virus Scan Report",
            "",
            f"- Generated: {generated_at}",
            f"- Total: {summary['total']}",
            f"- Clean: {summary['clean']}",
            f"- Suspicious: {summary['suspicious']}",
            f"- Malicious: {summary['malicious']}",
            f"- Undetected: {summary['undetected']}",
            f"- Cancelled: {summary['cancelled']}",
            f"- Errors: {summary['errors']}",
            "",
            "## Results",
            "",
            "| Item | Type | Malicious | Suspicious | Harmless | Undetected | Verdict | Status |",
            "|---|---:|---:|---:|---:|---:|---|---|",
        ]
        for r in results:
            lines.append(
                f"| {_md_cell(r.item)} | {_md_cell(r.type)} | {r.malicious} | "
                f"{r.suspicious} | {r.harmless} | {r.undetected} | "
                f"{_md_cell(r.threat_level)} | {_md_cell(r.status)} |"
            )
        return "\n".join(lines) + "\n"
    lines = [
        "VIRUS SCAN REPORT",
        "=" * separator_width,
        f"Generated: {generated_at}",
        f"Total: {summary['total']}",
        f"Clean: {summary['clean']}",
        f"Suspicious: {summary['suspicious']}",
        f"Malicious: {summary['malicious']}",
        f"Undetected: {summary['undetected']}",
        f"Cancelled: {summary['cancelled']}",
        f"Errors: {summary['errors']}",
        "",
        "Results:",
        "-" * separator_width,
    ]
    for r in results:
        lines.append(
            f"{r.item} [{r.type}] - "
            f"M:{r.malicious} S:{r.suspicious} "
            f"H:{r.harmless} U:{r.undetected} "
            f"=> {r.threat_level} ({r.status})"
        )
    return "\n".join(lines) + "\n"


def write_report(
    results: Sequence[ScanResult],
    output_path: str,
    report_format: str,
    separator_width: int = 72,
) -> None:
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(
        render_report_text(results, report_format, separator_width),
        encoding="utf-8",
    )
