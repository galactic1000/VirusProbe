"""Shared report generation for CLI and future GUI."""

from __future__ import annotations

import csv
import json
from datetime import datetime
from pathlib import Path


def build_summary(results: list[dict]) -> dict[str, int]:
    """Builds aggregate counts for reporting."""
    clean = suspicious = malicious = undetected = 0
    for r in results:
        tl = r.get("threat_level")
        m = r.get("malicious", 0)
        if tl == "Undetected":
            undetected += 1
        elif m >= 10:
            malicious += 1
        elif m > 0:
            suspicious += 1
        else:
            clean += 1
    return {
        "total": len(results),
        "clean": clean,
        "suspicious": suspicious,
        "malicious": malicious,
        "undetected": undetected,
    }


def write_report(results: list[dict], output_path: str, report_format: str, separator_width: int = 72) -> None:
    """Writes scan results to file."""
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    summary = build_summary(results)
    generated_at = datetime.now().isoformat(timespec="seconds")

    if report_format == "json":
        output.write_text(
            json.dumps({"generated_at": generated_at, "summary": summary, "results": results}, indent=2),
            encoding="utf-8",
        )
        return

    if report_format == "csv":
        fieldnames = ["item", "type", "file_hash", "malicious", "suspicious", "harmless", "undetected", "threat_level", "status", "message"]
        with output.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for row in results:
                writer.writerow({k: row.get(k, "") for k in fieldnames})
        return

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
            "",
            "## Results",
            "",
            "| Item | Type | Malicious | Suspicious | Harmless | Undetected | Verdict | Status |",
            "|---|---:|---:|---:|---:|---:|---|---|",
        ]
        for r in results:
            lines.append(
                f"| {r.get('item', '')} | {r.get('type', '')} | {r.get('malicious', 0)} | "
                f"{r.get('suspicious', 0)} | {r.get('harmless', 0)} | {r.get('undetected', 0)} | "
                f"{r.get('threat_level', '')} | {r.get('status', '')} |"
            )
        output.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return

    lines = [
        "VIRUS SCAN REPORT",
        "=" * separator_width,
        f"Generated: {generated_at}",
        f"Total: {summary['total']}",
        f"Clean: {summary['clean']}",
        f"Suspicious: {summary['suspicious']}",
        f"Malicious: {summary['malicious']}",
        f"Undetected: {summary['undetected']}",
        "",
        "Results:",
        "-" * separator_width,
    ]
    for r in results:
        lines.append(
            f"{r.get('item', '')} [{r.get('type', '')}] - "
            f"M:{r.get('malicious', 0)} S:{r.get('suspicious', 0)} "
            f"H:{r.get('harmless', 0)} U:{r.get('undetected', 0)} "
            f"=> {r.get('threat_level', '')} ({r.get('status', '')})"
        )
    output.write_text("\n".join(lines) + "\n", encoding="utf-8")

