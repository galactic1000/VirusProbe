"""Terminal display helpers for the VirusProbe CLI."""

from __future__ import annotations

import shutil

from colorama import Fore, Style

from common import ScanResult, build_summary
from common.models import ResultStatus, ScanTargetKind, ThreatLevel

TOOL_NAME = "VirusProbe"
TOOL_VERSION = "1.0.0"
TOOL_TAGLINE = "Malware Scanner Powered by VirusTotal"
BANNER_BORDER_CHAR = "#"
HEADER_BORDER_CHAR = "="
SUBSECTION_BORDER_CHAR = "-"


def _default_separator_width() -> int:
    # Keep output readable on smaller terminals and avoid very wide lines on large monitors.
    width = shutil.get_terminal_size(fallback=(95, 24)).columns
    return max(80, min(110, width))


SEPARATOR_WIDTH = _default_separator_width()


def format_colored(text: str, color: str) -> str:
    return f"{color}{text}{Style.RESET_ALL}"


def _line(char: str) -> str:
    return char * SEPARATOR_WIDTH


def _hash_frame_line() -> str:
    return "##" + (BANNER_BORDER_CHAR * max(SEPARATOR_WIDTH - 2, 0))


def _center_text(text: str, width: int) -> str:
    if len(text) >= width:
        return text
    left = (width - len(text)) // 2
    right = width - len(text) - left
    return (" " * left) + text + (" " * right)


def print_header(title: str, color: str = Fore.CYAN) -> None:
    print("\n" + _line(HEADER_BORDER_CHAR))
    print(format_colored(title, color))
    print(_line(HEADER_BORDER_CHAR))


def print_subsection(title: str, color: str = Fore.CYAN, leading_newline: bool = True) -> None:
    if leading_newline:
        print()
    print(_line(SUBSECTION_BORDER_CHAR))
    print(format_colored(title, color))
    print(_line(SUBSECTION_BORDER_CHAR))


def print_input_warnings(warnings: list[str]) -> None:
    if not warnings:
        return
    print_header("INPUT WARNINGS", Fore.YELLOW)
    for warning in warnings:
        print(format_colored(f"  - {warning}", Fore.YELLOW))


def print_banner() -> None:
    inner_width = max(SEPARATOR_WIDTH - 4, 0)
    title = _center_text(f"{TOOL_NAME} v{TOOL_VERSION}", inner_width)
    tagline = _center_text(f"[ {TOOL_TAGLINE} ]", inner_width)
    print()
    print(_hash_frame_line())
    print(format_colored(f"##{title}##", Fore.CYAN))
    print(format_colored(f"##{tagline}##", Fore.WHITE))
    print(_hash_frame_line())


def _verdict_color(threat_level: ThreatLevel) -> str:
    match threat_level:
        case ThreatLevel.CANCELLED:
            return Fore.MAGENTA
        case ThreatLevel.MALICIOUS:
            return Fore.RED
        case ThreatLevel.SUSPICIOUS:
            return Fore.YELLOW
        case ThreatLevel.UNDETECTED:
            return Fore.CYAN
        case _:
            return Fore.GREEN


def _item_label(result: ScanResult) -> str:
    item = result.item
    if result.kind is ScanTargetKind.FILE:
        return f"File path: {item}"
    elif result.kind is ScanTargetKind.HASH:
        return f"SHA-256 hash: {result.file_hash}" if result.file_hash else item
    return item


def print_result(result: ScanResult, index: int | None = None, total: int | None = None) -> None:
    scan_type = "SHA-256 HASH SCAN" if result.kind is ScanTargetKind.HASH else "FILE SCAN"
    if index is not None and total is not None:
        print_header(f"ITEM {index}/{total} - {scan_type}", Fore.BLUE)
    elif index is not None:
        print_header(f"ITEM {index} - {scan_type}", Fore.BLUE)
    else:
        print_header(scan_type, Fore.BLUE)
    if result.kind is ScanTargetKind.FILE:
        print(f"File path: {result.item}")
        if result.file_hash:
            print(f"SHA-256 hash: {result.file_hash}")
    else:
        print(f"SHA-256 hash: {result.file_hash}")

    match result.status:
        case ResultStatus.UNDETECTED:
            if result.was_cached:
                print("\n" + format_colored(result.message or "Using cached result", Fore.CYAN))
                print()
            else:
                print()
            print(format_colored("Undetected: No VirusTotal record found", Fore.YELLOW))
            return
        case ResultStatus.CANCELLED:
            print("\n" + format_colored("Cancelled by user", Fore.MAGENTA))
            return
        case ResultStatus.ERROR:
            print("\n" + format_colored(f"Error: {result.message or 'Unexpected error'}", Fore.RED))
            return

    if result.was_uploaded:
        msg_color = Fore.MAGENTA
    elif result.was_cached:
        msg_color = Fore.CYAN
    else:
        msg_color = Fore.BLUE
    print("\n" + format_colored(result.message, msg_color))
    detection_total = result.malicious + result.suspicious + result.harmless + result.undetected
    print_subsection("DETECTION RESULTS", Fore.WHITE)
    print(f"   Malicious:  {format_colored(str(result.malicious), Fore.RED)}")
    print(f"   Suspicious: {format_colored(str(result.suspicious), Fore.YELLOW)}")
    print(f"   Harmless:   {format_colored(str(result.harmless), Fore.GREEN)}")
    print(f"   Undetected: {result.undetected}")
    print(f"   Total:      {detection_total}")
    threat = result.threat_level
    print(f"\nVerdict: {format_colored(threat, _verdict_color(threat))}")


def print_scan_summary(results: list[ScanResult]) -> None:
    if not results:
        return
    summary = build_summary(results)
    buckets: dict[ThreatLevel, list[ScanResult]] = {ThreatLevel.ERROR: [], ThreatLevel.CANCELLED: [], ThreatLevel.UNDETECTED: [], ThreatLevel.SUSPICIOUS: [], ThreatLevel.MALICIOUS: []}
    for r in results:
        if r.threat_level in buckets:
            buckets[r.threat_level].append(r)
    error_items = buckets[ThreatLevel.ERROR]
    cancelled_items = buckets[ThreatLevel.CANCELLED]
    undetected_items = buckets[ThreatLevel.UNDETECTED]
    suspicious_items = buckets[ThreatLevel.SUSPICIOUS]
    malicious_items = buckets[ThreatLevel.MALICIOUS]

    print()
    print(_line(HEADER_BORDER_CHAR))
    print(format_colored("FINAL SCAN SUMMARY", Fore.CYAN))
    print(_line(HEADER_BORDER_CHAR))
    parts = [
        f"Total: {summary['total']}",
        format_colored(f"Malicious: {summary['malicious']}", Fore.RED),
        format_colored(f"Suspicious: {summary['suspicious']}", Fore.YELLOW),
        format_colored(f"Clean: {summary['clean']}", Fore.GREEN),
        format_colored(f"Undetected: {summary['undetected']}", Fore.CYAN),
    ]
    if summary["cancelled"]:
        parts.append(format_colored(f"Cancelled: {summary['cancelled']}", Fore.MAGENTA))
    if summary["errors"]:
        parts.append(format_colored(f"Errors: {summary['errors']}", Fore.RED))
    print(" | ".join(parts))
    if malicious_items or suspicious_items or undetected_items or cancelled_items or error_items:
        print()

    if malicious_items:
        print_subsection("MALICIOUS ITEMS", Fore.RED, leading_newline=False)
        for item in malicious_items:
            print(f"  - {_item_label(item)} ({item.malicious} detections)")
    if suspicious_items:
        print_subsection("SUSPICIOUS ITEMS", Fore.YELLOW, leading_newline=False)
        for item in suspicious_items:
            detections = item.malicious + item.suspicious
            print(f"  - {_item_label(item)} ({detections} detections)")
    if undetected_items:
        print_subsection("UNDETECTED ITEMS", Fore.CYAN, leading_newline=False)
        for item in undetected_items:
            print(f"  - {_item_label(item)} (No VirusTotal record found)")
    if cancelled_items:
        print_subsection("CANCELLED ITEMS", Fore.MAGENTA, leading_newline=False)
        for item in cancelled_items:
            print(f"  - {_item_label(item)}")
    if error_items:
        print_subsection("ERRORS", Fore.RED, leading_newline=False)
        for item in error_items:
            print(f"  - {_item_label(item)} ({item.message or 'Unexpected error'})")

    print()
    print(HEADER_BORDER_CHAR * SEPARATOR_WIDTH + "\n")
