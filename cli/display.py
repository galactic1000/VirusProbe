"""Terminal display helpers for the VirusProbe CLI."""

from __future__ import annotations

import shutil

from colorama import Fore, Style

from common import build_summary

TOOL_NAME = "VirusProbe"
TOOL_VERSION = "1.0.0"
TOOL_TAGLINE = "VirusTotal Scanner"
BANNER_BORDER_CHAR = "#"
HEADER_BORDER_CHAR = "="
SECTION_BORDER_CHAR = "-"
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


def print_section(title: str, color: str = Fore.CYAN) -> None:
    print("\n" + _line(SECTION_BORDER_CHAR))
    print(format_colored(title, color))
    print(_line(SECTION_BORDER_CHAR))


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


def _verdict_color(threat_level: str) -> str:
    if threat_level == "Cancelled":
        return Fore.MAGENTA
    if threat_level == "Malicious":
        return Fore.RED
    if threat_level == "Suspicious":
        return Fore.YELLOW
    if threat_level == "Undetected":
        return Fore.CYAN
    return Fore.GREEN


def _item_label(result: dict) -> str:
    item = str(result.get("item", ""))
    if result.get("type") == "file":
        return f"File path: {item}"
    if result.get("type") == "hash":
        return f"SHA-256 hash: {result.get('file_hash', item)}"
    return item


def print_result(result: dict, index: int | None = None, total: int | None = None) -> None:
    scan_type = "SHA-256 HASH SCAN" if result.get("type") == "hash" else "FILE SCAN"
    if index is not None and total is not None:
        print_header(f"ITEM {index}/{total} - {scan_type}", Fore.BLUE)
    elif index is not None:
        print_header(f"ITEM {index} - {scan_type}", Fore.BLUE)
    else:
        print_header(scan_type, Fore.BLUE)
    if result.get("type") == "file":
        print(f"File path: {result.get('item', '')}")
        if result.get("file_hash"):
            print(f"SHA-256 hash: {result['file_hash']}")
    else:
        print(f"SHA-256 hash: {result.get('file_hash', '')}")

    if result.get("status") == "undetected":
        print("\n" + format_colored("Undetected: No VirusTotal record found", Fore.YELLOW))
        return
    if result.get("status") == "cancelled":
        print("\n" + format_colored("Cancelled by user", Fore.MAGENTA))
        return
    if result.get("status") == "error":
        print("\n" + format_colored(f"Error: {result.get('message', 'Unexpected error')}", Fore.RED))
        return

    if result.get("was_uploaded"):
        msg_color = Fore.MAGENTA
    elif result.get("was_cached"):
        msg_color = Fore.CYAN
    else:
        msg_color = Fore.BLUE
    print("\n" + format_colored(result.get("message", ""), msg_color))
    detection_total = (
        result.get("malicious", 0) + result.get("suspicious", 0)
        + result.get("harmless", 0) + result.get("undetected", 0)
    )
    print_subsection("DETECTION RESULTS", Fore.WHITE)
    print(f"   Malicious:  {format_colored(str(result.get('malicious', 0)), Fore.RED)}")
    print(f"   Suspicious: {format_colored(str(result.get('suspicious', 0)), Fore.YELLOW)}")
    print(f"   Harmless:   {format_colored(str(result.get('harmless', 0)), Fore.GREEN)}")
    print(f"   Undetected: {result.get('undetected', 0)}")
    print(f"   Total:      {detection_total}")
    threat = result.get("threat_level", "Clean")
    print(f"\nVerdict: {format_colored(threat, _verdict_color(threat))}")


def print_scan_summary(results: list[dict]) -> None:
    if not results:
        return
    summary = build_summary(results)
    error_items = [r for r in results if r.get("threat_level") == "Error"]
    cancelled_items = [r for r in results if r.get("threat_level") == "Cancelled"]
    undetected_items = [r for r in results if r.get("threat_level") == "Undetected"]
    suspicious_items = [r for r in results if r.get("threat_level") == "Suspicious"]
    malicious_items = [r for r in results if r.get("threat_level") == "Malicious"]

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
            print(f"  - {_item_label(item)} ({item.get('malicious', 0)} detections)")
    if suspicious_items:
        print_subsection("SUSPICIOUS ITEMS", Fore.YELLOW, leading_newline=False)
        for item in suspicious_items:
            detections = int(item.get("malicious", 0)) + int(item.get("suspicious", 0))
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
            print(f"  - {_item_label(item)} ({item.get('message', 'Unexpected error')})")

    print()
    print(HEADER_BORDER_CHAR * SEPARATOR_WIDTH + "\n")
