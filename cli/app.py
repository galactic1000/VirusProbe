"""CLI frontend for VirusProbe."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

from colorama import Fore, Style, init

from common import ScannerService, build_summary, write_report

init(autoreset=True)

TOOL_NAME = "VirusProbe"
TOOL_VERSION = "1.0"
TOOL_TAGLINE = "VirusTotal Scanner"
SEPARATOR_WIDTH = 96
BANNER_BORDER_CHAR = "#"
HEADER_BORDER_CHAR = "="
SECTION_BORDER_CHAR = "-"
SUBSECTION_BORDER_CHAR = "."
CACHE_DB = Path(__file__).resolve().parents[1] / "cache" / "vt_cache.db"
DOTENV_PATH = Path(__file__).resolve().parents[1] / ".env"
API_KEY_ENV_VARS = ("VT_API_KEY", "VIRUSTOTAL_API_KEY")


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


def print_banner() -> None:
    inner_width = max(SEPARATOR_WIDTH - 4, 0)
    title = _center_text(f"{TOOL_NAME} v{TOOL_VERSION}", inner_width)
    tagline = _center_text(f"[ {TOOL_TAGLINE} ]", inner_width)
    print("\n" + _hash_frame_line())
    print(_hash_frame_line())
    print(format_colored(f"##{title}##", Fore.CYAN))
    print(format_colored(f"##{tagline}##", Fore.WHITE))
    print(_hash_frame_line())
    print(_hash_frame_line() + "\n")


def print_run_context(title: str, color: str = Fore.CYAN) -> None:
    print()
    print(_hash_frame_line())
    print(format_colored(title, color))
    print(_hash_frame_line())


def _verdict_color(threat_level: str) -> str:
    if threat_level == "Malicious":
        return Fore.RED
    if threat_level == "Suspicious":
        return Fore.YELLOW
    if threat_level == "Undetected":
        return Fore.CYAN
    return Fore.GREEN


def print_result(result: dict, index: int | None = None, total: int | None = None) -> None:
    scan_type = "SHA-256 HASH SCAN" if result.get("type") == "hash" else "FILE SCAN"
    if index is not None and total is not None:
        print_header(f"ITEM {index}/{total} - {scan_type}", Fore.BLUE)
    else:
        print_section(scan_type, Fore.BLUE)
    if result.get("type") == "file":
        print(f"Path: {result.get('item', '')}")
        if result.get("file_hash"):
            print(f"SHA-256 Hash: {result['file_hash']}")
    else:
        print(f"SHA-256 Hash: {result.get('file_hash', '')}")

    if result.get("status") == "undetected":
        print("\n" + format_colored("Undetected: No VirusTotal record found", Fore.YELLOW))
        return
    if result.get("status") == "error":
        print("\n" + format_colored(f"Error: {result.get('message', 'Unknown error')}", Fore.RED))
        return

    print("\n" + format_colored(result.get("message", ""), Fore.CYAN if result.get("was_cached") else Fore.BLUE))
    detection_total = result.get("malicious", 0) + result.get("suspicious", 0) + result.get("harmless", 0) + result.get("undetected", 0)
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
    undetected_items = [r for r in results if r.get("threat_level") == "Undetected"]
    suspicious_items = [r for r in results if 0 < r.get("malicious", 0) < 10]
    malicious_items = [r for r in results if r.get("malicious", 0) >= 10]

    print("\n")
    print(_line(BANNER_BORDER_CHAR))
    print(format_colored("FINAL SCAN SUMMARY", Fore.CYAN))
    print(_line(BANNER_BORDER_CHAR))
    print(
        " | ".join(
            [
                f"Total: {summary['total']}",
                format_colored(f"Malicious: {summary['malicious']}", Fore.RED),
                format_colored(f"Suspicious: {summary['suspicious']}", Fore.YELLOW),
                format_colored(f"Clean: {summary['clean']}", Fore.GREEN),
                format_colored(f"Undetected: {summary['undetected']}", Fore.CYAN),
            ]
        )
    )
    if malicious_items or suspicious_items or undetected_items:
        print()

    if malicious_items:
        print_subsection("MALICIOUS ITEMS", Fore.RED, leading_newline=False)
        for item in malicious_items:
            print(f"  - {item.get('item', '')} ({item.get('malicious', 0)} detections)")
    if suspicious_items:
        print_subsection("SUSPICIOUS ITEMS", Fore.YELLOW, leading_newline=False)
        for item in suspicious_items:
            print(f"  - {item.get('item', '')} ({item.get('malicious', 0)} detections)")
    if undetected_items:
        print_subsection("UNDETECTED ITEMS", Fore.CYAN, leading_newline=False)
        for item in undetected_items:
            print(f"  - {item.get('item', '')} (No VirusTotal record found)")

    print()
    print(_line(BANNER_BORDER_CHAR))
    print()


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=f"{TOOL_NAME} - scan files or SHA-256 Hashes using VirusTotal",
        add_help=False,
    )
    parser.add_argument("--help", action="help", help="Show this help message and exit")
    parser.add_argument("-f", "--file", "--files", dest="files", nargs="+", help="One or more file paths to scan")
    parser.add_argument("-h", "--hash", "--hashes", dest="hashes", nargs="+", help="One or more SHA-256 Hashes to scan")
    parser.add_argument("-d", "--directory", "--dir", help="Scan all files in a directory")
    parser.add_argument("-r", "--recursive", action="store_true", help="When using --directory, scan subdirectories recursively")
    parser.add_argument("-o", "--output", help="Write report to file")
    parser.add_argument("--format", choices=["json", "csv", "txt", "md"], default="json", help="Report format for --output (default: json)")
    parser.add_argument("--api-key", help="VirusTotal API key (overrides env/.env)")
    parser.add_argument("--save-api-key", action="store_true", help="Save --api-key into .env for future runs")
    parser.add_argument("--clear-api-key", action="store_true", help="Remove saved API key from .env")
    parser.add_argument("--clear-cache", action="store_true", help="Clear local SQLite scan cache")
    return parser


def _load_dotenv(dotenv_path: Path) -> None:
    """Loads environment variables from a local .env file if present."""
    if not dotenv_path.exists():
        return
    for raw_line in dotenv_path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _get_api_key() -> str | None:
    """Gets API key from environment or .env fallback."""
    _load_dotenv(DOTENV_PATH)
    for var_name in API_KEY_ENV_VARS:
        value = os.environ.get(var_name, "").strip()
        if value:
            return value
    return None


def _save_api_key_to_env(api_key: str) -> None:
    lines: list[str] = []
    if DOTENV_PATH.exists():
        lines = DOTENV_PATH.read_text(encoding="utf-8").splitlines()
    updated = False
    out: list[str] = []
    for line in lines:
        stripped = line.strip()
        if any(stripped.startswith(f"{name}=") for name in API_KEY_ENV_VARS):
            if not updated:
                out.append(f"VT_API_KEY={api_key}")
                updated = True
            continue
        out.append(line)
    if not updated:
        out.append(f"VT_API_KEY={api_key}")
    DOTENV_PATH.write_text("\n".join(out).rstrip() + "\n", encoding="utf-8")
    os.environ["VT_API_KEY"] = api_key


def _remove_api_key_from_env() -> bool:
    if not DOTENV_PATH.exists():
        for name in API_KEY_ENV_VARS:
            os.environ.pop(name, None)
        return False
    lines = DOTENV_PATH.read_text(encoding="utf-8").splitlines()
    out = [
        line
        for line in lines
        if not any(line.strip().startswith(f"{name}=") for name in API_KEY_ENV_VARS)
    ]
    if out:
        DOTENV_PATH.write_text("\n".join(out).rstrip() + "\n", encoding="utf-8")
    else:
        DOTENV_PATH.unlink(missing_ok=True)
    for name in API_KEY_ENV_VARS:
        os.environ.pop(name, None)
    return True


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    explicit_api_key = (args.api_key or "").strip()
    scan_requested = bool(args.directory or args.files or args.hashes)

    if args.save_api_key and args.clear_api_key:
        parser.error("Use only one of --save-api-key or --clear-api-key")
    if args.save_api_key and not explicit_api_key:
        parser.error("--save-api-key requires --api-key")
    if args.save_api_key:
        _save_api_key_to_env(explicit_api_key)
        print("Saved API key to .env")
    if args.clear_api_key:
        removed = _remove_api_key_from_env()
        print("Removed saved API key from .env" if removed else "No saved API key found")
    if args.clear_cache:
        cache_service = ScannerService(api_key=explicit_api_key or _get_api_key() or "", cache_db=CACHE_DB)
        deleted = cache_service.clear_cache()
        print(f"Cleared SQLite cache ({deleted} entr{'y' if deleted == 1 else 'ies'}).")
    if (args.save_api_key or args.clear_api_key or args.clear_cache) and not scan_requested:
        return

    api_key = explicit_api_key or _get_api_key()

    if args.recursive and not args.directory:
        parser.error("--recursive can only be used with --directory")
    if args.directory and args.files:
        parser.error("Use either --directory OR --file inputs, not both")
    if not scan_requested:
        parser.error("Provide one mode: -d <directory> (optionally with -h), OR -f <file1> [file2 ...], OR -h <hash1> [hash2 ...]")
    if not api_key:
        parser.error("VirusTotal API key is required. Set VT_API_KEY or VIRUSTOTAL_API_KEY (env or .env file).")

    print_banner()
    run_mode = "Directory Scan" if args.directory else "Item Scan"
    print_run_context(f"RUN CONTEXT: {run_mode}", Fore.CYAN)
    if args.output:
        print(format_colored(f"Report: {args.output} ({args.format})", Fore.CYAN))

    service = ScannerService(api_key=api_key, cache_db=CACHE_DB)
    service.init_cache()

    results: list[dict] = []
    if args.directory:
        results.extend(service.scan_directory(args.directory, recursive=args.recursive))

    if args.files:
        valid_files: list[str] = []
        for file_path in args.files:
            path_obj = Path(file_path)
            if not path_obj.exists():
                print(format_colored(f"Skipping missing file: {file_path}", Fore.RED))
                continue
            if not path_obj.is_file():
                print(format_colored(f"Skipping non-file path: {file_path}", Fore.RED))
                continue
            valid_files.append(file_path)
        results.extend(service.scan_file(file_path) for file_path in valid_files)

    if args.hashes:
        results.extend(service.scan_hash(h) for h in args.hashes)

    if results:
        for idx, result in enumerate(results, start=1):
            print_result(result, index=idx, total=len(results))
        print()
        print(_line(BANNER_BORDER_CHAR))
        print_scan_summary(results)
        if args.output:
            write_report(results, args.output, args.format, separator_width=SEPARATOR_WIDTH)
            print(format_colored(f"Report saved to {args.output}", Fore.CYAN))


if __name__ == "__main__":
    main()
