"""CLI frontend for VirusProbe."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

from colorama import Fore, init

from common import ScannerService, get_api_key, remove_api_key_from_env, save_api_key_to_env, write_report
from common.service import DEFAULT_REQUESTS_PER_MINUTE, DEFAULT_SCAN_WORKERS
from .display import (
    BANNER_BORDER_CHAR,
    SEPARATOR_WIDTH,
    TOOL_VERSION,
    _line,
    format_colored,
    print_banner,
    print_result,
    print_run_context,
    print_scan_summary,
)

init(autoreset=True)

CACHE_DB = Path(__file__).resolve().parents[1] / "cache" / "vt_cache.db"
_OUTPUT_AUTO = "__AUTO_OUTPUT__"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="VirusProbe - scan files or SHA-256 hashes using VirusTotal",
        add_help=True,
    )
    parser.add_argument("-f", "--file", "--files", dest="files", nargs="+", help="One or more file paths to scan")
    parser.add_argument("-s", "--hash", "--hashes", dest="hashes", nargs="+", help="One or more SHA-256 hashes to scan")
    parser.add_argument("-d", "--directory", "--dir", help="Scan all files in a directory")
    parser.add_argument("-r", "--recursive", action="store_true", help="When using --directory, scan subdirectories recursively")
    parser.add_argument(
        "-o",
        "--output",
        nargs="?",
        const=_OUTPUT_AUTO,
        metavar="OUTPUT",
        help="Write report to file (default: scan_report_YYYYMMDD_HHMMSS.<format>)",
    )
    parser.add_argument("--format", choices=["json", "csv", "txt", "md"], help="Report format for report output (default: json)")
    parser.add_argument("--workers", type=int, default=None, metavar="WORKERS", help="Concurrent scan workers (default: matches --requests-per-minute)")
    parser.add_argument(
        "--requests-per-minute",
        type=int,
        default=DEFAULT_REQUESTS_PER_MINUTE,
        metavar="N",
        help=f"Max VirusTotal API requests per minute (default: {DEFAULT_REQUESTS_PER_MINUTE}, 0 = unlimited)",
    )
    parser.add_argument("--api-key", help="VirusTotal API key (overrides env/.env)")
    parser.add_argument("--save-api-key", action="store_true", help="Save --api-key into .env for future runs")
    parser.add_argument("--clear-api-key", action="store_true", help="Remove saved API key from .env")
    parser.add_argument("--clear-cache", action="store_true", help="Clear local SQLite scan cache")
    parser.add_argument("--version", action="version", version=f"VirusProbe {TOOL_VERSION}")
    return parser


def _handle_admin_actions(
    parser: argparse.ArgumentParser,
    args: argparse.Namespace,
    explicit_api_key: str,
    workers: int,
) -> bool:
    has_admin_action = args.save_api_key or args.clear_api_key or args.clear_cache

    if args.save_api_key and args.clear_api_key:
        parser.error("Use only one of --save-api-key or --clear-api-key")
    if args.save_api_key and not explicit_api_key:
        parser.error("--save-api-key requires --api-key")

    if args.save_api_key:
        save_api_key_to_env(explicit_api_key)
        print("Saved API key to .env")

    if args.clear_api_key:
        removed = remove_api_key_from_env()
        print("Removed saved API key from .env" if removed else "No saved API key found")

    if args.clear_cache:
        cache_service = ScannerService(api_key=explicit_api_key or get_api_key() or "", cache_db=CACHE_DB, max_workers=workers)
        try:
            deleted = cache_service.clear_cache()
        finally:
            cache_service.close()
        print(f"Cleared SQLite cache ({deleted} entr{'y' if deleted == 1 else 'ies'}).")

    return has_admin_action


def _filter_existing_files(files: list[str]) -> list[str]:
    valid_files: list[str] = []
    for file_path in files:
        path_obj = Path(file_path)
        if not path_obj.exists():
            print(format_colored(f"Skipping missing file: {file_path}", Fore.RED))
        elif not path_obj.is_file():
            print(format_colored(f"Skipping non-file path: {file_path}", Fore.RED))
        else:
            valid_files.append(file_path)
    return valid_files


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()
    explicit_api_key = (args.api_key or "").strip()
    scan_requested = bool(args.directory or args.files or args.hashes)
    report_format = args.format or "json"
    if args.output == _OUTPUT_AUTO:
        args.output = f"scan_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.{report_format}"

    if args.requests_per_minute < 0:
        parser.error("--requests-per-minute must be >= 0")
    if args.workers is None:
        args.workers = args.requests_per_minute if args.requests_per_minute > 0 else DEFAULT_SCAN_WORKERS
    if args.workers < 1:
        parser.error("--workers must be >= 1")

    has_admin_action = _handle_admin_actions(parser, args, explicit_api_key, args.workers)
    if has_admin_action and not scan_requested:
        return

    if args.recursive and not args.directory:
        parser.error("--recursive can only be used with --directory")
    if args.directory and args.files:
        parser.error("Use either --directory OR --file inputs, not both")
    if not scan_requested:
        parser.error("Provide one mode: -d <directory> (optionally with -s), OR -f <file1> [file2 ...], OR -s <hash1> [hash2 ...]")

    api_key = explicit_api_key or get_api_key()
    if not api_key:
        parser.error("VirusTotal API key is required. Set VT_API_KEY or VIRUSTOTAL_API_KEY (env or .env file).")

    print_banner()
    print_run_context(f"RUN CONTEXT: {'Directory Scan' if args.directory else 'Item Scan'}", Fore.CYAN)
    if args.requests_per_minute > 0 and args.workers > args.requests_per_minute:
        print(format_colored(
            f"Note: {args.workers} workers but only {args.requests_per_minute} requests/min — "
            f"extra workers will idle waiting for API slots. Consider --workers {args.requests_per_minute}.",
            Fore.YELLOW,
        ))
    if args.output:
        print(format_colored(f"Report: {args.output} ({report_format})", Fore.CYAN))

    # Pre-collect scan targets to know the total count upfront and enable streaming output.
    dir_files: list[str] = []
    _dir_valid = False
    if args.directory:
        _dp = Path(args.directory)
        _dir_valid = _dp.exists() and _dp.is_dir()
        if _dir_valid:
            dir_files = [str(f) for f in (_dp.rglob("*") if args.recursive else _dp.iterdir()) if f.is_file()]
    file_list = _filter_existing_files(args.files) if args.files else []
    hash_list = args.hashes or []
    total = len(dir_files) + len(file_list) + len(hash_list)
    if args.directory and not _dir_valid:
        total += 1  # scan_directory returns one error result for a bad path

    completed = [0]

    def on_result(result: dict) -> None:
        completed[0] += 1
        print_result(result, index=completed[0], total=total)

    results: list[dict] = []
    service = ScannerService(api_key=api_key, cache_db=CACHE_DB, max_workers=args.workers, requests_per_minute=args.requests_per_minute)
    try:
        service.init_cache()

        if args.directory:
            results.extend(service.scan_directory(args.directory, recursive=args.recursive, on_result=on_result))
        if file_list:
            results.extend(service.scan_files(file_list, on_result=on_result))
        if hash_list:
            results.extend(service.scan_hashes(hash_list, on_result=on_result))
        if not results:
            return

        print()
        print(_line(BANNER_BORDER_CHAR))
        print_scan_summary(results)
        if args.output:
            write_report(results, args.output, report_format, separator_width=SEPARATOR_WIDTH)
            print(format_colored(f"Report saved to {args.output}", Fore.CYAN))
    finally:
        service.close()

    if any(r.get("status") == "error" for r in results):
        sys.exit(1)


if __name__ == "__main__":
    main()
