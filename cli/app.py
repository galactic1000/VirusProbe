"""CLI frontend for VirusProbe."""

from __future__ import annotations

import argparse
import fnmatch
import sys
import threading
from datetime import datetime
from pathlib import Path

from colorama import Fore, init

from common import ScannerService, get_api_key, remove_api_key_from_env, save_api_key_to_env, write_report
from common.service import DEFAULT_REQUESTS_PER_MINUTE, DEFAULT_SCAN_WORKERS
from .display import (
    SEPARATOR_WIDTH,
    TOOL_VERSION,
    format_colored,
    print_banner,
    print_input_warnings,
    print_result,
    print_scan_summary,
)

init(autoreset=True)

CACHE_DB = Path(__file__).resolve().parents[1] / "cache" / "vt_cache.db"
_OUTPUT_AUTO = "__AUTO_OUTPUT__"


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="VirusProbe - scan files or SHA-256 hashes using VirusTotal",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python cli.py -f sample.exe\n"
            "  python cli.py -d ./samples -r --upload --upload-filter *.exe *.dll\n"
            "  python cli.py -s <sha256> --requests-per-minute 10 --workers 4\n"
            "  python cli.py -f sample.exe -o --format md"
        ),
        add_help=True,
    )
    targets = parser.add_argument_group("Scan Targets")
    targets.add_argument("-f", "--file", "--files", dest="files", nargs="+", metavar="FILE", help="One or more file paths to scan")
    targets.add_argument("-s", "--hash", "--hashes", dest="hashes", nargs="+", metavar="SHA256", help="One or more SHA-256 hashes to scan")
    targets.add_argument("-d", "--directory", "--dir", metavar="DIR", help="Scan all files in a directory")
    targets.add_argument("-r", "--recursive", action="store_true", help="When using --directory, scan subdirectories recursively")

    upload = parser.add_argument_group("Upload Options")
    upload.add_argument(
        "-u", "--upload",
        action="store_true",
        help="Upload files not found in VirusTotal and wait for analysis results (uses extra API quota)",
    )
    upload.add_argument(
        "--upload-filter",
        nargs="+",
        metavar="GLOB",
        help="Only upload undetected files matching glob patterns (filename: *.exe; path: */src/*.dll). Requires --upload.",
    )

    output = parser.add_argument_group("Output")
    output.add_argument(
        "-o",
        "--output",
        nargs="?",
        const=_OUTPUT_AUTO,
        metavar="OUTPUT",
        help="Write report to file (default: scan_report_YYYYMMDD_HHMMSS.<format>)",
    )
    output.add_argument("--format", choices=["json", "csv", "txt", "md"], help="Report format when writing a report (default: json)")

    perf = parser.add_argument_group("Performance")
    perf.add_argument("-w", "--workers", type=int, default=None, metavar="WORKERS", help="Concurrent scan workers (default: matches --requests-per-minute)")
    perf.add_argument(
        "--rpm",
        "--requests-per-minute",
        dest="requests_per_minute",
        type=int,
        default=DEFAULT_REQUESTS_PER_MINUTE,
        metavar="N",
        help=f"Max VirusTotal API requests per minute (default: {DEFAULT_REQUESTS_PER_MINUTE}, 0 = unlimited)",
    )

    admin = parser.add_argument_group("API Key / Cache")
    admin.add_argument("--api-key", metavar="KEY", help="VirusTotal API key (overrides env/.env)")
    admin.add_argument("--save-api-key", action="store_true", help="Save --api-key into .env for future runs")
    admin.add_argument("--clear-api-key", action="store_true", help="Remove saved API key from .env")
    admin.add_argument("--clear-cache", action="store_true", help="Clear local SQLite scan cache")
    admin.add_argument("--version", action="version", version=f"VirusProbe {TOOL_VERSION}")
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


def _build_upload_filter(patterns: list[str]):
    """Returns a callable that returns True if a file path matches any of the glob patterns.

    Patterns without path separators (e.g. *.exe) are matched against the filename only.
    Patterns with separators are path globs matched against the resolved absolute path.
    """
    simple: list[str] = []
    path_pats: list[str] = []
    for pat in patterns:
        if "/" in pat or "\\" in pat:
            path_pats.append(pat)
        else:
            simple.append(pat)

    def _matches(file_path: str) -> bool:
        p = Path(file_path).resolve()
        name = p.name
        abs_norm = str(p).replace("\\", "/")
        for pat in simple:
            if fnmatch.fnmatch(name, pat):
                return True
        for pat in path_pats:
            pat_norm = pat.replace("\\", "/")
            if fnmatch.fnmatch(abs_norm, pat_norm):
                return True
        return False

    return _matches


def _filter_existing_files(files: list[str]) -> tuple[list[str], list[str]]:
    valid_files: list[str] = []
    warnings: list[str] = []
    for file_path in files:
        path_obj = Path(file_path)
        if not path_obj.exists():
            warnings.append(f"Skipping missing file: {file_path}")
        elif not path_obj.is_file():
            warnings.append(f"Skipping non-file path: {file_path}")
        else:
            valid_files.append(file_path)
    return valid_files, warnings


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
    if args.requests_per_minute > 0 and args.workers > args.requests_per_minute:
        print(format_colored(
            f"Note: {args.workers} workers but only {args.requests_per_minute} requests/min -- "
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
    file_list: list[str] = []
    input_warnings: list[str] = []
    if args.files:
        file_list, input_warnings = _filter_existing_files(args.files)
        if input_warnings:
            print_input_warnings(input_warnings)
    hash_list = args.hashes or []
    total = len(dir_files) + len(file_list) + len(hash_list)
    if args.directory and not _dir_valid:
        total += 1  # scan_directory returns one error result for a bad path

    completed = [0]
    results: list[dict] = []

    def on_result(result: dict) -> None:
        results.append(result)
        completed[0] += 1
        print_result(result, index=completed[0], total=total)

    if args.upload_filter and not args.upload:
        parser.error("--upload-filter requires --upload")
    upload_filter = _build_upload_filter(args.upload_filter) if args.upload_filter else None
    if args.upload:
        if args.upload_filter:
            print(format_colored(f"Upload mode: undetected files matching {args.upload_filter} will be submitted to VirusTotal.", Fore.YELLOW))
        else:
            print(format_colored("Upload mode: undetected files will be submitted to VirusTotal for scanning.", Fore.YELLOW))
    service = ScannerService(api_key=api_key, cache_db=CACHE_DB, max_workers=args.workers, requests_per_minute=args.requests_per_minute, upload_undetected=args.upload, upload_filter=upload_filter)
    cancel_event = threading.Event()
    cancelled = False
    try:
        service.init_cache()

        def _run_scan(call):
            before_results = len(results)
            before_completed = completed[0]
            batch = call()
            if len(results) == before_results and isinstance(batch, list) and batch:
                results.extend(batch)
                if completed[0] == before_completed:
                    for item in batch:
                        completed[0] += 1
                        print_result(item, index=completed[0], total=total)

        try:
            if args.directory:
                _run_scan(lambda: service.scan_directory(args.directory, recursive=args.recursive, on_result=on_result, cancel_event=cancel_event))
            if file_list and not cancel_event.is_set():
                _run_scan(lambda: service.scan_files(file_list, on_result=on_result, cancel_event=cancel_event))
            if hash_list and not cancel_event.is_set():
                _run_scan(lambda: service.scan_hashes(hash_list, on_result=on_result, cancel_event=cancel_event))
        except KeyboardInterrupt:
            cancel_event.set()
            cancelled = True
            print(format_colored("Cancellation requested. Finishing in-flight work...", Fore.YELLOW))
        if not results:
            if cancelled:
                sys.exit(130)
            return

        print_scan_summary(results)
        if args.output:
            write_report(results, args.output, report_format, separator_width=SEPARATOR_WIDTH)
            print(format_colored(f"Report saved to {args.output}", Fore.CYAN))
    finally:
        service.close()

    if cancelled:
        sys.exit(130)
    if any(r.get("status") == "error" for r in results):
        sys.exit(1)
