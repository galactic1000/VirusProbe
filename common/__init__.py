"""Shared scanning backend for CLI and future GUI."""

from .reporting import build_summary, write_report
from .service import ScannerService

__all__ = ["ScannerService", "build_summary", "write_report"]

