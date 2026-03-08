"""Shared VirusTotal API error classification."""

from __future__ import annotations


BATCH_FATAL_API_ERROR_CODES = frozenset({
    "QuotaExceededError",
    "WrongCredentialsError",
    "UnauthorizedError",
    "ForbiddenError",
})
