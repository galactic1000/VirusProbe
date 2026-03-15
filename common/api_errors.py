"""Shared VirusTotal API error classification."""

from __future__ import annotations

import vt


NOT_FOUND_ERROR_CODE = "NotFoundError"

BATCH_FATAL_API_ERROR_CODES = frozenset({
    "QuotaExceededError",
    "WrongCredentialsError",
    "UnauthorizedError",
    "ForbiddenError",
})


def is_batch_fatal_api_error(exc: Exception) -> bool:
    return isinstance(exc, vt.APIError) and exc.code in BATCH_FATAL_API_ERROR_CODES
