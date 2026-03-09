from __future__ import annotations

import asyncio
from unittest.mock import patch

import vt

from common import service_upload
from common.service import ScannerService


def _service(tmp_path) -> ScannerService:
    service = ScannerService(api_key="test", cache_db=tmp_path / "vt_cache.db")
    service.init_cache()
    return service


def test_scan_hash_quota_apierror_raises(tmp_path) -> None:
    service = _service(tmp_path)
    try:
        with patch.object(
            service,
            "_query_virustotal_async",
            side_effect=vt.APIError("QuotaExceededError", "quota exceeded"),
        ):
            try:
                asyncio.run(service._scan_hash_live_async(object(), object(), "d" * 64)) # type: ignore
                assert False, "Expected QuotaExceededError to abort the scan"
            except vt.APIError as exc:
                assert exc.code == "QuotaExceededError"
    finally:
        service.close()


def test_scan_hash_wrong_credentials_apierror_raises(tmp_path) -> None:
    service = _service(tmp_path)
    try:
        with patch.object(
            service,
            "_query_virustotal_async",
            side_effect=vt.APIError("WrongCredentialsError", "bad api key"),
        ):
            try:
                asyncio.run(service._scan_hash_live_async(object(), object(), "d" * 64)) # type: ignore
                assert False, "Expected WrongCredentialsError to abort the scan"
            except vt.APIError as exc:
                assert exc.code == "WrongCredentialsError"
    finally:
        service.close()


def test_upload_quota_apierror_raises(tmp_path) -> None:
    _ = tmp_path

    async def _upload_file(_: str) -> str:
        raise vt.APIError("QuotaExceededError", "quota exceeded")

    async def _poll_analysis(_: str, __) -> tuple[int, int, int, int]:
        assert False, "poll_analysis should not run after a fatal upload error"

    try:
        asyncio.run(
            service_upload.upload_and_scan_async(
                upload_file_fn=_upload_file,
                poll_analysis_fn=_poll_analysis,
                cache_save=lambda *_: None,
                classify_threat=lambda malicious, suspicious: "Clean",
                error_result=lambda item, item_type, message, file_hash="": {
                    "item": item,
                    "type": item_type,
                    "message": message,
                    "file_hash": file_hash,
                },
                cancelled_result=lambda item, item_type, file_hash="": {
                    "item": item,
                    "type": item_type,
                    "file_hash": file_hash,
                },
                file_path="sample.bin",
                file_hash="a" * 64,
            )
        )
        assert False, "Expected QuotaExceededError to abort the upload"
    except vt.APIError as exc:
        assert exc.code == "QuotaExceededError"


def test_upload_wrong_credentials_apierror_raises(tmp_path) -> None:
    _ = tmp_path

    async def _upload_file(_: str) -> str:
        raise vt.APIError("WrongCredentialsError", "bad api key")

    async def _poll_analysis(_: str, __) -> tuple[int, int, int, int]:
        assert False, "poll_analysis should not run after a fatal upload error"

    try:
        asyncio.run(
            service_upload.upload_and_scan_async(
                upload_file_fn=_upload_file,
                poll_analysis_fn=_poll_analysis,
                cache_save=lambda *_: None,
                classify_threat=lambda malicious, suspicious: "Clean",
                error_result=lambda item, item_type, message, file_hash="": {
                    "item": item,
                    "type": item_type,
                    "message": message,
                    "file_hash": file_hash,
                },
                cancelled_result=lambda item, item_type, file_hash="": {
                    "item": item,
                    "type": item_type,
                    "file_hash": file_hash,
                },
                file_path="sample.bin",
                file_hash="a" * 64,
            )
        )
        assert False, "Expected WrongCredentialsError to abort the upload"
    except vt.APIError as exc:
        assert exc.code == "WrongCredentialsError"
