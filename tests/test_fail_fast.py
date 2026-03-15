from __future__ import annotations

import pytest
import vt

from common import service_upload
from common import service_results
from common.models import ScanTarget, ThreatLevel


@pytest.mark.parametrize("error_code,error_msg", [
    ("QuotaExceededError", "quota exceeded"),
    ("WrongCredentialsError", "bad api key"),
])
async def test_scan_hash_fatal_apierror_raises(service_factory, mocker, error_code: str, error_msg: str) -> None:
    service = service_factory()
    mocker.patch.object(
        service,
        "_query_virustotal_async",
        side_effect=vt.APIError(error_code, error_msg),
    )
    with pytest.raises(vt.APIError) as exc_info:
        await service._scan_live_async(object(), object(), ScanTarget.from_hash("d" * 64))  # type: ignore[arg-type]
    assert exc_info.value.code == error_code


@pytest.mark.parametrize("error_code,error_msg", [
    ("QuotaExceededError", "quota exceeded"),
    ("WrongCredentialsError", "bad api key"),
])
async def test_upload_fatal_apierror_raises(error_code: str, error_msg: str) -> None:
    async def _upload_file(_: str) -> str:
        raise vt.APIError(error_code, error_msg)

    async def _poll_analysis(_: str, __) -> tuple[int, int, int, int]:
        assert False, "poll_analysis should not run after a fatal upload error"

    with pytest.raises(vt.APIError) as exc_info:
        await service_upload.upload_and_scan_async(
            upload_file_fn=_upload_file,
            poll_analysis_fn=_poll_analysis,
            cache_save=lambda *_: None,  # type: ignore[arg-type]
            classify_threat=lambda malicious, suspicious: ThreatLevel.CLEAN,
            error_result=service_results.error_result,
            cancelled_result=service_results.cancelled_result,
            file_path="sample.bin",
            file_hash="a" * 64,
        )
    assert exc_info.value.code == error_code
