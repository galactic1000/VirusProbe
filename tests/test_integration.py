from __future__ import annotations

import json

import vt

from common.models import ResultStatus, ScanTarget
from common.reporting import write_report


async def test_scan_and_report_json(service_factory, tmp_path, mocker) -> None:
    service = service_factory()
    mocker.patch.object(
        service,
        "_query_virustotal_async",
        side_effect=[
            ((10, 0, 1, 0), False),
            vt.APIError("NotFoundError", "not found"),
        ],
    )
    async with service:
        results = await service.scan_targets(
            [
                ScanTarget.from_hash("a" * 64),
                ScanTarget.from_hash("b" * 64),
            ]
        )

    output_path = tmp_path / "report.json"
    write_report(results, str(output_path), "json")
    data = json.loads(output_path.read_text(encoding="utf-8"))

    assert [result.file_hash for result in results] == ["a" * 64, "b" * 64]
    assert data["summary"] == {
        "total": 2,
        "malicious": 1,
        "suspicious": 0,
        "clean": 0,
        "undetected": 1,
        "errors": 0,
        "cancelled": 0,
    }
    assert data["results"][0]["threat_level"] == "Malicious"
    assert data["results"][1]["status"] == "undetected"


async def test_file_scan_negative_cache(service_factory, file_factory, mocker) -> None:
    sample = file_factory("sample.bin", b"sample")
    service = service_factory()
    query_mock = mocker.patch.object(
        service,
        "_query_virustotal_async",
        side_effect=vt.APIError("NotFoundError", "not found"),
    )
    async with service:
        first = await service.scan_targets([ScanTarget.from_file_path(str(sample))])
        second = await service.scan_targets([ScanTarget.from_file_path(str(sample))])

    assert query_mock.await_count == 1
    assert first[0].status == ResultStatus.UNDETECTED
    assert second[0].status == ResultStatus.UNDETECTED
    assert second[0].was_cached is True
    assert second[0].item == str(sample)
