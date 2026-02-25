from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import vt

from common.service import ScannerService


def _service(tmp_path) -> ScannerService:
    service = ScannerService(api_key="test", cache_db=tmp_path / "vt_cache.db")
    service.init_cache()
    return service


def test_scan_hash_invalid_format_returns_error(tmp_path) -> None:
    service = _service(tmp_path)
    try:
        result = service.scan_hash("not-a-hash")
    finally:
        service.close()

    assert result["status"] == "error"
    assert result["type"] == "hash"
    assert "Invalid SHA-256" in result["message"]


def test_scan_hash_uses_mocked_vt_response(tmp_path) -> None:
    service = _service(tmp_path)
    fake_response = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 12,
                    "suspicious": 1,
                    "harmless": 5,
                    "undetected": 7,
                }
            }
        }
    }
    try:
        with patch.object(service, "_query_virustotal", return_value=(fake_response, False)):
            result = service.scan_hash("a" * 64)
    finally:
        service.close()

    assert result["status"] == "ok"
    assert result["threat_level"] == "Malicious"
    assert result["malicious"] == 12
    assert result["file_hash"] == "a" * 64


def test_scan_hash_not_found_apierror_maps_to_undetected(tmp_path) -> None:
    service = _service(tmp_path)
    try:
        with patch.object(service, "_query_virustotal", side_effect=vt.APIError("NotFoundError", "not found")):
            result = service.scan_hash("c" * 64)
    finally:
        service.close()

    assert result["status"] == "undetected"
    assert result["threat_level"] == "Undetected"


def test_scan_hash_other_apierror_maps_to_error(tmp_path) -> None:
    service = _service(tmp_path)
    try:
        with patch.object(service, "_query_virustotal", side_effect=vt.APIError("QuotaExceededError", "quota")):
            result = service.scan_hash("d" * 64)
    finally:
        service.close()

    assert result["status"] == "error"
    assert result["threat_level"] == "Error"
    assert "quota" in result["message"]


def test_scan_hash_malformed_response_maps_to_undetected(tmp_path) -> None:
    service = _service(tmp_path)
    try:
        with patch.object(service, "_query_virustotal", return_value=({"invalid": "shape"}, False)):
            result = service.scan_hash("e" * 64)
    finally:
        service.close()

    assert result["status"] == "undetected"
    assert result["threat_level"] == "Undetected"


def test_scan_directory_passes_generator_to_scan_files(tmp_path) -> None:
    service = _service(tmp_path)
    sample_dir = tmp_path / "samples"
    sample_dir.mkdir()
    (sample_dir / "a.bin").write_bytes(b"a")
    (sample_dir / "b.bin").write_bytes(b"b")

    try:
        with patch.object(service, "scan_files", return_value=[]) as scan_files_mock:
            service.scan_directory(str(sample_dir), recursive=False)
            arg = scan_files_mock.call_args[0][0]
            discovered = sorted(list(arg))
    finally:
        service.close()

    assert not isinstance(arg, list)
    assert discovered == sorted([str(sample_dir / "a.bin"), str(sample_dir / "b.bin")])


def test_scan_items_mixed_hash_and_file(tmp_path) -> None:
    service = _service(tmp_path)
    f = tmp_path / "file.bin"
    f.write_bytes(b"sample")

    try:
        with patch.object(service, "scan_hash", return_value={"status": "ok", "type": "hash"}) as scan_hash_mock:
            with patch.object(service, "scan_file", return_value={"status": "ok", "type": "file"}) as scan_file_mock:
                results = service.scan_items([str(f), "f" * 64])
    finally:
        service.close()

    assert len(results) == 2
    scan_file_mock.assert_called_once_with(str(f))
    scan_hash_mock.assert_called_once_with("f" * 64)
