from __future__ import annotations

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
    try:
        with patch.object(service, "_query_virustotal", return_value=((12, 1, 5, 7), False)):
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


def test_scan_directory_passes_file_list_to_scan_files(tmp_path) -> None:
    service = _service(tmp_path)
    sample_dir = tmp_path / "samples"
    sample_dir.mkdir()
    (sample_dir / "a.bin").write_bytes(b"a")
    (sample_dir / "b.bin").write_bytes(b"b")
    try:
        with patch.object(service, "scan_files", return_value=[]) as scan_files_mock:
            service.scan_directory(str(sample_dir), recursive=False)
            arg = scan_files_mock.call_args[0][0]
    finally:
        service.close()
    assert sorted(arg) == sorted([str(sample_dir / "a.bin"), str(sample_dir / "b.bin")])


def test_scan_directory_nonexistent_returns_error_dict(tmp_path) -> None:
    service = _service(tmp_path)
    try:
        results = service.scan_directory(str(tmp_path / "nonexistent"))
    finally:
        service.close()
    assert len(results) == 1
    assert results[0]["status"] == "error"
    assert results[0]["type"] == "directory"


def test_scan_directory_not_a_directory_returns_error_dict(tmp_path) -> None:
    service = _service(tmp_path)
    not_a_dir = tmp_path / "file.txt"
    not_a_dir.write_text("data")
    try:
        results = service.scan_directory(str(not_a_dir))
    finally:
        service.close()
    assert len(results) == 1
    assert results[0]["status"] == "error"
    assert results[0]["type"] == "directory"


def test_scan_hashes_on_result_callback_fires_for_each_item(tmp_path) -> None:
    service = _service(tmp_path)
    fired: list[dict] = []
    try:
        with patch.object(service, "_query_virustotal", return_value=((0, 0, 5, 0), False)):
            service.scan_hashes(["a" * 64, "b" * 64], on_result=fired.append)
    finally:
        service.close()
    assert len(fired) == 2
    assert all(r["status"] == "ok" for r in fired)
