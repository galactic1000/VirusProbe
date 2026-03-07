from __future__ import annotations

from cli.display import print_scan_summary


def test_print_scan_summary_counts_suspicious_detections(capsys) -> None:
    print_scan_summary(
        [
            {
                "item": "SHA-256 hash: " + ("a" * 64),
                "type": "hash",
                "file_hash": "a" * 64,
                "malicious": 0,
                "suspicious": 3,
                "harmless": 12,
                "undetected": 1,
                "threat_level": "Suspicious",
                "status": "ok",
                "message": "",
            }
        ]
    )

    output = capsys.readouterr().out
    assert "SUSPICIOUS ITEMS" in output
    assert "(3 detections)" in output
