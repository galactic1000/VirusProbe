from __future__ import annotations

import pytest

from cli.app import _build_parser


def test_h_flag_shows_help() -> None:
    parser = _build_parser()
    with pytest.raises(SystemExit) as exc:
        parser.parse_args(["-h"])
    assert exc.value.code == 0


def test_s_flag_maps_to_hashes() -> None:
    parser = _build_parser()
    args = parser.parse_args(["-s", "a" * 64])
    assert args.hashes == ["a" * 64]


@pytest.mark.parametrize("argv,expected", [
    (["-o"], "__AUTO_OUTPUT__"),
    (["-o", "my_report.json"], "my_report.json"),
])
def test_output_flag_parsing(argv, expected) -> None:
    parser = _build_parser()
    args = parser.parse_args(argv)
    assert args.output == expected


@pytest.mark.parametrize("rpm_flags,expected", [
    ([], 4),
    (["--requests-per-minute", "0"], 0),
    (["--requests-per-minute", "60"], 60),
])
def test_requests_per_minute_parsing(rpm_flags, expected) -> None:
    parser = _build_parser()
    args = parser.parse_args(["-s", "a" * 64] + rpm_flags)
    assert args.requests_per_minute == expected

