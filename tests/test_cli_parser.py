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


def test_output_toggle_sets_auto_const() -> None:
    parser = _build_parser()
    args = parser.parse_args(['-o'])
    assert args.output == '__AUTO_OUTPUT__'

def test_output_accepts_explicit_path() -> None:
    parser = _build_parser()
    args = parser.parse_args(['-o', 'my_report.json'])
    assert args.output == 'my_report.json'

