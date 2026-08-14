"""End-to-end tests of the CLI against synthetic captures."""

from __future__ import annotations

import json
import re

import pytest

from investigator.cli import run


def test_success(mixed_pcap, tmp_path, capsys):
    out_dir = tmp_path / "out"
    assert run([str(mixed_pcap), "--output-dir", str(out_dir)]) == 0
    out = capsys.readouterr().out
    assert "AUTOMATIC PCAP INVESTIGATOR" in out
    assert re.search(r"Packets:\s+5\b", out)
    assert "TCP" in out
    assert "ARP" in out
    assert "Duration:" in out
    assert "Top talkers" in out
    assert "10.0.0.15" in out

    report_path = out_dir / "investigation.json"
    assert report_path.is_file()
    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert report["capture"]["packets"] == 5
    assert report["inventory"]["host_count"]["internal"] > 0


def test_max_packets_flag(mixed_pcap, tmp_path, capsys):
    assert run(
        ["--max-packets", "2", "--output-dir", str(tmp_path / "out"), str(mixed_pcap)]
    ) == 0
    assert re.search(r"Packets:\s+2\b", capsys.readouterr().out)


def test_missing_file(tmp_path, capsys):
    assert run([str(tmp_path / "missing.pcap")]) == 1
    assert "error:" in capsys.readouterr().err


def test_garbage_file(garbage_file, capsys):
    assert run([str(garbage_file)]) == 1
    assert "not a pcap" in capsys.readouterr().err


def test_rejects_non_positive_max_packets(mixed_pcap, capsys):
    with pytest.raises(SystemExit) as excinfo:
        run(["--max-packets", "0", str(mixed_pcap)])
    assert excinfo.value.code == 2  # argparse usage error


def test_version_flag(capsys):
    with pytest.raises(SystemExit) as excinfo:
        run(["--version"])
    assert excinfo.value.code == 0
