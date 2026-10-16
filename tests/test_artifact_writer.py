"""Regression tests for bounded private report artifact writes."""
from __future__ import annotations

import json
import os

import pytest

from mobileag.reporting.artifact_writer import write_private_artifact


def test_private_artifact_write_replaces_symlink_without_touching_target(tmp_path):
    target = tmp_path / "target.txt"
    target.write_text("original")
    output = tmp_path / "report.json"
    output.symlink_to(target)

    write_private_artifact(output, '{"status":"ok"}')

    assert not output.is_symlink()
    assert target.read_text() == "original"
    assert json.loads(output.read_text()) == {"status": "ok"}
    assert os.stat(output).st_mode & 0o077 == 0


def test_private_artifact_write_rejects_oversize_before_destination_change(tmp_path):
    output = tmp_path / "report.txt"
    output.write_text("preserve me")
    with pytest.raises(ValueError, match="size limit"):
        write_private_artifact(output, "too large", max_bytes=2)
    assert output.read_text() == "preserve me"


def test_private_artifact_write_accepts_bytes(tmp_path):
    output = tmp_path / "report.bin"
    assert write_private_artifact(output, b"\x00\x01") == output
    assert output.read_bytes() == b"\x00\x01"


def test_private_artifact_write_rejects_symlinked_parent(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "reports"
    link.symlink_to(outside, target_is_directory=True)

    with pytest.raises(OSError):
        write_private_artifact(link / "report.json", b"synthetic")
    assert not (outside / "report.json").exists()


def test_private_artifact_write_stays_in_pinned_parent_after_path_replacement(tmp_path, monkeypatch):
    parent = tmp_path / "reports"
    parent.mkdir()
    moved = tmp_path / "moved-reports"
    real_fdopen = os.fdopen
    moved_once = False

    def replace_parent_after_temp_open(fd, *args, **kwargs):
        nonlocal moved_once
        if not moved_once:
            parent.rename(moved)
            parent.mkdir()
            moved_once = True
        return real_fdopen(fd, *args, **kwargs)

    monkeypatch.setattr(os, "fdopen", replace_parent_after_temp_open)
    write_private_artifact(parent / "report.json", b"synthetic")

    assert (moved / "report.json").read_bytes() == b"synthetic"
    assert not (parent / "report.json").exists()
    assert list(parent.iterdir()) == []


def test_taint_cli_export_redacts_and_privately_persists_json(tmp_path, monkeypatch):
    from click.testing import CliRunner
    import mobileag.analysis as analysis
    from mobileag.cli import main

    class SyntheticFinding:
        def to_dict(self):
            return {"id": "synthetic", "description": "access_token=syntheticSecretValue"}

    class SyntheticEngine:
        def analyze_directory(self, _source):
            return [SyntheticFinding()]

    monkeypatch.setattr(analysis, "TaintEngine", SyntheticEngine)
    source = tmp_path / "source"
    source.mkdir()
    output = tmp_path / "cli-output"
    result = CliRunner().invoke(main, ["taint", "--src", str(source), "--output", str(output)])

    assert result.exit_code == 0, result.output
    report = output / "taint_findings.json"
    assert "syntheticSecretValue" not in report.read_text()
    assert "[REDACTED]" in report.read_text()
    assert os.stat(report).st_mode & 0o077 == 0
