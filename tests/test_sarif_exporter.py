"""Unit tests for OASIS SARIF v2.1.0 Exporter."""

import json
import os
import tempfile
from pathlib import Path

import pytest

from mobileag.reporting.finding import Finding, Severity
from mobileag.reporting.sarif_exporter import SARIFExporter
from mobileag.reporting.sarif_importer import SarifImportError, validate_sarif_document


def test_sarif_generation_and_export():
    findings = [
        Finding(
            id="test-001",
            title="CWE-926: Exported Activity Without Permission",
            description="DeepLinkRouterActivity is exported without permission guards.",
            severity=Severity.CRITICAL,
            cwe_id="CWE-926",
            cvss_score=8.4,
            affected_component="com.target.DeepLinkRouterActivity",
            file_path="AndroidManifest.xml",
            line_number=42,
            code_snippet='<activity android:name=".DeepLinkRouterActivity" android:exported="true"/>',
            remediation="Set android:exported=false",
        ),
        Finding(
            id="test-002",
            title="CWE-319: Cleartext HTTP Permitted",
            description="Cleartext HTTP enabled in network security config.",
            severity=Severity.HIGH,
            cwe_id="CWE-319",
            cvss_score=7.5,
            affected_component="res/xml/network_security_config.xml",
            file_path="res/xml/network_security_config.xml",
            line_number=12,
            code_snippet='<domain-config cleartextTrafficPermitted="true">',
            remediation="Remove cleartextTrafficPermitted=true",
        ),
    ]

    with tempfile.TemporaryDirectory() as tmpdir:
        sarif_file = Path(tmpdir) / "output.sarif"
        SARIFExporter.export_to_file(findings, sarif_file, target_name="TargetApp", scan_id="scan-42")

        assert sarif_file.exists()
        sarif_data = json.loads(sarif_file.read_text(encoding="utf-8"))

        assert sarif_data["version"] == "2.1.0"
        assert "$schema" in sarif_data
        assert len(sarif_data["runs"]) == 1

        run = sarif_data["runs"][0]
        assert run["tool"]["driver"]["name"] == "MobileAg Enterprise AppSec Scanner"
        assert len(run["results"]) == 2

        # Check first result
        r1 = run["results"][0]
        assert r1["ruleId"] == "CWE-926"
        assert r1["level"] == "error"
        assert r1["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "AndroidManifest.xml"
        assert r1["locations"][0]["physicalLocation"]["region"]["startLine"] == 42
        validate_sarif_document(sarif_data)


def test_sarif_export_replaces_symlink_atomically_with_private_file():
    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)
        victim = root / "victim.txt"
        victim.write_text("unchanged")
        output = root / "out.sarif"
        output.symlink_to(victim)

        SARIFExporter.export_to_file([], output)

        assert victim.read_text() == "unchanged"
        assert not output.is_symlink()
        assert json.loads(output.read_text())["version"] == "2.1.0"
        assert os.stat(output).st_mode & 0o077 == 0


def test_sarif_export_rejects_oversized_result_inventory():
    with pytest.raises(SarifImportError, match="inventory exceeds limits"):
        SARIFExporter.generate_sarif([{}] * 5001)


def test_sarif_export_preflights_large_input_before_projection(monkeypatch):
    monkeypatch.setattr(SARIFExporter, "MAX_INPUT_BYTES", 1024)
    with pytest.raises(SarifImportError, match="input exceeds"):
        SARIFExporter.generate_sarif([{"description": "x" * 300}])


def test_sarif_export_rejects_cyclic_input_before_projection():
    finding = {}
    finding["metadata"] = finding
    with pytest.raises(SarifImportError, match="cycle"):
        SARIFExporter.generate_sarif([finding])
