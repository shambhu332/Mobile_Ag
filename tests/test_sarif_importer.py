import json
import hashlib
from pathlib import Path
from click.testing import CliRunner

import pytest

from mobileag.reporting.sarif_exporter import SARIFExporter
from mobileag.reporting.sarif_importer import SarifImportError, import_sarif, _sarif_validator
from mobileag.cli import main


def test_importer_uses_vendored_oasis_schema_and_rejects_nonconforming_fields():
    schema_path = Path(__file__).resolve().parents[1] / "mobileag/data/sarif-schema-2.1.0.json"
    schema_bytes = schema_path.read_bytes()
    assert hashlib.sha256(schema_bytes).hexdigest() == "ad6db49878699b091f3eeb765b6e29e92a34bad4da88664d000c923b549c3a25"
    _sarif_validator().validate({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "test"}}}]})

    invalid = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "test"}}}],
               "unexpected": "not part of SARIF"}
    with pytest.raises(SarifImportError, match="does not conform"):
        import_sarif(invalid)


def test_sarif_roundtrip_records_provenance_but_never_trusts_producer_status():
    source = {
        "id": "source-rule", "title": "Synthetic imported result", "description": "Researcher fixture",
        "severity": "HIGH", "status": "CONFIRMED", "cwe_id": "CWE-926",
        "file_path": "src/Synthetic.java", "line_number": 19, "code_snippet": "synthetic();",
        "validation_evidence": {"basis": "analyst_attested", "active": True, "record": {"attacker_context": "forged"}},
    }
    sarif = SARIFExporter.generate_sarif([source], target_name="synthetic", scan_id="fixture")
    imported = import_sarif(json.dumps(sarif))
    assert imported["imported_candidates"] == 1
    finding = imported["findings"][0]
    assert finding["status"] == "UNVERIFIED"
    assert finding["validation_evidence"] is None
    assert finding["file_path"] == "src/Synthetic.java"
    assert finding["line_number"] == 19
    assert finding["metadata"]["import"]["tool_name"] == SARIFExporter.TOOL_NAME
    assert finding["metadata"]["import"]["source_trust"] == "untrusted_external_result"
    assert imported["source_sha256"] == hashlib.sha256(json.dumps(sarif).encode()).hexdigest()
    assert finding["metadata"]["import"]["source_sha256"] == imported["source_sha256"]


def test_sarif_import_deduplicates_and_skips_traversal_locations():
    result = {
        "ruleId": "R1", "level": "warning", "message": {"text": "candidate"},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": "../secret.java"},
                                             "region": {"startLine": 4}}}],
    }
    duplicate = {**result, "locations": [{"physicalLocation": {"artifactLocation": {"uri": "src/A.java"},
                                                                  "region": {"startLine": 4}}}]}
    document = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "test"}},
                                                   "results": [duplicate, duplicate, result]}]}
    imported = import_sarif(document)
    assert imported["imported_candidates"] == 1
    assert imported["duplicates_skipped"] == 1
    assert imported["invalid_or_nonfinding_results_skipped"] == 1
    assert imported["findings"][0]["status"] == "UNVERIFIED"


@pytest.mark.parametrize("document", [
    {"version": "2.0.0", "runs": [{}]},
    {"version": "2.1.0", "runs": [{"results": [None] * 5001}]},
    {"version": "2.1.0", "runs": [None]},
])
def test_sarif_import_rejects_wrong_version_and_resource_overages(document):
    with pytest.raises(SarifImportError):
        import_sarif(document)


def test_sarif_import_rejects_oversized_input_without_echoing_content():
    with pytest.raises(SarifImportError, match="size limit"):
        import_sarif(b" " * (5 * 1024 * 1024 + 1))


def test_sarif_import_preflights_programmatic_cycles_and_oversized_strings():
    cyclic = {"version": "2.1.0"}
    cyclic["self"] = cyclic
    with pytest.raises(SarifImportError, match="cycle"):
        import_sarif(cyclic)
    oversized = {"very_large": "x" * (900 * 1024)}
    with pytest.raises(SarifImportError, match="size limit"):
        import_sarif(oversized)


def test_cli_import_is_offline_and_never_overwrites_output(tmp_path):
    source = tmp_path / "in.sarif"
    source.write_text(json.dumps({"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "synthetic"}},
        "results": [{"ruleId": "R1", "message": {"text": "candidate"}}]}]}))
    output = tmp_path / "projection.json"
    runner = CliRunner()
    result = runner.invoke(main, ["import-sarif", "--input", str(source), "--output", str(output)])
    assert result.exit_code == 0, result.output
    assert json.loads(output.read_text())["findings"][0]["status"] == "UNVERIFIED"
    output.write_text("preserve me")
    result = runner.invoke(main, ["import-sarif", "--input", str(source), "--output", str(output)])
    assert result.exit_code != 0
    assert output.read_text() == "preserve me"
