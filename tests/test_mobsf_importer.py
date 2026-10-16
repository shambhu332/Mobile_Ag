"""Synthetic interoperability tests; no MobSF service or APK is used."""
import json
from pathlib import Path

import pytest
from click.testing import CliRunner
from jsonschema import Draft202012Validator

from mobileag.cli import main
from mobileag.reporting.mobsf_importer import MAX_BYTES, MobSFImportError, import_mobsf_json


def report():
    return {
        "mobsf_version": "synthetic-fixture",
        "package_name": "org.example.fixture",
        "code_analysis": {"findings": {
            "rule.synthetic.input": {
                "metadata": {"description": "External input review", "severity": "warning", "cwe": "CWE-79"},
                "files": {"src/Fixture.java": [12, 12], "../outside.java": [4]},
                "evidence": "producer-controlled evidence must be ignored",
            },
            "rule.synthetic.good": {
                "metadata": {"description": "Good state", "severity": "good"},
                "files": {},
            },
            "rule.synthetic.drive": {
                "metadata": {"description": "Drive path", "severity": "warning"},
                "files": {"C:/outside.java": [7]},
            },
        }},
        "manifest_analysis": {"manifest_findings": [
            {"title": "Exported component review", "description": "Synthetic manifest lead", "severity": "info"},
            {"title": "Secure state", "description": "not a finding", "severity": "secure"},
        ]},
        "dynamic_analysis": {"findings": [{"title": "ignored runtime assertion"}]},
    }


def test_mobsf_projection_is_bounded_untrusted_and_redacts_unsafe_locations():
    result=import_mobsf_json(report())
    assert result["source_trust"]=="untrusted_external_results"
    assert result["producer_version"]=="synthetic-fixture"
    assert result["reported_package_name"]=="org.example.fixture"
    assert result["producer_entries_seen"]==5
    assert result["imported_candidates"]==3
    assert result["duplicates_skipped"]==1
    assert result["invalid_or_nonfinding_results_skipped"]==2
    assert result["source_locations_omitted"]==2
    assert result["source_location_inventory_status"]=="within_limits"
    assert len(result["findings"])==3
    code=next(item for item in result["findings"] if item["metadata"]["import"]["category"]=="code_analysis")
    manifest=next(item for item in result["findings"] if item["metadata"]["import"]["category"]=="manifest_analysis")
    assert (code["file_path"],code["line_number"],code["cwe_id"])==("src/Fixture.java",12,"CWE-79")
    assert code["severity"]=="MEDIUM" and code["confidence"]==0.0
    assert code["status"]==manifest["status"]=="UNVERIFIED"
    assert code["metadata"]["proof_state"]=="not_proven"
    drive=next(item for item in result["findings"] if item["metadata"]["import"]["rule_id"]=="rule.synthetic.drive")
    assert drive["file_path"]=="" and drive["line_number"] is None
    assert "producer-controlled evidence" not in json.dumps(result)
    assert "ignored runtime assertion" not in json.dumps(result)
    assert "../outside.java" not in json.dumps(result)


def test_mobsf_projection_conforms_to_published_schema():
    result=import_mobsf_json(report())
    path=Path(__file__).resolve().parents[1]/"docs/schemas/mobsf-import-v1.schema.json"
    schema=json.loads(path.read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(result)
    result["source_trust"]="verified"
    assert list(Draft202012Validator(schema).iter_errors(result))


def test_mobsf_location_budget_marks_projection_truncated():
    data=report()
    data["code_analysis"]["findings"]["rule.synthetic.input"]["files"]={
        f"src/File{index}.java": [1] for index in range(101)
    }
    result=import_mobsf_json(data)
    assert result["source_location_inventory_status"]=="truncated"
    assert result["imported_candidates"]==101  # 100 code locations plus one manifest review item
    schema=json.loads((Path(__file__).resolve().parents[1]/"docs/schemas/mobsf-import-v1.schema.json").read_text())
    Draft202012Validator(schema).validate(result)


@pytest.mark.parametrize("raw", [
    b'{"code_analysis":{},"code_analysis":{}}',
    b'{"code_analysis":{"findings":[]}}',
    b'{"unrecognized":true}',
    b'{"code_analysis":{"findings":{"x":{"metadata":{},"files":{}}}},"manifest_analysis":{"manifest_findings":{}}}',
])
def test_mobsf_rejects_duplicate_keys_unknown_or_malformed_shapes(raw):
    with pytest.raises(MobSFImportError):
        import_mobsf_json(raw)


def test_mobsf_rejects_oversized_and_cyclic_programmatic_inputs():
    with pytest.raises(MobSFImportError,match="size limit"):
        import_mobsf_json(b" "*(MAX_BYTES+1))
    cyclic={}
    cyclic["code_analysis"]=cyclic
    with pytest.raises(MobSFImportError,match="cyclic or shared"):
        import_mobsf_json(cyclic)
    nested={"code_analysis":{"findings":{}}}
    cursor=nested
    for _ in range(70):
        cursor["child"]={}
        cursor=cursor["child"]
    with pytest.raises(MobSFImportError,match="nesting or item limits"):
        import_mobsf_json(nested)


def test_mobsf_cli_is_offline_new_file_only_and_never_overwrites(tmp_path):
    source=tmp_path/"mobsf.json"
    source.write_text(json.dumps(report()))
    output=tmp_path/"projection.json"
    result=CliRunner().invoke(main,["import-mobsf-json","--input",str(source),"--output",str(output)])
    assert result.exit_code==0,result.output
    assert output.stat().st_mode & 0o077 == 0
    projection=json.loads(output.read_text())
    assert projection["source_trust"]=="untrusted_external_results"
    output.write_text("preserve")
    result=CliRunner().invoke(main,["import-mobsf-json","--input",str(source),"--output",str(output)])
    assert result.exit_code!=0 and output.read_text()=="preserve"
