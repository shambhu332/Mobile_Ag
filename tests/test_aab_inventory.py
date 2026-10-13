import hashlib
import json
import struct
import zipfile
from pathlib import Path

import pytest
from click.testing import CliRunner
from jsonschema import Draft202012Validator

from mobileag.cli import main
from mobileag.ingestion.aab_inventory import inventory_android_app_bundle


def _dex_header(class_count=0):
    data = bytearray(112)
    data[:8] = b"dex\n035\0"
    struct.pack_into("<I", data, 32, 112)
    struct.pack_into("<I", data, 36, 112)
    struct.pack_into("<I", data, 40, 0x12345678)
    assert class_count == 0
    return bytes(data)


def _write_aab(path, *, feature_manifest=True, bad_dex_name=False, include_asset_pack=False):
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr("BundleConfig.pb", b"synthetic protobuf placeholder")
        archive.writestr("BUNDLE-METADATA/com.android.tools.build.libraries/dependencies.pb", b"metadata")
        archive.writestr("base/manifest/AndroidManifest.xml", b"synthetic manifest protobuf")
        archive.writestr("base/dex/classes.dex", _dex_header())
        archive.writestr("base/lib/arm64-v8a/libbase.so", b"synthetic ELF placeholder")
        feature_manifest_path = "feature/manifest/AndroidManifest.xml"
        if feature_manifest:
            archive.writestr(feature_manifest_path, b"synthetic manifest protobuf")
        dex_name = "classes0.dex" if bad_dex_name else "classes.dex"
        archive.writestr(f"feature/dex/{dex_name}", _dex_header())
        if include_asset_pack:
            archive.writestr("asset_pack_1/manifest/AndroidManifest.xml", b"synthetic asset pack manifest")
            archive.writestr("asset_pack_1/assets/synthetic.bin", b"synthetic asset")


def test_aab_inventory_counts_modules_and_inputs_without_claiming_analysis(tmp_path):
    artifact = tmp_path / "synthetic.aab"
    _write_aab(artifact, include_asset_pack=True)
    report = inventory_android_app_bundle(artifact)

    assert report["artifact_sha256"] == hashlib.sha256(artifact.read_bytes()).hexdigest()
    assert report["format"] == "android_app_bundle"
    assert report["module_count"] == 3
    assert report["module_manifest_count"] == 3
    assert report["dex_member_count"] == 2
    assert report["native_library_member_count"] == 1
    assert [item["name"] for item in report["modules"]] == ["asset_pack_1", "base", "feature"]
    assert report["modules"][1]["dex_class_count_status"] == "measured_dex_headers"
    assert report["modules"][1]["declared_dex_class_count"] == 0
    assert report["modules"][0]["dex_class_count_status"] == "not_applicable_no_dex_member"
    assert report["inventory_status"] == "complete_within_limits"
    assert report["analysis_state"] == "input_inventory_only_not_analyzed"
    assert report["split_delivery_set_status"] == "not_measured"
    assert report["proof_status"] == "not_proven"

    schema_path = Path(__file__).resolve().parents[1] / "docs" / "schemas" / "android-app-bundle-inventory-v1.schema.json"
    schema = json.loads(schema_path.read_text())
    Draft202012Validator.check_schema(schema)
    Draft202012Validator(schema).validate(report)


def test_aab_inventory_marks_missing_module_manifest_and_bad_dex_names_partial(tmp_path):
    artifact = tmp_path / "partial.aab"
    _write_aab(artifact, feature_manifest=False, bad_dex_name=True)

    report = inventory_android_app_bundle(artifact)

    feature = next(item for item in report["modules"] if item["name"] == "feature")
    assert report["inventory_status"] == "partial"
    assert feature["manifest_present"] is False
    assert feature["module_inventory_status"] == "incomplete_module_manifest_missing"
    assert feature["invalid_dex_member_count"] == 1
    assert feature["dex_class_count_status"] == "incomplete_or_unsupported_member_name"


@pytest.mark.parametrize("entries", [
    {"BundleConfig.pb": b"x"},
    {"BundleConfig.pb": b"x", "base/manifest/AndroidManifest.xml": b"x", "../evil": b"x"},
])
def test_aab_validator_rejects_incomplete_or_unsafe_bundle_shapes(tmp_path, entries):
    path = tmp_path / "bad.aab"
    with zipfile.ZipFile(path, "w") as archive:
        for name, data in entries.items():
            archive.writestr(name, data)
    with pytest.raises(ValueError):
        inventory_android_app_bundle(path)


def test_aab_cli_writes_offline_new_file_and_never_overwrites(tmp_path):
    artifact = tmp_path / "owned.aab"
    _write_aab(artifact)
    output = tmp_path / "inventory.json"
    runner = CliRunner()

    result = runner.invoke(main, ["inventory-aab", "--input", str(artifact), "--output", str(output)])
    assert result.exit_code == 0, result.output
    saved = json.loads(output.read_text())
    assert saved["analysis_state"] == "input_inventory_only_not_analyzed"
    assert "no manifest protobuf decoding" in result.output.lower()

    output.write_text("preserve")
    result = runner.invoke(main, ["inventory-aab", "--input", str(artifact), "--output", str(output)])
    assert result.exit_code != 0
    assert output.read_text() == "preserve"
