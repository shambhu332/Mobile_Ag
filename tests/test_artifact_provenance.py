import asyncio
import hashlib
import json
import zipfile
from pathlib import Path
from types import SimpleNamespace

from mobileag.core.state import create_initial_state
from mobileag.analysis.bounded_sources import SourceInventory
from mobileag.ingestion.apk_extractor import APKExtractor
from mobileag.reporting.report_engine import ReportEngine



def minimal_dex(class_count=1, descriptors=None):
    import struct
    if descriptors is None:
        descriptors=[f"Lsynthetic/C{index};" for index in range(class_count)]
    class_count=len(descriptors)
    string_off=112 if class_count else 0
    type_off=string_off + 4*class_count if class_count else 0
    class_off=type_off + 4*class_count if class_count else 0
    data_off=class_off + 32*class_count if class_count else 112
    string_items=[]; string_ids=[]; cursor=data_off
    for descriptor in descriptors:
        utf16=descriptor.encode('utf-16-be')
        units=[int.from_bytes(utf16[index:index+2], 'big') for index in range(0, len(utf16), 2)]
        raw=bytearray()
        for unit in units:
            if unit == 0:
                raw.extend(b'\xc0\x80')
            elif unit <= 0x7f:
                raw.append(unit)
            elif unit <= 0x7ff:
                raw.extend((0xc0 | (unit >> 6), 0x80 | (unit & 0x3f)))
            else:
                raw.extend((0xe0 | (unit >> 12), 0x80 | ((unit >> 6) & 0x3f), 0x80 | (unit & 0x3f)))
        string_ids.append(cursor)
        string_items.append(bytes([len(units)])+bytes(raw)+b"\0")
        cursor+=len(string_items[-1])
    payload=bytearray(cursor)
    payload[:8]=b"dex\n035\0"
    struct.pack_into("<I",payload,32,len(payload))
    struct.pack_into("<I",payload,36,112)
    struct.pack_into("<I",payload,40,0x12345678)
    if class_count:
        struct.pack_into("<II",payload,56,class_count,string_off)
        struct.pack_into("<II",payload,64,class_count,type_off)
        struct.pack_into("<II",payload,96,class_count,class_off)
        for index in range(class_count):
            struct.pack_into("<I",payload,string_off+4*index,string_ids[index])
            struct.pack_into("<I",payload,type_off+4*index,index)
            struct.pack_into("<IIIIIIII",payload,class_off+32*index,index,1,0xffffffff,0,0xffffffff,0,0,0)
            payload[string_ids[index]:string_ids[index]+len(string_items[index])]=string_items[index]
    return bytes(payload)


def test_apk_sha256_is_streamed_and_matches_standard_digest(tmp_path):
    artifact = tmp_path / "sample.apk"
    artifact.write_bytes(b"synthetic apk bytes" * 1000)
    before = artifact.read_bytes()

    assert APKExtractor._sha256(artifact) == hashlib.sha256(before).hexdigest()
    assert artifact.read_bytes() == before


def test_tool_version_failure_is_explicit_and_nonfatal():
    result = asyncio.run(APKExtractor._tool_version(
        str(Path("/definitely/missing/mobileag-tool")), ("--version",)))

    assert result["version"] is None
    assert result["version_error"] == "FileNotFoundError"


def test_tool_log_classification_drains_but_caps_inspection_and_retains_no_text():
    from mobileag.ingestion.apk_extractor import _MAX_TOOL_LOG_SCAN_BYTES

    class Reader:
        def __init__(self, data):
            self.data = data

        async def read(self, size):
            part, self.data = self.data[:size], self.data[size:]
            return part

    payload = b"ERROR - synthetic\n" + b"x" * (_MAX_TOOL_LOG_SCAN_BYTES + 100) + b"\nWARN - beyond cap\n"
    observation = asyncio.run(APKExtractor._drain_tool_log(Reader(payload)))

    assert observation["output_bytes"] == len(payload)
    assert observation["classified_bytes"] == _MAX_TOOL_LOG_SCAN_BYTES
    assert observation["classification_truncated"] is True
    assert observation["marker_line_counts"]["error"] == 1
    assert observation["marker_line_counts"]["warning"] == 0
    assert observation["raw_log_retained"] is False
    assert "synthetic" not in json.dumps(observation)


def test_apk_archive_inventory_compares_dex_inputs_without_claiming_analysis(tmp_path):
    from mobileag.reporting.capability_inventory import capability_inventory

    artifact = tmp_path / "synthetic.apk"
    apktool = tmp_path / "apktool_out"
    (apktool / "smali").mkdir(parents=True)
    (apktool / "smali_classes2").mkdir()
    (apktool / "smali" / "A.smali").write_text(".class LA;\n")
    (apktool / "smali_classes2" / "B.smali").write_text(".class LB;\n")
    with zipfile.ZipFile(artifact, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"synthetic")
        archive.writestr("classes.dex", minimal_dex(descriptors=["LA;"]))
        archive.writestr("classes2.dex", minimal_dex(descriptors=["LB;"]))
        archive.writestr("lib/arm64-v8a/libfixture.so", b"ELF")
        archive.writestr("assets/payload.bin", b"data")

    inventory = APKExtractor._archive_inventory(artifact, apktool)
    coverage = {"ingestion_inventory": {"apk_archive": inventory}}
    capabilities = capability_inventory(coverage)["formats"]["multidex"]

    assert inventory["status"] == "measured_input_inventory"
    assert inventory["zip_member_count"] == 5
    assert inventory["dex_members"] == 2
    assert inventory["root_dex_members"] == 2
    assert inventory["native_library_members"] == 1
    assert inventory["dex_smali_dirs_expected"] == 2
    assert inventory["dex_smali_dirs_found"] == 2
    assert inventory["dex_extraction_status"] == "matched"
    assert inventory["dex_class_definitions"] == {"status": "measured_dex_header_counts", "count": 2}
    assert inventory["dex_class_output_comparison"] == {
        "status": "declared_class_count_matches_smali_file_count", "count_delta": 0,
        "per_member": {
            "classes.dex": {"declared_class_count": 1, "smali_output_file_count": 1,
                             "count_delta": 0, "status": "count_match"},
            "classes2.dex": {"declared_class_count": 1, "smali_output_file_count": 1,
                              "count_delta": 0, "status": "count_match"},
        }}
    assert inventory["dex_class_descriptor_comparison"] == {
        "status": "exact_descriptor_set_match", "missing_from_smali_count": 0,
        "extra_smali_count": 0, "per_member": {
            "classes.dex": {"status": "exact_descriptor_set_match", "dex_class_count": 1,
                             "smali_class_count": 1, "missing_from_smali_count": 0,
                             "extra_smali_count": 0},
            "classes2.dex": {"status": "exact_descriptor_set_match", "dex_class_count": 1,
                              "smali_class_count": 1, "missing_from_smali_count": 0,
                              "extra_smali_count": 0},
        }}
    assert inventory["smali_output_files"] == {"status": "measured_output_inventory", "count": 2}
    assert inventory["smali_output_by_dex"] == {
        "smali": {"status": "measured_output_inventory", "count": 1},
        "smali_classes2": {"status": "measured_output_inventory", "count": 1},
    }
    assert inventory["unsupported_constructs"] == {"status": "not_measured", "count": None}
    assert capabilities["execution_state"] == "input_inventory_matched_not_analysis"
    assert capabilities["dex_class_output_comparison_status"] == "declared_class_count_matches_smali_file_count"
    assert capabilities["dex_class_output_count_delta"] == 0
    assert capabilities["dex_class_descriptor_comparison_status"] == "exact_descriptor_set_match"
    assert capabilities["dex_classes_missing_from_smali"] == 0
    assert capabilities["dex_classes_extra_in_smali"] == 0
    assert capabilities["dex_class_descriptor_comparison_by_member"]["classes.dex"]["missing_from_smali_count"] == 0
    assert "descriptors" not in json.dumps(capabilities["dex_class_descriptor_comparison_by_member"])
    assert capabilities["proof_status"] == "not_proven"


def test_dex_and_smali_descriptor_inventory_supports_modified_utf8_names(tmp_path):
    artifact = tmp_path / "unicode.apk"
    apktool = tmp_path / "apktool_out"
    (apktool / "smali").mkdir(parents=True)
    descriptors = ["Lsample/Café;", "Lsample/𐐀;"]
    for index, descriptor in enumerate(descriptors):
        (apktool / "smali" / f"C{index}.smali").write_text(
            f".class public {descriptor}\n", encoding="utf-8")
    with zipfile.ZipFile(artifact, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"synthetic")
        archive.writestr("classes.dex", minimal_dex(descriptors=descriptors))

    result = APKExtractor._archive_inventory(artifact, apktool)

    assert result["dex_class_descriptor_comparison"] == {
        "status": "exact_descriptor_set_match", "missing_from_smali_count": 0,
        "extra_smali_count": 0, "per_member": {
            "classes.dex": {"status": "exact_descriptor_set_match", "dex_class_count": 2,
                            "smali_class_count": 2, "missing_from_smali_count": 0,
                            "extra_smali_count": 0},
        }}


def test_dex_descriptor_parser_rejects_standard_four_byte_utf8_instead_of_mutf8(tmp_path):
    import struct
    descriptor = "Lsample/𐐀;"
    dex = minimal_dex(descriptors=[descriptor])
    # The valid DEX fixture encodes the supplementary character as two
    # Modified UTF-8 surrogate code units. Replace them with invalid four-byte
    # UTF-8 while retaining the old UTF-16 length prefix.
    mutf8_surrogate_pair = b"\xed\xa0\x81\xed\xb0\x80"
    malformed = dex.replace(mutf8_surrogate_pair, "𐐀".encode("utf-8"), 1)
    assert len(malformed) < len(dex)
    struct.pack_into("<I", malformed := bytearray(malformed), 32, len(malformed))
    artifact = tmp_path / "malformed-mutf8.apk"
    with zipfile.ZipFile(artifact, "w") as archive:
        archive.writestr("classes.dex", malformed)

    with zipfile.ZipFile(artifact) as archive:
        result = APKExtractor._read_dex_class_descriptors(archive, archive.getinfo("classes.dex"))

    assert result == {"status": "unsupported_or_invalid_class_descriptor",
                      "count": None, "descriptors": None}


def test_apk_archive_inventory_reports_missing_smali_output(tmp_path):
    artifact = tmp_path / "synthetic.apk"
    apktool = tmp_path / "apktool_out"
    apktool.mkdir()
    with zipfile.ZipFile(artifact, "w") as archive:
        archive.writestr("AndroidManifest.xml", b"synthetic")
        archive.writestr("classes.dex", minimal_dex(1))

    inventory = APKExtractor._archive_inventory(artifact, apktool)

    assert inventory["dex_extraction_status"] == "mismatch"
    assert inventory["dex_smali_dirs_expected"] == 1
    assert inventory["dex_smali_dirs_found"] == 0



def test_dex_header_class_count_mismatch_is_measured_but_not_called_skipped(tmp_path):
    artifact=tmp_path/"mismatch.apk"; apktool=tmp_path/"apktool_out"
    (apktool/"smali").mkdir(parents=True)
    (apktool/"smali"/"Only.smali").write_text(".class LOnly;\n")
    with zipfile.ZipFile(artifact,"w") as archive:
        archive.writestr("AndroidManifest.xml",b"synthetic")
        archive.writestr("classes.dex",minimal_dex(descriptors=["LOne;","LTwo;"]))
    inventory=APKExtractor._archive_inventory(artifact,apktool)
    assert inventory["dex_class_definitions"] == {"status":"measured_dex_header_counts","count":2}
    assert inventory["smali_output_files"] == {"status":"measured_output_inventory","count":1}
    assert inventory["dex_class_output_comparison"]["status"] == "class_count_mismatch"
    assert inventory["dex_class_output_comparison"]["count_delta"] == -1
    assert inventory["dex_class_output_comparison"]["per_member"]["classes.dex"]["status"] == "count_mismatch"
    assert inventory["dex_class_descriptor_comparison"] == {
        "status":"descriptor_set_mismatch", "missing_from_smali_count":2,
        "extra_smali_count":1,
        "per_member":{"classes.dex":{"status":"descriptor_set_mismatch","dex_class_count":2,
          "smali_class_count":1,"missing_from_smali_count":2,"extra_smali_count":1}}}
    assert inventory["unsupported_constructs"] == {"status":"not_measured","count":None}


def test_multidex_count_deltas_do_not_cancel_into_false_match(tmp_path):
    artifact=tmp_path/"cancel.apk"; apktool=tmp_path/"apktool_out"
    (apktool/"smali").mkdir(parents=True); (apktool/"smali_classes2").mkdir()
    (apktool/"smali_classes2"/"ExtraA.smali").write_text(".class LExtraA;\n")
    (apktool/"smali_classes2"/"ExtraB.smali").write_text(".class LExtraB;\n")
    with zipfile.ZipFile(artifact,"w") as archive:
        archive.writestr("AndroidManifest.xml",b"synthetic")
        archive.writestr("classes.dex",minimal_dex(descriptors=["LFirst;"]))
        archive.writestr("classes2.dex",minimal_dex(descriptors=["LSecond;"]))
    comparison=APKExtractor._archive_inventory(artifact,apktool)["dex_class_output_comparison"]
    assert comparison["count_delta"] == 0
    assert comparison["status"] == "class_count_mismatch"
    assert comparison["per_member"]["classes.dex"]["status"] == "count_mismatch"
    assert comparison["per_member"]["classes2.dex"]["status"] == "count_mismatch"

def test_invalid_dex_header_count_remains_unknown_not_zero(tmp_path):
    artifact=tmp_path/"invalid.apk"
    with zipfile.ZipFile(artifact,"w") as archive:
        archive.writestr("AndroidManifest.xml",b"synthetic")
        archive.writestr("classes.dex",b"dex\n035\0"+b"x"*104)
    inventory=APKExtractor._archive_inventory(artifact)
    assert inventory["dex_class_definitions"] == {"status":"incomplete","count":None}
    assert inventory["dex_class_output_comparison"] == {"status":"not_measured","count_delta":None,"per_member":{}}


def test_noncanonical_root_dex_mapping_stays_incomplete(tmp_path):
    from mobileag.reporting.capability_inventory import capability_inventory

    artifact = tmp_path / "noncanonical.apk"
    apktool = tmp_path / "apktool_out"
    (apktool / "smali").mkdir(parents=True)
    (apktool / "smali" / "A.smali").write_text(".class LA;\n")
    with zipfile.ZipFile(artifact, "w") as archive:
        archive.writestr("classes0.dex", minimal_dex(descriptors=["LA;"]))

    inventory = APKExtractor._archive_inventory(artifact, apktool)

    assert inventory["dex_extraction_status"] == "incomplete_or_ambiguous_mapping"
    assert inventory["dex_class_output_comparison"]["status"] == "incomplete"
    assert inventory["dex_class_descriptor_comparison"]["status"] == "incomplete_or_unsupported"
    row = capability_inventory({"ingestion_inventory": {"apk_archive": inventory}})["formats"]["multidex"]
    assert row["execution_state"] == "incomplete_or_ambiguous_inventory"
    assert row["dex_classes_missing_from_smali"] is None


def test_duplicate_root_dex_member_name_does_not_publish_class_totals(tmp_path):
    artifact = tmp_path / "duplicate.apk"
    apktool = tmp_path / "apktool_out"
    (apktool / "smali").mkdir(parents=True)
    with zipfile.ZipFile(artifact, "w") as archive:
        archive.writestr("classes.dex", minimal_dex(descriptors=["LA;"]))
        archive.writestr("classes.dex", minimal_dex(descriptors=["LB;"]))

    inventory = APKExtractor._archive_inventory(artifact, apktool)

    assert inventory["root_dex_members"] == 2
    assert inventory["dex_class_definitions"] == {"status": "incomplete", "count": None}
    assert inventory["dex_class_definitions_by_member"]["classes.dex"]["status"] == "duplicate_dex_member_name"
    assert inventory["dex_class_descriptor_comparison"]["status"] == "incomplete_or_unsupported"

def test_extract_records_provenance_and_tool_versions_without_modifying_apk(tmp_path, monkeypatch):
    import mobileag.security.archives as archives

    artifact = tmp_path / "owned.apk"
    original = b"synthetic owned artifact"
    artifact.write_bytes(original)
    monkeypatch.setattr(archives, "validate_archive", lambda _path: "android")

    class FakeStream:
        def __init__(self, value):
            self.value = value

        async def read(self, size):
            part, self.value = self.value[:size], self.value[size:]
            return part

    class FakeProcess:
        def __init__(self, argv):
            self.argv = argv
            self.returncode = 0
            self.stdout = FakeStream(
                b"I: decoded synthetic input\n"
                b"W: Unsupported synthetic construct: secret-do-not-retain\n"
                b"ERROR - skipped decoding synthetic method\n"
            )

        async def wait(self):
            return 0

        async def communicate(self):
            return (b"tool-version 1.2.3", None)

        def kill(self):
            self.returncode = -9

    async def fake_create_subprocess_exec(*argv, **_kwargs):
        output_flag = "-o" if "-o" in argv else "-d" if "-d" in argv else None
        if output_flag:
            out_dir = Path(argv[argv.index(output_flag) + 1])
            if Path(argv[0]).name == "apktool":
                out_dir.mkdir(parents=True, exist_ok=True)
                (out_dir / "AndroidManifest.xml").write_text('<manifest package="org.example.fixture"/>')
            else:
                out_dir.mkdir(parents=True, exist_ok=True)
        return FakeProcess(argv)

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)
    extractor = APKExtractor(SimpleNamespace(JADX_PATH="jadx", APKTOOL_PATH="apktool"))

    result = asyncio.run(extractor.extract(str(artifact), str(tmp_path / "out")))

    assert result["artifact_provenance"]["sha256"] == hashlib.sha256(original).hexdigest()
    assert result["artifact_provenance"]["tools"]["jadx"]["version"] == "tool-version 1.2.3"
    apktool_log = result["artifact_provenance"]["tools"]["apktool"]["execution"]["log_observation"]
    assert apktool_log["status"] == "bounded_text_classification"
    assert apktool_log["marker_line_counts"] == {
        "warning": 1, "error": 1, "unsupported": 1, "skip_or_omission": 1,
    }
    assert apktool_log["omitted_file_count"] is None
    assert apktool_log["unsupported_construct_count"] is None
    assert apktool_log["raw_log_retained"] is False
    diagnostics = result["artifact_provenance"]["decompiler_diagnostics"]
    assert diagnostics["review_state"] == "partial"
    assert diagnostics["marker_line_counts"]["unsupported"] == 2
    assert diagnostics["marker_line_counts"]["skip_or_omission"] == 2
    assert diagnostics["unsupported_construct_count"] is None
    assert result["artifact_provenance"]["archive_inventory"]["decompiler_diagnostics"] == diagnostics
    assert "secret-do-not-retain" not in json.dumps(result["artifact_provenance"])
    assert result["package_name"] == "org.example.fixture"
    assert artifact.read_bytes() == original


def test_initial_state_has_empty_artifact_provenance():
    state = create_initial_state("scan-1", "owned.apk", "out")

    assert state["artifact_provenance"] == {}


def test_decompiler_diagnostic_summary_is_count_only_and_downgrades_unsupported_markers():
    from mobileag.ingestion.apk_extractor import _TOOL_DIAGNOSTIC_MARKERS

    def observation(**markers):
        counts = {name: 0 for name in _TOOL_DIAGNOSTIC_MARKERS}
        counts.update(markers)
        return {"status": "bounded_text_classification", "classified_bytes": 100,
                "classification_truncated": False, "marker_line_counts": counts,
                "raw_log_retained": False}

    clean = APKExtractor._summarize_decompiler_diagnostics({
        "apktool": {"log_observation": observation(warning=2)},
        "jadx": {"log_observation": observation()},
    })
    assert clean["review_state"] == "completed"
    assert clean["marker_line_counts"]["warning"] == 2
    assert clean["unsupported_construct_count"] is None
    assert clean["omitted_file_count"] is None
    assert clean["per_tool"]["apktool"]["raw_log_retained"] is False
    assert any("not deduplicated" in note for note in clean["limitations"])

    incomplete = APKExtractor._summarize_decompiler_diagnostics({
        "apktool": {"log_observation": observation(unsupported=1, skip_or_omission=2)},
        "jadx": {"log_observation": observation()},
    })
    assert incomplete["review_state"] == "partial"
    assert incomplete["marker_line_counts"]["unsupported"] == 1


def test_decompiler_truncated_log_diagnostic_inventory_is_incomplete():
    from mobileag.ingestion.apk_extractor import _TOOL_DIAGNOSTIC_MARKERS
    counts = {name: 0 for name in _TOOL_DIAGNOSTIC_MARKERS}
    truncated = {"status": "bounded_text_classification", "classified_bytes": 100,
                 "classification_truncated": True, "marker_line_counts": counts,
                 "raw_log_retained": False}
    result = APKExtractor._summarize_decompiler_diagnostics({
        "apktool": {"log_observation": truncated},
        "jadx": {"log_observation": truncated},
    })
    assert result["status"] == "bounded_diagnostics_incomplete"
    assert result["review_state"] == "partial"
    assert result["marker_line_counts"] is None


def test_report_preserves_artifact_and_tool_provenance():
    state = create_initial_state("scan-1", "owned.apk", "out")
    state["artifact_provenance"] = {
        "sha256": "a" * 64,
        "size_bytes": 123,
        "filename": "owned.apk",
        "mobileag_version": "test",
        "python_version": "3.test",
        "tools": {"jadx": {"executable": "jadx", "version": "1.test"}},
    }

    report = ReportEngine()._prepare_data(state)

    assert report["artifact_provenance"] == state["artifact_provenance"]


def test_report_marks_decompiler_diagnostic_findings_as_static_coverage_gap():
    state = create_initial_state("scan-1", "owned.apk", "out")
    state["coverage"] = {"decompiler_diagnostics": {
        "static_status": "partial", "runtime_status": "not_tested",
        "proof_status": "not_proven", "unsupported_construct_count": None,
        "omitted_file_count": None, "limits_reached": False, "exhaustive": False,
    }}

    report = ReportEngine()._prepare_data(state)

    assert report["assessment_coverage"] == "partial"
    assert "coverage.decompiler_diagnostics.static_status=partial" in report["coverage_gaps"]
    assert report["coverage"]["decompiler_diagnostics"]["unsupported_construct_count"] is None


def test_source_inventory_order_is_stable_and_casefold_sorted(tmp_path):
    (tmp_path / "z.java").write_text("class Z {}", encoding="utf-8")
    (tmp_path / "A.java").write_text("class A {}", encoding="utf-8")
    (tmp_path / "nested").mkdir()
    (tmp_path / "nested" / "b.java").write_text("class B {}", encoding="utf-8")

    inventory = SourceInventory()
    actual = [str(path.relative_to(tmp_path)) for path, _ in inventory.read(tmp_path, {".java"})]

    assert actual == ["A.java", "z.java", "nested/b.java"]
