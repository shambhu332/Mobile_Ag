"""Unit test suite for advanced roadmap modules:
- Hermes Bytecode Analyzer
- Unity IL2CPP Auditor
- iOS Mach-O & Swift Parser
- Smart UI Crawler (Autonomous)
- Frida Stealth Harness
- Privacy Manifest Auditor
"""
import os
import plistlib
import struct
import tempfile
from pathlib import Path
import pytest

from mobileag.analysis.hermes_analyzer import HermesBytecodeAnalyzer
from mobileag.analysis.il2cpp_auditor import Il2CppAuditor
from mobileag.analysis.macho_parser import MachoBinaryParser
from mobileag.analysis.privacy_manifest_auditor import PrivacyManifestAuditor
from mobileag.dast.smart_crawler import SmartUICrawler
from mobileag.dast.ui_crawler import UICrawler
from mobileag.dast.frida_stealth import FridaStealthHarness
from mobileag.reporting.finding import FindingStatus, Severity


def _il2cpp_v29_metadata(literals, types=None):
    """Build a small structurally valid v29 literal-table fixture (not a real APK)."""
    encoded = [value.encode("utf-8") for value in literals]
    header_size = Il2CppAuditor.V29_HEADER_MIN_BYTES
    table_offset = header_size
    table_size = len(encoded) * 8
    data_offset = table_offset + table_size
    literal_data = b"".join(encoded)
    records = bytearray()
    cursor = 0
    for literal in encoded:
        records.extend(struct.pack("<II", len(literal), cursor))
        cursor += len(literal)
    string_pool = bytearray(b"\x00")
    string_indices = {"": 0}

    def add_name(value):
        if value not in string_indices:
            string_indices[value] = len(string_pool)
            string_pool.extend(value.encode("utf-8") + b"\x00")
        return string_indices[value]

    methods = bytearray()
    parameters = bytearray()
    field_records = bytearray()
    type_records = bytearray()
    for type_index, type_info in enumerate(types or []):
        name_index = add_name(type_info["name"])
        namespace_index = add_name(type_info.get("namespace", ""))
        method_start = len(methods) // 36
        method_list = type_info.get("methods", [])
        field_start = len(field_records) // 12
        type_fields = type_info.get("fields", [])
        for field_name in type_fields:
            field_records.extend(struct.pack("<3I", add_name(field_name), 0, 0))
        for method in method_list:
            parameter_start = len(parameters) // 12
            method_parameters = method.get("parameters", [])
            if not method_parameters and method.get("parameter_count", 0):
                method_parameters = [f"arg{index}" for index in range(method["parameter_count"])]
            for parameter_name in method_parameters:
                parameters.extend(struct.pack("<3I", add_name(parameter_name), 0, 0))
            methods.extend(struct.pack(
                "<7I4H", add_name(method["name"]), type_index, 0, 0,
                parameter_start, 0, 0, 0, 0, 0,
                len(method_parameters),
            ))
        fields = [0] * 16 + [0] * 8 + [0, 0]
        fields[0], fields[1], fields[8], fields[9], fields[16], fields[18] = (
            name_index, namespace_index, field_start, method_start,
            len(method_list), len(type_fields),
        )
        type_records.extend(struct.pack("<16I8H2I", *fields))

    string_offset = data_offset + len(literal_data)
    method_offset = string_offset + len(string_pool)
    parameter_offset = method_offset + len(methods)
    field_offset = parameter_offset + len(parameters)
    type_offset = field_offset + len(field_records)
    header = bytearray(header_size)
    struct.pack_into("<6I", header, 0, Il2CppAuditor.IL2CPP_METADATA_MAGIC, 29,
                     table_offset, table_size, data_offset, len(literal_data))
    struct.pack_into("<II", header, 24, string_offset, len(string_pool))
    struct.pack_into("<II", header, 48, method_offset, len(methods))
    struct.pack_into("<II", header, 88, parameter_offset, len(parameters))
    struct.pack_into("<II", header, 96, field_offset, len(field_records))
    struct.pack_into("<II", header, 160, type_offset, len(type_records))
    return (bytes(header) + bytes(records) + literal_data + bytes(string_pool)
            + bytes(methods) + bytes(parameters) + bytes(field_records) + bytes(type_records))


def test_hermes_bytecode_analyzer():
    with tempfile.TemporaryDirectory() as tmp_dir:
        bundle_path = os.path.join(tmp_dir, "index.android.bundle")

        # Create mock Hermes bundle with 0x1F480120 magic header and version 84
        magic_bytes = struct.pack("<Q", 0x1F480120)
        version_bytes = struct.pack("<I", 84)
        payload = (b"https://api.example.com/mobile/v1" + b"\x00" * 20
                   + b"https://api.example.com/mobile/token/synthetic-private-token" + b"\x00"
                   + b"https://api.example.com/auth/token/synthetic-string-secret?access_token=query-secret" + b"\x00"
                   + b'apiKey: "abcdef0123456789abcdef"')

        with open(bundle_path, "wb") as f:
            f.write(magic_bytes + version_bytes + b"\x00" * 16 + payload)

        analyzer = HermesBytecodeAnalyzer()
        res = analyzer.analyze_bundle(bundle_path)

        assert res.is_hermes is True
        assert res.bytecode_version == 84
        assert "https://api.example.com/mobile/v1" in res.api_endpoints
        assert "https://api.example.com/mobile/token/{id}" in res.api_endpoints
        assert "synthetic-private-token" not in repr(res.api_endpoints)
        assert "synthetic-string-secret" not in repr(res.extracted_strings)
        assert "query-secret" not in repr(res.extracted_strings)
        assert len(res.secrets) >= 1
        assert all(secret == {"name": "embedded credential", "value_redacted": True}
                   for secret in res.secrets)
        assert "abcdef0123456789abcdef" not in repr(res.secrets)
        assert "abcdef0123456789abcdef" not in repr(res.extracted_strings)
        assert "[REDACTED]" in repr(res.extracted_strings)
        assert res.function_count is None
        assert res.scan_status == "complete"


def test_hermes_analyzer_bounds_reads_and_skips_symlink_bundles():
    with tempfile.TemporaryDirectory() as tmp_dir, tempfile.TemporaryDirectory() as outside_dir:
        bundle = Path(tmp_dir) / "bundle.hbc"
        payload = struct.pack("<QI", HermesBytecodeAnalyzer.HERMES_MAGIC, 84)
        bundle.write_bytes(payload + b"x" * 32 + b"https://after-limit.example.invalid/api")
        analyzer = HermesBytecodeAnalyzer()
        analyzer.MAX_BUNDLE_BYTES = 24
        result = analyzer.analyze_bundle(bundle)

        external = Path(outside_dir) / "bundle.hbc"
        external.write_bytes(payload + b"https://outside.example.invalid/api")
        linked = Path(tmp_dir) / "linked.hbc"
        linked.symlink_to(external)
        linked_result = analyzer.analyze_bundle(linked)

    assert result.is_hermes is True
    assert result.scan_status == "partial"
    assert result.scan_truncated is True
    assert result.bytes_scanned == 24
    assert result.api_endpoints == []
    assert linked_result.scan_status == "invalid"
    assert "symlink_bundle_skipped" in linked_result.scan_errors


def test_hermes_analyzer_reports_candidate_and_printable_string_caps():
    with tempfile.TemporaryDirectory() as tmp_dir:
        bundle = Path(tmp_dir) / "bundle.hbc"
        header = struct.pack("<QI", HermesBytecodeAnalyzer.HERMES_MAGIC, 84)
        strings = (b"https://one.example.invalid/a\x00https://two.example.invalid/b\x00"
                   b"https://three.example.invalid/c")
        bundle.write_bytes(header + strings)

        output_limited = HermesBytecodeAnalyzer()
        output_limited.MAX_API_ENDPOINTS = 1
        output_limited.MAX_EXTRACTED_STRINGS = 1
        result = output_limited.analyze_bundle(bundle)

        iteration_limited = HermesBytecodeAnalyzer()
        iteration_limited.MAX_PRINTABLE_STRINGS = 1
        bounded = iteration_limited.analyze_bundle(bundle)

    assert result.scan_status == "partial"
    assert result.candidate_output_truncated is True
    assert len(result.api_endpoints) == len(result.extracted_strings) == 1
    assert {"api_endpoint_limit", "string_sample_limit"} <= set(result.scan_errors)
    assert bounded.scan_status == "partial"
    assert bounded.string_count == 1
    assert "printable_string_limit" in bounded.scan_errors


def test_il2cpp_auditor():
    with tempfile.TemporaryDirectory() as tmp_dir:
        meta_dir = os.path.join(tmp_dir, "assets", "bin", "Data", "Managed", "Metadata")
        os.makedirs(meta_dir)

        meta_file = os.path.join(meta_dir, "global-metadata.dat")
        content = _il2cpp_v29_metadata([
            "https://game-api.unity.com/v1", "AuthenticationManager",
            "https://game-api.unity.com/v1/auth/%74oken/synthetic-private-token",
            'apiKey: "synthetic-unity-secret-123"',
        ], types=[{"name": "AuthenticationManager", "namespace": "sample",
                   "fields": ["sessionToken"],
                   "methods": [{"name": "authenticate", "parameters": ["account", "token"]}]}])

        with open(meta_file, "wb") as f:
            f.write(content)

        auditor = Il2CppAuditor()
        res = auditor.audit_package(tmp_dir)

        assert res.is_il2cpp is True
        assert res.metadata_version == 29
        assert res.metadata_tables_status == "parsed"
        assert res.metadata_string_literals_count == 4
        assert "https://game-api.unity.com/v1" in res.api_endpoints
        assert "https://game-api.unity.com/v1/auth/%74oken/{id}" in res.api_endpoints
        assert "synthetic-private-token" not in repr(res.api_endpoints)
        assert res.metadata_definitions_status == "parsed"
        assert res.reconstructed_classes == ["sample.AuthenticationManager"]
        assert res.reconstructed_methods == [{
            "declaring_type": "sample.AuthenticationManager",
            "method_name": "authenticate", "parameter_count": 2,
            "parameter_names": ["account", "token"],
        }]
        assert res.reconstructed_fields == [{
            "declaring_type": "sample.AuthenticationManager", "field_name": "sessionToken",
        }]
        assert res.potential_secrets == [{"name": "embedded credential", "value_redacted": True}]
        assert "synthetic-unity-secret-123" not in repr(res.potential_secrets)
        assert res.scan_status == "complete"
        assert res.metadata_truncated is False


def test_il2cpp_auditor_reports_string_and_candidate_caps():
    with tempfile.TemporaryDirectory() as tmp_dir:
        metadata_dir = Path(tmp_dir) / "assets/bin/Data/Managed/Metadata"
        metadata_dir.mkdir(parents=True)
        metadata = metadata_dir / "global-metadata.dat"
        metadata.write_bytes(_il2cpp_v29_metadata([
            "https://one.example.invalid/a", "https://two.example.invalid/b",
            "AuthManager", "AccountManager", "PaymentManager",
        ]))

        candidate_limited = Il2CppAuditor()
        candidate_limited.MAX_ENDPOINTS = 1
        candidate_limited.MAX_CLASS_CANDIDATES = 1
        result = candidate_limited.audit_package(tmp_dir)

        iteration_limited = Il2CppAuditor()
        iteration_limited.MAX_STRING_LITERAL_ITEMS = 1
        bounded = iteration_limited.audit_package(tmp_dir)

    assert result.scan_status == "partial"
    assert result.candidate_output_truncated is True
    assert len(result.api_endpoints) == len(result.class_name_candidates) == 1
    assert {"api_endpoint_limit", "class_candidate_limit"} <= set(result.scan_errors)
    assert bounded.scan_status == "partial"
    assert bounded.string_literals_count == 1
    assert "string_literal_table_partial" in bounded.scan_errors
    assert bounded.metadata_string_literals_count == 1


def test_il2cpp_v29_literal_table_rejects_out_of_bounds_sections(tmp_path):
    metadata_dir = tmp_path / "assets/bin/Data/Managed/Metadata"
    metadata_dir.mkdir(parents=True)
    metadata = bytearray(_il2cpp_v29_metadata(["example literal"]))
    struct.pack_into("<I", metadata, 12, len(metadata) + 1)  # table byte size exceeds file
    (metadata_dir / "global-metadata.dat").write_bytes(metadata)

    result = Il2CppAuditor().audit_package(tmp_path)

    assert result.metadata_tables_status == "invalid"
    assert result.metadata_string_literals_count == 0
    assert "string_literal_table_invalid" in result.scan_errors
    assert result.scan_status == "partial"


def test_il2cpp_unsupported_metadata_version_marks_lexical_fallback_partial(tmp_path):
    metadata_dir = tmp_path / "assets/bin/Data/Managed/Metadata"
    metadata_dir.mkdir(parents=True)
    data = bytearray(_il2cpp_v29_metadata(["AuthenticationManager"]))
    struct.pack_into("<I", data, 4, 24)
    (metadata_dir / "global-metadata.dat").write_bytes(data)

    result = Il2CppAuditor().audit_package(tmp_path)

    assert result.metadata_version == 24
    assert result.metadata_tables_status == "unsupported_version"
    assert result.metadata_definitions_status == "unsupported_version"
    assert result.class_name_candidates == ["AuthenticationManager"]
    assert "unsupported_metadata_version" in result.scan_errors
    assert result.scan_status == "partial"


def test_il2cpp_v29_type_table_reports_bad_method_ranges(tmp_path):
    metadata_dir = tmp_path / "assets/bin/Data/Managed/Metadata"
    metadata_dir.mkdir(parents=True)
    data = bytearray(_il2cpp_v29_metadata(
        [], types=[{"name": "Vault", "namespace": "sample",
                    "methods": [{"name": "load", "parameter_count": 1}]}],
    ))
    type_offset = struct.unpack_from("<I", data, 160)[0]
    struct.pack_into("<H", data, type_offset + 64, 9)  # method_count exceeds table
    (metadata_dir / "global-metadata.dat").write_bytes(data)

    result = Il2CppAuditor().audit_package(tmp_path)

    assert result.metadata_definitions_status == "partial"
    assert result.reconstructed_classes == ["sample.Vault"]
    assert result.reconstructed_methods == []
    assert "type_method_tables_partial" in result.scan_errors


def test_il2cpp_v29_parameter_table_range_is_checked(tmp_path):
    metadata_dir = tmp_path / "assets/bin/Data/Managed/Metadata"
    metadata_dir.mkdir(parents=True)
    data = bytearray(_il2cpp_v29_metadata(
        [], types=[{"name": "Profile", "methods": [
            {"name": "load", "parameters": ["userId"]},
        ]}],
    ))
    method_offset = struct.unpack_from("<I", data, 48)[0]
    struct.pack_into("<I", data, method_offset + 16, 100)  # parameterStart exceeds table
    (metadata_dir / "global-metadata.dat").write_bytes(data)

    result = Il2CppAuditor().audit_package(tmp_path)

    assert result.metadata_definitions_status == "partial"
    assert result.reconstructed_methods[0]["method_name"] == "load"
    assert result.reconstructed_methods[0]["parameter_names"] == []
    assert "type_method_tables_partial" in result.scan_errors


def test_il2cpp_auditor_bounds_metadata_and_rejects_symlinked_metadata():
    with tempfile.TemporaryDirectory() as tmp_dir, tempfile.TemporaryDirectory() as outside_dir:
        base = Path(tmp_dir)
        metadata_dir = base / "assets/bin/Data/Managed/Metadata"
        metadata_dir.mkdir(parents=True)
        metadata = metadata_dir / "global-metadata.dat"
        metadata.write_bytes(_il2cpp_v29_metadata(
            ["https://late.example.invalid/api"],
        ))
        auditor = Il2CppAuditor()
        auditor.MAX_METADATA_BYTES = 32
        truncated = auditor.audit_package(base)

        outside = Path(outside_dir) / "global-metadata.dat"
        outside.write_bytes(_il2cpp_v29_metadata([]))
        metadata.unlink()
        metadata.symlink_to(outside)
        linked = Il2CppAuditor().audit_package(base)

    assert truncated.metadata_version == 29
    assert truncated.metadata_truncated is True
    assert truncated.metadata_bytes_scanned == 32
    assert truncated.metadata_tables_status == "parsed"
    assert truncated.metadata_string_literals_count == 1
    assert truncated.scan_status == "partial"
    assert "symlink_metadata_skipped" in linked.scan_errors
    assert linked.global_metadata_present is False


def test_il2cpp_library_inventory_is_entry_bounded_and_no_follow(tmp_path):
    base = tmp_path / "unity"
    library_dir = base / "lib" / "arm64-v8a"
    library_dir.mkdir(parents=True)
    (library_dir / "libil2cpp.so").write_bytes(b"synthetic")
    analyzer = Il2CppAuditor()
    analyzer.MAX_TREE_ENTRIES = 1

    result = analyzer.audit_package(base)

    assert result.scan_status == "partial"
    assert result.tree_entries_scanned == 1
    assert "tree_entry_limit" in result.scan_errors
    assert result.libil2cpp_present is False


def test_macho_binary_parser():
    with tempfile.TemporaryDirectory() as tmp_dir:
        bin_path = os.path.join(tmp_dir, "TargetApp")

        # Magic: 0xFEEDFACF (64-bit Mach-O) in little endian
        magic_bytes = struct.pack("<I", 0xFEEDFACF)
        payload = (b"\x00" * 30 + b"__swift5_types" + b"\x00" * 20 + b"CommonCrypto" + b"\x00" * 20
                   + b"https://ios.example.com/api\x00"
                   + b"https://ios.example.com/api/auth/token/synthetic-private-token")

        with open(bin_path, "wb") as f:
            f.write(magic_bytes + b"\x00" * 28 + payload)

        parser = MachoBinaryParser()
        res = parser.parse_binary(bin_path)

        assert res.is_macho is True
        assert res.is_64bit is True
        assert "__swift5_types" in res.swift_section_name_candidates
        assert "__swift5_types" not in res.swift_sections_detected
        assert "CommonCrypto" in res.crypto_frameworks
        assert "https://ios.example.com/api" in res.api_endpoints
        assert "https://ios.example.com/api/auth/token/{id}" in res.api_endpoints
        assert "synthetic-private-token" not in repr(res.api_endpoints)


def test_macho_parser_reads_bounded_load_commands_swift_sections_and_cstrings(tmp_path):
    import struct

    strings = (b"https://api.example.test/v1\0"
               b"https://api.example.test/auth/token/synthetic-cstring-secret\0")
    dylib_name = b"/System/Library/Frameworks/Security.framework/Security\0"
    dylib_size = (24 + len(dylib_name) + 7) & ~7
    dylib = struct.pack("<IIIIII", 0x0C, dylib_size, 24, 0, 0, 0) + dylib_name
    dylib += b"\0" * (dylib_size - len(dylib))
    string_offset = 32 + 232 + len(dylib)
    segment = struct.pack("<II16sQQQQiiII", 0x19, 232, b"__TEXT", 0x1000,
                          len(strings), string_offset, len(strings), 7, 5, 2, 0)
    cstrings = struct.pack("<16s16sQQIIIIIIII", b"__cstring", b"__TEXT", 0x1000,
                           len(strings), string_offset, 0, 0, 0, 0, 0, 0, 0)
    swift = struct.pack("<16s16sQQIIIIIIII", b"__swift5_types", b"__TEXT", 0x2000,
                        4, string_offset, 0, 0, 0, 0, 0, 0, 0)
    commands = segment + cstrings + swift + dylib
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2,
                         2, len(commands), 0, 0)
    binary = tmp_path / "ValidMachO"
    binary.write_bytes(header + commands + strings)

    result = MachoBinaryParser().parse_binary(binary)
    assert result.parse_status == "complete"
    assert result.load_commands_count == 2
    assert "/System/Library/Frameworks/Security.framework/Security" in result.imported_dylibs
    assert "__swift5_types" in result.swift_sections_detected
    assert "https://api.example.test/v1" in result.cstring_samples
    assert "https://api.example.test/auth/token/{id}" in result.cstring_samples
    assert "synthetic-cstring-secret" not in repr(result.cstring_samples)


def test_macho_parser_reports_malformed_load_commands_without_crashing(tmp_path):
    import struct

    header = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, 8, 0, 0)
    binary = tmp_path / "MalformedMachO"
    binary.write_bytes(header + struct.pack("<II", 0x19, 0))
    result = MachoBinaryParser().parse_binary(binary)
    assert result.is_macho is True
    assert result.parse_status == "partial"
    assert "Invalid load-command size" in result.parse_errors


def test_macho_parser_rejects_symlink_and_marks_bounded_thin_input_partial(tmp_path):
    real = tmp_path / "real.macho"
    real.write_bytes(struct.pack("<I", MachoBinaryParser.MH_MAGIC_64) + b"\x00" * 64)
    linked = tmp_path / "linked.macho"
    linked.symlink_to(real)
    linked_result = MachoBinaryParser().parse_binary(linked)
    assert linked_result.parse_status == "rejected_input"

    parser = MachoBinaryParser()
    parser.MAX_BINARY_BYTES = 16
    bounded = parser.parse_binary(real)
    assert bounded.is_macho is True
    assert bounded.binary_truncated is True
    assert bounded.parse_status == "partial"
    assert any("bounded read limit" in error for error in bounded.parse_errors)


def test_macho_parser_caps_url_candidate_iteration_and_output(tmp_path):
    header = struct.pack("<IiiIIIII", MachoBinaryParser.MH_MAGIC_64, 0x0100000C,
                         0, 2, 0, 0, 0, 0)
    binary = tmp_path / "URLs.macho"
    binary.write_bytes(header + b"https://one.example.test/a\x00https://two.example.test/b")
    parser = MachoBinaryParser()
    parser.MAX_API_ENDPOINTS = 1

    result = parser.parse_binary(binary)

    assert result.api_endpoints == ["https://one.example.test/a"]
    assert result.candidate_output_truncated is True
    assert result.parse_status == "partial"
    assert "API endpoint candidate limit reached" in result.parse_errors


def test_macho_parser_inventories_only_bounded_swift_nominal_type_names(tmp_path):
    import struct

    # One __swift5_types relative pointer to a synthetic struct descriptor/name.
    section_offset = 32 + 152
    metadata = bytearray(24)
    struct.pack_into("<i", metadata, 0, 4)
    struct.pack_into("<I", metadata, 4, 17)  # Swift struct context kind
    struct.pack_into("<i", metadata, 12, 12)  # name pointer is relative to descriptor+8
    metadata.extend("CaféType".encode("utf-8") + b"\0")
    segment = struct.pack("<II16sQQQQiiII", 0x19, 152, b"__TEXT", 0x1000,
                          len(metadata), section_offset, len(metadata), 7, 5, 1, 0)
    swift_section = struct.pack("<16s16sQQIIIIIIII", b"__swift5_types", b"__TEXT",
                                0x2000, 4, section_offset, 0, 0, 0, 0, 0, 0, 0)
    command = segment + swift_section
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, len(command), 0, 0)
    binary = tmp_path / "SwiftTypes"
    binary.write_bytes(header + command + metadata)
    result = MachoBinaryParser().parse_binary(binary)
    assert result.swift_type_metadata_status == "parsed"
    assert result.swift_type_name_candidates == ["CaféType"]


def test_macho_parser_does_not_dereference_indirect_swift_type_pointer(tmp_path):
    import struct

    section_offset = 32 + 152
    metadata = struct.pack("<i", 5)  # low bit marks an indirectable pointer
    segment = struct.pack("<II16sQQQQiiII", 0x19, 152, b"__TEXT", 0x1000,
                          4, section_offset, 4, 7, 5, 1, 0)
    swift_section = struct.pack("<16s16sQQIIIIIIII", b"__swift5_types", b"__TEXT",
                                0x2000, 4, section_offset, 0, 0, 0, 0, 0, 0, 0)
    command = segment + swift_section
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, len(command), 0, 0)
    binary = tmp_path / "SwiftIndirect"
    binary.write_bytes(header + command + metadata)
    result = MachoBinaryParser().parse_binary(binary)
    assert result.swift_type_metadata_status == "partial"
    assert result.swift_type_name_candidates == []


def test_macho_parser_reads_bounded_swift_field_names(tmp_path):
    import struct

    body_offset = 32 + 232
    type_name = b"Example\0"
    type_blob = bytearray(24)
    struct.pack_into("<i", type_blob, 0, 4)
    struct.pack_into("<I", type_blob, 4, 17)
    struct.pack_into("<i", type_blob, 12, 12)
    type_blob.extend(type_name)
    field_offset = body_offset + len(type_blob)
    struct.pack_into("<i", type_blob, 20, field_offset - (body_offset + 20))
    field_name = b"displayName\0"
    field_blob = bytearray(struct.pack("<iiHHI", 0, 0, 0, 12, 1))
    field_blob.extend(struct.pack("<Iii", 0, 0, 4))
    field_blob.extend(field_name)

    segment = struct.pack("<II16sQQQQiiII", 0x19, 232, b"__TEXT", 0x1000,
                          len(type_blob) + len(field_blob), body_offset,
                          len(type_blob) + len(field_blob), 7, 5, 2, 0)
    types_section = struct.pack("<16s16sQQIIIIIIII", b"__swift5_types", b"__TEXT",
                                0x2000, 4, body_offset, 0, 0, 0, 0, 0, 0, 0)
    fields_section = struct.pack("<16s16sQQIIIIIIII", b"__swift5_fieldmd", b"__TEXT",
                                 0x3000, len(field_blob), field_offset, 0, 0, 0, 0, 0, 0, 0)
    command = segment + types_section + fields_section
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, len(command), 0, 0)
    binary = tmp_path / "SwiftFields"
    binary.write_bytes(header + command + type_blob + field_blob)
    result = MachoBinaryParser().parse_binary(binary)
    assert result.swift_type_metadata_status == "parsed"
    assert result.swift_type_field_candidates == [{"type_name": "Example", "field_names": ["displayName"]}]

    malformed = bytearray(binary.read_bytes())
    struct.pack_into("<H", malformed, field_offset + 10, 11)  # unsupported record stride
    malformed_path = tmp_path / "SwiftFieldsMalformed"
    malformed_path.write_bytes(malformed)
    malformed_result = MachoBinaryParser().parse_binary(malformed_path)
    assert malformed_result.swift_type_metadata_status == "partial"
    assert malformed_result.swift_type_field_candidates == []


def test_macho_parser_inventories_direct_swift_protocol_descriptors(tmp_path):
    import struct

    section_offset = 32 + 152
    metadata = bytearray(28)
    struct.pack_into("<i", metadata, 0, 4)
    struct.pack_into("<I", metadata, 4, 3)  # Protocol context descriptor kind
    struct.pack_into("<i", metadata, 12, 16)
    metadata.extend(b"Displayable\0")
    segment = struct.pack("<II16sQQQQiiII", 0x19, 152, b"__TEXT", 0x1000,
                          len(metadata), section_offset, len(metadata), 7, 5, 1, 0)
    protocol_section = struct.pack("<16s16sQQIIIIIIII", b"__swift5_protos", b"__TEXT",
                                   0x2000, 4, section_offset, 0, 0, 0, 0, 0, 0, 0)
    command = segment + protocol_section
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, len(command), 0, 0)
    binary = tmp_path / "SwiftProtocol"
    binary.write_bytes(header + command + metadata)
    result = MachoBinaryParser().parse_binary(binary)
    assert result.swift_protocol_metadata_status == "parsed"
    assert result.swift_protocol_name_candidates == ["Displayable"]


def test_macho_parser_reads_bounded_fat_architecture_slices(tmp_path):
    import struct

    arm_slice = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 0, 0, 0, 0)
    x64_slice = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x01000007, 0, 2, 0, 0, 0, 0)
    arm_offset = 8 + 2 * 20
    x64_offset = arm_offset + len(arm_slice)
    fat_header = struct.pack(">II", 0xCAFEBABE, 2)
    arch_table = struct.pack(">iiIII", 0x0100000C, 0, arm_offset, len(arm_slice), 2)
    arch_table += struct.pack(">iiIII", 0x01000007, 0, x64_offset, len(x64_slice), 2)
    binary = tmp_path / "UniversalMachO"
    binary.write_bytes(fat_header + arch_table + arm_slice + x64_slice)

    result = MachoBinaryParser().parse_binary(binary)
    assert result.is_macho is True
    assert result.parse_status == "complete"
    assert result.slice_count == 2
    assert result.architectures == ["ARM64", "X86_64"]


def test_macho_parser_reports_invalid_fat_slice_range(tmp_path):
    import struct

    binary = tmp_path / "MalformedFatMachO"
    binary.write_bytes(struct.pack(">IIiiIII", 0xCAFEBABE, 1, 0x0100000C, 0,
                                  0xFFFFFF00, 64, 2))
    result = MachoBinaryParser().parse_binary(binary)
    assert result.parse_status == "partial"
    assert "Fat slice 0 has an invalid bounded file range" in result.parse_errors


def test_macho_parser_reads_32_bit_load_commands_and_cstring_sections(tmp_path):
    import struct

    strings = b"https://legacy.example.test/api\0"
    string_offset = 28 + 124
    segment = struct.pack("<II16sIIIIiiII", 1, 124, b"__TEXT", 0x1000,
                          len(strings), string_offset, len(strings), 7, 5, 1, 0)
    section = struct.pack("<16s16sIIIIIIIII", b"__cstring", b"__TEXT", 0x1000,
                          len(strings), string_offset, 0, 0, 0, 0, 0, 0)
    commands = segment + section
    header = struct.pack("<IiiIIII", 0xFEEDFACE, 12, 0, 2, 1, len(commands), 0)
    binary = tmp_path / "Legacy32MachO"
    binary.write_bytes(header + commands + strings)

    result = MachoBinaryParser().parse_binary(binary)
    assert result.parse_status == "complete"
    assert result.is_64bit is False
    assert result.architectures == ["ARM"]
    assert result.sections[0]["name"] == "__cstring"
    assert "https://legacy.example.test/api" in result.cstring_samples


def test_macho_parser_supports_32_bit_slice_in_fat_binary(tmp_path):
    import struct

    thin32 = struct.pack("<IiiIIII", 0xFEEDFACE, 12, 0, 2, 0, 0, 0)
    slice_offset = 8 + 20
    fat = struct.pack(">IIiiIII", 0xCAFEBABE, 1, 12, 0, slice_offset, len(thin32), 2)
    binary = tmp_path / "Fat32MachO"
    binary.write_bytes(fat + thin32)

    result = MachoBinaryParser().parse_binary(binary)
    assert result.parse_status == "complete"
    assert result.slice_count == 1
    assert result.architectures == ["ARM"]


def test_macho_parser_rejects_fat_architecture_slice_mismatch(tmp_path):
    import struct

    x64_slice = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x01000007, 0, 2, 0, 0, 0, 0)
    slice_offset = 8 + 20
    fat = struct.pack(">IIiiIII", 0xCAFEBABE, 1, 0x0100000C, 0,
                      slice_offset, len(x64_slice), 2)
    binary = tmp_path / "MismatchedFatMachO"
    binary.write_bytes(fat + x64_slice)

    result = MachoBinaryParser().parse_binary(binary)
    assert result.parse_status == "partial"
    assert "Fat slice 0 CPU type disagrees with its architecture-table entry" in result.parse_errors
    assert result.load_commands_count == 0


def test_macho_parser_reads_bounded_64_bit_symbol_names(tmp_path):
    import struct

    strings = b"\0_$s4Demo3fooyyF\0"
    symbol_offset = 32 + 24
    string_offset = symbol_offset + 16
    symtab_command = struct.pack("<IIIIII", 2, 24, symbol_offset, 1,
                                 string_offset, len(strings))
    symbol = struct.pack("<IBBHQ", 1, 0x0F, 1, 0, 0)
    header = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, 24, 0, 0)
    binary = tmp_path / "SymbolsMachO"
    binary.write_bytes(header + symtab_command + symbol + strings)

    result = MachoBinaryParser().parse_binary(binary)
    assert result.parse_status == "complete"
    assert result.symbol_names == ["_$s4Demo3fooyyF"]


def test_smart_ui_crawler():
    crawler = SmartUICrawler(test_user="researcher@example.test", test_pass="Synthetic-Only-123!")

    # Simulate permission prompt screen
    perm_xml = """<hierarchy rotation="0">
        <node class="android.widget.FrameLayout" bounds="[0,0][1080,2400]">
            <node class="android.widget.Button" text="While using the app" resource-id="com.android.permissioncontroller:id/permission_allow_foreground_only_button" clickable="true" bounds="[100,500][980,600]" />
        </node>
    </hierarchy>"""

    decision1 = crawler.decide_next_action("com.example.app.MainActivity", perm_xml)
    assert decision1.action == "WAIT"
    assert "explicit operator review" in decision1.explanation

    # Simulate login screen
    login_xml = """<hierarchy rotation="0">
        <node class="android.widget.LinearLayout" bounds="[0,0][1080,2400]">
            <node class="android.widget.EditText" resource-id="com.example.app:id/email_input" text="" bounds="[100,200][900,300]" />
            <node class="android.widget.EditText" resource-id="com.example.app:id/password_input" text="" bounds="[100,350][900,450]" />
            <node class="android.widget.Button" text="Sign In" resource-id="com.example.app:id/login_button" clickable="true" bounds="[100,500][900,600]" />
        </node>
    </hierarchy>"""

    decision2 = crawler.decide_next_action("com.example.app.LoginActivity", login_xml)
    assert decision2.action == "WAIT"
    assert "explicit operator approval" in decision2.explanation

    approved_credential_entry = SmartUICrawler(
        test_user="researcher@example.test", test_pass="Synthetic-Only-123!",
        allow_test_credential_entry=True,
    )
    decision2_approved = approved_credential_entry.decide_next_action(
        "com.example.app.LoginActivity", login_xml
    )
    assert decision2_approved.action == "TYPE_TEXT"
    assert decision2_approved.input_text == "researcher@example.test"

    # No embedded/default credentials and no submit action without an
    # operator-provided synthetic identity.
    default_crawler = SmartUICrawler()
    decision3 = default_crawler.decide_next_action("com.example.app.LoginActivity", login_xml)
    assert decision3.action == "WAIT"
    assert "operator-supplied" in decision3.explanation
    populated_login = login_xml.replace('text=""', 'text="synthetic"')
    decision4 = approved_credential_entry.decide_next_action("com.example.app.LoginActivity", populated_login)
    assert decision4.action == "WAIT"
    assert "explicit operator approval" in decision4.explanation


def test_smart_ui_crawler_omits_raw_labels_from_decision_explanations():
    private_label = "synthetic-user@example.invalid"
    permission = SmartUICrawler()
    decision = permission.decide_next_action(
        "com.example.app.MainActivity",
        '<hierarchy><node class="android.widget.Button" '
        f'text="Allow {private_label}" resource-id="permission_allow_button" '
        'clickable="true" bounds="[0,0][10,10]" /></hierarchy>',
    )
    assert decision.action == "WAIT"
    assert private_label not in decision.explanation
    assert private_label not in str(permission.visited_states)

    exploratory = SmartUICrawler(allow_exploratory_clicks=True)
    private_button_text = "Private Account Recovery 847291"
    decision = exploratory.decide_next_action(
        "com.example.app.MainActivity",
        '<hierarchy><node class="android.widget.Button" '
        f'text="{private_button_text}" clickable="true" bounds="[0,0][10,10]" '
        '/></hierarchy>',
    )
    assert decision.action == "CLICK"
    assert private_button_text not in decision.explanation

    submit = SmartUICrawler(allow_form_submit=True)
    decision = submit.decide_next_action(
        "com.example.app.LoginActivity",
        '<hierarchy><node class="android.widget.Button" '
        'text="Confirm synthetic-user@example.invalid" resource-id="submit" '
        'clickable="true" bounds="[0,0][10,10]" /></hierarchy>',
    )
    assert decision.action == "CLICK"
    assert "synthetic-user@example.invalid" not in decision.explanation


def test_smart_ui_crawler_requires_opt_in_for_back_navigation():
    xml = '<hierarchy rotation="0" />'
    default_crawler = SmartUICrawler()
    decisions = [default_crawler.decide_next_action("com.example.app.MainActivity", xml)
                 for _ in range(4)]
    assert decisions[-1].action == "WAIT"
    assert "BACK navigation requires explicit operator approval" in decisions[-1].explanation

    approved_crawler = SmartUICrawler(allow_back_navigation=True)
    approved_decisions = [approved_crawler.decide_next_action("com.example.app.MainActivity", xml)
                          for _ in range(4)]
    assert approved_decisions[-1].action == "BACK"


def test_smart_ui_crawler_stops_when_visited_state_budget_is_exhausted():
    crawler = SmartUICrawler(allow_exploratory_clicks=True)
    crawler.MAX_TRACKED_STATES = 1
    first = '<hierarchy><node class="android.widget.Button" clickable="true" bounds="[0,0][1,1]" /></hierarchy>'
    assert crawler.decide_next_action("com.example.app.FirstActivity", first).action == "CLICK"

    second = '<hierarchy><node class="android.widget.Button" clickable="true" bounds="[0,0][2,2]" /></hierarchy>'
    decision = crawler.decide_next_action("com.example.app.SecondActivity", second)

    assert decision.action == "WAIT"
    assert "tracking limit reached" in decision.explanation
    assert crawler.state_tracking_truncated is True
    assert len(crawler.visited_states) == 1


def test_smart_ui_crawler_fails_closed_on_large_or_truncated_hierarchies():
    crawler = SmartUICrawler(allow_exploratory_clicks=True)
    oversized = "<hierarchy>" + " " * crawler.MAX_HIERARCHY_CHARS + "</hierarchy>"
    assert crawler.decide_next_action("Activity", oversized).action == "WAIT"
    assert crawler.last_parse_status == "too_large"

    nodes = "".join('<node class="Button" clickable="true" bounds="[0,0][1,1]" />'
                    for _ in range(crawler.MAX_HIERARCHY_ELEMENTS + 1))
    truncated = f"<hierarchy>{nodes}</hierarchy>"
    assert len(crawler.parse_hierarchy_xml(truncated)) == crawler.MAX_HIERARCHY_ELEMENTS
    assert crawler.last_parse_status == "truncated"
    decision = crawler.decide_next_action("Activity", truncated)
    assert decision.action == "WAIT"
    assert "incomplete" in decision.explanation

    entity_xml = ('<!DOCTYPE hierarchy [<!ENTITY label "synthetic">]>'
                  '<hierarchy><node text="&label;" clickable="true" /></hierarchy>')
    assert crawler.decide_next_action("Activity", entity_xml).action == "WAIT"
    assert crawler.last_parse_status == "unsafe_declaration"


def test_ui_crawler_factory_propagates_smart_crawler_opt_ins():
    crawler = UICrawler().get_smart_crawler(
        test_user="synthetic@example.test", test_pass="synthetic-only",
        allow_test_credential_entry=True, allow_back_navigation=True,
    )
    assert crawler.allow_test_credential_entry is True
    assert crawler.allow_back_navigation is True


def test_frida_stealth_harness():
    harness = FridaStealthHarness()
    with pytest.raises(NotImplementedError, match="Stealthy daemon deployment is disabled"):
        harness.generate_random_config()
    with pytest.raises(NotImplementedError, match="Anti-detection hook generation is disabled"):
        harness.get_stealth_preamble_script()


def test_privacy_manifest_auditor():
    with tempfile.TemporaryDirectory() as tmp_dir:
        plist_path = os.path.join(tmp_dir, "PrivacyInfo.xcprivacy")
        plist_data = {
            "NSPrivacyTracking": True,
            "NSPrivacyTrackingDomains": ["analytics.thirdparty.com"],
            "NSPrivacyAccessedAPITypes": [
                {
                    "NSPrivacyAccessedAPIType": "NSPrivacyAccessedAPITypeUserDefaults",
                    "NSPrivacyAccessedAPITypeReasons": ["CA92.1", "CA92.2"],
                }
            ],
        }

        with open(plist_path, "wb") as f:
            plistlib.dump(plist_data, f)

        auditor = PrivacyManifestAuditor()
        res = auditor.audit_ios_privacy_manifest(tmp_dir)

        assert res.has_privacy_manifest is True
        assert res.tracking_enabled is True
        assert "analytics.thirdparty.com" in res.tracking_domains
        assert "NSPrivacyAccessedAPITypeUserDefaults" in res.declared_api_categories
        assert res.declared_api_reasons == [
            {"category": "NSPrivacyAccessedAPITypeUserDefaults", "reason_code": "CA92.1"},
            {"category": "NSPrivacyAccessedAPITypeUserDefaults", "reason_code": "CA92.2"},
        ]
        assert res.parse_status == "parsed"
        assert res.manifest_count == 1
        assert res.manifests[0]["path"] == "PrivacyInfo.xcprivacy"


def test_ios_privacy_manifest_audit_reports_partial_parse_and_keeps_bundle_results_separate():
    with tempfile.TemporaryDirectory() as tmp_dir:
        base = Path(tmp_dir)
        main = base / "PrivacyInfo.xcprivacy"
        nested = base / "Frameworks" / "Example.framework" / "PrivacyInfo.xcprivacy"
        nested.parent.mkdir(parents=True)
        with main.open("wb") as f:
            plistlib.dump({"NSPrivacyTracking": True, "NSPrivacyTrackingDomains": [],
                           "NSPrivacyAccessedAPITypes": []}, f)
        nested.write_bytes(b"not a plist")

        result = PrivacyManifestAuditor().audit_ios_privacy_manifest(base)

    assert result.has_privacy_manifest
    assert result.manifest_count == 2
    assert result.parse_status == "partial"
    assert result.manifest_paths == ["Frameworks/Example.framework/PrivacyInfo.xcprivacy",
                                    "PrivacyInfo.xcprivacy"]
    assert result.manifests == [{"path": "PrivacyInfo.xcprivacy", "tracking_enabled": True,
                                 "tracking_domains": [], "declared_api_categories": [],
                                 "declared_api_reasons": []}]
    assert result.tracking_enabled is True
    assert result.errors == ["manifest_parse_error"]


def test_ios_privacy_manifest_inventory_is_entry_bounded(tmp_path):
    (tmp_path / "PrivacyInfo.xcprivacy").write_bytes(plistlib.dumps({
        "NSPrivacyTracking": False, "NSPrivacyTrackingDomains": [],
        "NSPrivacyAccessedAPITypes": [],
    }))
    auditor = PrivacyManifestAuditor()
    auditor.MAX_TREE_ENTRIES = 0

    result = auditor.audit_ios_privacy_manifest(tmp_path)

    assert result.parse_status == "partial"
    assert result.manifest_count == 0
    assert "scan_limit_reached" in result.errors


def test_ios_privacy_manifest_enforces_aggregate_bytes_and_reports_coverage(tmp_path):
    root = tmp_path / "app"
    first = root / "A.framework" / "PrivacyInfo.xcprivacy"
    second = root / "B.framework" / "PrivacyInfo.xcprivacy"
    first.parent.mkdir(parents=True)
    second.parent.mkdir(parents=True)
    payload = plistlib.dumps({"NSPrivacyTracking": False, "NSPrivacyTrackingDomains": [],
                              "NSPrivacyAccessedAPITypes": []})
    first.write_bytes(payload)
    second.write_bytes(payload)
    auditor = PrivacyManifestAuditor()
    auditor.MAX_MANIFEST_TOTAL_BYTES = len(payload) + 1

    result = auditor.audit_ios_privacy_manifest(root)

    assert result.manifest_bytes_scanned == len(payload)
    assert result.manifest_count == 2
    assert len(result.manifests) == 1
    assert result.parse_status == "partial"
    assert "manifest_total_byte_limit" in result.errors


def test_ios_privacy_manifest_caps_domain_category_and_error_outputs(tmp_path):
    path = tmp_path / "PrivacyInfo.xcprivacy"
    with path.open("wb") as stream:
        plistlib.dump({
            "NSPrivacyTracking": False,
            "NSPrivacyTrackingDomains": ["one.example", "x" * 254,
                                         "two.example", "three.example", "four.example"],
            "NSPrivacyAccessedAPITypes": [
                {"NSPrivacyAccessedAPIType": "Category0"},
                {"NSPrivacyAccessedAPIType": "x" * 257},
                {"NSPrivacyAccessedAPIType": "Category1"},
                {"NSPrivacyAccessedAPIType": "Category2"},
            ],
        }, stream)
    auditor = PrivacyManifestAuditor()
    auditor.MAX_TRACKING_DOMAINS = 3
    auditor.MAX_API_CATEGORIES = 3

    result = auditor.audit_ios_privacy_manifest(tmp_path)

    assert result.parse_status == "partial"
    assert result.tracking_domains == ["one.example", "two.example"]
    assert len(result.declared_api_categories) == 2
    assert len(result.manifests[0]["tracking_domains"]) == 2
    assert len(result.errors) <= auditor.MAX_ERROR_CODES
    assert "tracking_domain_limit_reached" in result.errors
    assert "api_category_limit_reached" in result.errors
    assert "invalid_tracking_domains" in result.errors


def test_ios_privacy_manifest_retains_bounded_reason_codes_without_validating_them(tmp_path):
    path = tmp_path / "PrivacyInfo.xcprivacy"
    with path.open("wb") as stream:
        plistlib.dump({
            "NSPrivacyTracking": False,
            "NSPrivacyTrackingDomains": [],
            "NSPrivacyAccessedAPITypes": [{
                "NSPrivacyAccessedAPIType": "NSPrivacyAccessedAPITypeUserDefaults",
                "NSPrivacyAccessedAPITypeReasons": ["SYNTHETIC.1", "x" * 65, "SYNTHETIC.2"],
            }],
        }, stream)
    auditor = PrivacyManifestAuditor()
    auditor.MAX_API_REASONS_PER_CATEGORY = 3

    result = auditor.audit_ios_privacy_manifest(tmp_path)

    assert result.parse_status == "partial"
    assert result.declared_api_reasons == [
        {"category": "NSPrivacyAccessedAPITypeUserDefaults", "reason_code": "SYNTHETIC.1"},
        {"category": "NSPrivacyAccessedAPITypeUserDefaults", "reason_code": "SYNTHETIC.2"},
    ]
    assert "invalid_api_reason_codes" in result.errors


def test_ios_privacy_manifest_audit_rejects_coerced_boolean_and_symlink_root():
    with tempfile.TemporaryDirectory() as tmp_dir:
        path = Path(tmp_dir) / "PrivacyInfo.xcprivacy"
        with path.open("wb") as f:
            plistlib.dump({"NSPrivacyTracking": "false", "NSPrivacyTrackingDomains": [],
                           "NSPrivacyAccessedAPITypes": []}, f)
        result = PrivacyManifestAuditor().audit_ios_privacy_manifest(tmp_dir)
    assert result.parse_status == "partial"
    assert result.tracking_enabled is False
    assert result.errors == ["invalid_tracking_value"]

    with tempfile.TemporaryDirectory() as tmp_dir:
        base = Path(tmp_dir)
        link = base / "link"
        link.symlink_to(base, target_is_directory=True)
        result = PrivacyManifestAuditor().audit_ios_privacy_manifest(link)
    assert result.parse_status == "invalid"
    assert result.errors == ["invalid_scan_root"]


def test_ios_privacy_symbol_cross_check_emits_only_unverified_review_candidates():
    auditor = PrivacyManifestAuditor()

    report = auditor.audit_ios_binary_api_symbols(
        ["_stat", "_standardUserDefaults", "_mach_absolute_time", "_unrelatedStatistic"],
        {"NSPrivacyAccessedAPITypeUserDefaults"},
        app_manifest_state="parsed", binary_path="Synthetic.app/Synthetic",
        binary_parse_status="parsed",
    )

    assert report["status"] == "analyzed_heuristically"
    assert {item["category"] for item in report["candidate_categories"]} == {
        "NSPrivacyAccessedAPITypeFileTimestamp",
        "NSPrivacyAccessedAPITypeSystemBootTime",
        "NSPrivacyAccessedAPITypeUserDefaults",
    }
    assert len(report["findings"]) == 2
    assert all(finding.status == FindingStatus.UNVERIFIED for finding in report["findings"])
    assert all(finding.severity == Severity.INFO for finding in report["findings"])
    assert all(finding.metadata["proof_status"] == "not_proven"
               and finding.metadata["compliance_verdict"] == "not_assessed"
               for finding in report["findings"])
    assert all("does not prove a reachable API call" in finding.description
               for finding in report["findings"])


def test_ios_privacy_symbol_cross_check_withholds_on_invalid_manifest_and_caps_symbols():
    auditor = PrivacyManifestAuditor()
    invalid = auditor.audit_ios_binary_api_symbols(
        ["_stat"], [], app_manifest_state="invalid", binary_path="Synthetic",
        binary_parse_status="parsed",
    )
    assert invalid["status"] == "not_analyzed_invalid_app_manifest"
    assert invalid["findings"] == []

    auditor.MAX_BINARY_SYMBOLS = 1
    capped = auditor.audit_ios_binary_api_symbols(
        ["_stat", "_fstat"], [], app_manifest_state="absent", binary_path="Synthetic",
        binary_parse_status="partial",
    )
    assert capped["status"] == "partial"
    assert capped["truncated"] is True
    assert len(capped["findings"]) == 1


def test_android_data_safety_indicator_is_only_a_static_review_lead():
    with tempfile.TemporaryDirectory() as tmp_dir:
        src = os.path.join(tmp_dir, "App.java")
        with open(src, "w", encoding="utf-8") as f:
            f.write("com.google.firebase.analytics.FirebaseAnalytics")
        manifest = '<manifest xmlns:android="http://schemas.android.com/apk/res/android"><uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" /></manifest>'

        findings = PrivacyManifestAuditor().audit_android_data_safety_discrepancies(manifest, tmp_dir)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity.value == "INFO"
    assert finding.status.value == "UNVERIFIED"
    assert finding.metadata["evidence_state"] == "static_candidate"
    assert finding.metadata["compliance_verdict"] == "not_assessed"
    assert "does not establish" in finding.description
    assert finding.metadata["coverage"]["manifest_parse"] == "parsed"
    assert finding.metadata["coverage"]["source_tree"] == "complete"


def test_android_data_safety_uses_permission_elements_not_comments_or_substrings():
    with tempfile.TemporaryDirectory() as tmp_dir:
        source = Path(tmp_dir) / "App.java"
        source.write_text("com.google.firebase.analytics.FirebaseAnalytics", encoding="utf-8")
        manifest = '''<manifest xmlns:android="http://schemas.android.com/apk/res/android">
          <!-- <uses-permission android:name="android.permission.READ_CONTACTS"/> -->
          <uses-permission android:name="android.permission.ACCESS_FINE_LOCATION_EXTRA"/>
        </manifest>'''
        assert PrivacyManifestAuditor().audit_android_data_safety_discrepancies(manifest, tmp_dir) == []


def test_android_data_safety_rejects_manifest_dtd_and_entity_declarations():
    with tempfile.TemporaryDirectory() as tmp_dir:
        source = Path(tmp_dir) / "App.java"
        source.write_text("com.google.firebase.analytics.FirebaseAnalytics", encoding="utf-8")
        manifest = '''<!DOCTYPE manifest [<!ENTITY permission "android.permission.ACCESS_FINE_LOCATION">]>
          <manifest xmlns:android="http://schemas.android.com/apk/res/android">
            <uses-permission android:name="&permission;" />
          </manifest>'''
        findings = PrivacyManifestAuditor().audit_android_data_safety_discrepancies(manifest, tmp_dir)

    # A declaration-bearing manifest is invalid input, not a trusted source
    # for permission candidates; the method emits no discrepancy candidate.
    assert findings == []


def test_android_data_safety_package_scan_returns_coverage_without_findings(tmp_path):
    manifest = tmp_path / "AndroidManifest.xml"
    manifest.write_text('<manifest xmlns:android="http://schemas.android.com/apk/res/android"/>',
                        encoding="utf-8")
    (tmp_path / "App.java").write_text("class App {}", encoding="utf-8")

    result = PrivacyManifestAuditor().audit_android_data_safety_package(manifest, tmp_path)

    assert result["findings"] == []
    assert result["coverage"]["manifest_parse"] == "parsed"
    assert result["coverage"]["source_tree"] == "complete"
    assert result["coverage"]["files_read"] == 1


def test_android_data_safety_package_scan_rejects_manifest_symlink(tmp_path):
    real = tmp_path / "real.xml"
    real.write_text('<manifest/>', encoding="utf-8")
    linked = tmp_path / "AndroidManifest.xml"
    linked.symlink_to(real)

    result = PrivacyManifestAuditor().audit_android_data_safety_package(linked, tmp_path)

    assert result["findings"] == []
    assert result["coverage"]["manifest_parse"] == "invalid"
    assert "manifest_read_error" in result["coverage"]["errors"]


def test_android_data_safety_source_inventory_is_bounded_and_reports_partial_coverage():
    with tempfile.TemporaryDirectory() as tmp_dir:
        base = Path(tmp_dir)
        source = base / "App.java"
        source.write_text("com.google.firebase.analytics.FirebaseAnalytics", encoding="utf-8")
        auditor = PrivacyManifestAuditor()
        auditor.MAX_ANDROID_SOURCE_FILES = 0
        manifest = '<manifest xmlns:android="http://schemas.android.com/apk/res/android"><uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/></manifest>'
        results = auditor.audit_android_data_safety_discrepancies(manifest, base)

    assert results == []  # incomplete source coverage cannot produce an SDK match


def test_android_data_safety_no_follow_and_source_budget_are_exposed():
    with tempfile.TemporaryDirectory() as tmp_dir:
        base = Path(tmp_dir)
        (base / "App.java").write_text("com.google.firebase.analytics.FirebaseAnalytics", encoding="utf-8")
        (base / "Large.kt").write_text("x" * 2048, encoding="utf-8")
        outside = base.parent / f"{base.name}-outside.java"
        outside.write_text("com.google.firebase.analytics.FirebaseAnalytics", encoding="utf-8")
        (base / "Linked.java").symlink_to(outside)
        auditor = PrivacyManifestAuditor()
        auditor.MAX_ANDROID_SOURCE_BYTES = 1024
        manifest = '<manifest xmlns:android="http://schemas.android.com/apk/res/android"><uses-permission android:name="android.permission.ACCESS_FINE_LOCATION"/></manifest>'
        results = auditor.audit_android_data_safety_discrepancies(manifest, base)
        outside.unlink()

    assert len(results) == 1
    coverage = results[0].metadata["coverage"]
    assert coverage["files_read"] == 2
    assert coverage["source_tree"] == "partial"
    assert "source_file_truncated" in coverage["errors"]
    assert "source_symlink_skipped" in coverage["errors"]
