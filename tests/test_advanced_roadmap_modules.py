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

from mobileag.analysis.hermes_analyzer import HermesBytecodeAnalyzer
from mobileag.analysis.il2cpp_auditor import Il2CppAuditor
from mobileag.analysis.macho_parser import MachoBinaryParser
from mobileag.analysis.privacy_manifest_auditor import PrivacyManifestAuditor
from mobileag.dast.smart_crawler import SmartUICrawler
from mobileag.dast.frida_stealth import FridaStealthHarness


def test_hermes_bytecode_analyzer():
    with tempfile.TemporaryDirectory() as tmp_dir:
        bundle_path = os.path.join(tmp_dir, "index.android.bundle")

        # Create mock Hermes bundle with 0x1F480120 magic header and version 84
        magic_bytes = struct.pack("<Q", 0x1F480120)
        version_bytes = struct.pack("<I", 84)
        payload = b"https://api.example.com/mobile/v1" + b"\x00" * 20 + b'apiKey: "abcdef0123456789abcdef"'

        with open(bundle_path, "wb") as f:
            f.write(magic_bytes + version_bytes + b"\x00" * 16 + payload)

        analyzer = HermesBytecodeAnalyzer()
        res = analyzer.analyze_bundle(bundle_path)

        assert res.is_hermes is True
        assert res.bytecode_version == 84
        assert "https://api.example.com/mobile/v1" in res.api_endpoints
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


def test_il2cpp_auditor():
    with tempfile.TemporaryDirectory() as tmp_dir:
        meta_dir = os.path.join(tmp_dir, "assets", "bin", "Data", "Managed", "Metadata")
        os.makedirs(meta_dir)

        meta_file = os.path.join(meta_dir, "global-metadata.dat")
        # Magic: 0xFAB11BAF, Version: 29
        header = struct.pack("<II", 0xFAB11BAF, 29) + b"\x00" * 56
        content = (b"https://game-api.unity.com/v1" + b"\x00" * 20
                   + b"AuthenticationManager" + b"\x00"
                   + b'apiKey: "synthetic-unity-secret-123"')

        with open(meta_file, "wb") as f:
            f.write(header + content)

        auditor = Il2CppAuditor()
        res = auditor.audit_package(tmp_dir)

        assert res.is_il2cpp is True
        assert res.metadata_version == 29
        assert "https://game-api.unity.com/v1" in res.api_endpoints
        assert "AuthenticationManager" in res.reconstructed_classes
        assert res.potential_secrets == [{"name": "embedded credential", "value_redacted": True}]
        assert "synthetic-unity-secret-123" not in repr(res.potential_secrets)
        assert res.scan_status == "complete"
        assert res.metadata_truncated is False


def test_il2cpp_auditor_bounds_metadata_and_rejects_symlinked_metadata():
    with tempfile.TemporaryDirectory() as tmp_dir, tempfile.TemporaryDirectory() as outside_dir:
        base = Path(tmp_dir)
        metadata_dir = base / "assets/bin/Data/Managed/Metadata"
        metadata_dir.mkdir(parents=True)
        metadata = metadata_dir / "global-metadata.dat"
        metadata.write_bytes(struct.pack("<II", Il2CppAuditor.IL2CPP_METADATA_MAGIC, 29)
                             + b"\x00" * 56 + b"https://late.example.invalid/api")
        auditor = Il2CppAuditor()
        auditor.MAX_METADATA_BYTES = 32
        truncated = auditor.audit_package(base)

        outside = Path(outside_dir) / "global-metadata.dat"
        outside.write_bytes(struct.pack("<II", Il2CppAuditor.IL2CPP_METADATA_MAGIC, 29)
                            + b"\x00" * 56)
        metadata.unlink()
        metadata.symlink_to(outside)
        linked = Il2CppAuditor().audit_package(base)

    assert truncated.metadata_version == 29
    assert truncated.metadata_truncated is True
    assert truncated.metadata_bytes_scanned == 32
    assert truncated.scan_status == "partial"
    assert "symlink_metadata_skipped" in linked.scan_errors
    assert linked.global_metadata_present is False


def test_macho_binary_parser():
    with tempfile.TemporaryDirectory() as tmp_dir:
        bin_path = os.path.join(tmp_dir, "TargetApp")

        # Magic: 0xFEEDFACF (64-bit Mach-O) in little endian
        magic_bytes = struct.pack("<I", 0xFEEDFACF)
        payload = b"\x00" * 30 + b"__swift5_types" + b"\x00" * 20 + b"CommonCrypto" + b"\x00" * 20 + b"https://ios.example.com/api"

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


def test_macho_parser_reads_bounded_load_commands_swift_sections_and_cstrings(tmp_path):
    import struct

    strings = b"https://api.example.test/v1\0"
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


def test_macho_parser_reports_malformed_load_commands_without_crashing(tmp_path):
    import struct

    header = struct.pack("<IiiIIIII", 0xFEEDFACF, 0x0100000C, 0, 2, 1, 8, 0, 0)
    binary = tmp_path / "MalformedMachO"
    binary.write_bytes(header + struct.pack("<II", 0x19, 0))
    result = MachoBinaryParser().parse_binary(binary)
    assert result.is_macho is True
    assert result.parse_status == "partial"
    assert "Invalid load-command size" in result.parse_errors


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
    assert decision2.action == "TYPE_TEXT"
    assert decision2.input_text == "researcher@example.test"

    # No embedded/default credentials and no submit action without an
    # operator-provided synthetic identity.
    default_crawler = SmartUICrawler()
    decision3 = default_crawler.decide_next_action("com.example.app.LoginActivity", login_xml)
    assert decision3.action == "WAIT"
    assert "operator-supplied" in decision3.explanation
    populated_login = login_xml.replace('text=""', 'text="synthetic"')
    decision4 = crawler.decide_next_action("com.example.app.LoginActivity", populated_login)
    assert decision4.action == "WAIT"
    assert "explicit operator approval" in decision4.explanation


def test_frida_stealth_harness():
    harness = FridaStealthHarness()
    config = harness.generate_random_config()

    assert config.daemon_name.startswith("android_sys_")
    assert 32000 <= config.listen_port <= 59000
    assert config.socket_path.startswith("/data/local/tmp/.sock_")

    preamble = harness.get_stealth_preamble_script()
    assert "pthread_create" in preamble
    assert "release-keys" in preamble
    assert "java.io.File" in preamble


def test_privacy_manifest_auditor():
    with tempfile.TemporaryDirectory() as tmp_dir:
        plist_path = os.path.join(tmp_dir, "PrivacyInfo.xcprivacy")
        plist_data = {
            "NSPrivacyTracking": True,
            "NSPrivacyTrackingDomains": ["analytics.thirdparty.com"],
            "NSPrivacyAccessedAPITypes": [
                {
                    "NSPrivacyAccessedAPIType": "NSPrivacyAccessedAPITypeUserDefaults",
                    "NSPrivacyAccessedAPITypeReasons": ["CA92.1"],
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
                                 "tracking_domains": [], "declared_api_categories": []}]
    assert result.tracking_enabled is True
    assert result.errors == ["manifest_parse_error"]


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
    assert "source_read_error" in coverage["errors"]
