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


def test_il2cpp_auditor():
    with tempfile.TemporaryDirectory() as tmp_dir:
        meta_dir = os.path.join(tmp_dir, "assets", "bin", "Data", "Managed", "Metadata")
        os.makedirs(meta_dir)

        meta_file = os.path.join(meta_dir, "global-metadata.dat")
        # Magic: 0xFAB11BAF, Version: 29
        header = struct.pack("<II", 0xFAB11BAF, 29) + b"\x00" * 56
        content = b"https://game-api.unity.com/v1" + b"\x00" * 20 + b"AuthenticationManager"

        with open(meta_file, "wb") as f:
            f.write(header + content)

        auditor = Il2CppAuditor()
        res = auditor.audit_package(tmp_dir)

        assert res.is_il2cpp is True
        assert res.metadata_version == 29
        assert "https://game-api.unity.com/v1" in res.api_endpoints
        assert "AuthenticationManager" in res.reconstructed_classes


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
        assert "__swift5_types" in res.swift_sections_detected
        assert "CommonCrypto" in res.crypto_frameworks
        assert "https://ios.example.com/api" in res.api_endpoints


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


def test_android_data_safety_indicator_is_only_a_static_review_lead():
    with tempfile.TemporaryDirectory() as tmp_dir:
        src = os.path.join(tmp_dir, "App.java")
        with open(src, "w", encoding="utf-8") as f:
            f.write("com.google.firebase.analytics.FirebaseAnalytics")
        manifest = '<uses-permission android:name="android.permission.ACCESS_FINE_LOCATION" />'

        findings = PrivacyManifestAuditor().audit_android_data_safety_discrepancies(manifest, tmp_dir)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity.value == "INFO"
    assert finding.status.value == "UNVERIFIED"
    assert finding.metadata["evidence_state"] == "static_candidate"
    assert finding.metadata["compliance_verdict"] == "not_assessed"
    assert "does not establish" in finding.description
