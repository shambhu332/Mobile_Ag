"""Unit tests for iOS IPA and Mach-O Security Analyzer."""

import plistlib
import struct
import tempfile
import zipfile
from pathlib import Path

from mobileag.analysis.ios_analyzer import IOSSecurityAnalyzer, MH_MAGIC_64, MH_PIE


def test_ios_info_plist_auditing():
    analyzer = IOSSecurityAnalyzer()

    with tempfile.TemporaryDirectory() as tmpdir:
        plist_path = Path(tmpdir) / "Info.plist"

        # Create plist with NSAllowsArbitraryLoads = True and CFBundleURLSchemes
        plist_data = {
            "CFBundleIdentifier": "com.target.iosapp",
            "NSAppTransportSecurity": {
                "NSAllowsArbitraryLoads": True,
                "NSAllowsArbitraryLoadsInWebContent": True,
            },
            "CFBundleURLTypes": [
                {
                    "CFBundleURLName": "com.target.auth",
                    "CFBundleURLSchemes": ["targetapp", "targetauth"],
                }
            ],
        }

        with open(plist_path, "wb") as f:
            plistlib.dump(plist_data, f)

        findings = analyzer.audit_info_plist(plist_path)
        assert len(findings) >= 2

        cwe_ids = [f.cwe_id for f in findings]
        assert "CWE-319" in cwe_ids
        assert "CWE-926" in cwe_ids


def test_ios_macho_binary_auditing():
    analyzer = IOSSecurityAnalyzer()

    with tempfile.TemporaryDirectory() as tmpdir:
        binary_path = Path(tmpdir) / "TargetBinary"

        # Construct a synthetic 64-bit Mach-O header without MH_PIE and without stack canary
        # mach_header_64: magic(4), cputype(4), cpusubtype(4), filetype(4), ncmds(4), sizeofcmds(4), flags(4), reserved(4)
        magic = MH_MAGIC_64
        cputype = 0x0100000C  # CPU_TYPE_ARM64
        cpusubtype = 0x00000000
        filetype = 0x2  # MH_EXECUTE
        ncmds = 0
        sizeofcmds = 0
        flags = 0x0  # No MH_PIE (0x00200000)
        reserved = 0

        header_bytes = struct.pack("<IIIIIIII", magic, cputype, cpusubtype, filetype, ncmds, sizeofcmds, flags, reserved)
        binary_path.write_bytes(header_bytes + b"\x00" * 256)

        headers, findings = analyzer.audit_macho_binary(binary_path)
        assert headers.is_macho is True
        assert headers.is_64_bit is True
        assert headers.pie_enabled is False
        assert headers.has_stack_canary is False

        # Should flag missing PIE and missing stack canary
        cwe_ids = [f.cwe_id for f in findings]
        assert "CWE-119" in cwe_ids


def test_ios_ipa_full_pipeline():
    analyzer = IOSSecurityAnalyzer()

    with tempfile.TemporaryDirectory() as tmpdir:
        ipa_path = Path(tmpdir) / "TestApp.ipa"
        extract_dir = Path(tmpdir) / "extracted"

        # Package a synthetic IPA zip containing Payload/TestApp.app/
        with zipfile.ZipFile(ipa_path, "w") as zf:
            plist_data = {
                "CFBundleIdentifier": "com.target.iosapp",
                "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True},
            }
            plist_bytes = plistlib.dumps(plist_data)
            zf.writestr("Payload/TestApp.app/Info.plist", plist_bytes)

            # Synthetic binary
            magic = MH_MAGIC_64
            header_bytes = struct.pack("<IIIIIIII", magic, 0, 0, 2, 0, 0, MH_PIE, 0)
            zf.writestr("Payload/TestApp.app/TestApp", header_bytes + b"___stack_chk_fail\x00")

        results = analyzer.audit_ipa(ipa_path, extract_dir)
        assert results["platform"] == "iOS"
        assert results["app_name"] == "TestApp"
        assert results["findings_count"] >= 1
        assert results["macho_security"]["pie_enabled"] is True
        assert results["macho_security"]["has_stack_canary"] is True


def test_ios_advanced_api_and_keychain_audit():
    analyzer = IOSSecurityAnalyzer()

    with tempfile.TemporaryDirectory() as tmpdir:
        binary_path = Path(tmpdir) / "TargetBinary"

        # Binary containing strings for kSecAttrAccessibleAlways, kCCAlgorithmDES, CC_MD5, UIPasteboard
        binary_content = (
            b"\x00" * 64
            + b"kSecAttrAccessibleAlways\x00"
            + b"kCCAlgorithmDES\x00"
            + b"CC_MD5\x00"
            + b"UIPasteboard\x00generalPasteboard\x00"
        )
        binary_path.write_bytes(binary_content)

        findings = analyzer.audit_binary_symbols_and_apis(binary_path)
        assert len(findings) >= 4

        cwes = {f.cwe_id for f in findings}
        assert "CWE-312" in cwes  # Insecure keychain
        assert "CWE-327" in cwes  # Insecure DES
        assert "CWE-328" in cwes  # Broken MD5
        assert "CWE-200" in cwes  # General pasteboard


def test_ios_file_sharing_audit():
    analyzer = IOSSecurityAnalyzer()

    with tempfile.TemporaryDirectory() as tmpdir:
        plist_path = Path(tmpdir) / "Info.plist"

        plist_data = {
            "CFBundleIdentifier": "com.target.iosapp",
            "UIFileSharingEnabled": True,
            "LSSupportsOpeningDocumentsInPlace": True,
        }

        with open(plist_path, "wb") as f:
            plistlib.dump(plist_data, f)

        findings = analyzer.audit_info_plist(plist_path)
        assert len(findings) == 1
        assert findings[0].cwe_id == "CWE-200"
        assert "File Sharing Enabled" in findings[0].title

