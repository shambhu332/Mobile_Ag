"""Unit tests for iOS IPA and Mach-O Security Analyzer."""

import plistlib
import struct
import tempfile
import zipfile
from pathlib import Path

from mobileag.analysis.ios_analyzer import IOSSecurityAnalyzer, MH_MAGIC_64, MH_PIE
from mobileag.analysis.macho_parser import MachoAnalysisResult, MachoBinaryParser
from mobileag.reporting.finding import FindingStatus


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


def test_ios_ipa_pipeline_integrates_app_manifest_symbol_review(tmp_path, monkeypatch):
    ipa_path = tmp_path / "PrivacyFixture.ipa"
    extract_dir = tmp_path / "extract"
    with zipfile.ZipFile(ipa_path, "w") as archive:
        app = "Payload/PrivacyFixture.app/"
        archive.writestr(app + "Info.plist", plistlib.dumps({
            "CFBundleIdentifier": "org.example.synthetic",
            "CFBundleExecutable": "PrivacyFixture",
        }))
        archive.writestr(app + "PrivacyInfo.xcprivacy", plistlib.dumps({
            "NSPrivacyTracking": False,
            "NSPrivacyTrackingDomains": [],
            "NSPrivacyAccessedAPITypes": [{
                "NSPrivacyAccessedAPIType": "NSPrivacyAccessedAPITypeUserDefaults",
                "NSPrivacyAccessedAPITypeReasons": ["SYNTHETIC.1"],
            }],
        }))
        archive.writestr(app + "PrivacyFixture", struct.pack(
            "<IIIIIIII", MH_MAGIC_64, 0, 0, 2, 0, 0, MH_PIE, 0) + b"\x00" * 80)

    synthetic_parse = MachoAnalysisResult(
        is_macho=True, parse_status="parsed", symbol_names=["_stat"],
    )
    monkeypatch.setattr(MachoBinaryParser, "parse_binary", lambda _self, _path: synthetic_parse)

    report = IOSSecurityAnalyzer().audit_ipa(ipa_path, extract_dir)

    review = report["privacy_manifest"]["binary_api_symbol_review"]
    assert report["coverage"]["privacy_api_symbol_review"] == "analyzed_heuristically"
    assert review["manifest_state"] == "parsed"
    assert report["privacy_manifest"]["declared_api_reasons"] == [{
        "category": "NSPrivacyAccessedAPITypeUserDefaults", "reason_code": "SYNTHETIC.1",
    }]
    assert review["undeclared_review_candidates"] == [{
        "category": "NSPrivacyAccessedAPITypeFileTimestamp", "symbol_markers": ["stat"],
    }]
    candidate = next(f for f in report["findings"]
                     if f.id == "IOS_PRIVACY_API_SYMBOL_REVIEW_FileTimestamp")
    assert candidate.status == FindingStatus.UNVERIFIED
    assert candidate.metadata["proof_status"] == "not_proven"


def test_ios_ipa_pipeline_reviews_framework_symbols_against_its_own_manifest(tmp_path, monkeypatch):
    ipa_path = tmp_path / "FrameworkFixture.ipa"
    extract_dir = tmp_path / "framework-extract"
    with zipfile.ZipFile(ipa_path, "w") as archive:
        app = "Payload/FrameworkFixture.app/"
        archive.writestr(app + "Info.plist", plistlib.dumps({
            "CFBundleIdentifier": "org.example.synthetic",
            "CFBundleExecutable": "FrameworkFixture",
        }))
        archive.writestr(app + "PrivacyInfo.xcprivacy", plistlib.dumps({
            "NSPrivacyAccessedAPITypes": [{
                "NSPrivacyAccessedAPIType": "NSPrivacyAccessedAPITypeUserDefaults",
            }],
        }))
        archive.writestr(app + "FrameworkFixture", struct.pack(
            "<IIIIIIII", MH_MAGIC_64, 0, 0, 2, 0, 0, MH_PIE, 0) + b"\x00" * 80)
        framework = app + "Frameworks/SyntheticAnalytics.framework/"
        archive.writestr(framework + "SyntheticAnalytics", struct.pack(
            "<IIIIIIII", MH_MAGIC_64, 0, 0, 2, 0, 0, MH_PIE, 0) + b"\x00" * 80)
        archive.writestr(framework + "PrivacyInfo.xcprivacy", plistlib.dumps({
            "NSPrivacyAccessedAPITypes": [],
        }))

    def parse_synthetic_binary(_self, path):
        symbols = ["_standardUserDefaults"] if Path(path).parent.name == "SyntheticAnalytics.framework" else []
        return MachoAnalysisResult(is_macho=True, parse_status="parsed", symbol_names=symbols)

    monkeypatch.setattr(MachoBinaryParser, "parse_binary", parse_synthetic_binary)
    report = IOSSecurityAnalyzer().audit_ipa(ipa_path, extract_dir)

    review = report["privacy_manifest"]["framework_binary_api_symbol_reviews"]
    assert len(review) == 1
    assert review[0]["manifest_state"] == "parsed"
    assert review[0]["candidate_categories"] == [{
        "category": "NSPrivacyAccessedAPITypeUserDefaults",
        "symbol_markers": ["standardUserDefaults"],
    }]
    assert review[0]["undeclared_review_candidates"] == review[0]["candidate_categories"]
    assert report["coverage"]["framework_privacy_api_symbol_review"] == "analyzed_heuristically"
    framework_finding = next(f for f in report["findings"]
                             if f.affected_component == "SyntheticAnalytics embedded framework")
    assert framework_finding.status == FindingStatus.UNVERIFIED
    assert framework_finding.metadata["manifest_state"] == "parsed"
    assert framework_finding.id != "IOS_PRIVACY_API_SYMBOL_REVIEW_UserDefaults"
    assert "SyntheticAnalytics embedded framework symbol table" in framework_finding.description
    assert "SyntheticAnalytics embedded framework PrivacyInfo.xcprivacy" in framework_finding.description


def test_ios_framework_symbol_inventory_reports_candidate_cap(tmp_path, monkeypatch):
    from mobileag.analysis.privacy_manifest_auditor import PrivacyManifestAuditor

    app_dir = tmp_path / "Synthetic.app"
    for name in ("Alpha", "Beta"):
        framework = app_dir / "Frameworks" / f"{name}.framework"
        framework.mkdir(parents=True)
        (framework / name).write_bytes(b"synthetic")
    monkeypatch.setattr(
        MachoBinaryParser, "parse_binary",
        lambda _self, _path: MachoAnalysisResult(is_macho=True, parse_status="parsed", symbol_names=["_stat"]),
    )
    analyzer = IOSSecurityAnalyzer()
    analyzer.MAX_FRAMEWORK_SYMBOL_BINARIES = 1

    reports, _findings, coverage = analyzer._audit_ios_framework_api_symbols(
        app_dir, PrivacyManifestAuditor())

    assert len(reports) == 1
    assert coverage["binary_candidates"] == 2
    assert coverage["binaries_analyzed"] == 1
    assert coverage["status"] == "partial"
    assert coverage["limit_reasons"] == {"framework_binary_count": 1}


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

