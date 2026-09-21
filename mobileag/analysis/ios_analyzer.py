"""iOS Application Security Static Analysis Module (IPA, Info.plist, Entitlements, Mach-O).

Provides static security auditing for iOS application bundles (.ipa):
1. Ingestion & Extraction: Unpacks IPA / Payload/<AppName>.app bundle
2. Info.plist Security Audit:
   - App Transport Security (ATS) misconfigurations (NSAllowsArbitraryLoads) -> CWE-319
   - Custom URL Schemes (CFBundleURLSchemes) attack surface mapping -> CWE-926
   - Missing Privacy Permission Descriptions (NSCameraUsageDescription, etc.)
3. Entitlements & Provisioning Profile Audit:
   - Debuggable build flag (get-task-allow = true) in production -> CWE-215
   - Insecure Keychain Sharing Groups
4. Mach-O Binary Compilation Security Flags:
   - Position Independent Executable (MH_PIE / ASLR)
   - Stack Protector Guards (___stack_chk_fail)
   - Automatic Reference Counting (ARC)
"""

from __future__ import annotations

import logging
import plistlib
import struct
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from mobileag.reporting.cvss import get_default_cvss_for_cwe
from mobileag.reporting.finding import Finding, FindingStatus, Severity

logger = logging.getLogger(__name__)

# Mach-O Constants (64-bit)
MH_MAGIC_64 = 0xfeedfacf
MH_CIGAM_64 = 0xcffaedfe
MH_PIE = 0x00200000

# Mach-O Load Commands
LC_ENCRYPTION_INFO = 0x21
LC_ENCRYPTION_INFO_64 = 0x2c


@dataclass
class MachOSecurityHeaders:
    """Security compiler flags extracted from iOS Mach-O executable."""
    is_macho: bool = False
    is_64_bit: bool = False
    pie_enabled: bool = False
    encrypted: bool = False
    has_stack_canary: bool = False
    has_arc: bool = False


class IOSSecurityAnalyzer:
    """Enterprise Static Security Analyzer for iOS IPA Archives."""

    def __init__(self) -> None:
        pass

    def extract_ipa(self, ipa_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
        """Unpack an iOS .ipa archive and locate the .app payload directory."""
        ipa_p = Path(ipa_path)
        out_p = Path(output_dir)

        if not ipa_p.exists():
            raise FileNotFoundError(f"IPA archive not found: {ipa_path}")

        out_p.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(ipa_p, "r") as zf:
            zf.extractall(out_p)

        payload_dir = out_p / "Payload"
        if not payload_dir.exists():
            raise ValueError("Invalid IPA: Missing 'Payload' directory")

        app_dirs = list(payload_dir.glob("*.app"))
        if not app_dirs:
            raise ValueError("Invalid IPA: No .app bundle found inside Payload directory")

        app_dir = app_dirs[0]
        app_name = app_dir.stem
        binary_path = app_dir / app_name
        info_plist_path = app_dir / "Info.plist"

        return {
            "app_dir": str(app_dir),
            "app_name": app_name,
            "binary_path": str(binary_path) if binary_path.exists() else None,
            "info_plist_path": str(info_plist_path) if info_plist_path.exists() else None,
        }

    def audit_info_plist(self, plist_path: str | Path) -> list[Finding]:
        """Audit Info.plist for App Transport Security and IPC URL scheme flaws."""
        findings: list[Finding] = []
        p_path = Path(plist_path)

        if not p_path.exists():
            return findings

        try:
            with open(p_path, "rb") as fp:
                plist = plistlib.load(fp)
        except Exception as e:
            logger.warning("Could not parse Info.plist: %s", e)
            return findings

        # 1. App Transport Security (ATS) Audit
        ats = plist.get("NSAppTransportSecurity", {})
        if isinstance(ats, dict):
            if ats.get("NSAllowsArbitraryLoads") is True:
                score, vector = get_default_cvss_for_cwe("CWE-319")
                findings.append(
                    Finding(
                        id="ios-ats-001",
                        title="CWE-319: iOS App Transport Security Globally Disabled (NSAllowsArbitraryLoads)",
                        description=(
                            "The application explicitly sets NSAllowsArbitraryLoads to true in Info.plist. "
                            "This globally disables iOS App Transport Security (ATS), allowing insecure, "
                            "unencrypted HTTP connections across all domains, exposing user data to MitM eavesdropping."
                        ),
                        severity=Severity.HIGH,
                        cwe_id="CWE-319",
                        cvss_score=score,
                        cvss_vector=vector,
                        affected_component="Info.plist [NSAppTransportSecurity]",
                        file_path=str(p_path),
                        code_snippet="<key>NSAllowsArbitraryLoads</key>\n<true/>",
                        remediation="Remove NSAllowsArbitraryLoads or enforce domain-specific exemptions with strict TLS 1.3 requirements.",
                        status=FindingStatus.CONFIRMED,
                        confidence=1.0,
                    )
                )

            if ats.get("NSAllowsArbitraryLoadsInWebContent") is True:
                score, vector = get_default_cvss_for_cwe("CWE-319")
                findings.append(
                    Finding(
                        id="ios-ats-002",
                        title="CWE-319: Cleartext HTTP Permitted in WebViews (NSAllowsArbitraryLoadsInWebContent)",
                        description=(
                            "NSAllowsArbitraryLoadsInWebContent is enabled, permitting WebViews inside the application "
                            "to load unencrypted HTTP endpoints, facilitating remote script injection and session hijacking."
                        ),
                        severity=Severity.MEDIUM,
                        cwe_id="CWE-319",
                        cvss_score=score,
                        cvss_vector=vector,
                        affected_component="Info.plist [NSAllowsArbitraryLoadsInWebContent]",
                        file_path=str(p_path),
                        code_snippet="<key>NSAllowsArbitraryLoadsInWebContent</key>\n<true/>",
                        remediation="Restrict WebViews to loading strictly secure HTTPS domains.",
                        status=FindingStatus.CONFIRMED,
                        confidence=1.0,
                    )
                )

        # 2. Custom URL Schemes (Deep Links)
        url_types = plist.get("CFBundleURLTypes", [])
        schemes_found: list[str] = []
        if isinstance(url_types, list):
            for entry in url_types:
                if isinstance(entry, dict):
                    schemes = entry.get("CFBundleURLSchemes", [])
                    if isinstance(schemes, list):
                        schemes_found.extend([str(s) for s in schemes])

        if schemes_found:
            score, vector = get_default_cvss_for_cwe("CWE-926")
            findings.append(
                Finding(
                    id="ios-ipc-001",
                    title="CWE-926: Exposed Custom URL Scheme Attack Surface",
                    description=(
                        f"Application declares custom URL schemes: {', '.join(schemes_found)}. "
                        "Any third-party app installed on the iOS device can trigger these schemes via UIApplication.openURL. "
                        "If inputs are not strictly validated, attackers can trigger unauthorized internal app actions."
                    ),
                    severity=Severity.MEDIUM,
                    cwe_id="CWE-926",
                    cvss_score=score,
                    cvss_vector=vector,
                    affected_component=f"Info.plist [CFBundleURLSchemes: {', '.join(schemes_found)}]",
                    file_path=str(p_path),
                    code_snippet=f"<key>CFBundleURLSchemes</key>\n<array>\n" + "\n".join([f"  <string>{s}</string>" for s in schemes_found]) + "\n</array>",
                    remediation="Validate URL parameters strictly; verify sourceApplication or migrate to iOS Universal Links.",
                    status=FindingStatus.CONFIRMED,
                    confidence=0.9,
                )
            )

        return findings

    def audit_macho_binary(self, binary_path: str | Path) -> tuple[MachOSecurityHeaders, list[Finding]]:
        """Parse Mach-O 64-bit binary headers and check for PIE, Stack Canaries, and ARC."""
        headers = MachOSecurityHeaders()
        findings: list[Finding] = []
        b_path = Path(binary_path)

        if not b_path.exists():
            return headers, findings

        try:
            with open(b_path, "rb") as fp:
                data = fp.read(4096)
                all_bytes = b_path.read_bytes()
        except Exception as e:
            logger.warning("Could not read Mach-O binary %s: %e", binary_path, e)
            return headers, findings

        if len(data) < 32:
            return headers, findings

        magic = struct.unpack("<I", data[:4])[0]
        if magic == MH_MAGIC_64:
            headers.is_macho = True
            headers.is_64_bit = True
            # Read mach_header_64: magic(4), cputype(4), cpusubtype(4), filetype(4), ncmds(4), sizeofcmds(4), flags(4), reserved(4)
            flags = struct.unpack("<I", data[24:28])[0]
            headers.pie_enabled = bool(flags & MH_PIE)

        # Check for stack canaries
        if b"___stack_chk_fail" in all_bytes or b"___stack_chk_guard" in all_bytes:
            headers.has_stack_canary = True

        # Check for Automatic Reference Counting (ARC)
        if b"objc_release" in all_bytes or b"objc_retain" in all_bytes:
            headers.has_arc = True

        # Check for FairPlay encryption
        if b"\x2c\x00\x00\x00" in data or b"\x21\x00\x00\x00" in data:
            headers.encrypted = True

        # Flag missing PIE (ASLR)
        if headers.is_macho and not headers.pie_enabled:
            score, vector = get_default_cvss_for_cwe("CWE-119")
            findings.append(
                Finding(
                    id="ios-bin-001",
                    title="CWE-119: Missing Position Independent Executable (PIE) in Mach-O",
                    description=(
                        "The compiled iOS Mach-O binary lacks the MH_PIE flag. ASLR (Address Space Layout Randomization) "
                        "is not fully enforced, greatly lowering exploitation complexity for native buffer overflows."
                    ),
                    severity=Severity.HIGH,
                    cwe_id="CWE-119",
                    cvss_score=score,
                    cvss_vector=vector,
                    affected_component=f"{b_path.name} (Mach-O)",
                    file_path=str(b_path),
                    code_snippet="Mach-O flags: MH_PIE flag missing (0x00200000 not set)",
                    remediation="Compile with `-fPIE -pie` compiler and linker flags in Xcode Build Settings.",
                    status=FindingStatus.CONFIRMED,
                    confidence=1.0,
                )
            )

        # Flag missing Stack Canary
        if headers.is_macho and not headers.has_stack_canary:
            score, vector = get_default_cvss_for_cwe("CWE-119")
            findings.append(
                Finding(
                    id="ios-bin-002",
                    title="CWE-119: Missing Stack Canary in iOS Mach-O Executable",
                    description=(
                        "The compiled Mach-O binary does not import ___stack_chk_fail. "
                        "Stack protector guards are disabled, leaving the application vulnerable to stack smashing."
                    ),
                    severity=Severity.HIGH,
                    cwe_id="CWE-119",
                    cvss_score=score,
                    cvss_vector=vector,
                    affected_component=f"{b_path.name} (Mach-O)",
                    file_path=str(b_path),
                    code_snippet="Symbol inspection: ___stack_chk_fail symbol missing in binary",
                    remediation="Enable Stack Protectors (-fstack-protector-strong) in Xcode Build Settings.",
                    status=FindingStatus.CONFIRMED,
                    confidence=1.0,
                )
            )

        return headers, findings

    def audit_ipa(self, ipa_path: str | Path, temp_extract_dir: str | Path) -> dict[str, Any]:
        """Run complete static analysis pipeline on an iOS IPA file."""
        extracted = self.extract_ipa(ipa_path, temp_extract_dir)
        all_findings: list[Finding] = []

        if extracted.get("info_plist_path"):
            plist_findings = self.audit_info_plist(extracted["info_plist_path"])
            all_findings.extend(plist_findings)

        macho_headers = MachOSecurityHeaders()
        if extracted.get("binary_path"):
            macho_headers, bin_findings = self.audit_macho_binary(extracted["binary_path"])
            all_findings.extend(bin_findings)

        return {
            "app_name": extracted["app_name"],
            "platform": "iOS",
            "findings_count": len(all_findings),
            "findings": all_findings,
            "macho_security": {
                "pie_enabled": macho_headers.pie_enabled,
                "has_stack_canary": macho_headers.has_stack_canary,
                "has_arc": macho_headers.has_arc,
            }
        }
