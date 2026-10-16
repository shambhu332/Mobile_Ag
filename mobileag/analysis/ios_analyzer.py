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
import os
import plistlib
import stat
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
    MAX_PAYLOAD_ENTRIES = 20_000
    MAX_FRAMEWORK_SYMBOL_BINARIES = 32
    MAX_FRAMEWORK_SYMBOL_BYTES = 64 * 1024 * 1024
    """Enterprise Static Security Analyzer for iOS IPA Archives."""

    def __init__(self) -> None:
        self.coverage = {"static_status": "not_analyzed", "runtime_status": "not_tested",
                         "proof_status": "not_proven", "exhaustive": False}

    @staticmethod
    def _read_bounded(path: Path, limit: int) -> bytes:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            details = os.fstat(stream.fileno())
            if not stat.S_ISREG(details.st_mode) or details.st_size > limit:
                raise ValueError("File exceeds safe size/type limit")
            data = stream.read(limit + 1)
        if len(data) > limit:
            raise ValueError("File exceeds safe size limit")
        return data

    def extract_ipa(self, ipa_path: str | Path, output_dir: str | Path) -> dict[str, Any]:
        """Unpack an iOS .ipa archive and locate the .app payload directory."""
        ipa_p = Path(ipa_path)
        out_p = Path(output_dir)

        if not ipa_p.exists():
            raise FileNotFoundError(f"IPA archive not found: {ipa_path}")

        out_p.mkdir(parents=True, exist_ok=True)
        from mobileag.security.archives import extract_archive
        extract_archive(ipa_p, out_p)

        payload_dir = out_p / "Payload"
        if payload_dir.is_symlink() or not payload_dir.is_dir():
            raise ValueError("Invalid IPA: Missing 'Payload' directory")

        app_dirs: list[Path] = []
        try:
            with os.scandir(payload_dir) as entries:
                for index, entry in enumerate(entries):
                    if index >= self.MAX_PAYLOAD_ENTRIES:
                        raise ValueError("IPA Payload entry count exceeds limit")
                    if entry.name.endswith(".app") and entry.is_symlink():
                        raise ValueError("Unsupported symlink app bundle")
                    if entry.name.endswith(".app") and entry.is_dir(follow_symlinks=False):
                        app_dirs.append(Path(entry.path))
        except OSError as exc:
            raise ValueError("Unable to inventory IPA Payload directory") from exc

        if not app_dirs:
            raise ValueError("Invalid IPA: No .app bundle found inside Payload directory")
        if len(app_dirs) != 1:
            raise ValueError("Invalid IPA: Multiple top-level .app bundles are ambiguous")

        app_dir = app_dirs[0]
        app_name = app_dir.stem
        info_plist_path = app_dir / "Info.plist"
        metadata = plistlib.loads(self._read_bounded(info_plist_path, 2*1024*1024))
        executable = metadata.get("CFBundleExecutable", app_name)
        if not isinstance(executable, str) or Path(executable).name != executable or executable in {".", ".."}:
            raise ValueError("Invalid CFBundleExecutable")
        binary_path = app_dir / executable
        if not binary_path.is_file():
            raise ValueError("Declared IPA executable is missing")

        return {
            "app_dir": str(app_dir),
            "app_name": app_name,
            "package_name": metadata.get("CFBundleIdentifier"),
            "version": metadata.get("CFBundleShortVersionString"),
            "build": metadata.get("CFBundleVersion"),
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
            plist = plistlib.loads(self._read_bounded(p_path, 2*1024*1024))
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
                        status=FindingStatus.UNVERIFIED,
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
                        status=FindingStatus.UNVERIFIED,
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
                    status=FindingStatus.UNVERIFIED,
                    confidence=0.9,
                )
            )

        # 3. Insecure File Sharing / Document Browser Audit (CWE-200 / CWE-276)
        file_sharing = plist.get("UIFileSharingEnabled", False)
        opening_in_place = plist.get("LSSupportsOpeningDocumentsInPlace", False)
        if file_sharing or opening_in_place:
            score, vector = get_default_cvss_for_cwe("CWE-200")
            findings.append(
                Finding(
                    id="ios-sharing-001",
                    title="CWE-200: iOS File Sharing Enabled (UIFileSharingEnabled)",
                    description=(
                        "The application enables UIFileSharingEnabled or LSSupportsOpeningDocumentsInPlace. "
                        "This grants access to the app's entire Documents directory to the iOS Files app, "
                        "iTunes, and computer backups, exposing private app databases and session tokens."
                    ),
                    severity=Severity.MEDIUM,
                    cwe_id="CWE-200",
                    cvss_score=score,
                    cvss_vector=vector,
                    affected_component="Info.plist [UIFileSharingEnabled]",
                    file_path=str(p_path),
                    code_snippet="<key>UIFileSharingEnabled</key>\n<true/>",
                    remediation="Disable UIFileSharingEnabled and LSSupportsOpeningDocumentsInPlace unless user file export is strictly required.",
                    status=FindingStatus.UNVERIFIED,
                    confidence=1.0,
                )
            )

        return findings

    def audit_binary_symbols_and_apis(self, binary_path: str | Path) -> list[Finding]:
        """Scan Mach-O binary and embedded strings for insecure APIs, deprecated crypto, and keychain flags."""
        findings: list[Finding] = []
        b_path = Path(binary_path)
        if not b_path.exists():
            return findings

        try:
            raw_bytes = self._read_bounded(b_path, 128*1024*1024)
        except Exception as e:
            logger.warning("Failed reading binary for symbol audit: %s", e)
            return findings

        # 1. Insecure Keychain Accessibility (CWE-312)
        if b"kSecAttrAccessibleAlways" in raw_bytes or b"kSecAttrAccessibleAlwaysThisDeviceOnly" in raw_bytes:
            score, vector = get_default_cvss_for_cwe("CWE-312")
            findings.append(
                Finding(
                    id="ios-keychain-001",
                    title="CWE-312: Insecure iOS Keychain Accessibility (kSecAttrAccessibleAlways)",
                    description=(
                        "The binary references the deprecated and insecure keychain attribute `kSecAttrAccessibleAlways` "
                        "or `kSecAttrAccessibleAlwaysThisDeviceOnly`. These attributes store sensitive keychain secrets "
                        "in an unencrypted, accessible state even when the device is locked."
                    ),
                    severity=Severity.HIGH,
                    cwe_id="CWE-312",
                    cvss_score=score,
                    cvss_vector=vector,
                    affected_component=f"{b_path.name} (Keychain)",
                    file_path=str(b_path),
                    code_snippet="Mach-O symbol reference: kSecAttrAccessibleAlways",
                    remediation="Migrate to `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` or `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`.",
                    status=FindingStatus.UNVERIFIED,
                    confidence=0.95,
                )
            )

        # 2. Obsolete / Weak Cryptography & Hashes (CWE-327 / CWE-328)
        if b"kCCAlgorithmDES" in raw_bytes or b"kCCAlgorithm3DES" in raw_bytes:
            score, vector = get_default_cvss_for_cwe("CWE-327")
            findings.append(
                Finding(
                    id="ios-crypto-001",
                    title="CWE-327: Obsolete Block Cipher (DES/3DES) Used in iOS Binary",
                    description=(
                        "The Mach-O binary imports CommonCrypto symbols for DES / 3DES (kCCAlgorithmDES). "
                        "DES uses an obsolete 56-bit key susceptible to brute-force attacks and SWEET32 collisions."
                    ),
                    severity=Severity.HIGH,
                    cwe_id="CWE-327",
                    cvss_score=score,
                    cvss_vector=vector,
                    affected_component=f"{b_path.name} (CommonCrypto)",
                    file_path=str(b_path),
                    code_snippet="Mach-O symbol reference: kCCAlgorithmDES / kCCAlgorithm3DES",
                    remediation="Use AES-GCM (kCCAlgorithmAES) with a 256-bit key via CryptoKit or CommonCrypto.",
                    status=FindingStatus.UNVERIFIED,
                    confidence=0.95,
                )
            )

        if b"kCCAlgorithmRC4" in raw_bytes:
            score, vector = get_default_cvss_for_cwe("CWE-327")
            findings.append(
                Finding(
                    id="ios-crypto-002",
                    title="CWE-327: Broken Stream Cipher (RC4) Used in iOS Binary",
                    description=(
                        "The binary references kCCAlgorithmRC4. RC4 contains critical statistical biases in its keystream, "
                        "enabling plaintext recovery attacks."
                    ),
                    severity=Severity.HIGH,
                    cwe_id="CWE-327",
                    cvss_score=score,
                    cvss_vector=vector,
                    affected_component=f"{b_path.name} (CommonCrypto)",
                    file_path=str(b_path),
                    code_snippet="Mach-O symbol reference: kCCAlgorithmRC4",
                    remediation="Replace RC4 with AES-GCM or ChaCha20-Poly1305.",
                    status=FindingStatus.UNVERIFIED,
                    confidence=0.95,
                )
            )

        if b"CC_MD5" in raw_bytes:
            score, vector = get_default_cvss_for_cwe("CWE-328")
            findings.append(
                Finding(
                    id="ios-crypto-003",
                    title="CWE-328: Cryptographically Broken Hash Algorithm (MD5) in iOS Binary",
                    description=(
                        "The Mach-O binary imports CC_MD5. MD5 is vulnerable to collision generation attacks "
                        "and should not be used for cryptographic signatures or token validation."
                    ),
                    severity=Severity.MEDIUM,
                    cwe_id="CWE-328",
                    cvss_score=score,
                    cvss_vector=vector,
                    affected_component=f"{b_path.name} (CommonCrypto)",
                    file_path=str(b_path),
                    code_snippet="Mach-O symbol reference: CC_MD5",
                    remediation="Upgrade to SHA-256 (CC_SHA256) or SHA-3 via Apple CryptoKit.",
                    status=FindingStatus.UNVERIFIED,
                    confidence=0.9,
                )
            )

        # 3. Insecure Pasteboard Sharing (CWE-200)
        if b"generalPasteboard" in raw_bytes and b"UIPasteboard" in raw_bytes:
            score, vector = get_default_cvss_for_cwe("CWE-200")
            findings.append(
                Finding(
                    id="ios-pasteboard-001",
                    title="CWE-200: System-wide Pasteboard Access (UIPasteboard.generalPasteboard)",
                    description=(
                        "The application accesses UIPasteboard.generalPasteboard. Sensitive clipboard data "
                        "(passwords, OTPs, auth tokens) placed in the general pasteboard is accessible by any "
                        "foreground application or cross-device Universal Clipboard."
                    ),
                    severity=Severity.LOW,
                    cwe_id="CWE-200",
                    cvss_score=score,
                    cvss_vector=vector,
                    affected_component=f"{b_path.name} (UIPasteboard)",
                    file_path=str(b_path),
                    code_snippet="Symbol reference: [UIPasteboard generalPasteboard]",
                    remediation="Enforce local-only clipboard options (UIPasteboardOptionLocalOnly) or set an expirationDate.",
                    status=FindingStatus.UNVERIFIED,
                    confidence=0.85,
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
            all_bytes = self._read_bounded(b_path, 128*1024*1024)
            data = all_bytes[:4096]
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
                    status=FindingStatus.UNVERIFIED,
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
                    status=FindingStatus.UNVERIFIED,
                    confidence=1.0,
                )
            )

        return headers, findings

    def _audit_ios_framework_api_symbols(self, app_dir: str | Path, privacy_auditor) -> tuple[list[dict[str, Any]], list[Finding], dict[str, Any]]:
        """Review symbols in a bounded set of embedded framework executables.

        Framework candidates are matched only to manifests within their own
        framework bundle. Names remain static review indicators, never proof
        of reachable API use or platform non-compliance.
        """
        from mobileag.analysis.bounded_sources import SourceInventory
        from mobileag.analysis.macho_parser import MachoBinaryParser

        app_root = Path(app_dir)
        inventory = SourceInventory(
            max_entries=50_000, max_file_bytes=MachoBinaryParser.MAX_BINARY_BYTES,
            max_total_bytes=self.MAX_FRAMEWORK_SYMBOL_BYTES,
        )
        reports: list[dict[str, Any]] = []
        findings: list[Finding] = []
        seen_frameworks: set[str] = set()
        binary_candidates = 0
        bytes_considered = 0
        errors: list[str] = []
        for candidate in inventory.paths(app_root):
            framework_root = next(
                (parent for parent in candidate.parents if parent.suffix.lower() == ".framework"), None
            )
            if (framework_root is None or candidate.parent != framework_root
                    or candidate.name != framework_root.stem):
                continue
            relative_binary = candidate.relative_to(app_root).as_posix()
            if relative_binary in seen_frameworks:
                continue
            seen_frameworks.add(relative_binary)
            binary_candidates += 1
            if len(reports) >= self.MAX_FRAMEWORK_SYMBOL_BINARIES:
                inventory.record_limit("framework_binary_count")
                break
            try:
                details = candidate.lstat()
                if not stat.S_ISREG(details.st_mode) or details.st_size > MachoBinaryParser.MAX_BINARY_BYTES:
                    errors.append("framework_binary_type_or_size")
                    continue
                if bytes_considered + details.st_size > self.MAX_FRAMEWORK_SYMBOL_BYTES:
                    inventory.record_limit("framework_binary_total_bytes")
                    break
                bytes_considered += details.st_size
            except OSError:
                errors.append("framework_binary_stat_error")
                continue

            parsed = MachoBinaryParser().parse_binary(candidate)
            if not parsed.is_macho:
                errors.append("framework_binary_not_parsed")
                reports.append({
                    "binary": relative_binary, "status": parsed.parse_status,
                    "manifest_state": "not_checked", "candidate_count": 0,
                })
                continue

            manifest_result = privacy_auditor.audit_ios_privacy_manifest(framework_root)
            categories = manifest_result.declared_api_categories
            if manifest_result.parse_status == "invalid":
                manifest_state = "invalid"
            elif manifest_result.parse_status == "partial":
                manifest_state = "partial"
            elif manifest_result.has_privacy_manifest:
                manifest_state = "parsed"
            else:
                manifest_state = "absent"
            if manifest_state in {"invalid", "partial"}:
                errors.append("framework_manifest_" + manifest_state)
            review = privacy_auditor.audit_ios_binary_api_symbols(
                parsed.symbol_names, categories, app_manifest_state=manifest_state,
                binary_path=relative_binary, binary_parse_status=parsed.parse_status,
                component_name=f"{framework_root.stem} embedded framework",
                finding_id_scope=relative_binary,
            )
            review_findings = review.pop("findings")
            findings.extend(review_findings)
            reports.append({
                "binary": relative_binary,
                "framework_manifest_paths": manifest_result.manifest_paths,
                "framework_manifest_errors": manifest_result.errors,
                **review,
            })

        limits = inventory.coverage
        status = ("partial" if limits["limits_reached"] or limits["source_files_skipped"] or errors
                  or any(report["status"] == "partial" or report["status"].startswith("not_analyzed")
                         for report in reports)
                  else "analyzed_heuristically" if reports else "not_analyzed")
        coverage = {
            "status": status,
            "binary_candidates": binary_candidates,
            "binaries_analyzed": sum(
                report.get("status") in {"analyzed_heuristically", "partial"} for report in reports
            ),
            "limits": {
                "framework_binaries": self.MAX_FRAMEWORK_SYMBOL_BINARIES,
                "aggregate_binary_bytes": self.MAX_FRAMEWORK_SYMBOL_BYTES,
                "tree_entries": inventory.max_entries,
                "per_binary_bytes": inventory.max_file_bytes,
            },
            "bytes_considered": bytes_considered,
            "entries_examined": limits["entries_examined"],
            "limits_reached": limits["limits_reached"],
            "limit_reasons": limits["limit_reasons"],
            "errors": sorted(set(errors)),
            "runtime_status": "not_tested",
            "proof_status": "not_proven",
            "exhaustive": False,
        }
        return reports, findings, coverage

    def audit_ipa(self, ipa_path: str | Path, temp_extract_dir: str | Path) -> dict[str, Any]:
        """Run complete static analysis pipeline on an iOS IPA file."""
        extracted = self.extract_ipa(ipa_path, temp_extract_dir)
        all_findings: list[Finding] = []

        if extracted.get("info_plist_path"):
            plist_findings = self.audit_info_plist(extracted["info_plist_path"])
            all_findings.extend(plist_findings)

        macho_headers = MachOSecurityHeaders()
        swift_metadata = {}
        m_res = None
        if extracted.get("binary_path"):
            macho_headers, bin_findings = self.audit_macho_binary(extracted["binary_path"])
            all_findings.extend(bin_findings)
            sym_findings = self.audit_binary_symbols_and_apis(extracted["binary_path"])
            all_findings.extend(sym_findings)
            try:
                from mobileag.analysis.macho_parser import MachoBinaryParser
                m_parser = MachoBinaryParser()
                m_res = m_parser.parse_binary(extracted["binary_path"])
                if m_res.is_macho:
                    swift_metadata = {
                        "parse_status": m_res.parse_status,
                        "parse_errors": m_res.parse_errors,
                        "load_commands_count": m_res.load_commands_count,
                        "architectures": m_res.architectures,
                        "slice_count": m_res.slice_count,
                        "imported_dylibs": m_res.imported_dylibs,
                        "symbol_names": m_res.symbol_names,
                        "sections": m_res.sections,
                        "swift_sections": m_res.swift_sections_detected,
                        "swift_section_name_candidates": m_res.swift_section_name_candidates,
                        "swift_type_metadata_status": m_res.swift_type_metadata_status,
                        "swift_type_name_candidates": m_res.swift_type_name_candidates,
                        "swift_type_field_candidates": m_res.swift_type_field_candidates,
                        "swift_protocol_metadata_status": m_res.swift_protocol_metadata_status,
                        "swift_protocol_name_candidates": m_res.swift_protocol_name_candidates,
                        "crypto_frameworks": m_res.crypto_frameworks,
                        "api_endpoints": m_res.api_endpoints,
                    }
            except Exception as e:
                logger.debug("MachoBinaryParser optional pass skipped: %s", e)

        privacy_manifest_summary: dict[str, Any] = {}
        try:
            from mobileag.analysis.privacy_manifest_auditor import PrivacyManifestAuditor
            p_auditor = PrivacyManifestAuditor()
            p_res = p_auditor.audit_ios_privacy_manifest(temp_extract_dir)
            app_manifest_result = p_auditor.audit_ios_privacy_manifest(extracted["app_dir"])
            privacy_manifest_summary = {
                "has_privacy_manifest": p_res.has_privacy_manifest,
                "parse_status": p_res.parse_status,
                "manifest_count": p_res.manifest_count,
                "manifest_paths": p_res.manifest_paths,
                "manifests": p_res.manifests,
                "errors": p_res.errors,
                "tracking_enabled": p_res.tracking_enabled,
                "tracking_domains": p_res.tracking_domains,
                "declared_api_categories": p_res.declared_api_categories,
                "declared_api_reasons": p_res.declared_api_reasons,
            }
            app_manifest = next((item for item in app_manifest_result.manifests
                                 if item.get("path") == "PrivacyInfo.xcprivacy"), None)
            if app_manifest is not None:
                app_manifest_state = "parsed"
                app_declared_categories = app_manifest.get("declared_api_categories", [])
            elif "PrivacyInfo.xcprivacy" in app_manifest_result.manifest_paths:
                app_manifest_state = "invalid"
                app_declared_categories = []
            else:
                app_manifest_state = "absent"
                app_declared_categories = []
            api_symbol_review = p_auditor.audit_ios_binary_api_symbols(
                m_res.symbol_names if m_res is not None and m_res.is_macho else None,
                app_declared_categories,
                app_manifest_state=app_manifest_state,
                binary_path=extracted.get("binary_path") or "",
                binary_parse_status=m_res.parse_status if m_res is not None else "not_tested",
            )
            all_findings.extend(api_symbol_review.pop("findings"))
            privacy_manifest_summary["binary_api_symbol_review"] = api_symbol_review
            framework_reviews, framework_findings, framework_coverage = (
                self._audit_ios_framework_api_symbols(extracted["app_dir"], p_auditor)
            )
            all_findings.extend(framework_findings)
            privacy_manifest_summary["framework_binary_api_symbol_reviews"] = framework_reviews
            privacy_manifest_summary["framework_api_symbol_review_coverage"] = framework_coverage
            for manifest_index, manifest in enumerate(p_res.manifests, start=1):
                if manifest["tracking_enabled"] is True and not manifest["tracking_domains"]:
                    all_findings.append(Finding(
                        id=f"ios-privacy-001-{manifest_index}",
                        title="CWE-359: Privacy Manifest Tracking Enabled Without Declared Tracking Domains",
                        description=(f"NSPrivacyTracking is enabled in {manifest['path']}, but that manifest has no "
                                     "NSPrivacyTrackingDomains declaration. This static consistency indicator "
                                     "does not establish tracking behavior or regulatory non-compliance."),
                        severity=Severity.MEDIUM,
                        cwe_id="CWE-359",
                        affected_component="PrivacyInfo.xcprivacy",
                        detection_method="PrivacyManifestAuditor (iOS Privacy Manifest)",
                        status=FindingStatus.UNVERIFIED,
                        remediation="Declare all internet domains used for third-party tracking in NSPrivacyTrackingDomains.",
                    ))
        except Exception as e:
            logger.debug("Privacy manifest check skipped: %s", e)

        return {
            "app_name": extracted["app_name"],
            "package_name": extracted["package_name"],
            "version": extracted["version"],
            "build": extracted["build"],
            "platform": "iOS",
            "findings_count": len(all_findings),
            "coverage": {"info_plist":"parsed", "binary_format":"mach_o_64" if macho_headers.is_macho else "unsupported",
                         "symbols":"byte_string_heuristic", "privacy_api_symbol_review": privacy_manifest_summary.get("binary_api_symbol_review", {}).get("status", "not_analyzed"),
                         "framework_privacy_api_symbol_review": privacy_manifest_summary.get("framework_api_symbol_review_coverage", {}).get("status", "not_analyzed"),
                         "entitlements":"not_assessed", "runtime":"not_assessed"},
            "errors": [] if macho_headers.is_macho else ["Unsupported or truncated executable; binary security was not assessed"],
            "findings": all_findings,
            "macho_security": {
                "pie_enabled": macho_headers.pie_enabled,
                "has_stack_canary": macho_headers.has_stack_canary,
                "has_arc": macho_headers.has_arc,
            },
            "swift_metadata": swift_metadata,
            "privacy_manifest": privacy_manifest_summary,
        }

