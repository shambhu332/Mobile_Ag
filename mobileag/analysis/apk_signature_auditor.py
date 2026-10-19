"""APK Signature Scheme Verifier & Vulnerability Auditor.

Inspects APK files without external Java dependencies to extract and verify:
- APK Signature Schemes: v1 (JAR signing), v2 (APK Signing Block), v3, and v3.1
- Signing certificates (subject, issuer, algorithm, key size, fingerprints)
- Security vulnerabilities:
  * Janus vulnerability (CVE-2017-13156: v1-only signature with minSdk <= 26)
  * Broken / weak hash algorithms (MD5, SHA-1)
  * Weak public key algorithms / key lengths (RSA < 2048 bits, DSA)
  * Debug certificates (CN=Android Debug)
  * Certificate expiry and missing modern signature schemes
"""

from __future__ import annotations

import datetime
import hashlib
import io
import logging
import struct
import zipfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs7

from mobileag.reporting.finding import Finding, FindingStatus, Severity

logger = logging.getLogger(__name__)

# Android APK Signing Block Magic & IDs
APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
ID_APK_SIGNATURE_SCHEME_V2 = 0x7109871A
ID_APK_SIGNATURE_SCHEME_V3 = 0xF05368C0
ID_APK_SIGNATURE_SCHEME_V31 = 0x1B93FD61
ID_SOURCE_STAMP = 0x42726577


@dataclass(slots=True)
class CertificateDetails:
    subject: str
    issuer: str
    serial_number: str
    signature_algorithm: str
    key_type: str
    key_size: int
    not_valid_before: str
    not_valid_after: str
    sha256_fingerprint: str
    sha1_fingerprint: str
    is_debug: bool = False
    is_expired: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class SignatureAuditResult:
    apk_path: str
    signing_block_found: bool
    schemes: dict[str, bool] = field(default_factory=lambda: {"v1": False, "v2": False, "v3": False, "v3.1": False})
    certificates: list[CertificateDetails] = field(default_factory=list)
    vulnerabilities: list[dict[str, Any]] = field(default_factory=list)
    janus_vulnerable: bool = False
    min_sdk_version: int = 1
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "apk_path": self.apk_path,
            "signing_block_found": self.signing_block_found,
            "schemes": self.schemes,
            "certificates": [c.to_dict() for c in self.certificates],
            "vulnerabilities": self.vulnerabilities,
            "janus_vulnerable": self.janus_vulnerable,
            "min_sdk_version": self.min_sdk_version,
            "warnings": self.warnings,
        }


class ApkSignatureAuditor:
    """Audits APK signature schemes and certificate security."""

    def __init__(self, min_sdk_version: int = 1) -> None:
        self.min_sdk_version = min_sdk_version

    def audit(self, apk_path: str | Path, min_sdk_version: Optional[int] = None) -> SignatureAuditResult:
        """Run full signature audit against an APK file path."""
        path = Path(apk_path).resolve()
        if not path.is_file():
            raise FileNotFoundError(f"APK file not found: {path}")

        min_sdk = min_sdk_version if min_sdk_version is not None else self.min_sdk_version
        result = SignatureAuditResult(
            apk_path=str(path),
            signing_block_found=False,
            min_sdk_version=min_sdk,
        )

        try:
            apk_bytes = path.read_bytes()
        except Exception as exc:
            result.warnings.append(f"Could not read APK bytes: {exc}")
            return result

        # 1. Parse ZIP Central Directory & APK Signing Block
        v2_v3_certs_der = self._extract_signing_block_certificates(apk_bytes, result)

        # 2. Parse META-INF v1 JAR Signatures
        v1_certs_der = self._extract_v1_certificates(apk_bytes, result)

        # 3. Parse all extracted certificates
        all_raw_ders = list(dict.fromkeys(v2_v3_certs_der + v1_certs_der))
        parsed_certs: list[CertificateDetails] = []
        for raw_der in all_raw_ders:
            cert_detail = self._parse_x509_certificate(raw_der)
            if cert_detail:
                parsed_certs.append(cert_detail)
        result.certificates = parsed_certs

        # 4. Assess Vulnerabilities
        findings = self._evaluate_vulnerabilities(result)
        result.vulnerabilities = [f.to_dict() for f in findings]

        return result

    def audit_findings(self, apk_path: str | Path, min_sdk_version: Optional[int] = None) -> list[Finding]:
        """Return Findings directly for integration with scan pipeline."""
        audit_res = self.audit(apk_path, min_sdk_version=min_sdk_version)
        findings: list[Finding] = []
        for vuln in audit_res.vulnerabilities:
            findings.append(Finding(
                title=vuln["title"],
                description=vuln["description"],
                severity=Severity(vuln["severity"]),
                cwe_id=vuln.get("cwe_id", "CWE-347"),
                cvss_score=vuln.get("cvss_score", 0.0),
                affected_component="APK Signature",
                detection_method="ApkSignatureAuditor",
                status=FindingStatus.CONFIRMED,
                remediation=vuln.get("remediation", ""),
                file_path=str(apk_path),
                line_number=1,
                code_snippet=vuln.get("code_snippet", ""),
                metadata=vuln.get("metadata", {}),
            ))
        return findings

    # --- APK Signing Block Extraction ---

    def _extract_signing_block_certificates(self, apk: bytes, result: SignatureAuditResult) -> list[bytes]:
        """Locate and extract certificates from the APK Signing Block (schemes v2, v3, v3.1)."""
        certs_der: list[bytes] = []
        if len(apk) < 32:
            return certs_der

        # Locate EOCD (End of Central Directory)
        eocd_offset = self._find_eocd_offset(apk)
        if eocd_offset < 0:
            result.warnings.append("Could not find ZIP End of Central Directory record.")
            return certs_der

        # Central Directory offset is at eocd + 16 (uint32 LE)
        cd_offset = struct.unpack_from("<I", apk, eocd_offset + 16)[0]
        if cd_offset < 32 or cd_offset > len(apk):
            result.warnings.append("Central directory offset is invalid or out of bounds.")
            return certs_der

        # Check for APK Signing Block magic (16 bytes before CD start)
        magic_offset = cd_offset - 16
        if apk[magic_offset:cd_offset] != APK_SIG_BLOCK_MAGIC:
            return certs_der

        result.signing_block_found = True

        # Read 64-bit block size (at cd_offset - 24)
        block_size = struct.unpack_from("<Q", apk, cd_offset - 24)[0]
        block_start = cd_offset - block_size - 8
        if block_start < 0 or block_size < 24:
            result.warnings.append("APK signing block size is corrupted.")
            return certs_der

        # Iterate ID-value pairs
        offset = block_start + 8
        pairs_end = cd_offset - 24
        while offset + 12 <= pairs_end:
            pair_len = struct.unpack_from("<Q", apk, offset)[0]
            if pair_len < 4 or offset + 8 + pair_len > cd_offset:
                break
            scheme_id = struct.unpack_from("<I", apk, offset + 8)[0]
            value_bytes = apk[offset + 12: offset + 8 + pair_len]

            if scheme_id == ID_APK_SIGNATURE_SCHEME_V2:
                result.schemes["v2"] = True
                certs_der.extend(self._parse_v2_v3_signers(value_bytes))
            elif scheme_id == ID_APK_SIGNATURE_SCHEME_V3:
                result.schemes["v3"] = True
                certs_der.extend(self._parse_v2_v3_signers(value_bytes))
            elif scheme_id == ID_APK_SIGNATURE_SCHEME_V31:
                result.schemes["v3.1"] = True
                certs_der.extend(self._parse_v2_v3_signers(value_bytes))

            offset += 8 + pair_len

        return certs_der

    def _find_eocd_offset(self, apk: bytes) -> int:
        """Find the start of the ZIP EOCD record searching backwards from EOF."""
        max_search = min(len(apk), 65557)
        start_search = len(apk) - 22
        end_search = len(apk) - max_search
        for i in range(start_search, end_search - 1, -1):
            if apk[i:i + 4] == b"\x50\x4b\x05\x06":  # 0x06054b50
                return i
        return -1

    def _parse_v2_v3_signers(self, value: bytes) -> list[bytes]:
        """Extract DER certificates from a v2 or v3 scheme block value."""
        certs: list[bytes] = []
        if len(value) < 8:
            return certs
        try:
            # First 4 bytes: length of signers sequence
            signers_len = struct.unpack_from("<I", value, 0)[0]
            offset = 4
            end_signers = min(len(value), 4 + signers_len)

            while offset + 4 <= end_signers and len(certs) < 16:
                signer_len = struct.unpack_from("<I", value, offset)[0]
                offset += 4
                signer_bytes = value[offset: offset + signer_len]
                offset += signer_len

                if len(signer_bytes) < 4:
                    continue

                # signed data
                signed_data_len = struct.unpack_from("<I", signer_bytes, 0)[0]
                signed_data = signer_bytes[4: 4 + signed_data_len]

                if len(signed_data) < 4:
                    continue

                # digests length
                digests_len = struct.unpack_from("<I", signed_data, 0)[0]
                p = 4 + digests_len
                if p + 4 > len(signed_data):
                    continue

                # certificates sequence length
                certs_seq_len = struct.unpack_from("<I", signed_data, p)[0]
                q = p + 4
                end_certs = min(len(signed_data), q + certs_seq_len)

                while q + 4 <= end_certs and len(certs) < 16:
                    cert_len = struct.unpack_from("<I", signed_data, q)[0]
                    q += 4
                    if q + cert_len <= len(signed_data):
                        certs.append(signed_data[q: q + cert_len])
                    q += cert_len
        except Exception as exc:
            logger.debug(f"Error parsing v2/v3 signers sequence: {exc}")
        return certs

    # --- v1 (JAR Signature) Extraction ---

    def _extract_v1_certificates(self, apk: bytes, result: SignatureAuditResult) -> list[bytes]:
        """Extract v1 signing certificates from META-INF entries in the APK ZIP."""
        certs_der: list[bytes] = []
        try:
            with zipfile.ZipFile(io.BytesIO(apk), "r") as zf:
                manifest_present = any(name.upper() == "META-INF/MANIFEST.MF" for name in zf.namelist())
                cert_sf_present = any(name.upper().startswith("META-INF/") and name.upper().endswith(".SF") for name in zf.namelist())

                for name in zf.namelist():
                    upper = name.upper()
                    if upper.startswith("META-INF/") and (upper.endswith(".RSA") or upper.endswith(".DSA") or upper.endswith(".EC")):
                        data = zf.read(name)
                        result.schemes["v1"] = True
                        extracted = self._extract_certs_from_pkcs7(data)
                        certs_der.extend(extracted)

                if manifest_present and cert_sf_present and not result.schemes["v1"]:
                    result.schemes["v1"] = True
        except Exception as exc:
            result.warnings.append(f"Error inspecting META-INF: {exc}")
        return certs_der

    def _extract_certs_from_pkcs7(self, data: bytes) -> list[bytes]:
        """Extract DER X.509 certificates from PKCS#7 block, with DER fallback scanner."""
        certs: list[bytes] = []
        try:
            p7_certs = pkcs7.load_der_pkcs7_certificates(data)
            for cert in p7_certs:
                certs.append(cert.public_bytes(x509.Encoding.DER))
            if certs:
                return certs
        except Exception:
            pass

        # Fallback DER scanner: locate ASN.1 SEQUENCE headers (0x30 0x82)
        for i in range(len(data) - 4):
            if data[i] == 0x30 and data[i + 1] == 0x82:
                seq_len = (data[i + 2] << 8) | data[i + 3]
                total_len = seq_len + 4
                if total_len > 200 and i + total_len <= len(data):
                    candidate = data[i: i + total_len]
                    try:
                        cert = x509.load_der_x509_certificate(candidate)
                        certs.append(candidate)
                    except Exception:
                        pass
        return certs

    # --- Certificate Analysis ---

    def _parse_x509_certificate(self, der_bytes: bytes) -> Optional[CertificateDetails]:
        """Parse DER X.509 certificate into CertificateDetails."""
        try:
            cert = x509.load_der_x509_certificate(der_bytes)
        except Exception as exc:
            logger.debug(f"Could not load DER X.509 cert: {exc}")
            return None

        subject_str = cert.subject.rfc4514_string()
        issuer_str = cert.issuer.rfc4514_string()
        serial_str = hex(cert.serial_number)[2:].upper()

        # Signature algorithm
        sig_alg = cert.signature_hash_algorithm.name.upper() if cert.signature_hash_algorithm else "UNKNOWN"

        # Key type and size
        pub_key = cert.public_key()
        if isinstance(pub_key, rsa.RSAPublicKey):
            key_type = "RSA"
            key_size = pub_key.key_size
        elif isinstance(pub_key, dsa.DSAPublicKey):
            key_type = "DSA"
            key_size = pub_key.key_size
        elif isinstance(pub_key, ec.EllipticCurvePublicKey):
            key_type = f"EC ({pub_key.curve.name})"
            key_size = pub_key.key_size
        else:
            key_type = "OTHER"
            key_size = getattr(pub_key, "key_size", 0)

        # Validity
        try:
            nvb = cert.not_valid_before_utc.isoformat()
            nva = cert.not_valid_after_utc.isoformat()
            now = datetime.datetime.now(datetime.timezone.utc)
            is_expired = now > cert.not_valid_after_utc or now < cert.not_valid_before_utc
        except AttributeError:
            nvb = cert.not_valid_before.isoformat()
            nva = cert.not_valid_after.isoformat()
            now_naive = datetime.datetime.utcnow()
            is_expired = now_naive > cert.not_valid_after or now_naive < cert.not_valid_before

        sha256_fp = cert.fingerprint(hashes.SHA256()).hex().lower()
        sha1_fp = cert.fingerprint(hashes.SHA1()).hex().lower()

        # Debug cert check
        is_debug = "CN=Android Debug" in subject_str or "O=Android" in subject_str

        return CertificateDetails(
            subject=subject_str,
            issuer=issuer_str,
            serial_number=serial_str,
            signature_algorithm=sig_alg,
            key_type=key_type,
            key_size=key_size,
            not_valid_before=nvb,
            not_valid_after=nva,
            sha256_fingerprint=sha256_fp,
            sha1_fingerprint=sha1_fp,
            is_debug=is_debug,
            is_expired=is_expired,
        )

    # --- Vulnerability Evaluation ---

    def _evaluate_vulnerabilities(self, result: SignatureAuditResult) -> list[Finding]:
        """Evaluate signature scheme combinations and certificate properties for security issues."""
        findings: list[Finding] = []
        schemes = result.schemes
        min_sdk = result.min_sdk_version

        # 1. Janus Vulnerability (CVE-2017-13156)
        # Condition: App has v1 signature, but NO v2 or v3 signature, and minSdkVersion <= 26.
        if schemes["v1"] and not schemes["v2"] and not schemes["v3"] and min_sdk <= 26:
            result.janus_vulnerable = True
            findings.append(Finding(
                title="Vulnerable to Janus APK Signature Bypass (CVE-2017-13156)",
                description=(
                    f"The APK is signed only with APK Signature Scheme v1 (JAR signing) without v2/v3 signatures, "
                    f"and targets minSdkVersion {min_sdk} <= 26. On Android 5.0 to 8.0, the ART runtime executes "
                    f"DEX files prepended to an APK file without invalidating the v1 signature, allowing an attacker "
                    f"to inject arbitrary executable code into the application while retaining the publisher's valid signature."
                ),
                severity=Severity.HIGH if min_sdk <= 23 else Severity.MEDIUM,
                cwe_id="CWE-347",
                cvss_score=8.1 if min_sdk <= 23 else 6.5,
                affected_component="APK Signature",
                detection_method="ApkSignatureAuditor",
                status=FindingStatus.CONFIRMED,
                remediation=(
                    "Enable APK Signature Scheme v2 and v3 in your Android build configuration "
                    "(e.g., v2SigningEnabled true in Gradle or apksigner sign --v2-signing-enabled true), "
                    "and consider bumping minSdkVersion to 24+."
                ),
                file_path=result.apk_path,
                line_number=1,
                code_snippet="Signature Schemes: v1=True, v2=False, v3=False | minSdkVersion: " + str(min_sdk),
                metadata={
                    "cve": "CVE-2017-13156",
                    "schemes": schemes,
                    "min_sdk": min_sdk,
                },
            ))

        # 2. Missing Modern Signature Schemes (v2/v3)
        if not schemes["v2"] and not schemes["v3"] and not result.janus_vulnerable:
            findings.append(Finding(
                title="APK Missing Signature Scheme v2/v3",
                description=(
                    "The APK lacks APK Signature Scheme v2 (Full APK Signature) and v3 signatures. "
                    "v2/v3 signature schemes verify whole-file integrity including ZIP metadata, preventing "
                    "unauthorized modifications and accelerating package verification during installation."
                ),
                severity=Severity.LOW,
                cwe_id="CWE-347",
                cvss_score=3.5,
                affected_component="APK Signature",
                detection_method="ApkSignatureAuditor",
                status=FindingStatus.CONFIRMED,
                remediation="Sign the application with APK Signature Scheme v2 and v3 using apksigner.",
                file_path=result.apk_path,
                line_number=1,
                code_snippet="Schemes present: " + str(schemes),
                metadata={"schemes": schemes},
            ))

        # 3. No signatures present
        if not any(schemes.values()):
            findings.append(Finding(
                title="Unsigned or Invalid APK Package",
                description="The APK does not contain any valid v1, v2, or v3 signatures.",
                severity=Severity.HIGH,
                cwe_id="CWE-347",
                cvss_score=7.5,
                affected_component="APK Signature",
                detection_method="ApkSignatureAuditor",
                status=FindingStatus.CONFIRMED,
                remediation="Sign the APK before distribution using apksigner.",
                file_path=result.apk_path,
                line_number=1,
                code_snippet="No signature schemes detected.",
            ))

        # Certificate-level audits
        for idx, cert in enumerate(result.certificates, start=1):
            cert_id = f"Cert #{idx} ({cert.subject})"

            # 4. Debug Certificate
            if cert.is_debug:
                findings.append(Finding(
                    title="APK Signed with Android Debug Certificate",
                    description=(
                        f"The APK is signed with a debug certificate ({cert.subject}). "
                        "The Android debug keystore uses a publicly known password ('android'), "
                        "meaning anyone can produce conflicting updates or spoof the application identity."
                    ),
                    severity=Severity.HIGH,
                    cwe_id="CWE-295",
                    cvss_score=7.4,
                    affected_component="APK Signature",
                    detection_method="ApkSignatureAuditor",
                    status=FindingStatus.CONFIRMED,
                    remediation="Sign release builds with a private, protected production key.",
                    file_path=result.apk_path,
                    line_number=1,
                    code_snippet=f"Subject: {cert.subject} | Issuer: {cert.issuer}",
                    metadata={"certificate": cert.to_dict()},
                ))

            # 5. Weak Hash Algorithm (MD5, SHA1)
            sig_hash = cert.signature_algorithm.upper()
            if "MD5" in sig_hash or "MD2" in sig_hash:
                findings.append(Finding(
                    title=f"APK Certificate Uses Broken Hash Algorithm ({cert.signature_algorithm})",
                    description=(
                        f"Signing certificate for {cert.subject} utilizes {cert.signature_algorithm}, "
                        "which is cryptographically broken and vulnerable to practical collision attacks."
                    ),
                    severity=Severity.HIGH,
                    cwe_id="CWE-327",
                    cvss_score=7.5,
                    affected_component="APK Signature",
                    detection_method="ApkSignatureAuditor",
                    status=FindingStatus.CONFIRMED,
                    remediation="Re-sign the APK using SHA-256 or SHA-512 with RSA or ECDSA.",
                    file_path=result.apk_path,
                    line_number=1,
                    code_snippet=f"Signature Algorithm: {cert.signature_algorithm}",
                    metadata={"certificate": cert.to_dict()},
                ))
            elif "SHA1" in sig_hash:
                findings.append(Finding(
                    title=f"APK Certificate Uses Deprecated SHA-1 Hash ({cert.signature_algorithm})",
                    description=(
                        f"Signing certificate for {cert.subject} utilizes {cert.signature_algorithm}. "
                        "SHA-1 is deprecated for digital signatures due to known collision vulnerabilities."
                    ),
                    severity=Severity.MEDIUM,
                    cwe_id="CWE-327",
                    cvss_score=5.3,
                    affected_component="APK Signature",
                    detection_method="ApkSignatureAuditor",
                    status=FindingStatus.CONFIRMED,
                    remediation="Migrate signing certificates to SHA-256 or stronger.",
                    file_path=result.apk_path,
                    line_number=1,
                    code_snippet=f"Signature Algorithm: {cert.signature_algorithm}",
                    metadata={"certificate": cert.to_dict()},
                ))

            # 6. Weak Public Key Size or Algorithm
            if cert.key_type == "RSA" and cert.key_size < 2048:
                sev = Severity.HIGH if cert.key_size < 1024 else Severity.MEDIUM
                findings.append(Finding(
                    title=f"APK Certificate Uses Weak RSA Key ({cert.key_size} bits)",
                    description=(
                        f"The RSA key size is {cert.key_size} bits, which is below the recommended "
                        "minimum of 2048 bits and may be vulnerable to factorization."
                    ),
                    severity=sev,
                    cwe_id="CWE-326",
                    cvss_score=7.1 if cert.key_size < 1024 else 5.0,
                    affected_component="APK Signature",
                    detection_method="ApkSignatureAuditor",
                    status=FindingStatus.CONFIRMED,
                    remediation="Generate an RSA key of at least 2048 bits (preferably 4096) or use ECDSA.",
                    file_path=result.apk_path,
                    line_number=1,
                    code_snippet=f"Key: RSA {cert.key_size} bits",
                    metadata={"certificate": cert.to_dict()},
                ))
            elif cert.key_type == "DSA":
                findings.append(Finding(
                    title="APK Certificate Uses Deprecated DSA Algorithm",
                    description="DSA is deprecated for Android application signing; RSA or ECDSA should be used.",
                    severity=Severity.MEDIUM,
                    cwe_id="CWE-327",
                    cvss_score=5.0,
                    affected_component="APK Signature",
                    detection_method="ApkSignatureAuditor",
                    status=FindingStatus.CONFIRMED,
                    remediation="Re-sign the APK using RSA 2048+ bits or ECDSA.",
                    file_path=result.apk_path,
                    line_number=1,
                    code_snippet="Key: DSA",
                    metadata={"certificate": cert.to_dict()},
                ))

            # 7. Expired Certificate
            if cert.is_expired:
                findings.append(Finding(
                    title="APK Signing Certificate Has Expired or Is Not Yet Valid",
                    description=(
                        f"Certificate {cert.subject} validity period ({cert.not_valid_before} to "
                        f"{cert.not_valid_after}) does not cover the current time."
                    ),
                    severity=Severity.LOW,
                    cwe_id="CWE-295",
                    cvss_score=3.0,
                    affected_component="APK Signature",
                    detection_method="ApkSignatureAuditor",
                    status=FindingStatus.CONFIRMED,
                    remediation="Ensure certificate validity period is configured properly (standard Android app validity is 25+ years).",
                    file_path=result.apk_path,
                    line_number=1,
                    code_snippet=f"Valid from {cert.not_valid_before} to {cert.not_valid_after}",
                    metadata={"certificate": cert.to_dict()},
                ))

        return findings
