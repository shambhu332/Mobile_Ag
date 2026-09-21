"""Network Security Configuration auditor for Android applications.

Audits res/xml/network_security_config.xml (or the custom XML referenced in
AndroidManifest.xml) for TLS misconfigurations, user trust-anchor exposure,
cleartext traffic overrides, and expired certificate pinning sets.
"""

from datetime import datetime, timezone
import asyncio
import logging
from pathlib import Path
from typing import Any, Optional
import xml.etree.ElementTree as ET

from mobileag.reporting.finding import Finding, Severity, FindingStatus
from mobileag.reporting.cvss import get_default_cvss_for_cwe

logger = logging.getLogger(__name__)

ANDROID_NS = "http://schemas.android.com/apk/res/android"


class NetworkSecurityConfigAuditor:
    """Audits Android Network Security Configuration XML files."""

    def __init__(self) -> None:
        pass

    def locate_config_path(
        self,
        decompiled_dir: str,
        manifest_path: Optional[str] = None
    ) -> Optional[Path]:
        """Locate network_security_config.xml from AndroidManifest.xml or standard fallback paths.

        Args:
            decompiled_dir: Root directory of decompiled APK (apktool or jadx output).
            manifest_path: Optional direct path to AndroidManifest.xml.

        Returns:
            Path object to the XML file if found, else None.
        """
        root_path = Path(decompiled_dir)
        xml_name = "network_security_config"

        # 1. Inspect manifest for android:networkSecurityConfig attribute
        manifest_file = Path(manifest_path) if manifest_path else root_path / "AndroidManifest.xml"
        if not manifest_file.exists():
            # Check common apktool/jadx locations
            for alt in [root_path / "apktool_out" / "AndroidManifest.xml", root_path / "resources" / "AndroidManifest.xml"]:
                if alt.exists():
                    manifest_file = alt
                    break

        if manifest_file.exists():
            try:
                tree = ET.parse(manifest_file)
                app_elem = tree.getroot().find("application")
                if app_elem is not None:
                    attr_val = app_elem.attrib.get(f"{{{ANDROID_NS}}}networkSecurityConfig", "")
                    # Format: @xml/network_security_config or @7F120001
                    if attr_val.startswith("@xml/"):
                        xml_name = attr_val.replace("@xml/", "").strip()
            except Exception as e:
                logger.debug(f"Could not parse manifest for networkSecurityConfig attribute: {e}")

        # 2. Check candidates in decompiled directory
        candidate_paths = [
            root_path / "res" / "xml" / f"{xml_name}.xml",
            root_path / "apktool_out" / "res" / "xml" / f"{xml_name}.xml",
            root_path / "resources" / "res" / "xml" / f"{xml_name}.xml",
        ]

        for candidate in candidate_paths:
            if candidate.exists():
                return candidate

        # 3. Fallback: Recursive search for the xml filename or any network_security_config
        found = list(root_path.rglob(f"{xml_name}.xml"))
        if found:
            return found[0]

        generic_found = list(root_path.rglob("network_security_config.xml"))
        if generic_found:
            return generic_found[0]

        return None

    def audit_file(self, config_path: str | Path) -> list[dict[str, Any]]:
        """Parse and audit a specific Network Security Configuration file.

        Args:
            config_path: Path to the network security config XML file.

        Returns:
            List of findings as standardized dictionaries.
        """
        path = Path(config_path)
        if not path.exists():
            logger.warning(f"Network security config file not found: {path}")
            return []

        try:
            tree = ET.parse(path)
            root = tree.getroot()
        except ET.ParseError as e:
            logger.error(f"Failed to parse Network Security Configuration XML at {path}: {e}")
            return [{
                "issue_id": "NSC-XML-PARSE-ERROR",
                "cwe": "CWE-112",
                "severity": "Medium",
                "title": "Invalid Network Security Configuration XML",
                "description": f"The XML file at {path.name} is malformed or could not be parsed: {e}",
                "file_path": str(path),
                "remediation": "Ensure the XML is valid and conforms to Android's network_security_config schema."
            }]

        findings: list[dict[str, Any]] = []

        # Audit components
        findings.extend(self._check_user_trust_anchors(root, str(path)))
        findings.extend(self._check_cleartext_traffic(root, str(path)))
        findings.extend(self._check_pinning_expiration(root, str(path)))

        return findings

    def _check_user_trust_anchors(self, root: ET.Element, file_path: str) -> list[dict[str, Any]]:
        """Audit for user-installed CA certificates allowed in non-debug contexts."""
        findings: list[dict[str, Any]] = []

        # Elements to check (exclude <debug-overrides> which only affects debug builds)
        target_tags = ["base-config", "domain-config"]

        for tag in target_tags:
            for parent in root.iter(tag):
                trust_anchors = parent.find("trust-anchors")
                if trust_anchors is None:
                    continue

                for cert in trust_anchors.findall("certificates"):
                    src = cert.attrib.get("src", "").strip().lower()
                    if src == "user":
                        # Check if overridePins is enabled
                        override_pins = cert.attrib.get("overridePins", "false").lower() == "true"
                        context_desc = "base-config (all network traffic)" if tag == "base-config" else "domain-config"

                        findings.append({
                            "issue_id": "NSC-USER-TRUST-ANCHOR",
                            "cwe": "CWE-295",
                            "severity": "High",
                            "title": f"User-Installed CA Certificates Trusted in {tag}",
                            "description": (
                                f"The Network Security Configuration permits user-installed CA certificates "
                                f"in <{tag}> ({context_desc}). This allows adversaries or users to decrypt and inspect "
                                f"HTTPS traffic using custom root certificates without requiring root privileges."
                            ),
                            "file_path": file_path,
                            "remediation": (
                                "Remove <certificates src=\"user\" /> from base-config and domain-config. "
                                "If required for QA testing, encapsulate user certificates strictly inside "
                                "a <debug-overrides> block, which is only activated in debuggable builds."
                            )
                        })

        return findings

    def _check_cleartext_traffic(self, root: ET.Element, file_path: str) -> list[dict[str, Any]]:
        """Check for cleartext HTTP traffic allowed globally or per-domain."""
        findings: list[dict[str, Any]] = []

        # 1. Base Config check
        base_config = root.find("base-config")
        if base_config is not None:
            cleartext_attr = base_config.attrib.get("cleartextTrafficPermitted", "").lower()
            if cleartext_attr == "true":
                findings.append({
                    "issue_id": "NSC-GLOBAL-CLEARTEXT-ALLOWED",
                    "cwe": "CWE-319",
                    "severity": "High",
                    "title": "Global Cleartext HTTP Traffic Permitted in Base Config",
                    "description": (
                        "The <base-config> element explicitly sets cleartextTrafficPermitted=\"true\". "
                        "All network connections initiated by the app default to permitting unencrypted HTTP communication."
                    ),
                    "file_path": file_path,
                    "remediation": (
                        "Set cleartextTrafficPermitted=\"false\" on <base-config> and ensure all application endpoints "
                        "communicate over secure TLS/HTTPS channels."
                    )
                })

        # 2. Domain Config checks
        for domain_config in root.findall("domain-config"):
            cleartext_attr = domain_config.attrib.get("cleartextTrafficPermitted", "").lower()
            if cleartext_attr == "true":
                domains = [d.text.strip() for d in domain_config.findall("domain") if d.text]
                domain_list_str = ", ".join(domains) if domains else "unspecified domains"
                
                findings.append({
                    "issue_id": "NSC-DOMAIN-CLEARTEXT-ALLOWED",
                    "cwe": "CWE-319",
                    "severity": "Medium",
                    "title": f"Cleartext Traffic Permitted for Domains: {domain_list_str}",
                    "description": (
                        f"The <domain-config> block permits unencrypted cleartext HTTP connections "
                        f"for the following target domain(s): {domain_list_str}."
                    ),
                    "file_path": file_path,
                    "remediation": (
                        f"Enforce HTTPS across all domain endpoints ({domain_list_str}) and remove "
                        "cleartextTrafficPermitted=\"true\" from domain-config."
                    )
                })

        return findings

    def _check_pinning_expiration(self, root: ET.Element, file_path: str) -> list[dict[str, Any]]:
        """Audit certificate pinning expiration dates."""
        findings: list[dict[str, Any]] = []
        now = datetime.now(timezone.utc)

        for pin_set in root.iter("pin-set"):
            exp_str = pin_set.attrib.get("expiration", "").strip()
            if not exp_str:
                continue

            try:
                # Format: YYYY-MM-DD
                exp_date = datetime.strptime(exp_str, "%Y-%m-%d").replace(tzinfo=timezone.utc)
                if exp_date < now:
                    findings.append({
                        "issue_id": "NSC-PINNING-EXPIRED",
                        "cwe": "CWE-295",
                        "severity": "Medium",
                        "title": "Certificate Pinning Set Expired",
                        "description": (
                            f"Certificate pinning definition in <pin-set> expired on {exp_str}. "
                            "On Android 7.0 (API 24)+, once a pin-set expires, certificate pinning is completely "
                            "disabled and certificate chains fall back to standard system trust anchors."
                        ),
                        "file_path": file_path,
                        "remediation": "Update the expiration attribute with a valid future date and update the public key pins."
                    })
                else:
                    days_remaining = (exp_date - now).days
                    if days_remaining <= 30:
                        findings.append({
                            "issue_id": "NSC-PINNING-EXPIRING-SOON",
                            "cwe": "CWE-295",
                            "severity": "Low",
                            "title": f"Certificate Pinning Set Expiring Soon ({days_remaining} days left)",
                            "description": (
                                f"The <pin-set> expiration date is {exp_str}, leaving only {days_remaining} days before "
                                "certificate pinning verification is automatically deactivated."
                            ),
                            "file_path": file_path,
                            "remediation": "Schedule certificate key rotation and extend the pin-set expiration date."
                        })
            except ValueError:
                findings.append({
                    "issue_id": "NSC-INVALID-PINNING-DATE-FORMAT",
                    "cwe": "CWE-295",
                    "severity": "Low",
                    "title": "Malformed Pinning Expiration Date Format",
                    "description": f"Expiration date value '{exp_str}' does not conform to the expected 'yyyy-MM-dd' format.",
                    "file_path": file_path,
                    "remediation": "Specify the expiration attribute in 'yyyy-MM-dd' format (e.g., '2027-01-01')."
                })

        return findings

    async def audit_directory_async(
        self,
        decompiled_dir: str | Path,
        manifest_path: Optional[str] = None
    ) -> list[Finding]:
        """Locate network_security_config.xml and return standard Finding objects."""
        config_path = self.locate_config_path(str(decompiled_dir), manifest_path)
        if not config_path:
            return []

        raw_findings = await asyncio.to_thread(self.audit_file, config_path)
        findings: list[Finding] = []

        sev_map = {
            "Critical": Severity.CRITICAL,
            "High": Severity.HIGH,
            "Medium": Severity.MEDIUM,
            "Low": Severity.LOW,
        }

        for item in raw_findings:
            cwe = item["cwe"]
            score, vector = get_default_cvss_for_cwe(cwe)
            severity = sev_map.get(item["severity"], Severity.MEDIUM)

            findings.append(Finding(
                title=item["title"],
                description=item["description"],
                severity=severity,
                cwe_id=cwe,
                cvss_score=score,
                cvss_vector=vector,
                affected_component=Path(item["file_path"]).name,
                detection_method="NetworkSecurityConfigAuditor",
                status=FindingStatus.CONFIRMED,
                remediation=item["remediation"],
                file_path=item["file_path"],
                code_snippet=item.get("code_snippet", "")
            ))

        return findings

