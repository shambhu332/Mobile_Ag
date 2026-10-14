"""Apple Privacy Manifest & Google Play Data Safety Auditor.

Inspects iOS Privacy Manifests (PrivacyInfo.xcprivacy) for declared API types (UserDefaults,
SystemBootTime, FileTimestamp), and audits Android third-party SDK privacy compliance
against Google Play Data Safety requirements.
"""
from __future__ import annotations

import os
import plistlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

from mobileag.reporting.finding import Finding, FindingStatus, Severity


@dataclass
class PrivacyManifestResult:
    has_privacy_manifest: bool = False
    tracking_enabled: bool = False
    tracking_domains: List[str] = field(default_factory=list)
    declared_api_categories: List[str] = field(default_factory=list)
    undeclared_api_findings: List[Finding] = field(default_factory=list)


class PrivacyManifestAuditor:
    """Audits PrivacyInfo.xcprivacy on iOS and Data Safety disclosures on Android."""

    # Apple Mandated Required Reason API categories
    REQUIRED_REASON_APIS = {
        "NSPrivacyAccessedAPITypeFileTimestamp": ["getattrlist", "stat", "fstat"],
        "NSPrivacyAccessedAPITypeSystemBootTime": ["systemUptime", "mach_absolute_time"],
        "NSPrivacyAccessedAPITypeDiskSpace": ["statfs", "volumeAvailableCapacityKey"],
        "NSPrivacyAccessedAPITypeActiveKeyboards": ["activeInputModes"],
        "NSPrivacyAccessedAPITypeUserDefaults": ["NSUserDefaults", "standardUserDefaults"],
    }

    THIRD_PARTY_TRACKING_SDKS = {
        "com.facebook.android": "Facebook Analytics / Graph SDK",
        "com.appsflyer": "AppsFlyer Attribution SDK",
        "io.branch.referral": "Branch Metrics SDK",
        "com.adjust.sdk": "Adjust Attribution SDK",
        "com.google.firebase.analytics": "Google Firebase Analytics",
    }

    def audit_ios_privacy_manifest(self, app_dir: str | Path) -> PrivacyManifestResult:
        """Parse PrivacyInfo.xcprivacy plist in iOS app."""
        base = Path(app_dir)
        result = PrivacyManifestResult()

        manifest_file = base / "PrivacyInfo.xcprivacy"
        if not manifest_file.is_file():
            # Check subdirectories
            candidates = list(base.glob("**/PrivacyInfo.xcprivacy"))
            if candidates:
                manifest_file = candidates[0]
            else:
                return result

        result.has_privacy_manifest = True

        try:
            with open(manifest_file, "rb") as f:
                data = plistlib.load(f)
        except Exception:
            return result

        if not isinstance(data, dict):
            return result

        result.tracking_enabled = bool(data.get("NSPrivacyTracking", False))
        result.tracking_domains = [str(d) for d in data.get("NSPrivacyTrackingDomains", [])]

        api_types = data.get("NSPrivacyAccessedAPITypes", [])
        if isinstance(api_types, list):
            for entry in api_types:
                if isinstance(entry, dict) and "NSPrivacyAccessedAPIType" in entry:
                    result.declared_api_categories.append(entry["NSPrivacyAccessedAPIType"])

        return result

    def audit_android_data_safety_discrepancies(self, manifest_content: str, source_tree_dir: str | Path) -> List[Finding]:
        """Emit a review lead for permissions and SDK fingerprints in Android sources.

        This is not a Google Play Data Safety compliance check: APK/source
        evidence cannot establish what the developer declared in Play Console,
        which SDK code executes, or whether data is transmitted/shared.
        """
        findings: List[Finding] = []
        path = Path(source_tree_dir)

        # Check declared sensitive permissions in AndroidManifest.xml
        has_location = "ACCESS_FINE_LOCATION" in manifest_content or "ACCESS_COARSE_LOCATION" in manifest_content
        has_contacts = "READ_CONTACTS" in manifest_content

        detected_trackers: Set[str] = set()

        if path.is_dir():
            for root, _, files in os.walk(path):
                for f in files:
                    if f.endswith((".java", ".kt", ".smali")):
                        try:
                            with open(os.path.join(root, f), "r", encoding="utf-8", errors="ignore") as src:
                                text = src.read()
                                for pkg, desc in self.THIRD_PARTY_TRACKING_SDKS.items():
                                    if pkg in text:
                                        detected_trackers.add(desc)
                        except OSError:
                            continue

        if (has_location or has_contacts) and detected_trackers:
            findings.append(
                Finding(
                    id="GOOGLE_PLAY_DATA_SAFETY_DISCREPANCY",
                    title="Review Data Safety disclosures for sensitive permissions and SDK fingerprints",
                    description=(
                        f"Static source/manifest indicators include sensitive permissions and SDK package "
                        f"fingerprints ({', '.join(sorted(detected_trackers))}). This does not establish that "
                        "the SDK executes, collects or shares data, nor what was declared in Play Console. "
                        "Compare the actual Play Console Data Safety declaration with the app's observed "
                        "data collection/sharing behavior before alleging a discrepancy."
                    ),
                    severity=Severity.INFO,
                    status=FindingStatus.UNVERIFIED,
                    cwe_id="CWE-Unknown",
                    file_path=str(path),
                    remediation="Manually review the publisher's current Data Safety declaration and validate SDK behavior using authorized, synthetic-data testing.",
                    metadata={
                        "trackers": sorted(detected_trackers),
                        "evidence_state": "static_candidate",
                        "compliance_verdict": "not_assessed",
                        "limitations": [
                            "Play Console declarations are not present in the APK/source tree",
                            "package-name matches do not prove SDK execution or data sharing",
                        ],
                    },
                )
            )

        return findings
