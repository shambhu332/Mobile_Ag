"""Apple Privacy Manifest & Google Play Data Safety Auditor.

Inspects iOS Privacy Manifests (PrivacyInfo.xcprivacy) for declared API types (UserDefaults,
SystemBootTime, FileTimestamp), and audits Android third-party SDK privacy compliance
against Google Play Data Safety requirements.
"""
from __future__ import annotations

import os
import plistlib
import re
import stat
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
    parse_status: str = "absent"
    manifest_count: int = 0
    manifest_paths: List[str] = field(default_factory=list)
    manifests: List[Dict[str, object]] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


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

    MAX_MANIFESTS = 128
    MAX_TREE_ENTRIES = 50_000
    MAX_MANIFEST_BYTES = 2 * 1024 * 1024

    def audit_ios_privacy_manifest(self, app_dir: str | Path) -> PrivacyManifestResult:
        """Inventory bounded PrivacyInfo.xcprivacy files without claiming compliance.

        Frameworks may carry their own manifests, so inspect the extracted app
        tree instead of silently selecting the first match. Parse/shape failures
        are represented in the result rather than turning into an empty pass.
        """
        base = Path(app_dir)
        result = PrivacyManifestResult()
        if base.is_symlink() or not base.is_dir():
            result.parse_status = "invalid"
            result.errors.append("invalid_scan_root")
            return result

        candidates: list[Path] = []
        tree_entries = 0
        tree_limited = False

        def record_walk_error(_error: OSError) -> None:
            result.errors.append("directory_scan_error")

        try:
            for root, dirs, files in os.walk(base, followlinks=False, onerror=record_walk_error):
                # Do not recurse through extracted symlink directories.
                dirs[:] = sorted(d for d in dirs if not (Path(root) / d).is_symlink())
                tree_entries += len(dirs) + len(files)
                if tree_entries > self.MAX_TREE_ENTRIES:
                    tree_limited = True
                    break
                if "PrivacyInfo.xcprivacy" in files:
                    candidate = Path(root) / "PrivacyInfo.xcprivacy"
                    if candidate.is_symlink():
                        result.errors.append("symlink_manifest_skipped")
                        continue
                    candidates.append(candidate)
                    if len(candidates) > self.MAX_MANIFESTS:
                        tree_limited = True
                        candidates.pop()
                        break
        except OSError:
            result.errors.append("directory_scan_error")

        candidates.sort(key=lambda path: path.relative_to(base).as_posix())
        result.manifest_count = len(candidates)
        result.has_privacy_manifest = bool(candidates)
        result.manifest_paths = [path.relative_to(base).as_posix() for path in candidates]
        if tree_limited:
            result.errors.append("scan_limit_reached")

        parsed_count = 0
        malformed_count = 0
        domains: set[str] = set()
        categories: set[str] = set()
        tracking_flags: list[bool] = []
        for manifest_file in candidates:
            try:
                fd = os.open(manifest_file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd, "rb") as stream:
                    details = os.fstat(stream.fileno())
                    if not stat.S_ISREG(details.st_mode):
                        raise ValueError("manifest_not_regular")
                    if details.st_size > self.MAX_MANIFEST_BYTES:
                        raise ValueError("manifest_too_large")
                    raw = stream.read(self.MAX_MANIFEST_BYTES + 1)
                if len(raw) > self.MAX_MANIFEST_BYTES:
                    raise ValueError("manifest_too_large")
                data = plistlib.loads(raw)
            except ValueError as exc:
                malformed_count += 1
                error_code = str(exc)
                result.errors.append(error_code if error_code in {"manifest_not_regular", "manifest_too_large"}
                                     else "manifest_parse_error")
                continue
            except Exception:
                malformed_count += 1
                result.errors.append("manifest_parse_error")
                continue

            if not isinstance(data, dict):
                malformed_count += 1
                result.errors.append("manifest_root_not_dictionary")
                continue
            parsed_count += 1

            tracking = data.get("NSPrivacyTracking", False)
            if isinstance(tracking, bool):
                tracking_flags.append(tracking)
            else:
                malformed_count += 1
                result.errors.append("invalid_tracking_value")

            manifest_domains = data.get("NSPrivacyTrackingDomains", [])
            if isinstance(manifest_domains, list) and all(isinstance(domain, str) for domain in manifest_domains):
                domains.update(manifest_domains)
            else:
                malformed_count += 1
                result.errors.append("invalid_tracking_domains")

            api_types = data.get("NSPrivacyAccessedAPITypes", [])
            local_categories: set[str] = set()
            if isinstance(api_types, list):
                for entry in api_types:
                    if not isinstance(entry, dict) or not isinstance(entry.get("NSPrivacyAccessedAPIType"), str):
                        malformed_count += 1
                        result.errors.append("invalid_api_type_entry")
                        continue
                    local_categories.add(entry["NSPrivacyAccessedAPIType"])
                    categories.add(entry["NSPrivacyAccessedAPIType"])
            else:
                malformed_count += 1
                result.errors.append("invalid_api_types")
            result.manifests.append({
                "path": manifest_file.relative_to(base).as_posix(),
                "tracking_enabled": tracking if isinstance(tracking, bool) else None,
                "tracking_domains": sorted(manifest_domains) if isinstance(manifest_domains, list)
                                    and all(isinstance(domain, str) for domain in manifest_domains) else [],
                "declared_api_categories": sorted(local_categories),
            })

        # True means at least one manifest declared tracking; it is not a
        # compliance judgment and avoids silently coercing malformed values.
        result.tracking_enabled = any(tracking_flags)
        result.tracking_domains = sorted(domains)
        result.declared_api_categories = sorted(categories)
        result.errors = sorted(set(result.errors))
        if not candidates:
            result.parse_status = "partial" if result.errors else "absent"
        elif parsed_count == 0:
            result.parse_status = "invalid"
        elif malformed_count or result.errors:
            result.parse_status = "partial"
        else:
            result.parse_status = "parsed"
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
