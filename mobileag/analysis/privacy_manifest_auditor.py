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
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Set

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
    MAX_ANDROID_SOURCE_FILES = 5_000
    MAX_ANDROID_SOURCE_BYTES = 2 * 1024 * 1024
    MAX_ANDROID_TOTAL_SOURCE_BYTES = 32 * 1024 * 1024
    MAX_ANDROID_MANIFEST_CHARS = 2 * 1024 * 1024

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

    def audit_android_data_safety_package(self, manifest_path: str | Path,
                                          source_tree_dir: str | Path) -> Dict[str, Any]:
        """Run bounded Data Safety indicators from an extracted APK directory.

        The manifest is opened without following symlinks and is size-checked
        before decoding. Coverage is returned even when no candidate finding is
        produced, so callers do not mistake an empty list for a complete review.
        """
        content: str | None = None
        read_error: str | None = None
        path = Path(manifest_path) if manifest_path else None
        if path is None:
            read_error = "manifest_path_missing"
        else:
            try:
                fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd, "rb") as stream:
                    info = os.fstat(stream.fileno())
                    if not stat.S_ISREG(info.st_mode):
                        read_error = "manifest_not_regular"
                    elif info.st_size > self.MAX_ANDROID_MANIFEST_CHARS:
                        read_error = "manifest_too_large"
                    else:
                        raw = stream.read(self.MAX_ANDROID_MANIFEST_CHARS + 1)
                        if len(raw) > self.MAX_ANDROID_MANIFEST_CHARS:
                            read_error = "manifest_too_large"
                        else:
                            content = raw.decode("utf-8", errors="replace")
            except OSError:
                read_error = "manifest_read_error"

        coverage: Dict[str, Any] = {}
        findings = self.audit_android_data_safety_discrepancies(
            content, source_tree_dir, _coverage_out=coverage,
        )
        if read_error:
            coverage["manifest_parse"] = "invalid"
            coverage["manifest_truncated"] = read_error == "manifest_too_large"
            errors = set(coverage.get("errors", []))
            errors.discard("manifest_missing_or_too_large")
            errors.add(read_error)
            coverage["errors"] = sorted(errors)
        return {"findings": findings, "coverage": coverage}

    def audit_android_data_safety_discrepancies(
        self, manifest_content: str | None, source_tree_dir: str | Path,
        *, _coverage_out: Dict[str, Any] | None = None,
    ) -> List[Finding]:
        """Emit a review lead for permissions and SDK fingerprints in Android sources.

        This is not a Google Play Data Safety compliance check: APK/source
        evidence cannot establish what the developer declared in Play Console,
        which SDK code executes, or whether data is transmitted/shared.
        """
        findings: List[Finding] = []
        path = Path(source_tree_dir) if str(source_tree_dir).strip() else None
        coverage = {
            "manifest_parse": "not_attempted", "manifest_truncated": False,
            "source_tree": "invalid", "files_read": 0, "bytes_read": 0,
            "limits_reached": [], "errors": [],
        }

        # Parse actual permission elements; substring scans also matched comments,
        # examples and unrelated permission names. APK/source evidence remains a lead.
        permissions: Set[str] = set()
        if not isinstance(manifest_content, str) or len(manifest_content) > self.MAX_ANDROID_MANIFEST_CHARS:
            coverage["manifest_parse"] = "invalid"
            coverage["manifest_truncated"] = isinstance(manifest_content, str)
            coverage["errors"].append("manifest_missing_or_too_large")
        elif re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", manifest_content, re.IGNORECASE):
            # Android manifests do not require DTD entities. Reject them before
            # parsing so attacker-supplied XML cannot alter parser behavior.
            coverage["manifest_parse"] = "invalid"
            coverage["errors"].append("manifest_entity_declaration_unsupported")
        else:
            try:
                root = ET.fromstring(manifest_content)
                for element in root.iter():
                    tag_name = element.tag.rsplit("}", 1)[-1]
                    if tag_name not in {"uses-permission", "uses-permission-sdk-23"}:
                        continue
                    name = next((value for key, value in element.attrib.items()
                                 if key.rsplit("}", 1)[-1] == "name"), None)
                    if isinstance(name, str):
                        permissions.add(name)
                coverage["manifest_parse"] = "parsed"
            except ET.ParseError:
                coverage["manifest_parse"] = "invalid"
                coverage["errors"].append("manifest_parse_error")
        has_location = bool(permissions & {
            "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_COARSE_LOCATION",
        })
        has_contacts = "android.permission.READ_CONTACTS" in permissions

        detected_trackers: Set[str] = set()
        if path is not None and path.is_dir() and not path.is_symlink():
            coverage["source_tree"] = "complete"
            entries = 0
            total_bytes = 0
            limited = False
            def record_walk_error(_error: OSError) -> None:
                coverage["errors"].append("source_directory_read_error")

            for root_dir, dirs, files in os.walk(path, followlinks=False, onerror=record_walk_error):
                dirs[:] = sorted(name for name in dirs if not (Path(root_dir) / name).is_symlink())
                files.sort()
                entries += len(dirs) + len(files)
                if entries > self.MAX_TREE_ENTRIES:
                    coverage["limits_reached"].append("tree_entries")
                    limited = True
                    break
                for filename in files:
                    candidate = Path(root_dir) / filename
                    if candidate.suffix.lower() not in {".java", ".kt", ".smali"}:
                        continue
                    if coverage["files_read"] >= self.MAX_ANDROID_SOURCE_FILES:
                        coverage["limits_reached"].append("source_files")
                        limited = True
                        break
                    try:
                        fd = os.open(candidate, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                        with os.fdopen(fd, "rb") as stream:
                            info = os.fstat(stream.fileno())
                            if not stat.S_ISREG(info.st_mode):
                                coverage["errors"].append("non_regular_source_skipped")
                                continue
                            remaining = self.MAX_ANDROID_TOTAL_SOURCE_BYTES - total_bytes
                            read_limit = min(self.MAX_ANDROID_SOURCE_BYTES, remaining)
                            if read_limit <= 0:
                                coverage["limits_reached"].append("total_source_bytes")
                                limited = True
                                break
                            raw = stream.read(read_limit + 1)
                        if len(raw) > read_limit:
                            coverage["errors"].append("source_file_truncated")
                            raw = raw[:read_limit]
                        total_bytes += len(raw)
                        coverage["bytes_read"] = total_bytes
                        coverage["files_read"] += 1
                        text = raw.decode("utf-8", errors="ignore")
                        for package, description in self.THIRD_PARTY_TRACKING_SDKS.items():
                            if package in text:
                                detected_trackers.add(description)
                    except OSError:
                        coverage["errors"].append("source_read_error")
                if limited:
                    break
            if limited or coverage["errors"]:
                coverage["source_tree"] = "partial"

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
                        "coverage": coverage,
                        "limitations": [
                            "Play Console declarations are not present in the APK/source tree",
                            "package-name matches do not prove SDK execution or data sharing",
                        ],
                    },
                )
            )

        if _coverage_out is not None:
            _coverage_out.update(coverage)
        return findings
