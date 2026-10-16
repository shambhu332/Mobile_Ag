"""Apple Privacy Manifest & Google Play Data Safety Auditor.

Inspects iOS Privacy Manifests (PrivacyInfo.xcprivacy) for declared API types (UserDefaults,
SystemBootTime, FileTimestamp), and audits Android third-party SDK privacy compliance
against Google Play Data Safety requirements.
"""
from __future__ import annotations

import os
import hashlib
import plistlib
import re
import stat
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from mobileag.analysis.bounded_sources import SourceInventory, explicit_scan_root
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
    manifest_bytes_scanned: int = 0
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
    MAX_MANIFEST_TOTAL_BYTES = 16 * 1024 * 1024
    MAX_TRACKING_DOMAINS = 2_048
    MAX_TRACKING_DOMAIN_CHARS = 253
    MAX_API_CATEGORIES = 512
    MAX_API_CATEGORY_CHARS = 256
    MAX_ERROR_CODES = 64
    MAX_ANDROID_SOURCE_FILES = 5_000
    MAX_ANDROID_SOURCE_BYTES = 2 * 1024 * 1024
    MAX_ANDROID_TOTAL_SOURCE_BYTES = 32 * 1024 * 1024
    MAX_ANDROID_MANIFEST_CHARS = 2 * 1024 * 1024
    MAX_BINARY_SYMBOLS = 2_000
    MAX_BINARY_SYMBOL_CHARS = 512

    def audit_ios_privacy_manifest(self, app_dir: str | Path) -> PrivacyManifestResult:
        """Inventory bounded PrivacyInfo.xcprivacy files without claiming compliance.

        Frameworks may carry their own manifests, so inspect the extracted app
        tree instead of silently selecting the first match. Parse/shape failures
        are represented in the result rather than turning into an empty pass.
        """
        base = explicit_scan_root(app_dir)
        result = PrivacyManifestResult()
        error_codes: set[str] = set()

        def record_error(code: str) -> None:
            if code in error_codes:
                return
            if len(result.errors) >= self.MAX_ERROR_CODES - 1:
                code = "error_code_limit_reached"
                if code in error_codes:
                    return
            error_codes.add(code)
            result.errors.append(code)

        if base is None or base.is_symlink() or not base.is_dir():
            result.parse_status = "invalid"
            record_error("invalid_scan_root")
            return result

        candidates: list[Path] = []
        inventory = SourceInventory(max_entries=self.MAX_TREE_ENTRIES, max_file_bytes=1,
                                    max_total_bytes=1)
        tree_limited = False
        for candidate in inventory.paths(base):
            if candidate.name != "PrivacyInfo.xcprivacy":
                continue
            if len(candidates) >= self.MAX_MANIFESTS:
                tree_limited = True
                inventory.record_limit("manifest_count")
                break
            candidates.append(candidate)

        if inventory.coverage["limits_reached"]:
            tree_limited = True
        if inventory.coverage["source_file_skip_reasons"].get("symlink_entry"):
            record_error("symlink_entry_skipped")
        if inventory.coverage["source_file_skip_reasons"].get("directory_read_error"):
            record_error("directory_scan_error")

        candidates.sort(key=lambda path: path.relative_to(base).as_posix())
        result.manifest_count = len(candidates)
        result.has_privacy_manifest = bool(candidates)
        result.manifest_paths = [path.relative_to(base).as_posix() for path in candidates]
        if tree_limited:
            record_error("scan_limit_reached")

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
                    remaining = self.MAX_MANIFEST_TOTAL_BYTES - result.manifest_bytes_scanned
                    if details.st_size > remaining:
                        record_error("manifest_total_byte_limit")
                        tree_limited = True
                        break
                    read_limit = min(self.MAX_MANIFEST_BYTES, remaining)
                    raw = stream.read(read_limit + 1)
                    result.manifest_bytes_scanned += min(len(raw), read_limit)
                if len(raw) > read_limit:
                    raise ValueError("manifest_total_byte_limit" if read_limit < self.MAX_MANIFEST_BYTES
                                     else "manifest_too_large")
                data = plistlib.loads(raw)
            except ValueError as exc:
                malformed_count += 1
                error_code = str(exc)
                if error_code == "manifest_total_byte_limit":
                    tree_limited = True
                record_error(error_code if error_code in {"manifest_not_regular", "manifest_too_large"}
                             else error_code if error_code == "manifest_total_byte_limit"
                             else "manifest_parse_error")
                continue
            except Exception:
                malformed_count += 1
                record_error("manifest_parse_error")
                continue

            if not isinstance(data, dict):
                malformed_count += 1
                record_error("manifest_root_not_dictionary")
                continue
            parsed_count += 1

            tracking = data.get("NSPrivacyTracking", False)
            if isinstance(tracking, bool):
                tracking_flags.append(tracking)
            else:
                malformed_count += 1
                record_error("invalid_tracking_value")

            manifest_domains = data.get("NSPrivacyTrackingDomains", [])
            safe_domains: list[str] = []
            if isinstance(manifest_domains, list):
                for index, domain in enumerate(manifest_domains):
                    if index >= self.MAX_TRACKING_DOMAINS:
                        record_error("tracking_domain_limit_reached")
                        break
                    if (not isinstance(domain, str) or not domain
                            or len(domain) > self.MAX_TRACKING_DOMAIN_CHARS
                            or any(ord(char) < 0x20 or ord(char) == 0x7f for char in domain)):
                        malformed_count += 1
                        record_error("invalid_tracking_domains")
                        continue
                    if domain not in domains and len(domains) >= self.MAX_TRACKING_DOMAINS:
                        record_error("tracking_domain_limit_reached")
                        break
                    domains.add(domain)
                    if domain not in safe_domains:
                        safe_domains.append(domain)
            else:
                malformed_count += 1
                record_error("invalid_tracking_domains")

            api_types = data.get("NSPrivacyAccessedAPITypes", [])
            local_categories: set[str] = set()
            if isinstance(api_types, list):
                for index, entry in enumerate(api_types):
                    if index >= self.MAX_API_CATEGORIES:
                        record_error("api_category_limit_reached")
                        break
                    if not isinstance(entry, dict) or not isinstance(entry.get("NSPrivacyAccessedAPIType"), str):
                        malformed_count += 1
                        record_error("invalid_api_type_entry")
                        continue
                    category = entry["NSPrivacyAccessedAPIType"]
                    if (not category or len(category) > self.MAX_API_CATEGORY_CHARS
                            or any(ord(char) < 0x20 or ord(char) == 0x7f for char in category)):
                        malformed_count += 1
                        record_error("invalid_api_type_entry")
                        continue
                    if category not in categories and len(categories) >= self.MAX_API_CATEGORIES:
                        record_error("api_category_limit_reached")
                        break
                    local_categories.add(category)
                    categories.add(category)
            else:
                malformed_count += 1
                record_error("invalid_api_types")
            result.manifests.append({
                "path": manifest_file.relative_to(base).as_posix(),
                "tracking_enabled": tracking if isinstance(tracking, bool) else None,
                "tracking_domains": sorted(safe_domains),
                "declared_api_categories": sorted(local_categories),
            })

        # True means at least one manifest declared tracking; it is not a
        # compliance judgment and avoids silently coercing malformed values.
        result.tracking_enabled = any(tracking_flags)
        result.tracking_domains = sorted(domains)
        result.declared_api_categories = sorted(categories)
        result.errors = sorted(error_codes)
        if not candidates:
            result.parse_status = "partial" if result.errors else "absent"
        elif parsed_count == 0:
            result.parse_status = "invalid"
        elif malformed_count or result.errors:
            result.parse_status = "partial"
        else:
            result.parse_status = "parsed"
        return result

    def audit_ios_binary_api_symbols(
        self, symbol_names: object, declared_categories: Set[str] | List[str], *,
        app_manifest_state: str, binary_path: str | Path,
        binary_parse_status: str, component_name: str = "Main iOS executable",
        finding_id_scope: str | None = None,
    ) -> Dict[str, Any]:
        """Compare bounded executable symbol candidates to its bundle declarations.

        This is a review heuristic: symbol-table presence is not proof that an
        API is called, that it executes, or that Apple requires a reason for
        that use. Callers may supply app or framework bundle declarations;
        Objective-C message dispatch is not covered.
        """
        report: Dict[str, Any] = {
            "status": "not_analyzed", "symbol_count": 0,
            "manifest_state": app_manifest_state,
            "candidate_categories": [], "undeclared_review_candidates": [],
            "findings": [],
            "runtime_status": "not_tested", "proof_status": "not_proven",
            "exhaustive": False,
            "limitations": [
                "Mach-O symbol names are candidates, not proof of reachable API calls",
                "Objective-C message dispatch and binaries outside the analyzed executable are not covered",
                "No Apple compliance or runtime-use verdict is produced",
            ],
        }
        if app_manifest_state == "invalid":
            report["status"] = "not_analyzed_invalid_app_manifest"
            return report
        if not isinstance(symbol_names, list):
            report["status"] = "not_analyzed_symbols_unavailable"
            return report

        symbols = [value[:self.MAX_BINARY_SYMBOL_CHARS] for value in symbol_names[:self.MAX_BINARY_SYMBOLS]
                   if isinstance(value, str)]
        symbols = [value.lstrip("_") for value in symbols]
        truncated = (len(symbol_names) > self.MAX_BINARY_SYMBOLS
                     or any(len(value) > self.MAX_BINARY_SYMBOL_CHARS
                            for value in symbol_names[:self.MAX_BINARY_SYMBOLS]
                            if isinstance(value, str)))
        report["symbol_count"] = len(symbols)
        if not symbols:
            report["status"] = "not_analyzed_no_symbols"
            return report

        declared = ({value for value in declared_categories if isinstance(value, str)}
                    if isinstance(declared_categories, (set, list)) else set())
        manifest_label = ("app-root PrivacyInfo.xcprivacy" if component_name == "Main iOS executable"
                          else f"{component_name} PrivacyInfo.xcprivacy")
        missing = []
        for category, markers in self.REQUIRED_REASON_APIS.items():
            observed = sorted({marker for marker in markers if any(
                re.search(r"(?<![A-Za-z0-9_])" + re.escape(marker) + r"(?![A-Za-z0-9_])", symbol)
                for symbol in symbols
            )})
            if not observed:
                continue
            report["candidate_categories"].append({"category": category, "symbol_markers": observed})
            if category not in declared:
                missing.append({"category": category, "symbol_markers": observed})
                manifest_note = (f"No {manifest_label} declaration was parsed."
                                 if app_manifest_state == "absent" else
                                 f"The {manifest_label} did not declare this category.")
                report["findings"].append(Finding(
                    id=("IOS_PRIVACY_API_SYMBOL_REVIEW_" + category.rsplit("Type", 1)[-1]
                        + ("_" + hashlib.sha256(
                            finding_id_scope.encode("utf-8", errors="replace")
                        ).hexdigest()[:10] if finding_id_scope else "")),
                    title=f"Review {category} symbol candidates against the iOS Privacy Manifest",
                    description=(
                        f"The {component_name} symbol table contains candidate marker(s) "
                        f"{', '.join(observed)} associated with {category}, but {manifest_note} "
                        "Symbol-table presence does not prove a reachable API call or establish that "
                        "a required-reason declaration is legally/platform-required for this binary."
                    ),
                    severity=Severity.INFO,
                    status=FindingStatus.UNVERIFIED,
                    cwe_id="CWE-Unknown",
                    affected_component=component_name,
                    file_path=str(binary_path),
                    detection_method="PrivacyManifestAuditor (bounded Mach-O symbol candidate cross-check)",
                    remediation=(f"Verify the API use and applicable Apple requirements for {component_name}; "
                                 "if required, add an accurate approved reason in its PrivacyInfo.xcprivacy."),
                    metadata={
                        "evidence_state": "static_candidate",
                        "candidate_category": category,
                        "candidate_symbol_markers": observed,
                        "manifest_state": app_manifest_state,
                        "binary_parse_status": binary_parse_status,
                        "proof_status": "not_proven",
                        "compliance_verdict": "not_assessed",
                    },
                ))
        report["undeclared_review_candidates"] = missing
        report["status"] = ("partial" if truncated or binary_parse_status not in {"parsed", "complete"}
                            or app_manifest_state == "partial"
                            else "analyzed_heuristically")
        report["truncated"] = truncated
        report["declared_categories"] = sorted(declared)
        return report

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
        path = explicit_scan_root(source_tree_dir)
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
            inventory = SourceInventory(max_entries=self.MAX_TREE_ENTRIES,
                                        max_file_bytes=1, max_total_bytes=1)
            for candidate in inventory.paths(path, {".java", ".kt", ".smali"}):
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

            coverage["tree_entries_examined"] = inventory.coverage["entries_examined"]
            if inventory.coverage["limits_reached"]:
                coverage["limits_reached"].append("tree_entries")
                limited = True
            if inventory.coverage["source_file_skip_reasons"].get("symlink_entry"):
                coverage["errors"].append("source_symlink_skipped")
            if inventory.coverage["source_file_skip_reasons"].get("directory_read_error"):
                coverage["errors"].append("source_directory_read_error")
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
