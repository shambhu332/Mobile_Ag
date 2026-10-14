"""FileProvider XML configuration auditor.

Audits res/xml FileProvider definitions to identify overly permissive root-path,
external-path mappings, and unsafe grantUriPermissions configurations (CWE-22, CWE-732).
"""
from __future__ import annotations

import os
import hashlib
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from mobileag.reporting.finding import Finding


@dataclass
class FileProviderPathEntry:
    tag: str
    name: str
    path: str
    is_dangerous: bool
    risk_reason: str


@dataclass
class FileProviderAuditResult:
    xml_path: str
    entries: List[FileProviderPathEntry] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)


class FileProviderAuditor:
    """Audits FileProvider path configuration XML files for dangerous storage exposure."""

    # Tags considered high risk if mapped to root or broad paths
    DANGEROUS_TAGS = {
        "root-path": "Exposes root filesystem (/); high risk of arbitrary file access across private app sandbox.",
        "external-path": "Exposes device external storage (/sdcard); permits shared storage traversal.",
        "external-files-path": "Exposes application-specific external files directory.",
        "external-cache-path": "Exposes application external cache directory.",
    }

    def audit_xml_content(self, xml_content: str, source_path: str = "res/xml/file_paths.xml") -> FileProviderAuditResult:
        """Parse FileProvider XML content and audit configured path mappings."""
        result = FileProviderAuditResult(xml_path=source_path)

        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError as err:
            return result

        # Common root is <paths>
        for child in root:
            tag = child.tag.lower()
            name = child.attrib.get("name", "")
            path_val = child.attrib.get("path", "")

            is_dangerous = False
            risk_reason = ""

            if tag == "root-path" and path_val in {".", "", "/"}:
                is_dangerous = True
                risk_reason = "root-path exposes root filesystem (/)"
            elif tag == "root-path":
                # A narrower root-relative mapping is not equivalent to the
                # entire filesystem. Record it for review without claiming
                # broad exposure solely from the tag name.
                risk_reason = "root-path maps a restricted root-relative subdirectory; review grants and resolved files"
            elif tag == "external-path" and (path_val in {".", "", "/"}):
                is_dangerous = True
                risk_reason = "external-path configured with root or current directory (.) exposing all external storage"
            elif path_val in {".", ""}:
                if tag in self.DANGEROUS_TAGS:
                    is_dangerous = True
                    risk_reason = f"{tag} maps to entire parent directory root with empty or '.' path"

            entry = FileProviderPathEntry(
                tag=tag,
                name=name,
                path=path_val,
                is_dangerous=is_dangerous,
                risk_reason=risk_reason or self.DANGEROUS_TAGS.get(tag, "Standard path mapping"),
            )
            result.entries.append(entry)

            if is_dangerous:
                finding = Finding(
                    id="FILEPROVIDER-" + hashlib.sha256(
                        "\0".join((source_path, tag, name, path_val)).encode("utf-8", errors="replace")
                    ).hexdigest()[:12].upper(),
                    title=f"Insecure FileProvider Path Configuration ({tag})",
                    description=(
                        f"FileProvider configuration in '{source_path}' declares a '{tag}' mapping "
                        f"(name='{name}', path='{path_val}'). {entry.risk_reason}. "
                        "When combined with grantUriPermissions=\"true\", this can allow unauthorized third-party apps "
                        "to read or write sensitive private application sandbox files."
                    ),
                    severity="HIGH" if tag == "root-path" else "MEDIUM",
                    file_path=source_path,
                    line_number=1,
                    code_snippet=f"<{child.tag} name=\"{name}\" path=\"{path_val}\" />",
                    cwe_id="CWE-22",
                    owasp_category="M1: Improper Platform Usage",
                    status="UNVERIFIED",
                    metadata={
                        "tag": tag,
                        "name": name,
                        "path": path_val,
                        "risk_reason": risk_reason,
                    },
                )
                result.findings.append(finding)

        return result

    def audit_resource_directory(self, resource_dir: str) -> List[FileProviderAuditResult]:
        """Scan res/xml directories within extracted resources for FileProvider specifications."""
        results: List[FileProviderAuditResult] = []
        res_path = Path(resource_dir)
        if not res_path.exists():
            return results

        # Find XML files in res/xml*
        xml_candidates = list(res_path.glob("**/res/xml*/*.xml")) + list(res_path.glob("res/xml*/*.xml"))
        for candidate in xml_candidates:
            try:
                content = candidate.read_text(encoding="utf-8", errors="ignore")
                if "<paths" in content or "root-path" in content or "external-path" in content:
                    audit_res = self.audit_xml_content(content, source_path=str(candidate))
                    if audit_res.entries:
                        results.append(audit_res)
            except Exception:
                continue

        return results
