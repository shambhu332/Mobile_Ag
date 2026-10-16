"""FileProvider XML configuration auditor.

Audits res/xml FileProvider definitions to identify overly permissive root-path,
external-path mappings, and unsafe grantUriPermissions configurations (CWE-22, CWE-732).
"""
from __future__ import annotations

import hashlib
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from mobileag.analysis.bounded_sources import SourceInventory, explicit_scan_root
from mobileag.reporting.finding import Finding


class _UnexpectedRootElement(Exception):
    """Internal signal used to distinguish a wrong root from malformed XML."""


class _XMLNestingLimit(Exception):
    """Internal signal for bounded parser depth exhaustion."""


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
    parse_status: str = "parsed"
    error_code: Optional[str] = None


class FileProviderAuditor:
    """Audits FileProvider path configuration XML files for dangerous storage exposure."""

    MAX_XML_CHARS = 1024 * 1024
    MAX_XML_DEPTH = 64
    MAX_PATH_ENTRIES = 5000
    MAX_ATTRIBUTE_CHARS = 256

    def __init__(self) -> None:
        self.coverage: Dict[str, Any] = {
            "static_status": "not_analyzed", "runtime_status": "not_tested",
            "proof_status": "not_proven", "exhaustive": False,
            "fileprovider_xml_candidates": 0, "fileprovider_xml_parse_errors": 0,
            "fileprovider_xml_error_codes": {},
        }

    # Tags considered high risk if mapped to root or broad paths
    DANGEROUS_TAGS = {
        "root-path": "Exposes root filesystem (/); high risk of arbitrary file access across private app sandbox.",
        "files-path": "Maps the app's internal files directory; review whether the full private files area should be shareable.",
        "cache-path": "Maps the app's internal cache directory; review whether the full cache area should be shareable.",
        "external-path": "Exposes device external storage (/sdcard); permits shared storage traversal.",
        "external-files-path": "Exposes application-specific external files directory.",
        "external-cache-path": "Exposes application external cache directory.",
        "external-media-path": "Exposes application external media directories.",
    }

    @staticmethod
    def _iter_path_children(xml_content: str):
        """Yield direct children using a pull parser and discard completed subtrees."""
        parser = ET.XMLPullParser(events=("start", "end"))
        root = None
        depth = 0

        def completed(events):
            nonlocal root, depth
            for event, element in events:
                if event == "start":
                    if depth == 0:
                        root = element
                        if root.tag.rsplit("}", 1)[-1] != "paths":
                            raise _UnexpectedRootElement
                    if depth >= FileProviderAuditor.MAX_XML_DEPTH:
                        raise _XMLNestingLimit
                    depth += 1
                else:
                    if depth == 2:
                        yield element
                        element.clear()
                        if root is not None:
                            root.clear()
                    depth -= 1

        for offset in range(0, len(xml_content), 4096):
            parser.feed(xml_content[offset:offset + 4096])
            yield from completed(parser.read_events())
        parser.close()
        yield from completed(parser.read_events())
        if root is None:
            raise ET.ParseError("no XML root element")

    def audit_xml_content(self, xml_content: str, source_path: str = "res/xml/file_paths.xml") -> FileProviderAuditResult:
        """Parse FileProvider XML content and audit configured path mappings."""
        result = FileProviderAuditResult(xml_path=source_path)

        if not isinstance(xml_content, str):
            result.parse_status = "invalid"
            result.error_code = "xml_input_type"
            return result
        if len(xml_content) > self.MAX_XML_CHARS:
            result.parse_status = "invalid"
            result.error_code = "xml_size_limit"
            return result

        # APK resources are untrusted input. ElementTree does not resolve
        # external entities by default, but accepting DTDs can still enable
        # internal-entity expansion and needlessly enlarges the parser surface.
        if "<!doctype" in xml_content.lower() or "<!entity" in xml_content.lower():
            result.parse_status = "invalid"
            result.error_code = "xml_dtd_entity_rejected"
            return result

        # Cap both result amplification and attacker-controlled strings copied
        # into findings. These limits are coverage boundaries, not evidence
        # that omitted entries are safe.
        try:
            for entry_index, child in enumerate(self._iter_path_children(xml_content)):
                if entry_index >= self.MAX_PATH_ENTRIES:
                    result.parse_status = "partial"
                    result.error_code = "xml_path_entry_limit"
                    break
                tag = child.tag.lower()
                name = child.attrib.get("name", "")
                path_val = child.attrib.get("path", "")
                if (len(name) > self.MAX_ATTRIBUTE_CHARS
                        or len(path_val) > self.MAX_ATTRIBUTE_CHARS):
                    result.parse_status = "partial"
                    result.error_code = "xml_path_attribute_limit"
                    continue

                is_dangerous = False
                risk_reason = ""
                # A literal parent segment may broaden the configured directory
                # after filesystem normalization. This remains a review candidate:
                # this parser cannot establish canonicalization, URI grants, or
                # caller reachability.
                has_parent_segment = ".." in path_val.split("/")
                path_is_root = all(part in {"", "."} for part in path_val.split("/"))

                if has_parent_segment:
                    is_dangerous = True
                    risk_reason = "path contains a '..' segment; review the normalized configured root and provider canonicalization"
                elif tag == "root-path" and path_is_root:
                    is_dangerous = True
                    risk_reason = "root-path exposes root filesystem (/)"
                elif tag == "root-path":
                    # A narrower root-relative mapping is not equivalent to the
                    # entire filesystem. Record it for review without claiming
                    # broad exposure solely from the tag name.
                    risk_reason = "root-path maps a restricted root-relative subdirectory; review grants and resolved files"
                elif tag == "external-path" and path_is_root:
                    is_dangerous = True
                    risk_reason = "external-path configured with root or current directory (.) exposing all external storage"
                elif path_is_root:
                    if tag in self.DANGEROUS_TAGS:
                        is_dangerous = True
                        risk_reason = (self.DANGEROUS_TAGS[tag] if tag in {"files-path", "cache-path"}
                                       else f"{tag} maps to entire parent directory root with empty or '.' path")

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
                        title=(f"Review FileProvider Parent-Path Segment ({tag})" if has_parent_segment
                               else f"Review Broad FileProvider Path Configuration ({tag})"
                               if tag in {"files-path", "cache-path"} and path_is_root
                               else f"Insecure FileProvider Path Configuration ({tag})"),
                        description=(
                            f"FileProvider configuration in '{source_path}' declares a '{tag}' mapping "
                            f"(name='{name}', path='{path_val}'). {entry.risk_reason}. "
                            "This XML candidate alone does not establish exposure. A recipient can access a file only if "
                            "the effective provider implementation can construct/serve its URI and the app issues an "
                            "applicable read or write URI grant (or exposes equivalent access); actual file scope and "
                            "caller reachability require separate review."
                        ),
                        severity=("INFO" if has_parent_segment or
                                  (tag in {"files-path", "cache-path"} and path_is_root)
                                  else "HIGH" if tag == "root-path" else "MEDIUM"),
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

        except _UnexpectedRootElement:
            result.parse_status = "invalid"
            result.error_code = "unexpected_root_element"
            result.entries.clear()
            result.findings.clear()
        except _XMLNestingLimit:
            result.parse_status = "partial"
            result.error_code = "xml_depth_limit"
        except ET.ParseError:
            result.parse_status = "invalid"
            result.error_code = "xml_parse_error"
            result.entries.clear()
            result.findings.clear()

        return result

    def audit_resource_directory(self, resource_dir: str) -> List[FileProviderAuditResult]:
        """Scan res/xml directories within extracted resources for FileProvider specifications."""
        results: List[FileProviderAuditResult] = []
        res_path = explicit_scan_root(resource_dir)
        inventory = SourceInventory(max_entries=5000, max_file_bytes=2 * 1024 * 1024,
                                    max_total_bytes=32 * 1024 * 1024)
        if res_path is None or not res_path.exists() or res_path.is_symlink():
            self.coverage = dict(inventory.coverage)
            self.coverage.update(fileprovider_xml_candidates=0, fileprovider_xml_parse_errors=0,
                                 fileprovider_xml_error_codes={})
            return results

        def is_fileprovider_xml(candidate: Path) -> bool:
            parent = candidate.parent
            return parent.name.lower().startswith("xml") and parent.parent.name.lower() == "res"

        candidate_count = 0
        error_codes: Dict[str, int] = {}
        for candidate, data in inventory.read(
                res_path, {".xml"}, path_filter=is_fileprovider_xml):
            content = data.decode("utf-8", errors="replace")
            if "<paths" not in content and "root-path" not in content and "external-path" not in content:
                continue
            candidate_count += 1
            audit_res = self.audit_xml_content(content, source_path=str(candidate))
            if audit_res.error_code:
                error_codes[audit_res.error_code] = error_codes.get(audit_res.error_code, 0) + 1
            if audit_res.entries or audit_res.parse_status != "parsed":
                results.append(audit_res)

        self.coverage = dict(inventory.coverage)
        self.coverage.update(
            fileprovider_xml_candidates=candidate_count,
            fileprovider_xml_parse_errors=sum(error_codes.values()),
            fileprovider_xml_error_codes=error_codes,
        )

        return results
