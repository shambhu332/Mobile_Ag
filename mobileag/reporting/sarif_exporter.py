"""OASIS SARIF v2.1.0 (Static Analysis Results Interchange Format) Exporter.

Enables seamless enterprise CI/CD integration:
- GitHub Advanced Security / Pull Request Code Scanning annotations
- GitLab SAST Reports
- Azure DevOps Security Alerts
- SonarQube / DefectDojo ingestion
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Sequence

from mobileag.reporting.finding import Finding, Severity


class SARIFExporter:
    """Exports MobileAg findings into standard OASIS SARIF v2.1.0 JSON format."""

    SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    TOOL_NAME = "MobileAg Enterprise AppSec Scanner"
    TOOL_VERSION = "2.2.0"

    @classmethod
    def severity_to_sarif_level(cls, severity: Severity | str) -> str:
        """Map MobileAg severity to SARIF level (error, warning, note, none)."""
        sev_str = severity.value if isinstance(severity, Severity) else str(severity).upper()
        if sev_str in ("CRITICAL", "HIGH"):
            return "error"
        if sev_str == "MEDIUM":
            return "warning"
        return "note"

    @classmethod
    def generate_sarif(
        cls,
        findings: Sequence[Finding | dict[str, Any]],
        target_name: str = "mobile_target",
        scan_id: str = "scan-001"
    ) -> dict[str, Any]:
        """Convert findings into a compliant SARIF v2.1.0 JSON report dictionary."""
        rules_map: dict[str, dict[str, Any]] = {}
        results: list[dict[str, Any]] = []

        for f in findings:
            # Handle both Finding objects and raw dicts
            if isinstance(f, Finding):
                f_id = f.cwe_id or f.id
                f_title = f.title
                f_desc = f.description
                f_sev = f.severity
                f_cwe = f.cwe_id
                f_cvss = f.cvss_score
                f_masvs = f.owasp_masvs or "MASVS"
                f_file = f.file_path or "AndroidManifest.xml"
                f_line = f.line_number or 1
                f_snippet = f.code_snippet or ""
                f_remediation = f.remediation or ""
            else:
                f_id = f.get("cwe_id") or f.get("id", "CWE-Unknown")
                f_title = f.get("title", "Security Finding")
                f_desc = f.get("description", "")
                f_sev = f.get("severity", "MEDIUM")
                f_cwe = f.get("cwe_id", "CWE-000")
                f_cvss = f.get("cvss_score", 5.0)
                f_masvs = f.get("owasp_masvs", "MASVS")
                f_file = f.get("file_path", "AndroidManifest.xml")
                f_line = f.get("line_number", 1)
                f_snippet = f.get("code_snippet", "")
                f_remediation = f.get("remediation", "")

            sarif_level = cls.severity_to_sarif_level(f_sev)

            # Register rule if not already present
            if f_id not in rules_map:
                rules_map[f_id] = {
                    "id": f_id,
                    "name": f_title,
                    "shortDescription": {"text": f_title},
                    "fullDescription": {"text": f_desc or f_title},
                    "defaultConfiguration": {"level": sarif_level},
                    "help": {
                        "text": f"{f_desc}\n\nRemediation Guidance:\n{f_remediation}",
                        "markdown": f"### Vulnerability Description\n{f_desc}\n\n### Remediation\n{f_remediation}",
                    },
                    "properties": {
                        "tags": ["security", "mobile", f_cwe.lower(), f_masvs.lower()],
                        "security-severity": str(f_cvss),
                    },
                }

            # Build result
            result_item: dict[str, Any] = {
                "ruleId": f_id,
                "level": sarif_level,
                "message": {"text": f"{f_title}: {f_desc}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f_file.replace("\\", "/"),
                                "uriBaseId": "%SRCROOT%",
                            },
                            "region": {
                                "startLine": max(1, int(f_line)),
                                "snippet": {"text": f_snippet},
                            },
                        }
                    }
                ],
                "properties": {
                    "cwe": f_cwe,
                    "cvss": f_cvss,
                    "masvs": f_masvs,
                },
            }
            results.append(result_item)

        sarif_doc: dict[str, Any] = {
            "$schema": cls.SCHEMA_URI,
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": cls.TOOL_NAME,
                            "version": cls.TOOL_VERSION,
                            "informationUri": "https://github.com/shambhu332/Mobile_Ag",
                            "rules": list(rules_map.values()),
                        }
                    },
                    "results": results,
                    "properties": {
                        "scanId": scan_id,
                        "target": target_name,
                    },
                }
            ],
        }
        return sarif_doc

    @classmethod
    def export_to_file(
        cls,
        findings: Sequence[Finding | dict[str, Any]],
        output_path: str | Path,
        target_name: str = "mobile_target",
        scan_id: str = "scan-001"
    ) -> Path:
        """Generate and save SARIF JSON report to disk."""
        sarif_data = cls.generate_sarif(findings, target_name, scan_id)
        out_p = Path(output_path)
        out_p.parent.mkdir(parents=True, exist_ok=True)
        out_p.write_text(json.dumps(sarif_data, indent=2), encoding="utf-8")
        return out_p
