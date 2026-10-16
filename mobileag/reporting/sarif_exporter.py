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
from mobileag.reporting.coverage import review_surface_ledger
from mobileag import __version__
from mobileag.security.privacy import redact
from mobileag.reporting.sarif_importer import MAX_BYTES, MAX_RESULTS, MAX_RULES, SarifImportError, validate_sarif_document
from mobileag.reporting.artifact_writer import preflight_bounded_structure, write_private_artifact


class SARIFExporter:
    """Exports MobileAg findings into standard OASIS SARIF v2.1.0 JSON format."""

    SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
    TOOL_NAME = "MobileAg Enterprise AppSec Scanner"
    TOOL_VERSION = __version__
    MAX_INPUT_BYTES = MAX_BYTES * 2
    MAX_INPUT_NODES = 100_000
    MAX_INPUT_DEPTH = 64

    @classmethod
    def _preflight_input(cls, value: Any) -> None:
        """Bound caller-owned SARIF inputs before deep copies/redaction/schema work."""
        try:
            preflight_bounded_structure(
                value, max_bytes=cls.MAX_INPUT_BYTES,
                max_nodes=cls.MAX_INPUT_NODES, max_depth=cls.MAX_INPUT_DEPTH,
                label="SARIF input",
            )
        except ValueError as exc:
            raise SarifImportError(str(exc)) from None

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
        scan_id: str = "scan-001",
        artifact: dict[str, Any] | None = None,
        coverage: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Convert findings into a compliant SARIF v2.1.0 JSON report dictionary."""
        if len(findings) > MAX_RESULTS:
            raise SarifImportError("SARIF result inventory exceeds limits")
        cls._preflight_input((findings, target_name, scan_id, artifact, coverage))
        rules_map: dict[str, dict[str, Any]] = {}
        results: list[dict[str, Any]] = []

        for f in findings:
            data = f.model_dump(mode='json') if isinstance(f, Finding) else f
            from mobileag.reporting.evidence_contract import prepare_finding
            data = prepare_finding(data, artifact)
            status = data.get('status', 'UNVERIFIED')
            if status in {'FALSE_POSITIVE', 'DUPLICATE'}:
                continue
            proof_basis = data['evidence_assessment']['basis']
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
                f_cvss = f.get("cvss_score", 0.0)
                f_masvs = f.get("owasp_masvs", "MASVS")
                f_file = f.get("file_path", "AndroidManifest.xml")
                f_line = f.get("line_number") or 1
                f_snippet = f.get("code_snippet") or ""
                f_remediation = f.get("remediation") or ""

            sarif_level = cls.severity_to_sarif_level(f_sev)

            # Register rule if not already present
            if f_id not in rules_map:
                if len(rules_map) >= MAX_RULES:
                    raise SarifImportError("SARIF rule inventory exceeds limits")
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
            line_val = 1
            try:
                line_val = max(1, int(f_line)) if f_line is not None else 1
            except (ValueError, TypeError):
                line_val = 1

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
                                "startLine": line_val,
                                "snippet": {"text": f_snippet},
                            },
                        }
                    }
                ],
                "properties": {
                    "cwe": f_cwe,
                    "cvss": f_cvss,
                    "masvs": f_masvs,
                    "status": status,
                    "proof_basis": proof_basis,
                    "evidence_assessment": data["evidence_assessment"],
                    "investigation_plan": data["investigation_plan"],
                    **({"source_sink_trace": data.get("metadata", {}).get("source_sink_trace")}
                       if isinstance(data.get("metadata"), dict) and data["metadata"].get("source_sink_trace") else {}),
                    **({"validation_evidence": data.get("validation_evidence")}
                       if proof_basis == "analyst_attested" else {}),
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
                        **({"artifact": {key: artifact[key] for key in
                            ("artifact_sha256", "package_name", "app_version") if artifact.get(key)} }
                           if artifact else {}),
                        **({"review_surface_ledger": review_surface_ledger(coverage)}
                           if coverage is not None else {}),
                    },
                }
            ],
        }
        output = redact(sarif_doc)
        validate_sarif_document(output)
        return output

    @classmethod
    def export_to_file(
        cls,
        findings: Sequence[Finding | dict[str, Any]],
        output_path: str | Path,
        target_name: str = "mobile_target",
        scan_id: str = "scan-001",
        artifact: dict[str, Any] | None = None,
        coverage: dict[str, Any] | None = None,
    ) -> Path:
        """Generate and save SARIF JSON report to disk."""
        sarif_data = cls.generate_sarif(findings, target_name, scan_id, artifact, coverage)
        out_p = Path(output_path)
        payload = json.dumps(sarif_data, indent=2, ensure_ascii=True, allow_nan=False).encode("utf-8")
        if len(payload) > MAX_BYTES:
            raise SarifImportError("SARIF output exceeds the report size limit")
        return write_private_artifact(out_p, payload, MAX_BYTES)
