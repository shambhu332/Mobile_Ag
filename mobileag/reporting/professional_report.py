"""Professional Penetration Test Report Generator.

Produces a complete, professional-grade security assessment report in
Markdown format suitable for conversion to PDF (via pandoc or similar).

Report sections:
1. Executive Summary — high-level risk overview for non-technical stakeholders
2. Scope & Methodology — what was tested, how, and tool inventory
3. Risk Summary Dashboard — severity distribution, CVSS stats, top CWEs
4. Detailed Findings — per-finding: title, severity, CVSS, CWE, description,
   evidence, reproduction steps, remediation, references
5. Attack Surface Overview — components, deep links, API endpoints, services
6. Compliance Mapping — OWASP MASVS / MSTG alignment
7. Recommendations — prioritised remediation roadmap
8. Appendices — tool versions, scan metadata, methodology notes
"""

from __future__ import annotations

import json
import logging
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Sequence

from mobileag.reporting.finding import Finding, FindingStatus, Severity
from mobileag.security.privacy import redact

logger = logging.getLogger(__name__)


class ProfessionalReportExporter:
    """Generates a structured Markdown penetration test report."""

    SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    SEVERITY_EMOJI = {
        "CRITICAL": "🔴",
        "HIGH": "🟠",
        "MEDIUM": "🟡",
        "LOW": "🔵",
        "INFO": "⚪",
    }

    def __init__(
        self,
        app_name: str = "Target Application",
        package_name: str = "",
        version: str = "",
        tester_name: str = "MobileAg Security Platform",
        engagement_type: str = "Evidence-limited mobile security review",
    ) -> None:
        self.app_name = app_name
        self.package_name = package_name
        self.version = version
        self.tester_name = tester_name
        self.engagement_type = engagement_type

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate_report(
        self,
        findings: Sequence[Finding | dict[str, Any]],
        scan_metadata: dict[str, Any] | None = None,
        attack_surface: dict[str, Any] | None = None,
        output_path: str | Path | None = None,
    ) -> str:
        """Generate the full Markdown report and optionally write to file.

        Returns the Markdown text.
        """
        scan_metadata = redact(scan_metadata or {})
        attack_surface = redact(attack_surface or {})

        # Normalise findings to dicts
        normalised: list[dict[str, Any]] = []
        for f in findings:
            if isinstance(f, dict):
                normalised.append(redact(f))
            elif isinstance(f, Finding):
                normalised.append(redact(f.model_dump(mode="json")))
            elif hasattr(f, "to_dict"):
                normalised.append(f.to_dict())
            else:
                normalised.append({"title": str(f)})

        # Filter out false positives / duplicates
        active = [
            f for f in normalised
            if f.get("status", "UNVERIFIED") not in ("FALSE_POSITIVE", "DUPLICATE")
        ]

        sections = [
            self._title_page(scan_metadata),
            self._executive_summary(active, scan_metadata),
            self._scope_methodology(scan_metadata),
            self._risk_dashboard(active),
            self._detailed_findings(active),
            self._attack_surface_section(attack_surface),
            self._compliance_mapping(active),
            self._recommendations(active),
            self._appendices(scan_metadata),
        ]

        report = redact("\n\n---\n\n".join(sections))

        if output_path:
            p = Path(output_path)
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(report, encoding="utf-8")
            logger.info("Professional report written to %s", p)

        return report

    # ------------------------------------------------------------------
    # Section builders
    # ------------------------------------------------------------------

    def _title_page(self, meta: dict[str, Any]) -> str:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return (
            f"# Mobile Application Security Assessment Report\n\n"
            f"**Application:** {self.app_name}  \n"
            f"**Package:** `{self.package_name}`  \n"
            f"**Version:** {self.version}  \n"
            f"**Assessment Type:** {self.engagement_type}  \n"
            f"**Date:** {now}  \n"
            f"**Assessed by:** {self.tester_name}  \n"
            f"**Classification:** CONFIDENTIAL\n"
        )

    def _executive_summary(
        self, findings: list[dict], meta: dict[str, Any]
    ) -> str:
        attested = sum(
            f.get("status") == "CONFIRMED"
            and (f.get("validation_evidence") or {}).get("basis") == "analyst_attested"
            and (f.get("validation_evidence") or {}).get("active") is True
            for f in findings
        )
        return (
            "## 1. Executive Summary\n\n"
            f"Recorded review items: {len(findings)}. Active analyst attestations: {attested}.\n\n"
            "Overall risk: not automatically assessed. No findings does not establish security or complete coverage. "
            "Automated candidates, checklist completion and analyst assertions are not independent exploit proof. "
            "Runtime and manual testing must be supported by the supplied evidence."
        )

    def _scope_methodology(self, meta: dict[str, Any]) -> str:
        return (
            "## 2. Scope and Recorded Coverage\n\n"
            "Only explicitly supplied metadata is recorded below; missing stages remain not tested. "
            "No exhaustive, runtime, manual or compliance coverage is inferred.\n\n"
            + "```json\n" + json.dumps(redact(meta), indent=2, default=str) + "\n```"
        )

    def _risk_dashboard(self, findings: list[dict]) -> str:
        counts = Counter(
            str(f.get("severity", "MEDIUM")).upper() for f in findings
        )
        cwe_counts = Counter(
            str(f.get("cwe_id", "Unknown")) for f in findings
        )
        top_cwes = cwe_counts.most_common(10)

        cvss_scores = [
            float(f.get("cvss_score", 0.0)) for f in findings
            if f.get("cvss_score")
        ]
        avg_cvss = sum(cvss_scores) / len(cvss_scores) if cvss_scores else 0.0
        max_cvss = max(cvss_scores) if cvss_scores else 0.0

        lines = [
            "## 3. Risk Summary Dashboard\n",
            "### Severity Distribution\n",
            "| Severity | Count | Percentage |",
            "|----------|-------|------------|",
        ]
        total = len(findings) or 1
        for sev in self.SEVERITY_ORDER:
            c = counts.get(sev, 0)
            pct = (c / total) * 100
            lines.append(f"| {self.SEVERITY_EMOJI[sev]} {sev} | {c} | {pct:.1f}% |")

        lines.extend([
            "",
            "### CVSS Score Statistics\n",
            f"- **Maximum CVSS:** {max_cvss:.1f}",
            f"- **Average CVSS:** {avg_cvss:.1f}",
            f"- **Total Unique Findings:** {len(findings)}",
            "",
            "### Top CWE Categories\n",
            "| CWE ID | Count |",
            "|--------|-------|",
        ])
        for cwe, cnt in top_cwes:
            lines.append(f"| {cwe} | {cnt} |")

        return "\n".join(lines)

    def _detailed_findings(self, findings: list[dict]) -> str:
        lines = ["## 4. Detailed Findings\n"]

        # Sort by severity then CVSS
        severity_rank = {s: i for i, s in enumerate(self.SEVERITY_ORDER)}
        sorted_findings = sorted(
            findings,
            key=lambda f: (
                severity_rank.get(
                    str(f.get("severity", "MEDIUM")).upper(), 99
                ),
                -float(f.get("cvss_score", 0)),
            ),
        )

        for idx, f in enumerate(sorted_findings, 1):
            sev = str(f.get("severity", "MEDIUM")).upper()
            emoji = self.SEVERITY_EMOJI.get(sev, "⚪")
            title = f.get("title", "Untitled Finding")
            cwe = f.get("cwe_id", "N/A")
            cvss = f.get("cvss_score", "N/A")
            cvss_vec = f.get("cvss_vector", "")
            desc = f.get("description", "")
            component = f.get("affected_component", "")
            file_path = f.get("file_path", "")
            snippet = f.get("code_snippet", "")
            remediation = f.get("remediation", "")
            status = f.get("status", "UNVERIFIED")
            detection = f.get("detection_method", "")
            masvs = f.get("masvs_id", "")

            lines.extend([
                f"### {idx}. {emoji} {title}\n",
                "| Attribute | Value |",
                "|-----------|-------|",
                f"| **Severity** | {sev} |",
                f"| **CWE** | {cwe} |",
                f"| **CVSS Score** | {cvss} |",
                f"| **CVSS Vector** | `{cvss_vec}` |",
                f"| **Status** | {status} |",
                f"| **Detection** | {detection} |",
                f"| **Component** | `{component}` |",
            ])
            if masvs:
                lines.append(f"| **MASVS** | {masvs} |")
            lines.append("")

            if desc:
                lines.extend(["**Description:**\n", desc, ""])
            if file_path:
                lines.append(f"**Affected File:** `{file_path}`\n")
            if snippet:
                lines.extend([
                    "**Evidence:**\n",
                    "```",
                    snippet[:500],
                    "```",
                    "",
                ])
            if remediation:
                lines.extend(["**Remediation:**\n", f"> {remediation}", ""])

        return "\n".join(lines)

    def _attack_surface_section(self, surface: dict[str, Any]) -> str:
        lines = ["## 5. Attack Surface Overview\n"]

        components = surface.get("components", [])
        if components:
            lines.extend([
                "### Exported Components\n",
                "| Type | Name | Exported | Permission |",
                "|------|------|----------|------------|",
            ])
            for c in components[:50]:
                lines.append(
                    f"| {c.get('type', 'N/A')} | `{c.get('name', '')}` "
                    f"| {c.get('exported', 'N/A')} "
                    f"| {c.get('permission', 'none')} |"
                )
            lines.append("")

        deep_links = surface.get("deep_links", [])
        if deep_links:
            lines.extend(["### Deep Links\n"])
            for dl in deep_links[:30]:
                if isinstance(dl, dict):
                    lines.append(f"- `{dl.get('uri', dl)}`")
                else:
                    lines.append(f"- `{dl}`")
            lines.append("")

        apis = surface.get("api_endpoints", [])
        if apis:
            lines.extend([
                "### Discovered API Endpoints\n",
                "| Method | URL | Auth |",
                "|--------|-----|------|",
            ])
            for api in apis[:50]:
                if isinstance(api, dict):
                    lines.append(
                        f"| {api.get('method', 'GET')} "
                        f"| `{api.get('url', api.get('endpoint', ''))}` "
                        f"| {api.get('has_auth', 'Unknown')} |"
                    )
                else:
                    lines.append(f"| GET | `{api}` | Unknown |")
            lines.append("")

        return "\n".join(lines)

    def _compliance_mapping(self, findings: list[dict]) -> str:
        masvs_counts: Counter[str] = Counter()
        for f in findings:
            masvs = f.get("masvs_id", "")
            if masvs:
                cat = masvs.split("-")[0] + "-" + masvs.split("-")[1] if "-" in masvs else masvs
                masvs_counts[cat] += 1

        lines = [
            "## 6. OWASP MASVS Review Mapping (not a compliance verdict)\n",
            "| MASVS Category | Findings |",
            "|----------------|----------|",
        ]
        categories = [
            "MASVS-STORAGE", "MASVS-CRYPTO", "MASVS-AUTH",
            "MASVS-NETWORK", "MASVS-PLATFORM", "MASVS-CODE",
            "MASVS-RESILIENCE",
        ]
        for cat in categories:
            count = sum(v for k, v in masvs_counts.items() if cat in k)
            status = "Not assessed from finding counts" if count == 0 else f"{count} review item(s); validation required"
            lines.append(f"| {cat} | {status} |")

        return "\n".join(lines)

    def _recommendations(self, findings: list[dict]) -> str:
        lines = [
            "## 7. Prioritized Recommendations\n",
            "### Immediate (Critical/High)\n",
        ]
        crit_high = [
            f for f in findings
            if str(f.get("severity", "")).upper() in ("CRITICAL", "HIGH")
        ]
        for i, f in enumerate(crit_high[:10], 1):
            lines.append(
                f"{i}. **{f.get('title', 'N/A')}** — "
                f"{f.get('remediation', 'Review and remediate.')}"
            )

        lines.extend(["", "### Short-term (Medium)\n"])
        med = [
            f for f in findings
            if str(f.get("severity", "")).upper() == "MEDIUM"
        ]
        for i, f in enumerate(med[:10], 1):
            lines.append(
                f"{i}. **{f.get('title', 'N/A')}** — "
                f"{f.get('remediation', 'Review and remediate.')}"
            )

        lines.extend([
            "",
            "### Long-term (Low/Informational)\n",
            "- Review and address remaining low-severity and informational "
            "findings during regular development sprints.",
            "- Implement automated security scanning in CI/CD pipeline.",
            "- Schedule periodic penetration tests (quarterly recommended).",
        ])

        return "\n".join(lines)

    def _appendices(self, meta: dict[str, Any]) -> str:
        lines = [
            "## 8. Appendices\n",
            "### A. Scan Metadata\n",
        ]
        if meta:
            for k, v in meta.items():
                if isinstance(v, (dict, list)):
                    v = json.dumps(v, default=str)[:200]
                lines.append(f"- **{k}:** {v}")
        else:
            lines.append("- No additional metadata recorded.")

        lines.extend([
            "",
            "### B. Severity Definitions\n",
            "| Severity | CVSS Range | Description |",
            "|----------|-----------|-------------|",
            "| CRITICAL | 9.0-10.0 | Immediate exploitation risk; "
            "data breach or RCE likely |",
            "| HIGH | 7.0-8.9 | Significant security impact; "
            "sensitive data exposure |",
            "| MEDIUM | 4.0-6.9 | Moderate risk; requires specific "
            "conditions to exploit |",
            "| LOW | 0.1-3.9 | Minor security concern; "
            "limited impact |",
            "| INFO | 0.0 | Informational; best practice "
            "recommendation |",
            "",
            "### C. Disclaimer\n",
            "This assessment was conducted using the information and access "
            "provided at the time of testing. The findings represent the "
            "security posture observed during the assessment period. New "
            "vulnerabilities may be discovered after this assessment. "
            "This report is confidential and intended solely for the "
            "authorized recipient.",
        ])

        return "\n".join(lines)
