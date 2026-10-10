"""Report generation engine — outputs findings in Markdown, JSON, and PDF formats."""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader, TemplateNotFound

from mobileag.core.state import ScanState
from mobileag.reporting.finding import Severity, FindingStatus

logger = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).parent / "templates"


class ReportEngine:
    """Generates vulnerability reports from scan state."""

    def __init__(self):
        self._env: Optional[Environment] = None
        self._init_templates()

    def _init_templates(self) -> None:
        if _TEMPLATES_DIR.exists():
            self._env = Environment(
                loader=FileSystemLoader(str(_TEMPLATES_DIR)),
                autoescape=False,
            )
        else:
            logger.warning("Report templates directory not found: %s", _TEMPLATES_DIR)

    async def generate_reports(self, state: ScanState) -> None:
        """Generate all report formats and save them to the output directory."""
        output_dir = Path(state["output_dir"])
        output_dir.mkdir(parents=True, exist_ok=True)
        scan_id = state["scan_id"]
        
        # Prepare data for templates
        report_data = self._prepare_data(state)
        state["assessment_coverage"] = report_data["assessment_coverage"]
        state["coverage_gaps"] = report_data["coverage_gaps"]
        
        # Save JSON
        json_path = output_dir / f"report_{scan_id}.json"
        with json_path.open("w") as f:
            json.dump(report_data, f, indent=2)
        logger.info("Saved JSON report to %s", json_path)
        
        # Save Markdown
        md_path = output_dir / f"report_{scan_id}.md"
        md_content = self._generate_markdown(report_data)
        md_path.write_text(md_content)
        logger.info("Saved Markdown report to %s", md_path)
        
        state["report_path"] = str(md_path)
        state["json_report_path"] = str(json_path)

    def _prepare_data(self, state: ScanState) -> dict:
        """Extract and format data for reporting."""
        findings = [
            f for f in state.get("filtered_findings", [])
            if f.get("status") not in {FindingStatus.FALSE_POSITIVE.value, FindingStatus.DUPLICATE.value}
        ]
        
        # Sort by severity
        severity_order = {
            Severity.CRITICAL.value: 0,
            Severity.HIGH.value: 1,
            Severity.MEDIUM.value: 2,
            Severity.LOW.value: 3,
            Severity.INFO.value: 4,
        }
        findings.sort(key=lambda x: (severity_order.get(x["severity"], 99), -x.get("cvss_score", 0.0)))
        
        # Impact labels on unverified candidates are provisional. Keep the
        # legacy top-level severity counters, but define them as confirmed-only
        # and expose candidate counts separately so dashboards cannot present
        # heuristic labels as demonstrated vulnerability totals.
        confirmed_findings = [f for f in findings if f.get("status") == FindingStatus.CONFIRMED.value]
        candidate_findings = [f for f in findings if f.get("status", FindingStatus.UNVERIFIED.value) == FindingStatus.UNVERIFIED.value]
        stats = {
            "critical": sum(1 for f in confirmed_findings if f["severity"] == Severity.CRITICAL.value),
            "high": sum(1 for f in confirmed_findings if f["severity"] == Severity.HIGH.value),
            "medium": sum(1 for f in confirmed_findings if f["severity"] == Severity.MEDIUM.value),
            "low": sum(1 for f in confirmed_findings if f["severity"] == Severity.LOW.value),
            "info": sum(1 for f in confirmed_findings if f["severity"] == Severity.INFO.value),
            "total": len(findings),
            "confirmed": len(confirmed_findings),
            "unverified_candidates": len(candidate_findings),
            "candidate_severity": {
                severity.lower(): sum(1 for f in candidate_findings if f.get("severity") == severity)
                for severity in (Severity.CRITICAL.value, Severity.HIGH.value, Severity.MEDIUM.value,
                                 Severity.LOW.value, Severity.INFO.value)
            },
        }

        # Pipeline completion and assessment coverage are different claims.
        # A finished job may still have skipped, failed, or budget-limited engines.
        incomplete_markers = {"partial", "incomplete", "error", "unavailable", "unsupported",
                              "fallback_lexical", "skipped", "skipped_offline", "skipped_disabled",
                              "not_analyzed", "not_started"}
        coverage_gaps: list[str] = []
        static_status_count = 0

        def inspect_coverage(value: object, path: str = "coverage") -> None:
            nonlocal static_status_count
            if isinstance(value, dict):
                for key, child in value.items():
                    child_path = f"{path}.{key}"
                    if key == "static_status" and isinstance(child, str):
                        static_status_count += 1
                        if child in incomplete_markers:
                            coverage_gaps.append(f"{child_path}={child}")
                    else:
                        inspect_coverage(child, child_path)
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    inspect_coverage(child, f"{path}[{index}]")

        coverage = state.get("coverage", {})
        inspect_coverage(coverage)
        
        return {
            "scan_id": state["scan_id"],
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "app_info": {
                "package_name": state.get("package_name", "Unknown"),
                "framework": state.get("framework_info", {}).get("framework", "Native"),
                "obfuscation_level": state.get("obfuscation_info", {}).get("obfuscation", {}).get("level", "Unknown"),
            },
            "stats": stats,
            "findings": findings,
            "api_endpoints": state.get("api_endpoints", []),
            "errors": state.get("errors", []),
            "coverage": state.get("coverage", {}),
            "assessment_coverage": ("unknown" if not static_status_count else
                                    "partial" if coverage_gaps else "recorded_no_static_gaps"),
            "coverage_gaps": sorted(set(coverage_gaps)),
            "analysis_mode": "static analysis; runtime coverage is reported separately",
            "exhaustive_analysis": False,
            "confirmation_policy": "Structured analyst attestation is not independent automated exploit proof.",
            "candidate_count_semantics": "Confirmed severity counts include only analyst-attested findings; candidate_severity counts are provisional labels for unverified review items. Confirmation is not independently verified by the tool.",
        }

    def _generate_markdown(self, data: dict) -> str:
        """Generate markdown report using Jinja2."""
        if not self._env:
            return self._fallback_markdown(data)
            
        try:
            template = self._env.get_template("report.md.j2")
            return template.render(**data)+self._coverage_markdown(data)
        except TemplateNotFound:
            return self._fallback_markdown(data)
        except Exception as exc:
            logger.error("Markdown generation failed: %s", exc)
            return self._fallback_markdown(data)

    def _fallback_markdown(self, data: dict) -> str:
        """Fallback markdown generator if templates are missing."""
        app = data["app_info"]
        stats = data["stats"]
        
        md = [
            f"# Security Analysis Report: {app['package_name']}",
            f"\n**Scan ID:** {data['scan_id']}",
            f"**Date:** {data['date']}",
            f"**Framework:** {app['framework']}",
            f"\n## Summary",
            "Severity totals below count confirmed findings only; candidate labels are provisional review classifications, not verified impact.",
            f"- Confirmed — Critical: {stats['critical']}",
            f"- Confirmed — High: {stats['high']}",
            f"- Confirmed — Medium: {stats['medium']}",
            f"- Confirmed — Low: {stats['low']}",
            f"- Confirmed — Info: {stats['info']}",
            f"- Unverified candidates: {stats['unverified_candidates']}",
            "- Unverified candidate labels: " + ", ".join(
                f"{severity.title()} {count}" for severity, count in stats["candidate_severity"].items()
            ),
            f"- Total: {stats['total']}",
            "\n## Findings\n"
        ]
        
        for f in data["findings"]:
            md.extend([
                f"### {f['title']}",
                f"**Severity:** {f['severity']} | **CVSS:** {f.get('cvss_score', 'N/A')} | **CWE:** {f.get('cwe_id', 'N/A')}",
                f"\n**Component:** `{f['affected_component']}`",
                f"\n**Description:**\n{f['description']}",
                f"\n**Remediation:**\n{f.get('remediation', 'N/A')}",
                "\n---\n"
            ])
            
        return "\n".join(md)+self._coverage_markdown(data)

    @staticmethod
    def _coverage_markdown(data):
        rows=['\n## Coverage and proof boundaries\n', 'Analysis is not exhaustive. Zero candidates is not a security verdict. Structured confirmation is analyst-attested, not independently proven by the tool.']
        categories=data.get('coverage',{}).get('android_surface',{}).get('categories',{})
        for name in ('deep_links','webview','intent'):
            row=categories.get(name,{})
            rows.append(f"- {name}: static={row.get('static_status','not_recorded')}; runtime={row.get('runtime_status','not_recorded')}; proof={row.get('proof_status','not_recorded')}")
        for name in ('auth_session', 'firebase', 'dependencies'):
            row = data.get('coverage', {}).get(name, {})
            rows.append(f"- {name}: static={row.get('static_status', 'not_recorded')}; runtime={row.get('runtime_status', 'not_recorded')}; proof={row.get('proof_status', 'not_recorded')}")
        return '\n'.join(rows)+'\n'
