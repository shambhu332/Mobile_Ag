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

    def _prepare_data(self, state: ScanState) -> dict:
        """Extract and format data for reporting."""
        findings = [
            f for f in state.get("filtered_findings", [])
            if f.get("status") == FindingStatus.CONFIRMED.value
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
        
        # Calculate stats
        stats = {
            "critical": sum(1 for f in findings if f["severity"] == Severity.CRITICAL.value),
            "high": sum(1 for f in findings if f["severity"] == Severity.HIGH.value),
            "medium": sum(1 for f in findings if f["severity"] == Severity.MEDIUM.value),
            "low": sum(1 for f in findings if f["severity"] == Severity.LOW.value),
            "info": sum(1 for f in findings if f["severity"] == Severity.INFO.value),
            "total": len(findings),
        }
        
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
        }

    def _generate_markdown(self, data: dict) -> str:
        """Generate markdown report using Jinja2."""
        if not self._env:
            return self._fallback_markdown(data)
            
        try:
            template = self._env.get_template("report.md.j2")
            return template.render(**data)
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
            f"- Critical: {stats['critical']}",
            f"- High: {stats['high']}",
            f"- Medium: {stats['medium']}",
            f"- Low: {stats['low']}",
            f"- Info: {stats['info']}",
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
            
        return "\n".join(md)
