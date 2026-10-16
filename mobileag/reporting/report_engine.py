"""Report generation engine — outputs findings in Markdown, JSON, and PDF formats."""

import html
import json
import logging
import os
import re
import tempfile
from datetime import datetime
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader, TemplateNotFound

from mobileag.core.state import ScanState
from mobileag.reporting.finding import Severity, FindingStatus
from mobileag.reporting.evidence_contract import prepare_finding
from mobileag.reporting.coverage import review_surface_ledger
from mobileag.reporting.capability_inventory import capability_inventory
from mobileag.security.privacy import redact

logger = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).parent / "templates"


class ReportEngine:
    """Generates vulnerability reports from scan state."""

    MAX_PDF_HTML_CHARS = 16 * 1024 * 1024
    MAX_PDF_BYTES = 64 * 1024 * 1024

    @staticmethod
    def _safe_scan_id(scan_id: object) -> str:
        if (not isinstance(scan_id, str) or len(scan_id) > 128
                or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", scan_id)):
            raise ValueError("Invalid scan identifier for report artifact paths")
        return scan_id

    @staticmethod
    def _atomic_private_write(path: Path, content: bytes) -> None:
        """Replace a report artifact without following an existing symlink."""
        fd, temporary_path = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary_path, path)
        except Exception:
            try:
                os.unlink(temporary_path)
            except OSError:
                pass
            raise

    def __init__(self):
        self._env: Optional[Environment] = None
        self._init_templates()

    def _init_templates(self) -> None:
        if _TEMPLATES_DIR.exists():
            self._env = Environment(
                loader=FileSystemLoader(str(_TEMPLATES_DIR)),
                autoescape=False,
            )
            self._env.filters['report_json'] = self._report_json
        else:
            logger.warning("Report templates directory not found: %s", _TEMPLATES_DIR)

    async def generate_reports(self, state: ScanState) -> None:
        """Generate all report formats and save them to the output directory."""
        output_dir = Path(state["output_dir"])
        scan_id = self._safe_scan_id(state.get("scan_id"))
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Prepare data for templates
        report_data = self._prepare_data(state)
        state["assessment_coverage"] = report_data["assessment_coverage"]
        state["coverage_gaps"] = report_data["coverage_gaps"]
        
        # Save JSON
        json_path = output_dir / f"report_{scan_id}.json"
        self._atomic_private_write(
            json_path, json.dumps(report_data, indent=2).encode("utf-8")
        )
        logger.info("Saved JSON report to %s", json_path)
        
        # Save Markdown
        md_path = output_dir / f"report_{scan_id}.md"
        md_content = self._generate_markdown(report_data)
        self._atomic_private_write(md_path, md_content.encode("utf-8"))
        logger.info("Saved Markdown report to %s", md_path)

        pdf_path = output_dir / f"report_{scan_id}.pdf"
        pdf_content = self._generate_pdf(report_data)
        self._atomic_private_write(pdf_path, pdf_content)
        logger.info("Saved PDF report to %s", pdf_path)
        
        state["report_path"] = str(md_path)
        state["json_report_path"] = str(json_path)
        state["pdf_report_path"] = str(pdf_path)

    @staticmethod
    def _pdf_text(value: object) -> str:
        if value is None:
            value = "not recorded"
        return html.escape(str(value), quote=True).replace("\n", "<br>\n")

    def _generate_pdf(self, data: dict) -> bytes:
        """Render escaped report data into a bounded, offline-only PDF."""
        from weasyprint import HTML

        app_info = data.get("app_info", {}) if isinstance(data.get("app_info"), dict) else {}
        stats = data.get("stats", {}) if isinstance(data.get("stats"), dict) else {}
        findings = data.get("findings", []) if isinstance(data.get("findings"), list) else []
        blocks = [
            "<!doctype html><html><head><meta charset='utf-8'><style>",
            "@page { size: A4; margin: 18mm; } body { font-family: sans-serif; color: #17202a; font-size: 10pt; }",
            "h1 { color: #17365d; } h2 { border-bottom: 1px solid #7f8c8d; margin-top: 1.5em; }",
            ".muted { color: #555; } .finding { page-break-inside: avoid; margin: 1em 0; }",
            "pre, code { white-space: pre-wrap; overflow-wrap: anywhere; }",
            "</style></head><body>",
            f"<h1>MobileAg Security Analysis Report</h1><p><b>Package:</b> {self._pdf_text(app_info.get('package_name'))}</p>",
            f"<p><b>Version:</b> {self._pdf_text(app_info.get('version_name'))} &nbsp; <b>Scan:</b> {self._pdf_text(data.get('scan_id'))}</p>",
            f"<p class='muted'>Generated: {self._pdf_text(data.get('date'))}</p>",
            "<h2>Summary</h2><p>Confirmed severity totals exclude unverified candidates. Candidate labels are provisional and are not proof of impact.</p><ul>",
        ]
        for severity in ("critical", "high", "medium", "low", "info"):
            blocks.append(f"<li>Confirmed {severity.title()}: {self._pdf_text(stats.get(severity, 0))}</li>")
        blocks.extend([
            f"<li>Unverified candidates: {self._pdf_text(stats.get('unverified_candidates', 0))}</li>",
            f"<li>Total findings: {self._pdf_text(stats.get('total', len(findings)))}</li></ul>",
            "<h2>Coverage and proof boundaries</h2><p>Analysis is not exhaustive. Zero candidates is not a security verdict. Structured confirmation is analyst-attested, not independently proven.</p>",
        ])
        coverage_gaps = data.get("coverage_gaps", [])
        if isinstance(coverage_gaps, list) and coverage_gaps:
            blocks.append("<ul>" + "".join(f"<li>{self._pdf_text(item)}</li>" for item in coverage_gaps) + "</ul>")
        blocks.append("<h2>Findings</h2>")
        for index, finding in enumerate(findings, 1):
            if not isinstance(finding, dict):
                continue
            blocks.extend([
                "<section class='finding'>",
                f"<h3>{index}. {self._pdf_text(finding.get('title'))}</h3>",
                f"<p><b>Status:</b> {self._pdf_text(finding.get('status'))} &nbsp; <b>Severity:</b> {self._pdf_text(finding.get('severity'))} &nbsp; <b>CWE:</b> {self._pdf_text(finding.get('cwe_id'))}</p>",
                f"<p><b>Component:</b> {self._pdf_text(finding.get('affected_component'))}</p>",
                f"<p><b>Description:</b><br>{self._pdf_text(finding.get('description'))}</p>",
                f"<p><b>Remediation:</b><br>{self._pdf_text(finding.get('remediation'))}</p>",
                "</section>",
            ])
        blocks.append("</body></html>")
        document = "".join(blocks)
        if len(document) > self.MAX_PDF_HTML_CHARS:
            raise ValueError("PDF report exceeds the bounded HTML input limit")

        # The document contains only inline styles and escaped text; rejecting
        # resource lookups provides a second barrier against accidental fetches.
        def deny_resource_fetch(_url: str, **_kwargs):
            raise ValueError("External resources are disabled in PDF reports")

        pdf_content = HTML(string=document, url_fetcher=deny_resource_fetch).write_pdf()
        if len(pdf_content) > self.MAX_PDF_BYTES:
            raise ValueError("PDF report exceeds the bounded output limit")
        return pdf_content

    def _prepare_data(self, state: ScanState) -> dict:
        """Extract and format data for reporting."""
        findings = [
            f for f in state.get("filtered_findings", [])
            if f.get("status") not in {FindingStatus.FALSE_POSITIVE.value, FindingStatus.DUPLICATE.value}
        ]
        
        # Export gate also covers raw dictionaries that bypassed API triage.
        provenance = state.get("artifact_provenance", {})
        artifact = {
            "artifact_sha256": provenance.get("sha256") or state.get("artifact_sha256"),
            "package_name": state.get("package_name"),
            "app_version": state.get("manifest_data", {}).get("version_name") or state.get("version"),
        }
        findings = [prepare_finding(f, artifact) for f in findings]

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
        coverage_gaps: list[str] = []
        static_status_count = 0
        non_exhaustive_paths: list[str] = []
        limit_paths: list[str] = []

        def inspect_coverage(value: object, path: str = "coverage") -> None:
            nonlocal static_status_count
            if isinstance(value, dict):
                for key, child in value.items():
                    child_path = f"{path}.{key}"
                    if key == "static_status":
                        static_status_count += 1
                        if not isinstance(child, str) or child not in {"completed", "analyzed", "not_applicable"}:
                            coverage_gaps.append(f"{child_path}={child}")
                    elif key == "exhaustive" and child is False:
                        non_exhaustive_paths.append(path)
                        coverage_gaps.append(f"{path}.exhaustive=false")
                    elif key == "limits_reached" and child is True:
                        limit_paths.append(path)
                        coverage_gaps.append(f"{path}.limits_reached=true")
                    else:
                        inspect_coverage(child, child_path)
            elif isinstance(value, list):
                for index, child in enumerate(value):
                    inspect_coverage(child, f"{path}[{index}]")

        coverage = state.get("coverage", {})
        inspect_coverage(coverage)
        if state.get("errors"):
            coverage_gaps.append("scan.errors_present")
        
        report_data = {
            "report_schema_version": 1,
            "scan_id": state["scan_id"],
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "app_info": {
                "package_name": state.get("package_name", "Unknown"),
                "framework": state.get("framework_info", {}).get("framework", "Native"),
                "obfuscation_level": state.get("obfuscation_info", {}).get("obfuscation", {}).get("level", "Unknown"),
                "version_name": state.get("manifest_data", {}).get("version_name"),
                "version_code": state.get("manifest_data", {}).get("version_code"),
                "min_sdk": state.get("manifest_data", {}).get("min_sdk"),
                "target_sdk": state.get("manifest_data", {}).get("target_sdk"),
            },
            "artifact_provenance": state.get("artifact_provenance", {}),
            "stats": stats,
            "findings": findings,
            "api_endpoints": state.get("api_endpoints", []),
            "errors": state.get("errors", []),
            "coverage": state.get("coverage", {}),
            "review_surface_ledger": review_surface_ledger(state.get("coverage", {})),
            "capability_inventory": capability_inventory(state.get("coverage", {}), state.get("framework_info", {})),
            "coverage_summary": {
                "static_status_count": static_status_count,
                "non_exhaustive_analysis_count": len(set(non_exhaustive_paths)),
                "non_exhaustive_paths": sorted(set(non_exhaustive_paths)),
                "limits_reached_count": len(set(limit_paths)),
                "limits_reached_paths": sorted(set(limit_paths)),
            },
            "assessment_coverage": ("unknown" if not static_status_count else
                                    "partial" if coverage_gaps else "recorded_no_static_gaps"),
            "coverage_gaps": sorted(set(coverage_gaps)),
            "analysis_mode": "static analysis; runtime coverage is reported separately",
            "exhaustive_analysis": False,
            "confirmation_policy": "Structured analyst attestation is not independent automated exploit proof.",
            "candidate_count_semantics": "Confirmed severity counts include only analyst-attested findings; candidate_severity counts are provisional labels for unverified review items. Confirmation is not independently verified by the tool.",
        }
        return redact(report_data)

    @staticmethod
    def _report_json(value: object) -> str:
        """Safe, bounded-to-schema JSON presentation for report code blocks."""
        return json.dumps(redact(value), indent=2, ensure_ascii=True).replace('`', r'\u0060')

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
            f"**App version:** {app.get('version_name') or 'not recorded'} (code {app.get('version_code') or 'not recorded'})",
            f"**SDK range:** min {app.get('min_sdk') or 'not recorded'}, target {app.get('target_sdk') or 'not recorded'}",
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
        ledger = data.get('review_surface_ledger', {})
        if ledger:
            rows.append('\n### Review-surface ledger\n')
            rows.append('This crosswalk records mapped analyzer execution only; every surface remains unproven unless separately validated.\n')
            rows.append('| Surface | Static analysis | Runtime | Evidence | Mapped coverage paths | Recorded counts | Coverage gap |\n|---|---|---|---|---|---|---|')
            for name, item in ledger.get('surfaces', {}).items():
                paths = ', '.join(f"`{path}`" for path in item.get('mapped_coverage_paths', [])) or 'none'
                counts = ', '.join(f"{path}: {values}" for path, values in item.get('recorded_counts', {}).items()) or 'none'
                gap_reasons = item.get('gap_reasons', [])
                gap = '; '.join(reason for reason in gap_reasons if isinstance(reason, str)) if isinstance(gap_reasons, list) else ''
                if not gap:
                    gap = item.get('gap') or 'no additional mapping gap recorded'
                rows.append(f"| {name} | {item.get('analysis_state', 'not_tested')} | {item.get('runtime_state', 'not_tested')} | {item.get('evidence_state', 'not_tested')} | {paths} | {counts} | {gap} |")
        inventory = data.get('capability_inventory', {})
        if inventory:
            rows.append('\n### Framework and format support inventory\n')
            rows.append(f"Framework hint: `{inventory.get('detected_framework_hint', 'not_recorded')}` (signature detection only; does not establish code coverage).\n")
            rows.append('| Area | Implemented support | This scan | Evidence path | Input skips / limits | Limitations |\n|---|---|---|---|---|---|')
            for name, item in inventory.get('formats', {}).items():
                input_details = []
                if item.get('source_files_skipped') is not None:
                    input_details.append(f"skipped files={item['source_files_skipped']}")
                for label, key in [('skip reasons', 'source_file_skip_reasons'), ('limit reasons', 'limit_reasons')]:
                    reasons = item.get(key, {})
                    if isinstance(reasons, dict) and reasons:
                        input_details.append(label + ': ' + ', '.join(f"{reason}={count}" for reason, count in sorted(reasons.items())))
                summaries = item.get('same_file_parameter_summary', {})
                if isinstance(summaries, dict) and summaries:
                    input_details.append(
                        f"helper summaries: direct={summaries.get('direct_summaries', 0)}, "
                        f"transitive={summaries.get('transitive_summaries', 0)}, "
                        f"round-limited files={summaries.get('round_limit_files', 0)}, "
                        f"candidate-limited files={summaries.get('candidate_limit_files', 0)}")
                rows.append(f"| {name} | {item.get('support_level')} | {item.get('execution_state')} ({item.get('static_status')}) | {item.get('coverage_path') or 'none'} | {'; '.join(input_details) or 'not reported'} | {'; '.join(item.get('limitations', []))} |")
            rows.append('This is an implementation inventory, not a benchmark, completeness claim, or security verdict.\n')
        summary = data.get('coverage_summary', {})
        rows.append(f"- Assessment coverage: {data.get('assessment_coverage', 'not_recorded')}; static statuses recorded: {summary.get('static_status_count', 0)}; non-exhaustive analyses: {summary.get('non_exhaustive_analysis_count', 0)}; limits reached: {summary.get('limits_reached_count', 0)}")
        gaps = data.get('coverage_gaps', [])
        if gaps:
            rows.append('- Recorded coverage gaps/limits:')
            rows.extend(f"  - `{gap}`" for gap in gaps[:20])
            if len(gaps) > 20:
                rows.append(f"  - ... {len(gaps) - 20} additional gap(s) are listed in the JSON report")
        categories=data.get('coverage',{}).get('android_surface',{}).get('categories',{})
        for name in ('deep_links','webview','intent'):
            row=categories.get(name,{})
            rows.append(f"- {name}: static={row.get('static_status','not_recorded')}; runtime={row.get('runtime_status','not_recorded')}; proof={row.get('proof_status','not_recorded')}")
        for name in ('auth_session', 'firebase', 'dependencies'):
            row = data.get('coverage', {}).get(name, {})
            rows.append(f"- {name}: static={row.get('static_status', 'not_recorded')}; runtime={row.get('runtime_status', 'not_recorded')}; proof={row.get('proof_status', 'not_recorded')}")
        return '\n'.join(rows)+'\n'
