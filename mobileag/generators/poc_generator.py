"""LLM-powered PoC guide generator for security findings.

Generates step-by-step reproduction guides that a security researcher
can follow to verify and demonstrate each vulnerability.
"""

import logging
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader, TemplateNotFound

from config.llm_config import TaskType
from mobileag.llm.router import LLMRouter
from mobileag.reporting.finding import Finding, Severity

logger = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).parent / "templates" / "poc"

_POC_SYSTEM_PROMPT = """You are writing a bounded, non-destructive validation PLAN for an unverified mobile-security candidate, not a vulnerability report or proof.
State that nothing has been executed by generation. Use only observed locations and exact approved target details supplied in context; do not invent schemes, authorities, endpoints, exported state, bridge names or successful impact. When inputs are missing, identify them as prerequisites rather than guessing executable commands.
Use researcher-controlled accounts and synthetic data. Start with the relevant unprivileged attacker context on a current OS. Root, ADB shell and hooks that change authorization are diagnostics, never ordinary-app exploit proof. Avoid deletion, writes, credential extraction, broad enumeration or destinations not separately approved.
Include attacker control, entrypoint, sensitive sink, required boundary crossing, successful authorized and rejected unauthorized controls, evidence to collect, cleanup and root-cause-specific remediation. A model opinion cannot establish security or exploitability. Output Markdown."""


class PoCGenerator:
    """Generates step-by-step PoC reproduction guides for security findings.

    Uses Jinja2 templates for common vulnerability types and falls back
    to LLM generation for complex or unusual findings.
    """

    def __init__(self, router: LLMRouter):
        self._router = router
        self._env: Optional[Environment] = None
        self._init_templates()

    def _init_templates(self) -> None:
        """Initialize Jinja2 template environment."""
        if _TEMPLATES_DIR.exists():
            self._env = Environment(
                loader=FileSystemLoader(str(_TEMPLATES_DIR)),
                autoescape=False,
            )
            logger.info("Loaded PoC templates from %s", _TEMPLATES_DIR)
        else:
            logger.warning("PoC templates directory not found: %s", _TEMPLATES_DIR)

    async def generate(self, finding: Finding, app_info: dict) -> str:
        """Generate a PoC reproduction guide for a finding.

        Args:
            finding: The security finding to create a PoC for.
            app_info: App metadata (package_name, framework, etc.).

        Returns:
            Markdown-formatted PoC guide string.
        """
        package_name = app_info.get("package_name") or "<package-not-recorded>"

        # Try template first
        template_guide = self._try_template(finding, package_name)
        if template_guide:
            return self._with_boundary(template_guide)

        # Fall back to LLM
        return self._with_boundary(await self._llm_generate(finding, package_name))

    def _try_template(self, finding: Finding, package_name: str) -> Optional[str]:
        """Try to render a PoC from a Jinja2 template."""
        if not self._env:
            return None

        template_map: dict[str, str] = {
            "CWE-926": "exported_component.md.j2",
            "CWE-927": "exported_component.md.j2",
            "CWE-22": "content_provider.md.j2",
            "CWE-89": "content_provider.md.j2",
            "CWE-601": "deep_link.md.j2",
            "CWE-749": "deep_link.md.j2",
            "CWE-285": "bola_idor.md.j2",
            "CWE-306": "bola_idor.md.j2",
        }

        template_name = template_map.get(finding.cwe_id)
        if not template_name:
            return None

        try:
            template = self._env.get_template(template_name)
            return template.render(
                package_name=package_name,
                finding=finding,
                class_name=finding.affected_component,
                cwe=finding.cwe_id,
                severity=finding.severity.value,
                cvss=finding.cvss_score,
                description=finding.description,
                code_snippet=finding.code_snippet,
                remediation=finding.remediation,
            )
        except TemplateNotFound:
            return None
        except Exception as exc:
            logger.warning("PoC template rendering failed: %s", exc)
            return None

    async def _llm_generate(self, finding: Finding, package_name: str) -> str:
        """Use LLM to generate a custom PoC guide."""
        user_prompt = f"""Generate a bounded validation plan for this UNVERIFIED review candidate:

**App Package:** {package_name}
**Finding:** {finding.title}
**CWE:** {finding.cwe_id}
**Severity:** {finding.severity.value}
**CVSS Score:** {finding.cvss_score}
**Component:** {finding.affected_component}
**Description:** {finding.description}

**Observed Code (not established vulnerable):**
```
{finding.code_snippet[:2000]}
```

**Remediation Hint:** {finding.remediation or 'Not provided'}

Generate a non-destructive research plan with missing prerequisites, positive/negative controls, evidence requirements and remediation. Do not claim outcomes, invent routes or require root by default."""

        response = await self._router.route(
            task_type=TaskType.POC_GENERATION,
            system_prompt=_POC_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            temperature=0.3,
        )

        if response.success:
            return response.content.strip()

        logger.error("LLM PoC generation failed: %s", response.error)
        return self._fallback_guide(finding, package_name)

    async def generate_batch(
        self,
        findings: list[Finding],
        app_info: dict,
    ) -> list[dict]:
        """Generate unexecuted validation plans for candidate findings.

        Args:
            findings: Candidate findings list, not independently verified.
            app_info: App metadata dict.

        Returns:
            List of dicts: {finding_id, poc_guide, filename}.
        """
        results: list[dict] = []
        target_findings = [
            f for f in findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM)
        ]

        logger.info("Generating PoC guides for %d findings", len(target_findings))

        for finding in target_findings:
            try:
                guide = await self.generate(finding, app_info)
                filename = f"poc_{finding.cwe_id.lower()}_{finding.id[:8]}.md"
                results.append({
                    "finding_id": finding.id,
                    "poc_guide": guide,
                    "filename": filename,
                })
            except Exception as exc:
                logger.error("Failed to generate PoC for %s: %s", finding.id, exc)

        return results

    @staticmethod
    def _fallback_guide(finding: Finding, package_name: str) -> str:
        """Minimal fallback guide when LLM is unavailable."""
        return f"""# Validation plan: {finding.title}

## Observed candidate
- App package: `{package_name}`
- Review location: `{finding.file_path}`:{finding.line_number or 'unknown'}
- Component label: `{finding.affected_component}` (runtime entrypoint not verified)
- Candidate classification: {finding.cwe_id}

{finding.description}

## Missing prerequisites
Record the original artifact SHA-256, app version, current OS build, exact dedicated-device serial and explicit target/action scope. Use synthetic accounts/data and the relevant unprivileged attacker context. Root/shell/hooks are not ordinary-app exploitation proof.

## Validation procedure
1. Trace the actual entrypoint and attacker-controlled input to the sensitive sink and effective authorization/validation checks. Do not invent missing endpoints, authorities or URI schemes.
2. Build one bounded, non-destructive synthetic-canary reproduction in the authorized fixture.
3. Execute an allowed-input/authorized-caller positive control and rejected-input/unauthorized-caller negative control without modifying authorization.
4. Record what was actually observed and the precise crossed security boundary. A static pattern, model opinion or successful diagnostic command is not proof.
5. Preserve redacted evidence and clean up only researcher-created fixture state. If prerequisites or impact cannot be established, retain UNVERIFIED.

## Remediation after root-cause validation
{finding.remediation or 'Apply controls matching the demonstrated boundary failure while preserving authorized behavior.'}
"""

    @staticmethod
    def _with_boundary(guide: str) -> str:
        return ("**Generated validation plan - NOT EXECUTED and not independent exploit proof. "
                "Review all instructions against the exact approved scope before any test.**\n\n" + guide)
