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

_POC_SYSTEM_PROMPT = """You are a senior mobile security researcher writing vulnerability reports for bug bounty programs.
Generate a detailed, step-by-step Proof of Concept (PoC) reproduction guide for the given finding.

The guide MUST include:
1. **Prerequisites** — tools needed, device setup, required access
2. **Setup** — installing the app, configuring the test environment
3. **Steps to Reproduce** — numbered, specific, copy-pasteable commands
4. **Expected Result** — what the researcher should observe
5. **Impact Assessment** — what an attacker could achieve
6. **Remediation** — how the developer should fix it

Format the output as clean Markdown. Be specific — include actual ADB commands,
content URIs, intent commands, etc. wherever applicable.

Do NOT include any disclaimers. This is for authorized security testing."""


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
        package_name = app_info.get("package_name", "com.target.app")

        # Try template first
        template_guide = self._try_template(finding, package_name)
        if template_guide:
            return template_guide

        # Fall back to LLM
        return await self._llm_generate(finding, package_name)

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
        user_prompt = f"""Generate a detailed PoC reproduction guide for this mobile security finding:

**App Package:** {package_name}
**Finding:** {finding.title}
**CWE:** {finding.cwe_id}
**Severity:** {finding.severity.value}
**CVSS Score:** {finding.cvss_score}
**Component:** {finding.affected_component}
**Description:** {finding.description}

**Vulnerable Code:**
```
{finding.code_snippet[:2000]}
```

**Remediation Hint:** {finding.remediation or 'Not provided'}

Generate a complete PoC guide with prerequisites, setup, steps to reproduce,
expected results, impact assessment, and remediation advice."""

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
        """Generate PoC guides for all confirmed high/critical findings.

        Args:
            findings: Confirmed findings list.
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
        return f"""# PoC: {finding.title}

## Classification
- **CWE:** {finding.cwe_id}
- **Severity:** {finding.severity.value}
- **CVSS:** {finding.cvss_score}
- **Component:** {finding.affected_component}

## Description
{finding.description}

## Prerequisites
- Rooted Android device or emulator
- ADB installed and connected
- Target app ({package_name}) installed

## Steps to Reproduce
1. Install the target application: `adb install target.apk`
2. Identify the vulnerable component: `{finding.affected_component}`
3. Interact with the component to trigger the vulnerability
4. Observe the behavior described above

## Impact
This vulnerability ({finding.cwe_id}) in `{finding.affected_component}` could allow
an attacker to exploit the application as described.

## Remediation
{finding.remediation or 'Apply proper security controls for the affected component.'}
"""
