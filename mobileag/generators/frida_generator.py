"""LLM-powered Frida script generator for vulnerability verification.

Generates app-specific Frida hooks that a security researcher can
review and execute manually to verify findings on a rooted device.
"""

import logging
from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader, TemplateNotFound

from config.llm_config import TaskType
from mobileag.llm.router import LLMRouter
from mobileag.reporting.finding import Finding, Severity

logger = logging.getLogger(__name__)

_TEMPLATES_DIR = Path(__file__).parent / "templates" / "frida"

_FRIDA_SYSTEM_PROMPT = """You are an expert mobile security researcher who writes Frida instrumentation scripts.
Given a security finding, generate a complete, ready-to-run Frida JavaScript hook script.

Requirements:
- The script must be syntactically valid JavaScript for the Frida runtime
- Include Java.perform() wrapper for Java-layer hooks
- Include Interceptor.attach() for native hooks
- Add console.log() statements to display intercepted data
- Add comments explaining what each hook does
- Include the frida command to run the script as a comment at the top
- Handle errors gracefully with try/catch

Output ONLY the JavaScript code. No markdown fences, no explanations outside the script."""


class FridaGenerator:
    """Generates Frida instrumentation scripts for security findings.

    Uses Jinja2 templates for common patterns and falls back to
    LLM generation for complex/custom hooks.
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
            logger.info("Loaded Frida templates from %s", _TEMPLATES_DIR)
        else:
            logger.warning("Frida templates directory not found: %s", _TEMPLATES_DIR)

    async def generate(self, finding: Finding, app_info: dict) -> str:
        """Generate a Frida script for a specific finding.

        Args:
            finding: The security finding to create a hook for.
            app_info: App metadata (package_name, framework, etc.).

        Returns:
            Complete Frida JavaScript hook script as a string.
        """
        package_name = app_info.get("package_name", "com.target.app")

        # Try template-based generation first
        template_script = self._try_template(finding, package_name)
        if template_script:
            return template_script

        # Fall back to LLM generation
        return await self._llm_generate(finding, package_name)

    def _try_template(self, finding: Finding, package_name: str) -> Optional[str]:
        """Try to render a Frida script from a Jinja2 template."""
        if not self._env:
            return None

        # Map CWE/finding type to template
        template_map: dict[str, str] = {
            "CWE-295": "ssl_pinning.js.j2",       # Certificate pinning
            "CWE-319": "ssl_pinning.js.j2",        # Cleartext traffic
            "CWE-798": "string_decrypt.js.j2",     # Hardcoded secrets
            "CWE-321": "string_decrypt.js.j2",     # Hardcoded crypto key
            "CWE-327": "method_hook.js.j2",        # Weak crypto
        }

        # Check if finding mentions native/JNI
        if "native" in finding.title.lower() or ".so" in finding.description.lower():
            template_name = "native_jni.js.j2"
        else:
            template_name = template_map.get(finding.cwe_id)

        if not template_name:
            return None

        try:
            template = self._env.get_template(template_name)
            return template.render(
                package_name=package_name,
                class_name=finding.affected_component,
                method_name=self._extract_method(finding),
                cwe=finding.cwe_id,
                title=finding.title,
                description=finding.description,
                code_snippet=finding.code_snippet,
            )
        except TemplateNotFound:
            return None
        except Exception as exc:
            logger.warning("Template rendering failed: %s", exc)
            return None

    async def _llm_generate(self, finding: Finding, package_name: str) -> str:
        """Use LLM to generate a custom Frida script."""
        user_prompt = f"""Generate a Frida hook script for the following mobile security finding:

**Package:** {package_name}
**Finding:** {finding.title}
**CWE:** {finding.cwe_id}
**Severity:** {finding.severity.value}
**Component:** {finding.affected_component}
**Description:** {finding.description}

**Vulnerable Code:**
```
{finding.code_snippet[:2000]}
```

Generate a complete Frida script that hooks into the affected component to demonstrate or verify this vulnerability.
Include the frida command to run it as a comment at the top."""

        response = await self._router.route(
            task_type=TaskType.FRIDA_GENERATION,
            system_prompt=_FRIDA_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            temperature=0.2,
        )

        if response.success:
            script = response.content.strip()
            # Strip markdown fences if present
            if script.startswith("```"):
                script = script.split("\n", 1)[1] if "\n" in script else script[3:]
            if script.endswith("```"):
                script = script.rsplit("```", 1)[0]
            return script.strip()

        logger.error("LLM Frida generation failed: %s", response.error)
        return self._fallback_script(finding, package_name)

    async def generate_batch(
        self,
        findings: list[Finding],
        app_info: dict,
    ) -> list[dict]:
        """Generate Frida scripts for all high/critical findings.

        Args:
            findings: List of confirmed findings.
            app_info: App metadata dict.

        Returns:
            List of dicts: {finding_id, script, filename}.
        """
        results: list[dict] = []
        high_crit = [
            f for f in findings
            if f.severity in (Severity.CRITICAL, Severity.HIGH)
        ]

        logger.info("Generating Frida scripts for %d high/critical findings", len(high_crit))

        for finding in high_crit:
            try:
                script = await self.generate(finding, app_info)
                filename = f"frida_{finding.cwe_id.lower()}_{finding.id[:8]}.js"
                results.append({
                    "finding_id": finding.id,
                    "script": script,
                    "filename": filename,
                })
            except Exception as exc:
                logger.error("Failed to generate Frida script for %s: %s", finding.id, exc)

        return results

    @staticmethod
    def _extract_method(finding: Finding) -> str:
        """Extract method name from affected component."""
        component = finding.affected_component
        if "." in component:
            parts = component.rsplit(".", 1)
            last = parts[-1]
            if last[0].islower():
                return last
        return "targetMethod"

    @staticmethod
    def _fallback_script(finding: Finding, package_name: str) -> str:
        """Generate a minimal fallback script when LLM is unavailable."""
        return f"""// Frida hook for: {finding.title}
// CWE: {finding.cwe_id}
// Run: frida -U -f {package_name} -l this_script.js --no-pause
//
// NOTE: This is a template — customize for your target.

Java.perform(function() {{
    console.log("[*] Hooking {finding.affected_component}...");

    try {{
        var targetClass = Java.use("{finding.affected_component}");

        // Hook all methods of the target class
        var methods = targetClass.class.getDeclaredMethods();
        methods.forEach(function(method) {{
            console.log("[*] Found method: " + method.getName());
        }});

        console.log("[+] Hook installed successfully");
    }} catch(e) {{
        console.log("[-] Error: " + e);
    }}
}});
"""
