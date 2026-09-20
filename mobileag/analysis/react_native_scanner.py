"""React Native JavaScript bundle security scanner.

Audits assets/index.android.bundle (and other assets bundles) for:
- Embedded secret tokens, private keys, API keys
- Staging/development/internal URLs and IP addresses
- Hardcoded authentication headers (Bearer, Basic)
- Internal API routes and deep link schemas
"""

import asyncio
import logging
import math
import re
from pathlib import Path
from typing import Any, Optional

from mobileag.reporting.finding import Finding, Severity, FindingStatus
from mobileag.reporting.cvss import get_default_cvss_for_cwe

logger = logging.getLogger(__name__)


class ReactNativeScanner:
    """Scans React Native JavaScript bundles for secrets and architectural leaks."""

    def __init__(self, entropy_threshold: float = 4.6) -> None:
        self.entropy_threshold = entropy_threshold

        self.secret_rules = [
            ("AWS Access Key", re.compile(r"AKIA[0-9A-Z]{16}"), "CWE-798", "Critical"),
            ("Google API Key", re.compile(r"AIza[0-9A-Za-z-_]{35}"), "CWE-798", "Critical"),
            ("Stripe Secret Key", re.compile(r"sk_(?:live|test)_[0-9a-zA-Z]{24,}"), "CWE-798", "Critical"),
            ("Stripe Publishable Key", re.compile(r"pk_live_[0-9a-zA-Z]{24,}"), "CWE-200", "Low"),
            ("OpenAI API Key", re.compile(r"sk-[a-zA-Z0-9]{32,}"), "CWE-798", "Critical"),
            ("Firebase Database URL", re.compile(r"https://[a-zA-Z0-9_-]+\.firebaseio\.com"), "CWE-200", "Medium"),
            ("JWT Token", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "CWE-798", "High"),
            ("Private Key Block", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"), "CWE-312", "Critical"),
            ("Hardcoded Bearer Token", re.compile(r"(?:['\"]Bearer\s+[a-zA-Z0-9_\-\.]{20,}['\"])", re.IGNORECASE), "CWE-798", "High"),
            ("Hardcoded Basic Auth", re.compile(r"(?:['\"]Basic\s+[a-zA-Z0-9+/=]{16,}['\"])", re.IGNORECASE), "CWE-798", "High"),
        ]

        self.url_rules = [
            ("Localhost Reference", re.compile(r"https?://(?:localhost|127\.0\.0\.1)(?::\d+)?(?:/[^\s\"']*)?"), "CWE-489", "Medium"),
            ("Internal Staging/Dev URL", re.compile(r"https?://[a-zA-Z0-9.-]*(?:dev|staging|test|qa|internal)[a-zA-Z0-9.-]*(?:\.[a-zA-Z]{2,})+(?::\d+)?(?:/[^\s\"']*)?"), "CWE-489", "Medium"),
            ("Private Subnet IP", re.compile(r"https?://(?:10\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}(?::\d+)?(?:/[^\s\"']*)?"), "CWE-200", "Medium"),
        ]

        self.route_pattern = re.compile(r"""(?:path|route|screen)\s*:\s*['"]([/a-zA-Z0-9_-]+)['"]""", re.IGNORECASE)
        self.api_endpoint_pattern = re.compile(r"""['"](/api/v\d+/[a-zA-Z0-9_/-]+)['"]""")

    def locate_bundle(self, decompiled_dir: str | Path) -> Optional[Path]:
        """Locate assets/index.android.bundle in an extracted APK directory."""
        root = Path(decompiled_dir)
        candidates = [
            root / "assets" / "index.android.bundle",
            root / "apktool_out" / "assets" / "index.android.bundle",
            root / "resources" / "assets" / "index.android.bundle",
        ]
        for c in candidates:
            if c.is_file():
                return c

        found = list(root.rglob("index.android.bundle"))
        return found[0] if found else None

    @staticmethod
    def calculate_entropy(data: str) -> float:
        """Calculate the Shannon entropy of a string."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        for x in set(data):
            p_x = float(data.count(x)) / length
            entropy -= p_x * math.log(p_x, 2)
        return entropy

    @staticmethod
    def format_bundle_snippet(content: str, start: int, end: int, context: int = 60) -> str:
        """Extract a snippet around a character offset in the bundle."""
        s = max(0, start - context)
        e = min(len(content), end + context)
        snippet = content[s:e].replace("\n", " ")
        return f"...{snippet}..."

    def scan_bundle_text(self, content: str, file_path_str: str) -> list[dict[str, Any]]:
        """Scan raw bundle content and extract security findings with character offsets."""
        findings: list[dict[str, Any]] = []

        # 1. Scan for secrets
        for name, pattern, cwe, sev in self.secret_rules:
            for match in pattern.finditer(content):
                val = match.group(0)
                offset = match.start()
                snippet = self.format_bundle_snippet(content, match.start(), match.end())

                findings.append({
                    "issue_id": f"RN-SECRET-{name.replace(' ', '-').upper()}",
                    "cwe": cwe,
                    "severity": sev,
                    "title": f"Hardcoded {name} in React Native Bundle",
                    "description": f"Found embedded {name} inside JavaScript assets bundle.",
                    "file_path": file_path_str,
                    "offset": offset,
                    "code_snippet": snippet,
                    "remediation": "Move secrets to secure server-side infrastructure or fetch tokens at runtime via authenticated session."
                })

        # 2. Scan for internal/staging URLs
        for name, pattern, cwe, sev in self.url_rules:
            for match in pattern.finditer(content):
                url = match.group(0)
                offset = match.start()
                snippet = self.format_bundle_snippet(content, match.start(), match.end())

                findings.append({
                    "issue_id": f"RN-URL-{name.replace(' ', '-').upper()}",
                    "cwe": cwe,
                    "severity": sev,
                    "title": f"{name} Exposed in React Native Bundle: {url}",
                    "description": f"Internal or non-production URL found inside client JavaScript bundle: {url}.",
                    "file_path": file_path_str,
                    "offset": offset,
                    "code_snippet": snippet,
                    "remediation": "Ensure release configurations exclude development/staging hostnames from client bundles."
                })

        # 3. Scan for internal routes & API paths
        api_routes = set()
        for match in self.api_endpoint_pattern.finditer(content):
            api_routes.add(match.group(1))

        if any("admin" in r.lower() or "internal" in r.lower() for r in api_routes):
            priv_routes = [r for r in api_routes if "admin" in r.lower() or "internal" in r.lower()]
            route_summary = ", ".join(priv_routes[:5])
            findings.append({
                "issue_id": "RN-PRIVILEGED-ROUTES-EXPOSED",
                "cwe": "CWE-285",
                "severity": "Medium",
                "title": f"Privileged API Routes Declared in Bundle: {route_summary}",
                "description": f"Client bundle registers privileged or internal API routes: {route_summary}.",
                "file_path": file_path_str,
                "offset": 0,
                "code_snippet": f"Routes: {route_summary}",
                "remediation": "Do not package administrative routes or privileged endpoints into client application code."
            })

        return findings

    def scan_bundle_file(self, bundle_path: str | Path) -> list[dict[str, Any]]:
        """Audit bundle file synchronously."""
        path = Path(bundle_path)
        if not path.is_file():
            return []

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            return self.scan_bundle_text(content, str(path))
        except Exception as e:
            logger.error(f"Failed to read bundle at {path}: {e}")
            return []

    async def scan_directory_async(self, decompiled_dir: str | Path) -> list[Finding]:
        """Asynchronously locate bundle and return standard Finding objects."""
        bundle_path = self.locate_bundle(decompiled_dir)
        if not bundle_path:
            logger.info("No React Native JavaScript bundle discovered.")
            return []

        raw_findings = await asyncio.to_thread(self.scan_bundle_file, bundle_path)
        findings: list[Finding] = []

        for item in raw_findings:
            cwe = item["cwe"]
            score, vector = get_default_cvss_for_cwe(cwe)
            sev_map = {
                "Critical": Severity.CRITICAL,
                "High": Severity.HIGH,
                "Medium": Severity.MEDIUM,
                "Low": Severity.LOW,
            }
            severity = sev_map.get(item["severity"], Severity.MEDIUM)

            findings.append(Finding(
                title=item["title"],
                description=item["description"],
                severity=severity,
                cwe_id=cwe,
                cvss_score=score,
                cvss_vector=vector,
                affected_component="assets/index.android.bundle",
                detection_method="ReactNativeScanner",
                status=FindingStatus.UNVERIFIED,
                remediation=item["remediation"],
                file_path=item["file_path"],
                code_snippet=item.get("code_snippet", "")
            ))

        return findings
