import asyncio
import logging
import math
import re
from pathlib import Path
from typing import Any

from config.llm_config import TaskType
from mobileag.llm.router import LLMRouter
from mobileag.reporting.finding import Finding, Severity, FindingStatus
from mobileag.analysis.bounded_sources import SourceInventory, explicit_scan_root

logger = logging.getLogger(__name__)


class SecretScanner:
    """Agent for detecting hardcoded secrets and cryptographic weaknesses."""

    def __init__(self, router: LLMRouter, entropy_threshold: float = 4.5):
        """Initialize the secret scanner with an LLM router and entropy threshold."""
        self.router = router
        self.entropy_threshold = entropy_threshold
        self.coverage = {"static_status": "not_analyzed", "runtime_status": "not_tested",
                         "proof_status": "not_proven", "exhaustive": False}
        
        self.secret_patterns = {
            "Google API Key": re.compile(r"AIza[0-9A-Za-z-_]{35}"),
            "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
            "GitHub Access Token": re.compile(r"(?:ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{22,})"),
            "Slack Webhook URL": re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+"),
            "Stripe Secret Key": re.compile(r"sk_(?:live|test)_[0-9a-zA-Z]{24,}"),
            "Twilio Account SID": re.compile(r"AC[a-zA-Z0-9]{32}"),
            "OpenAI API Key": re.compile(r"sk-(?:proj|svcacct|admin|[a-zA-Z0-9]{20,})-[A-Za-z0-9_-]{20,}"),
            "Anthropic API Key": re.compile(r"sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_-]{80,}"),
            "Telegram Bot Token": re.compile(r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b"),
            "Discord Bot Token": re.compile(r"\b[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}\b"),
            "Database Connection URI": re.compile(r"\b(?:jdbc:[a-z]+|mongodb(?:\+srv)?|redis|postgres(?:ql)?|mysql|amqp)://[^\s\"'<>]{4,}"),
            "Credentials in URL": re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\/\s:@\"'<>]{1,64}:[^\/\s@\"'<>]{1,64}@[\w.-]+"),
            "SendGrid API Key": re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b"),
            "Square Access Token": re.compile(r"\bsq0(?:atp|csp)-[0-9A-Za-z_-]{22,}"),
            "Mapbox Secret Token": re.compile(r"\bsk\.eyJ[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{20,}"),
            "xAI API Key": re.compile(r"xai-[a-zA-Z0-9_-]+"),
            "Firebase URL": re.compile(r"https://[a-zA-Z0-9_-]+\.firebaseio\.com"),
            "JWT Token": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
            "Private RSA/EC Key": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----"),
        }
        
        self.crypto_patterns = {
            "ECB Mode": re.compile(r"AES/ECB/PKCS5Padding"),
            "DES Usage": re.compile(r"DES/CBC/PKCS5Padding|SecretKeyFactory\.getInstance\(\"DES\"\)"),
            "RC4 Usage": re.compile(r"Cipher\.getInstance\(\"RC4\"\)"),
            "Insecure MD5 Hash": re.compile(r"MessageDigest\.getInstance\(\"MD5\"\)"),
            "Weak SHA-1 Hash": re.compile(r"MessageDigest\.getInstance\(\"SHA-1\"\)"),
            "Hardcoded IV": re.compile(r"IvParameterSpec\([^{]*\{[0-9,\s]+\}\)"),
            "Static Seed SecureRandom": re.compile(r"SecureRandom\(.*\.getBytes\(\)\)"),
        }
        self._token_literal = re.compile(r"[\"']([A-Za-z0-9_+/=-]{24,})[\"']")
        self._entropy_context = re.compile(
            r"(?i)(?:secret|token|api[_-]?key|access[_-]?key|password|credential|private[_-]?key)"
        )

    def key_shaped(self, s: str) -> Optional[str]:
        """Detect standalone key-shaped constants: Base64 or hex of an AES/crypto key."""
        if len(s) < 16 or len(s) > 128:
            return None
        if len(s) in (32, 48, 64) and re.fullmatch(r"[0-9a-fA-F]+", s) and re.search(r"\d", s) and re.search(r"[a-fA-F]", s):
            if self.calculate_entropy(s) >= 3.0:
                return "Hex key-sized value"
        if (len(s) in (16, 20, 22, 24, 32, 43, 44, 64, 88) or len(s) >= 22) and re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", s):
            digits = sum(1 for c in s if c.isdigit())
            symbols = sum(1 for c in s if c in "+/=")
            if re.search(r"[a-z]", s) and re.search(r"[A-Z]", s):
                if (digits + symbols) / len(s) >= 0.15 and self.calculate_entropy(s) >= 4.0:
                    if len(re.findall(r"[A-Z][a-z]{2,}", s)) < 2 and not re.search(r"[a-z]{7,}", s):
                        return "Base64 key-sized value"
        return None

    @staticmethod
    def _mask_secret(val: str) -> str:
        """Mask sensitive value for logging."""
        if len(val) <= 8:
            return "******"
        return f"{val[:4]}...{val[-4:]}"

    def calculate_entropy(self, data: str) -> float:
        """Calculate the Shannon entropy of a string."""
        if not data:
            return 0.0
        entropy = 0.0
        length = len(data)
        for x in set(data):
            p_x = float(data.count(x)) / length
            entropy -= p_x * math.log(p_x, 2)
        return entropy

    def _sync_scan_files(self, base_path: Path) -> tuple[list[dict], list[dict], list[dict]]:
        """Synchronously scan files on disk for secret and crypto matches."""
        # Credentials are often shipped in packaged resources and cross-platform
        # bundles, not only decompiled JVM source. The inventory remains size/
        # entry bounded; React Native .bundle files use their dedicated scanner.
        target_exts = {
            ".java", ".kt", ".xml", ".json", ".properties", ".js", ".ts",
            ".dart", ".plist", ".yaml", ".yml", ".toml", ".conf", ".cfg",
            ".ini", ".gradle", ".kts",
        }
        raw_secret_matches = []
        crypto_matches = []
        entropy_matches = []

        inventory = SourceInventory()
        for file_path, data in inventory.read(base_path, target_exts,
                                               suffixes=(".gradle.kts",)):
            try:
                content = data.decode("utf-8", errors="ignore")
                rel_path = str(file_path.relative_to(base_path))
                
                for line_num, line in enumerate(content.splitlines(), start=1):
                    # Check regex patterns for secrets
                    if len(raw_secret_matches) < 1000:
                        for name, pattern in self.secret_patterns.items():
                            for match in pattern.finditer(line):
                                raw_secret_matches.append({
                                    "name": name,
                                    "val": match.group(0),
                                    "file_path": rel_path,
                                    "line_num": line_num,
                                    "line": line.strip(),
                                    "stem": file_path.stem
                                })
                                if len(raw_secret_matches) >= 1000:
                                    inventory.record_limit('secret_candidate_count')
                                    break
                            if len(raw_secret_matches) >= 1000:
                                break

                    # Catch unknown token formats conservatively. These are
                    # inventory leads only (INFO/CWE-Unknown); never retain the
                    # candidate literal in report evidence.
                    known_spans = [match.span() for pattern in self.secret_patterns.values()
                                   for match in pattern.finditer(line)]
                    for match in self._token_literal.finditer(line):
                        value = match.group(1)
                        if any(match.start(1) < end and match.end(1) > start for start, end in known_spans):
                            continue
                        is_context_entropy = (
                            self.calculate_entropy(value) >= self.entropy_threshold
                            and self._entropy_context.search(line[max(0, match.start() - 160):match.start(1)])
                        )
                        shape = self.key_shaped(value)
                        if len(entropy_matches) < 1000 and (is_context_entropy or shape):
                            entropy_matches.append({
                                "file_path": rel_path,
                                "line_num": line_num,
                                "stem": file_path.stem,
                                "shape": shape,
                            })
                        if len(entropy_matches) >= 1000:
                            inventory.record_limit('entropy_candidate_count')
                            break

                    # Check crypto patterns
                    if len(crypto_matches) < 1000:
                        for name, pattern in self.crypto_patterns.items():
                            if pattern.search(line):
                                crypto_matches.append({
                                    "name": name,
                                    "file_path": rel_path,
                                    "line_num": line_num,
                                    "line": line.strip(),
                                    "stem": file_path.stem
                                })
                                if len(crypto_matches) >= 1000:
                                    inventory.record_limit('crypto_candidate_count')
                                    break
            except (OSError, UnicodeError) as e:
                logger.debug(f"Could not read file {file_path}: {e}")
                continue
        self.coverage = dict(inventory.coverage)
        self.coverage.update(runtime_status='not_tested', proof_status='not_proven', exhaustive=False,
                             candidate_count=len(raw_secret_matches)+len(crypto_matches)+len(entropy_matches),
                             entropy_candidate_count=len(entropy_matches),
                             limits={'secret_candidates':1000,'crypto_candidates':1000,
                                     'entropy_candidates':1000,**inventory.coverage['limits']})
        return raw_secret_matches, crypto_matches, entropy_matches

    async def scan(self, decompiled_path: str) -> list[Finding]:
        """Scan files for hardcoded secrets and weak cryptography."""
        logger.info(f"Starting secret scan in: {decompiled_path}")
        findings: list[Finding] = []
        base_path = explicit_scan_root(decompiled_path)
        if base_path is None:
            self.coverage = {"static_status": "not_analyzed", "runtime_status": "not_tested",
                             "proof_status": "not_proven", "exhaustive": False}
            return findings
        
        # Offload file I/O and regex iteration to worker thread
        raw_secrets, crypto_matches, entropy_matches = await asyncio.to_thread(self._sync_scan_files, base_path)

        # Process crypto findings directly
        for item in crypto_matches:
            cwe = "CWE-327"
            findings.append(Finding(
                title=f"Weak Cryptography: {item['name']}",
                description=f"A source pattern resembling {item['name']} was found. Whether it is reachable, security-relevant or used for protection is not established.",
                severity=Severity.INFO,
                cwe_id=cwe,
                cvss_score=0.0,
                cvss_vector="",
                affected_component=item["stem"],
                detection_method="SecretScanner",
                status=FindingStatus.UNVERIFIED,
                remediation="Use strong modern cryptographic algorithms (e.g., AES/GCM/NoPadding) and secure key management.",
                file_path=item["file_path"],
                line_number=item["line_num"],
                code_snippet=item["line"]
            ))

        for item in entropy_matches:
            findings.append(Finding(
                title="Review High-Entropy String Literal",
                description=("A long quoted token-like string exceeds the configured Shannon-entropy threshold. "
                             "This is an unknown-format secret review lead only; hashes, identifiers and public keys "
                             "can also be high entropy. Value validity and secrecy are not established."),
                severity=Severity.INFO, cwe_id="CWE-Unknown", cvss_score=0.0,
                affected_component=item["stem"], detection_method="SecretScanner (entropy heuristic)",
                status=FindingStatus.UNVERIFIED, remediation="Verify whether the value is a credential; rotate only if it is a valid exposed secret.",
                file_path=item["file_path"], line_number=item["line_num"],
                code_snippet="[REDACTED high-entropy candidate; inspect original source locally]",
                metadata={"analysis_kind": "high_entropy_literal", "proof_state": "not_proven"},
            ))

        # Process and validate secrets with prompt sandboxing
        for item in raw_secrets:
            logger.debug("Candidate %s pattern found in %s", item['name'], item['file_path'])
            
            # Never send candidate credential bytes to a model. Pattern presence
            # is only a local review lead; it cannot establish validity/secrecy.
            cwe = "CWE-798"
            findings.append(Finding(
                    title=f"Hardcoded {item['name']}",
                    description=f"A {item['name']} pattern was identified; credential validity and secrecy require analyst review.",
                    severity=Severity.INFO,
                    cwe_id=cwe,
                    cvss_score=0.0,
                    cvss_vector="",
                    affected_component=item["stem"],
                    detection_method="SecretScanner",
                    status=FindingStatus.UNVERIFIED,
                    remediation="Extract sensitive credentials to secure remote vaults or Android Keystore backed by hardware security.",
                    file_path=item["file_path"],
                    line_number=item["line_num"],
                    code_snippet="[REDACTED credential; inspect the original file at the recorded line]"
                ))

        logger.info(f"Secret scan completed: {len(findings)} findings.")
        return findings
