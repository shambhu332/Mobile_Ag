import asyncio
import logging
import math
import re
from pathlib import Path
from typing import Any

from config.llm_config import TaskType
from mobileag.llm.router import LLMRouter
from mobileag.reporting.finding import Finding, Severity, FindingStatus
from mobileag.analysis.bounded_sources import SourceInventory

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
            "GitHub Access Token": re.compile(r"(?:ghp_[0-9a-zA-Z]{36}|github_pat_[0-9a-zA-Z_]{82})"),
            "Slack Webhook URL": re.compile(r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+"),
            "Stripe Secret Key": re.compile(r"sk_(?:live|test)_[0-9a-zA-Z]{24,}"),
            "Twilio Account SID": re.compile(r"AC[a-zA-Z0-9]{32}"),
            "OpenAI API Key": re.compile(r"sk-[a-zA-Z0-9]{32,}"),
            "xAI API Key": re.compile(r"xai-[a-zA-Z0-9_-]+"),
            "Firebase URL": re.compile(r"https://[a-zA-Z0-9_-]+\.firebaseio\.com"),
            "JWT Token": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
            "Private RSA/EC Key": re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"),
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

    def _sync_scan_files(self, base_path: Path) -> tuple[list[dict], list[dict]]:
        """Synchronously scan files on disk for secret and crypto matches."""
        target_exts = {".java", ".kt", ".xml", ".json", ".properties"}
        raw_secret_matches = []
        crypto_matches = []

        inventory = SourceInventory()
        for file_path, data in inventory.read(base_path, target_exts):
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
                                    inventory.coverage['limits_reached'] = True
                                    break
                            if len(raw_secret_matches) >= 1000:
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
                                    inventory.coverage['limits_reached'] = True
                                    break
            except (OSError, UnicodeError) as e:
                logger.debug(f"Could not read file {file_path}: {e}")
                continue
        self.coverage = dict(inventory.coverage)
        self.coverage.update(runtime_status='not_tested', proof_status='not_proven', exhaustive=False,
                             candidate_count=len(raw_secret_matches)+len(crypto_matches),
                             limits={'secret_candidates':1000,'crypto_candidates':1000,**inventory.coverage['limits']})
        return raw_secret_matches, crypto_matches

    async def scan(self, decompiled_path: str) -> list[Finding]:
        """Scan files for hardcoded secrets and weak cryptography."""
        logger.info(f"Starting secret scan in: {decompiled_path}")
        findings: list[Finding] = []
        base_path = Path(decompiled_path)
        
        # Offload file I/O and regex iteration to worker thread
        raw_secrets, crypto_matches = await asyncio.to_thread(self._sync_scan_files, base_path)

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
