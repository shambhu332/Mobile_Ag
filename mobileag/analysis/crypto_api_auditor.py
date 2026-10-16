"""Bounded static inventory of literal platform cryptography API calls.

This module records only API names, allowlisted algorithm/mode literals, counts,
and source locations. It never evaluates or records key, IV, or plaintext data.
"""
from __future__ import annotations

from bisect import bisect_left
import re
from pathlib import Path

from mobileag.analysis.api_mapper import _mask_java_kotlin_comments
from mobileag.analysis.bounded_sources import SourceInventory, explicit_scan_root


_FACTORIES = {
    "Cipher": "javax.crypto.Cipher",
    "Mac": "javax.crypto.Mac",
    "KeyGenerator": "javax.crypto.KeyGenerator",
    "SecretKeyFactory": "javax.crypto.SecretKeyFactory",
    "KeyAgreement": "javax.crypto.KeyAgreement",
    "MessageDigest": "java.security.MessageDigest",
    "Signature": "java.security.Signature",
    "KeyPairGenerator": "java.security.KeyPairGenerator",
}
_API_NAMES = "|".join(sorted(_FACTORIES))
_CALL_RE = re.compile(rf"\b(?P<class>{_API_NAMES})\s*\.\s*getInstance\s*\(")
_LITERAL_RE = re.compile(
    rf"\b(?P<class>{_API_NAMES})\s*\.\s*getInstance\s*\(\s*"
    r"(?P<quote>['\"])(?P<algorithm>[^'\"\r\n]{1,256})(?P=quote)"
)
_ALGORITHM_RE = re.compile(
    r"(?:AES(?:/(?:GCM|CBC|CTR|ECB|CCM|XTS|CFB|OFB|KW|KWP)"
    r"(?:/(?:NoPadding|PKCS5Padding|PKCS7Padding))?)?|"
    r"RSA(?:/(?:ECB|NONE)/(?:OAEPWithSHA-(?:1|256|384|512)AndMGF1Padding|"
    r"PKCS1Padding|NoPadding))?|"
    r"(?:SHA-?(?:1|224|256|384|512)|SHA3-(?:224|256|384|512))"
    r"(?:with(?:RSA|ECDSA|DSA))?|MD5|"
    r"HmacSHA(?:1|224|256|384|512)|"
    r"(?:Ed25519|Ed448|X25519|X448|ECDH|ECDSA|DSA|DH|"
    r"DES|DESede|Blowfish|RC2|ChaCha20|Poly1305)|"
    r"PBKDF2WithHmacSHA(?:1|224|256|384|512)|"
    r"PBEWithHmacSHA(?:1|256|512)AndAES(?:_128|_256))\Z",
    re.IGNORECASE,
)


class CryptoApiMetadataAuditor:
    """Report bounded source-level factory calls without security verdicts."""

    MAX_RECORDS = 500
    MAX_LOCATIONS_PER_RECORD = 20
    MAX_INVENTORY_ENTRIES = 5000
    MAX_FILE_BYTES = 2 * 1024 * 1024
    MAX_TOTAL_BYTES = 32 * 1024 * 1024

    def audit_directory(self, directory: str | Path | None) -> dict:
        root = explicit_scan_root(directory)
        if root is None:
            return self._empty("not_analyzed", "source root is absent or invalid")
        if root.is_symlink() or not root.is_dir():
            return self._empty("incomplete", "source root is unavailable or unsafe")

        inventory = SourceInventory(
            max_entries=self.MAX_INVENTORY_ENTRIES,
            max_file_bytes=self.MAX_FILE_BYTES,
            max_total_bytes=self.MAX_TOTAL_BYTES,
        )
        records: dict[tuple[str, str], dict] = {}
        factory_calls = 0
        unmodeled_calls = 0
        records_truncated = False
        decode_errors = 0
        for path, raw in inventory.read(root, {".java", ".kt"}):
            try:
                source = raw.decode("utf-8")
            except UnicodeDecodeError:
                decode_errors += 1
                continue
            masked = _mask_java_kotlin_comments(source)
            literal_matches = list(_LITERAL_RE.finditer(masked))
            literals_by_start = {match.start(): match for match in literal_matches}
            newline_offsets = [index for index, char in enumerate(masked) if char == "\n"]
            for call in _CALL_RE.finditer(masked):
                factory_calls += 1
                match = literals_by_start.get(call.start())
                if match is None:
                    unmodeled_calls += 1
                    continue
                algorithm = match.group("algorithm")
                if not _ALGORITHM_RE.fullmatch(algorithm):
                    unmodeled_calls += 1
                    continue
                api = _FACTORIES[match.group("class")]
                key = (api, algorithm)
                record = records.get(key)
                if record is None:
                    if len(records) >= self.MAX_RECORDS:
                        records_truncated = True
                        continue
                    record = {"api": api, "algorithm": algorithm, "call_count": 0,
                              "locations": []}
                    records[key] = record
                record["call_count"] += 1
                if len(record["locations"]) < self.MAX_LOCATIONS_PER_RECORD:
                    line = bisect_left(newline_offsets, match.start()) + 1
                    try:
                        relative = str(path.relative_to(root))[:512]
                    except ValueError:
                        relative = "<outside-root>"
                    record["locations"].append({"file": relative, "line": line})

        status = inventory.coverage.get("static_status", "not_analyzed")
        if records_truncated or decode_errors or unmodeled_calls:
            status = "partial"
        limitations = [
            "Only Java/Kotlin literal getInstance calls for selected platform APIs are inventoried.",
            "Class-name matching is lexical; imports and same-named application classes are not resolved.",
            "Smali, native, reflection, aliases, dynamic algorithm names, dataflow, and runtime calls are not resolved.",
            "No key sizes, key material, IVs, plaintext, cryptographic correctness, or reachability are inferred.",
        ]
        return {
            "inventory": sorted(records.values(), key=lambda row: (row["api"], row["algorithm"])),
            "coverage": {
                **inventory.coverage,
                "static_status": status,
                "runtime_status": "not_tested",
                "proof_status": "not_proven",
                "exhaustive": False,
                "analysis_kind": "bounded_java_kotlin_crypto_factory_inventory",
                "factory_call_count": factory_calls,
                "literal_algorithm_call_count": sum(row["call_count"] for row in records.values()),
                "candidate_count": sum(row["call_count"] for row in records.values()),
                "unmodeled_call_count": unmodeled_calls,
                "algorithm_record_count": len(records),
                "records_truncated": records_truncated,
                "decode_error_files": decode_errors,
                "limitations": limitations,
            },
        }

    @staticmethod
    def _empty(status: str, reason: str) -> dict:
        return {
            "inventory": [],
            "coverage": {
                "static_status": status,
                "runtime_status": "not_tested",
                "proof_status": "not_proven",
                "exhaustive": False,
                "analysis_kind": "bounded_java_kotlin_crypto_factory_inventory",
                "factory_call_count": 0,
                "literal_algorithm_call_count": 0,
                "candidate_count": 0,
                "unmodeled_call_count": 0,
                "algorithm_record_count": 0,
                "records_truncated": False,
                "decode_error_files": 0,
                "source_files_analyzed": 0,
                "source_files_skipped": 0,
                "limits_reached": False,
                "limitations": [reason],
            },
        }
