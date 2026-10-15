"""OWASP MASVS-RESILIENCE Binary Hardening & RASP Auditor.

Evaluates an Android application binary across 6 core resilience vectors:
1. Identifier Obfuscation Ratio
2. Control Flow Complexity & Flattening
3. String Pool Entropy & Encryption
4. Anti-Root / Jailbreak Detection Checks
5. Anti-Debugging & Tracer Checks
6. Signature & Tamper Verification Checks
"""
from __future__ import annotations

import math
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional


@dataclass
class ResilienceVectorScore:
    vector_name: str
    masvs_category: str
    score: Optional[float]  # None when this vector is not meaningfully measured
    detected_indicators: List[str] = field(default_factory=list)
    passed: Optional[bool] = False  # None means the analyzer cannot determine pass/fail


@dataclass
class ResilienceAssessmentResult:
    overall_score: Optional[float] = None
    grade: str = "Not validated"
    vectors: Dict[str, ResilienceVectorScore] = field(default_factory=dict)


class RaspResilienceAuditor:
    """Evaluates mobile binary resilience against reverse engineering and tampering."""

    ROOT_INDICATORS = [
        "su", "/system/bin/su", "/system/xbin/su", "/sbin/su", "daemonsu",
        "magisk", "zygisk", "Superuser", "eu.chainfire.supersu", "busybox",
        "test-keys", "which su", "/data/local/su"
    ]

    DEBUG_INDICATORS = [
        "isDebuggerConnected", "waitingForDebugger", "ptrace",
        "PTRACE_TRACEME", "TracerPid", "/proc/self/status", "android:debuggable"
    ]

    TAMPER_INDICATORS = [
        "GET_SIGNATURES", "GET_SIGNING_CERTIFICATES", "getPackageInfo",
        "verifySignature", "checkSignature", "SHA-256", "signingCertificateHistory"
    ]

    def audit_package(self, smali_dir: str | Path) -> ResilienceAssessmentResult:
        """Audit decompiled Smali sources for resilience vectors."""
        path = Path(smali_dir)
        result = ResilienceAssessmentResult()

        total_classes = 0
        obfuscated_classes = 0
        root_detections: set[str] = set()
        debug_detections: set[str] = set()
        tamper_detections: set[str] = set()
        string_samples: List[str] = []

        if not path.is_dir():
            return result

        for root, _, files in os.walk(path):
            for file in files:
                if file.endswith(".smali"):
                    total_classes += 1
                    base_name = file[:-6]
                    # Obfuscated names are typically 1-3 characters (e.g. a.smali, b.smali, x1.smali)
                    if len(base_name) <= 2 or (len(base_name) == 3 and base_name[0].isalpha() and base_name[1:].isdigit()):
                        obfuscated_classes += 1

                    full_path = os.path.join(root, file)
                    try:
                        with open(full_path, "r", encoding="utf-8", errors="replace") as f:
                            content = f.read()
                    except OSError:
                        continue

                    # Scan indicators
                    for ind in self.ROOT_INDICATORS:
                        if ind in content:
                            root_detections.add(ind)
                    for ind in self.DEBUG_INDICATORS:
                        if ind in content:
                            debug_detections.add(ind)
                    for ind in self.TAMPER_INDICATORS:
                        if ind in content:
                            tamper_detections.add(ind)

                    # Extract const-string samples for entropy
                    for s_match in re.findall(r'const-string[^\"]*\"([^\"]+)\"', content):
                        if len(s_match) > 8:
                            string_samples.append(s_match)
                            if len(string_samples) >= 500:
                                break

        # 1. Identifier Obfuscation
        obf_ratio = (obfuscated_classes / total_classes * 100.0) if total_classes > 0 else 0.0
        v_obf = ResilienceVectorScore(
            vector_name="Identifier Obfuscation",
            masvs_category="MASVS-RESILIENCE-1",
            score=min(100.0, obf_ratio * 1.25),
            detected_indicators=[f"Obfuscated class ratio: {obf_ratio:.1f}% ({obfuscated_classes}/{total_classes})"],
            passed=obf_ratio >= 40.0,
        )

        # 2. Control flow cannot be inferred from class-name obfuscation. Do not
        # fabricate a score or pass/fail result from an unrelated signal.
        v_flow = ResilienceVectorScore(
            vector_name="Control Flow Flattening",
            masvs_category="MASVS-RESILIENCE-2",
            score=None,
            detected_indicators=["Not assessed: control-flow graph/branch analysis is not implemented"],
            passed=None,
        )

        # 3. String Pool Entropy
        avg_entropy = self._calculate_average_entropy(string_samples)
        # High entropy (> 4.5 bits) suggests encrypted or packed strings
        entropy_score = min(100.0, max(0.0, (avg_entropy - 3.0) * 50.0))
        v_entropy = ResilienceVectorScore(
            vector_name="String Pool Encryption",
            masvs_category="MASVS-RESILIENCE-3",
            score=entropy_score,
            detected_indicators=[f"Average string entropy: {avg_entropy:.2f} bits/byte"],
            passed=avg_entropy >= 4.2,
        )

        # 4. Anti-Root / Jailbreak
        root_score = min(100.0, len(root_detections) * 20.0)
        v_root = ResilienceVectorScore(
            vector_name="Device Integrity & Root Detection",
            masvs_category="MASVS-RESILIENCE-4",
            score=root_score,
            detected_indicators=sorted(root_detections),
            passed=len(root_detections) >= 3,
        )

        # 5. Anti-Debugging
        debug_score = min(100.0, len(debug_detections) * 33.3)
        v_debug = ResilienceVectorScore(
            vector_name="Anti-Debugging & Dynamic Inspection",
            masvs_category="MASVS-RESILIENCE-5",
            score=debug_score,
            detected_indicators=sorted(debug_detections),
            passed=len(debug_detections) >= 2,
        )

        # 6. Tamper Resistance
        tamper_score = min(100.0, len(tamper_detections) * 33.3)
        v_tamper = ResilienceVectorScore(
            vector_name="Signature Verification & Tamper Resistance",
            masvs_category="MASVS-RESILIENCE-6",
            score=tamper_score,
            detected_indicators=sorted(tamper_detections),
            passed=len(tamper_detections) >= 2,
        )

        result.vectors = {
            "obfuscation": v_obf,
            "control_flow": v_flow,
            "string_encryption": v_entropy,
            "root_detection": v_root,
            "anti_debugging": v_debug,
            "tamper_resistance": v_tamper,
        }

        # Calculate Overall Weighted Score
        # An aggregate score would imply comparable, validated measurements;
        # the current heuristics do not support that interpretation.
        result.overall_score = None

        return result

    def _calculate_average_entropy(self, samples: List[str]) -> float:
        """Calculate Shannon entropy across string samples."""
        if not samples:
            return 0.0

        total_entropy = 0.0
        count = 0
        for s in samples[:200]:
            if not s:
                continue
            prob = [float(s.count(c)) / len(s) for c in dict.fromkeys(list(s))]
            entropy = -sum([p * math.log(p) / math.log(2.0) for p in prob])
            total_entropy += entropy
            count += 1

        return (total_entropy / count) if count > 0 else 0.0
