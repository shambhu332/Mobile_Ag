"""Bounded Smali string-inventory helper for resilience review (not MASVS scoring).

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
    passed: Optional[bool] = None  # None means the analyzer cannot determine pass/fail


@dataclass
class ResilienceAssessmentResult:
    overall_score: Optional[float] = None
    grade: str = "Not validated"
    vectors: Dict[str, ResilienceVectorScore] = field(default_factory=dict)


class RaspResilienceAuditor:
    """Inventory candidate resilience-related strings without scoring effectiveness."""

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

        # These are candidate indicators only. Their observed presence does not
        # prove that a defense is reachable, effective, or complete.
        obf_ratio = (obfuscated_classes / total_classes * 100.0) if total_classes > 0 else 0.0
        v_obf = ResilienceVectorScore(
            vector_name="Identifier Obfuscation",
            masvs_category="MASVS-RESILIENCE-1",
            score=None,
            detected_indicators=[f"Obfuscated class ratio: {obf_ratio:.1f}% ({obfuscated_classes}/{total_classes})"],
            passed=None,
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

        # Entropy is a content statistic, not evidence of string encryption.
        avg_entropy = self._calculate_average_entropy(string_samples)
        v_entropy = ResilienceVectorScore(
            vector_name="String Pool Encryption",
            masvs_category="MASVS-RESILIENCE-3",
            score=None,
            detected_indicators=[f"Average entropy of sampled strings: {avg_entropy:.2f} bits/character; encryption not inferred"],
            passed=None,
        )

        # 4. Anti-Root / Jailbreak
        v_root = ResilienceVectorScore(
            vector_name="Device Integrity & Root Detection",
            masvs_category="MASVS-RESILIENCE-4",
            score=None,
            detected_indicators=sorted(root_detections) or ["No root-related indicator strings found in scanned Smali"],
            passed=None,
        )

        # 5. Anti-Debugging
        v_debug = ResilienceVectorScore(
            vector_name="Anti-Debugging & Dynamic Inspection",
            masvs_category="MASVS-RESILIENCE-5",
            score=None,
            detected_indicators=sorted(debug_detections) or ["No debug-related indicator strings found in scanned Smali"],
            passed=None,
        )

        # 6. Tamper Resistance
        v_tamper = ResilienceVectorScore(
            vector_name="Signature Verification & Tamper Resistance",
            masvs_category="MASVS-RESILIENCE-6",
            score=None,
            detected_indicators=sorted(tamper_detections) or ["No signature/tamper-related indicator strings found in scanned Smali"],
            passed=None,
        )

        result.vectors = {
            "obfuscation": v_obf,
            "control_flow": v_flow,
            "string_encryption": v_entropy,
            "root_detection": v_root,
            "anti_debugging": v_debug,
            "tamper_resistance": v_tamper,
        }

        # No aggregate score: these unrelated string/name heuristics are not
        # validated measures of resilience or MASVS conformance.
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
