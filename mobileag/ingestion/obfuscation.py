import logging
import re
from pathlib import Path
from typing import Any, Dict
from mobileag.analysis.bounded_sources import SourceInventory

logger = logging.getLogger(__name__)

class ObfuscationAnalyzer:
    """
    Assesses the level of obfuscation in the decompiled Java code.
    """

    def __init__(self) -> None:
        self.coverage = {"static_status": "not_analyzed", "exhaustive": False}

    def analyze(self, decompiled_path: str) -> Dict[str, Any]:
        """
        Analyzes decompiled source code to measure obfuscation.

        Args:
            decompiled_path: Path to the JADX decompiled output.

        Returns:
            Dictionary with obfuscation metrics and recommendations.
        """
        self.coverage = {"static_status": "not_analyzed", "exhaustive": False}
        base_dir = Path(decompiled_path)
        
        proguard_detected = False
        string_encryption_detected = False
        api_anchor_classes = []
        
        if not decompiled_path or not base_dir.is_dir():
            logger.error("Decompiled directory does not exist.")
            return self._build_result("unknown", False, False, [], ["Cannot access decompiled code."])

        # Analyze a subset of files to save time
        inventory = SourceInventory(max_entries=5000, max_file_bytes=2*1024*1024,
                                    max_total_bytes=32*1024*1024)
        source_rows = list(inventory.read(base_dir, {".java"}))
        self.coverage = dict(inventory.coverage)
        java_files = [path for path, _ in source_rows]
        if not java_files:
            return self._build_result("none", False, False, [], ["No Java source files found."])

        total_files = len(java_files)
        short_name_count = 0
        encrypted_string_patterns = 0
        
        # Pattern to check for basic byte array decryption loops or base64 decoding in static blocks
        str_enc_pattern = re.compile(r'(Base64\.decode|Cipher\.getInstance|\^= \d+|<< \d+)')

        sample_size = min(total_files, 500)  # Check up to 500 files
        for i, (file_path, data) in enumerate(source_rows[:sample_size]):
            
            # Check for ProGuard (short class names)
            if len(file_path.stem) <= 2:
                short_name_count += 1

            # Check for standard API usage as anchors (unobfuscated parts)
            if "Activity" in file_path.name or "Service" in file_path.name:
                api_anchor_classes.append(file_path.stem)

            # Check for string encryption in content
            try:
                content = data.decode('utf-8', errors='ignore')
                if str_enc_pattern.search(content):
                    encrypted_string_patterns += 1
            except Exception:
                pass

        # Calculate heuristics
        short_name_ratio = short_name_count / sample_size
        if short_name_ratio > 0.1:
            proguard_detected = True

        if encrypted_string_patterns > 0:
            string_encryption_detected = True

        # Determine level
        level = "none"
        if proguard_detected and string_encryption_detected:
            level = "moderate"
            if short_name_ratio > 0.5 and encrypted_string_patterns > (sample_size * 0.05):
                level = "heavy"
        elif proguard_detected:
            level = "light"
        elif string_encryption_detected:
            level = "moderate"

        recommendations = []
        if level != "none":
            recommendations.append("Obfuscation detected. Analysis might yield false negatives.")
        if string_encryption_detected:
            recommendations.append("String encryption detected. Consider dynamic analysis to recover plaintexts.")
        if proguard_detected:
            recommendations.append("Identifier renaming detected (ProGuard/R8). Map back traces if mapping.txt is available.")

        return self._build_result(
            level, 
            proguard_detected, 
            string_encryption_detected, 
            api_anchor_classes[:10], # limit to 10 anchors
            recommendations
        )

    def _build_result(self, level: str, proguard: bool, str_enc: bool, anchors: list, recs: list) -> Dict[str, Any]:
        return {
            "level": level,
            "proguard_detected": proguard,
            "string_encryption_detected": str_enc,
            "api_anchor_classes": anchors,
            "recommendations": recs,
            "coverage": dict(self.coverage)
        }
