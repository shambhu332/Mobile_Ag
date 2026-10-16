import logging
import fnmatch
from pathlib import Path
from mobileag.analysis.bounded_sources import SourceInventory
from typing import Any, Dict

logger = logging.getLogger(__name__)

class FrameworkDetector:
    """
    Detects cross-platform frameworks used in the app.
    """

    def __init__(self) -> None:
        pass

    def detect(self, decompiled_path: str) -> Dict[str, Any]:
        """
        Detects if a mobile app is built with a cross-platform framework.

        Args:
            decompiled_path: Path to the root of the decompiled APK (e.g., apktool out).

        Returns:
            A dictionary containing detection results.
        """
        inventory = SourceInventory(max_entries=5000)
        if not decompiled_path:
            return {
                "framework": "Unknown",
                "version_hint": "unknown",
                "detection_evidence": [],
                "analysis_notes": ["Decompiled directory not found."],
                "coverage": dict(inventory.coverage),
            }
        base_dir = Path(decompiled_path)
        
        frameworks = {
            "React Native": {
                "evidence": [
                    "assets/index.android.bundle",
                    "smali/com/facebook/react"
                ]
            },
            "Flutter": {
                "evidence": [
                    "lib/*/libflutter.so",
                    "smali/io/flutter"
                ]
            },
            "Xamarin": {
                "evidence": [
                    "assemblies",
                    "lib/*/libmonodroid.so",
                    "unknown/assemblies"
                ]
            },
            "Cordova": {
                "evidence": [
                    "assets/www/cordova.js",
                    "smali/org/apache/cordova"
                ]
            },
            "Unity": {
                "evidence": [
                    "lib/*/libunity.so",
                    "lib/*/libil2cpp.so",
                    "assets/bin/Data"
                ]
            }
        }

        detected_framework = "Native"
        detected_frameworks = []
        version_hint = "unknown"
        detected_evidence = []
        notes = []

        if not decompiled_path or not base_dir.is_dir():
            logger.error(f"Decompiled path does not exist: {decompiled_path}")
            return {
                "framework": "Unknown",
                "version_hint": version_hint,
                "detection_evidence": [],
                "analysis_notes": ["Decompiled directory not found."],
                "coverage": dict(inventory.coverage),
            }

        paths = list(inventory.paths(base_dir))
        relative_paths = [str(path.relative_to(base_dir)) for path in paths]

        for framework, data in frameworks.items():
            for pattern in data["evidence"]:
                prefix = pattern.rstrip("/") + "/"
                if any(fnmatch.fnmatchcase(rel, pattern) or rel == pattern or rel.startswith(prefix)
                       for rel in relative_paths):
                    if framework not in detected_frameworks:
                        detected_frameworks.append(framework)
                    detected_evidence.append(pattern)

        # Preserve the historical singular field for callers (last matching
        # signature family wins), but do not lose evidence when a package
        # contains signatures for more than one framework. Ordering is
        # deterministic and is not a confidence ranking or proof that
        # framework code ran.
        if detected_frameworks:
            detected_framework = detected_frameworks[-1]
            notes.append(f"Detected {detected_framework} artifacts.")
        else:
            notes.append("No common cross-platform framework signatures found. Assuming Native.")

        return {
            "framework": detected_framework,
            "detected_frameworks": detected_frameworks,
            "version_hint": version_hint,
            "detection_evidence": detected_evidence,
            "analysis_notes": notes,
            "coverage": dict(inventory.coverage)
        }
