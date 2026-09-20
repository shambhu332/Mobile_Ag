import logging
from pathlib import Path
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
        version_hint = "unknown"
        detected_evidence = []
        notes = []

        if not base_dir.exists():
            logger.error(f"Decompiled path does not exist: {decompiled_path}")
            return {
                "framework": "Unknown",
                "version_hint": version_hint,
                "detection_evidence": [],
                "analysis_notes": ["Decompiled directory not found."]
            }

        for framework, data in frameworks.items():
            for pattern in data["evidence"]:
                # Use glob to handle patterns like lib/*/libflutter.so
                matches = list(base_dir.rglob(pattern.replace("*/", "*"))) if "*" in pattern else [base_dir / pattern]
                
                for match in matches:
                    if match.exists() or list(base_dir.glob(f"**/{pattern}")):
                        if framework not in detected_framework:
                            detected_framework = framework
                        detected_evidence.append(pattern)

        if detected_framework != "Native":
            notes.append(f"Detected {detected_framework} artifacts.")
        else:
            notes.append("No common cross-platform framework signatures found. Assuming Native.")

        return {
            "framework": detected_framework,
            "version_hint": version_hint,
            "detection_evidence": detected_evidence,
            "analysis_notes": notes
        }
