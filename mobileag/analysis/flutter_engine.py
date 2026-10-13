"""Flutter Engine & Dart Binary Analyzer.

Inspects Flutter APK/AAB packages to extract embedded Dart snapshot strings,
network endpoints, named routes, and bundled asset configurations.
"""
from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set


@dataclass
class FlutterAnalysisResult:
    is_flutter_app: bool = False
    libapp_present: bool = False
    libflutter_present: bool = False
    extracted_strings_count: int = 0
    api_endpoints: List[str] = field(default_factory=list)
    named_routes: List[str] = field(default_factory=list)
    bundled_assets: List[str] = field(default_factory=list)
    potential_secrets: List[Dict[str, str]] = field(default_factory=list)


class FlutterEngineAnalyzer:
    """Analyzes compiled Flutter applications (libapp.so, libflutter.so, assets)."""

    URL_PATTERN = re.compile(r"https?://[a-zA-Z0-9.-]+(?::\d+)?(?:/[a-zA-Z0-9_.~!$&'()*+,;=:@%/-]*)?")
    SECRET_PATTERN = re.compile(r"(?:api_?key|auth_?token|bearer|secret|password)[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9_\-]{16,})[\"']", re.IGNORECASE)
    ROUTE_PATTERN = re.compile(r"/(?:login|auth|dashboard|settings|admin|profile|home|checkout|payment|cart)")

    def analyze_package_directory(self, extracted_dir: str | Path) -> FlutterAnalysisResult:
        """Scan extracted APK directory for Flutter libraries and assets."""
        base_path = Path(extracted_dir)
        result = FlutterAnalysisResult()

        lib_dir = base_path / "lib"
        assets_dir = base_path / "assets" / "flutter_assets"

        # Check for Flutter shared libraries
        if lib_dir.is_dir():
            for root, _, files in os.walk(lib_dir):
                if "libapp.so" in files:
                    result.libapp_present = True
                    result.is_flutter_app = True
                    self._extract_strings_from_binary(os.path.join(root, "libapp.so"), result)
                if "libflutter.so" in files:
                    result.libflutter_present = True
                    result.is_flutter_app = True

        # Check for Flutter assets
        if assets_dir.is_dir():
            result.is_flutter_app = True
            for root, _, files in os.walk(assets_dir):
                for f in files:
                    rel_path = os.path.relpath(os.path.join(root, f), str(assets_dir))
                    result.bundled_assets.append(rel_path)

        return result

    def _extract_strings_from_binary(self, binary_path: str, result: FlutterAnalysisResult, min_length: int = 4) -> None:
        """Extract ASCII strings from ELF binary and identify endpoints and secrets."""
        try:
            with open(binary_path, "rb") as f:
                data = f.read(10 * 1024 * 1024)  # Read up to 10MB
        except OSError:
            return

        # Simple ASCII / UTF-8 string scanner
        ascii_strings = re.findall(b"[\x20-\x7E]{" + str(min_length).encode() + b",}", data)
        result.extracted_strings_count = len(ascii_strings)

        endpoints: Set[str] = set()
        routes: Set[str] = set()

        for raw in ascii_strings:
            try:
                s = raw.decode("utf-8", errors="ignore")
            except Exception:
                continue

            for url in self.URL_PATTERN.findall(s):
                if not url.endswith((".png", ".jpg", ".svg", ".ttf", ".woff")):
                    endpoints.add(url)

            if self.ROUTE_PATTERN.search(s) and len(s) < 60 and not s.startswith("http"):
                routes.add(s)

            secret_match = self.SECRET_PATTERN.search(s)
            if secret_match:
                result.potential_secrets.append({"raw": s[:80], "candidate": secret_match.group(1)})

        result.api_endpoints = sorted(endpoints)[:100]
        result.named_routes = sorted(routes)[:100]
