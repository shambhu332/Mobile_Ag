"""Flutter Engine & Dart Binary Analyzer.

Inspects Flutter APK/AAB packages to extract embedded Dart snapshot strings,
network endpoints, named routes, and bundled asset configurations.
"""
from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set
from mobileag.analysis.bounded_sources import SourceInventory, explicit_scan_root
from mobileag.analysis.api_endpoint_safety import safe_api_route


@dataclass
class FlutterAnalysisResult:
    is_flutter_app: bool = False
    libapp_present: bool = False
    libflutter_present: bool = False
    extracted_strings_count: int = 0
    api_endpoints: List[str] = field(default_factory=list)
    named_routes: List[str] = field(default_factory=list)
    bundled_assets: List[str] = field(default_factory=list)
    potential_secrets: List[Dict[str, object]] = field(default_factory=list)
    scan_status: str = "not_started"
    tree_entries_scanned: int = 0
    binary_bytes_scanned: int = 0
    binary_truncated: bool = False
    asset_inventory_truncated: bool = False
    candidate_output_truncated: bool = False
    scan_errors: List[str] = field(default_factory=list)


class FlutterEngineAnalyzer:
    """Analyzes compiled Flutter applications (libapp.so, libflutter.so, assets)."""

    MAX_TREE_ENTRIES = 50_000
    MAX_BINARY_BYTES = 10 * 1024 * 1024
    MAX_TOTAL_BINARY_BYTES = 32 * 1024 * 1024
    MAX_PRINTABLE_STRINGS_PER_BINARY = 100_000
    MAX_ASSETS = 10_000
    MAX_ENDPOINTS = 100
    MAX_NAMED_ROUTES = 100
    MAX_SECRET_MARKERS = 100

    URL_PATTERN = re.compile(r"https?://[a-zA-Z0-9.-]+(?::\d+)?(?:/[a-zA-Z0-9_.~!$&'()*+,;=:@%/-]*)?")
    SECRET_PATTERN = re.compile(r"(?:api_?key|auth_?token|bearer|secret|password)[\"']?\s*[:=]\s*[\"']([a-zA-Z0-9_\-]{16,})[\"']", re.IGNORECASE)
    ROUTE_PATTERN = re.compile(r"/(?:login|auth|dashboard|settings|admin|profile|home|checkout|payment|cart)")

    def analyze_package_directory(self, extracted_dir: str | Path) -> FlutterAnalysisResult:
        """Scan extracted APK directory for Flutter libraries and assets."""
        base_path = explicit_scan_root(extracted_dir)
        result = FlutterAnalysisResult()
        if base_path is None or base_path.is_symlink() or not base_path.is_dir():
            result.scan_status = "invalid"
            result.scan_errors.append("invalid_scan_root")
            return result

        lib_dir = base_path / "lib"
        assets_dir = base_path / "assets" / "flutter_assets"
        inventory = SourceInventory(max_entries=self.MAX_TREE_ENTRIES, max_file_bytes=1,
                                    max_total_bytes=1)
        limited = False

        def has_symlink_component(path: Path) -> bool:
            current = path
            while current != base_path:
                if current.is_symlink():
                    return True
                current = current.parent
            return base_path.is_symlink()

        # Check for Flutter shared libraries
        if has_symlink_component(lib_dir):
            result.scan_errors.append("symlink_library_directory_skipped")
        elif lib_dir.is_dir():
            for binary in inventory.paths(lib_dir):
                if binary.name == "libapp.so":
                    result.libapp_present = True
                    result.is_flutter_app = True
                    self._extract_strings_from_binary(str(binary), result)
                elif binary.name == "libflutter.so":
                    result.libflutter_present = True
                    result.is_flutter_app = True

        # Check for Flutter assets
        if has_symlink_component(assets_dir):
            result.scan_errors.append("symlink_asset_directory_skipped")
        elif assets_dir.is_dir():
            result.is_flutter_app = True
            for candidate in inventory.paths(assets_dir):
                if len(result.bundled_assets) >= self.MAX_ASSETS:
                    result.asset_inventory_truncated = True
                    limited = True
                    inventory.record_limit("asset_count")
                    break
                result.bundled_assets.append(candidate.relative_to(assets_dir).as_posix())

        result.tree_entries_scanned = inventory.coverage["entries_examined"]
        if inventory.coverage["limits_reached"]:
            limited = True
            result.scan_errors.append("tree_entry_limit")
        if inventory.coverage["source_file_skip_reasons"].get("symlink_entry"):
            result.scan_errors.append("symlink_entry_skipped")
        if inventory.coverage["source_file_skip_reasons"].get("directory_read_error"):
            result.scan_errors.append("directory_scan_error")

        result.scan_errors = sorted(set(result.scan_errors))
        result.scan_status = "partial" if limited or result.scan_errors or result.binary_truncated else "complete"

        return result

    def _extract_strings_from_binary(self, binary_path: str, result: FlutterAnalysisResult, min_length: int = 4) -> None:
        """Extract ASCII strings from ELF binary and identify endpoints and secrets."""
        remaining = self.MAX_TOTAL_BINARY_BYTES - result.binary_bytes_scanned
        if remaining <= 0:
            result.binary_truncated = True
            result.scan_errors.append("total_binary_byte_limit")
            return
        read_limit = min(self.MAX_BINARY_BYTES, remaining)
        try:
            fd = os.open(binary_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as f:
                if not stat.S_ISREG(os.fstat(f.fileno()).st_mode):
                    result.scan_errors.append("non_regular_binary_skipped")
                    return
                data = f.read(read_limit + 1)
                if len(data) > read_limit:
                    result.binary_truncated = True
                    data = data[:read_limit]
                    result.scan_errors.append(
                        "total_binary_byte_limit" if read_limit == remaining else "binary_file_byte_limit"
                    )
                result.binary_bytes_scanned += len(data)
        except OSError:
            result.scan_errors.append("binary_read_error")
            return

        # Simple ASCII / UTF-8 string scanner
        endpoints: Set[str] = set(result.api_endpoints)
        routes: Set[str] = set(result.named_routes)
        strings_scanned = 0
        string_pattern = b"[\x20-\x7E]{" + str(min_length).encode() + b",}"
        for match in re.finditer(string_pattern, data):
            if strings_scanned >= self.MAX_PRINTABLE_STRINGS_PER_BINARY:
                result.candidate_output_truncated = True
                result.scan_errors.append("printable_string_limit")
                break
            strings_scanned += 1
            raw = match.group(0)
            try:
                s = raw.decode("utf-8", errors="ignore")
            except Exception:
                continue

            for url in self.URL_PATTERN.findall(s):
                safe_url = safe_api_route(url)
                if (safe_url != "[REDACTED URL]"
                        and not safe_url.endswith((".png", ".jpg", ".svg", ".ttf", ".woff"))):
                    if safe_url not in endpoints and len(endpoints) >= self.MAX_ENDPOINTS:
                        result.candidate_output_truncated = True
                        result.scan_errors.append("endpoint_candidate_limit")
                    else:
                        endpoints.add(safe_url)

            if self.ROUTE_PATTERN.search(s) and len(s) < 60 and not s.startswith("http"):
                if s not in routes and len(routes) >= self.MAX_NAMED_ROUTES:
                    result.candidate_output_truncated = True
                    result.scan_errors.append("route_candidate_limit")
                else:
                    routes.add(s)

            secret_match = self.SECRET_PATTERN.search(s)
            if secret_match:
                # Keep the signal, never copy a credential-like value from an
                # application binary into a report or downstream persistence.
                if len(result.potential_secrets) >= self.MAX_SECRET_MARKERS:
                    result.candidate_output_truncated = True
                    result.scan_errors.append("secret_marker_limit")
                else:
                    result.potential_secrets.append({"name": "embedded credential", "value_redacted": True})

        result.extracted_strings_count += strings_scanned
        result.api_endpoints = sorted(endpoints)
        result.named_routes = sorted(routes)
