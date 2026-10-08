"""Compatibility facade for bounded WebView lexical review, not exploit proof."""
from __future__ import annotations
import asyncio
from pathlib import Path
from mobileag.analysis.android_surface import AndroidSurfaceAnalyzer
from mobileag.analysis.bounded_sources import SourceInventory


class WebViewAuditor:
    def __init__(self, scan_id: str = ""):
        self.scan_id = scan_id
        self.coverage = {"static_status": "not_analyzed", "runtime_status": "not_tested"}

    async def audit_source(self, decompiled_dir: str | Path):
        result = await asyncio.to_thread(AndroidSurfaceAnalyzer().scan, decompiled_dir, {})
        self.coverage = result["coverage"]["categories"]["webview"]
        return [finding for finding in result["findings"]
                if finding.metadata.get("category") == "webview"]

    def _analyze_file(self, file_path: Path):
        inventory = SourceInventory(max_file_bytes=2*1024*1024, max_total_bytes=2*1024*1024)
        for candidate, data in inventory.read(file_path.parent, {file_path.suffix}, names={file_path.name}):
            if candidate != file_path:
                continue
            findings, _ = AndroidSurfaceAnalyzer().analyze_source(
                data.decode("utf-8", errors="replace"), str(file_path))
            self.coverage = dict(inventory.coverage)
            return [finding for finding in findings if finding.metadata.get("category") == "webview"]
        self.coverage = dict(inventory.coverage)
        return []
