"""Compatibility facade for bounded WebView lexical review, not exploit proof."""
from __future__ import annotations
import asyncio
from pathlib import Path
from mobileag.analysis.android_surface import AndroidSurfaceAnalyzer


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
        if file_path.is_symlink() or file_path.stat().st_size > 2 * 1024 * 1024:
            return []
        findings, _ = AndroidSurfaceAnalyzer().analyze_source(
            file_path.read_text(errors="replace"), str(file_path))
        return [finding for finding in findings if finding.metadata.get("category") == "webview"]
