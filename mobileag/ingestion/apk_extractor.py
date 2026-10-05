import asyncio
import logging
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict

from config.settings import Settings

logger = logging.getLogger(__name__)

class APKExtractor:
    """
    Extracts and decompiles an APK using APKTool and JADX.
    """

    def __init__(self, settings: Settings) -> None:
        """
        Initializes the APKExtractor.

        Args:
            settings: Configuration settings containing tool paths.
        """
        self.settings = settings
        configured_jadx = getattr(settings, "JADX_PATH", None)
        if configured_jadx and Path(configured_jadx).exists():
            self.jadx_path = configured_jadx
        else:
            self.jadx_path = shutil.which("jadx") or "jadx"

        configured_apktool = getattr(settings, "APKTOOL_PATH", None)
        if configured_apktool and Path(configured_apktool).exists():
            self.apktool_path = configured_apktool
        else:
            self.apktool_path = shutil.which("apktool") or "apktool"

    async def extract(self, apk_path: str, output_dir: str) -> Dict[str, Any]:
        """
        Extracts resources and Java source code from the APK.

        Args:
            apk_path: The path to the APK file.
            output_dir: The directory where the extracted files will be saved.

        Returns:
            A dictionary containing paths to the extracted directories, the manifest,
            and the parsed package name.
        """
        apk_p = Path(apk_path)
        out_p = Path(output_dir)

        if not apk_p.exists():
            raise FileNotFoundError(f"APK file not found: {apk_path}")

        out_p.mkdir(parents=True, exist_ok=True)
        
        apktool_dir = out_p / "apktool_out"
        jadx_dir = out_p / "jadx_out"

        from mobileag.security.archives import validate_archive
        if validate_archive(apk_p) != "android":
            raise ValueError("Expected an Android APK archive")

        async def run_tool(command, timeout):
            process = await asyncio.create_subprocess_exec(
                *command, stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
            try:
                code = await asyncio.wait_for(process.wait(), timeout)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                process.kill()
                await process.wait()
                raise
            if code != 0:
                raise RuntimeError(f"{Path(command[0]).name} failed (exit {code}); scan is incomplete")

        await run_tool([self.apktool_path, "d", str(apk_p), "-o", str(apktool_dir), "-f"], 120)
        await run_tool([self.jadx_path, str(apk_p), "-d", str(jadx_dir), "--no-res", "--show-bad-code", "-j", "4"], 120)
        if not jadx_dir.is_dir() or not (apktool_dir / "AndroidManifest.xml").is_file():
            raise RuntimeError("Decompilation output is incomplete")

        manifest_path = apktool_dir / "AndroidManifest.xml"
        if not manifest_path.exists():
            candidates = [
                jadx_dir / "resources" / "AndroidManifest.xml",
                out_p / "AndroidManifest.xml",
            ]
            for c in candidates:
                if c.exists():
                    manifest_path = c
                    break

        package_name = self._parse_package_name(manifest_path)

        return {
            "apktool_dir": str(apktool_dir) if apktool_dir.exists() else "",
            "jadx_dir": str(jadx_dir) if jadx_dir.exists() else "",
            "manifest_path": str(manifest_path) if manifest_path.exists() else "",
            "package_name": package_name
        }

    def _parse_package_name(self, manifest_path: Path) -> str:
        """Parses the package name from the AndroidManifest.xml."""
        if not manifest_path.exists():
            logger.warning("AndroidManifest.xml not found.")
            return "unknown"
        
        try:
            tree = ET.parse(manifest_path)
            root = tree.getroot()
            return root.attrib.get("package", "unknown")
        except Exception as e:
            logger.error(f"Failed to parse manifest for package name: {e}")
            return "unknown"
