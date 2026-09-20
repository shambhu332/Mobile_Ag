import asyncio
import logging
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
        self.jadx_path = getattr(settings, "JADX_PATH", "jadx")
        self.apktool_path = getattr(settings, "APKTOOL_PATH", "apktool")

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

        # Run APKTool
        logger.info(f"Running APKTool on {apk_path}...")
        apktool_cmd = [self.apktool_path, "d", str(apk_path), "-o", str(apktool_dir), "-f"]
        process_apktool = await asyncio.create_subprocess_exec(
            *apktool_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process_apktool.communicate()
        if process_apktool.returncode != 0:
            logger.error(f"APKTool failed: {stderr.decode()}")
            raise RuntimeError(f"APKTool failed with return code {process_apktool.returncode}")

        # Run JADX
        logger.info(f"Running JADX on {apk_path}...")
        jadx_cmd = [self.jadx_path, str(apk_path), "-d", str(jadx_dir), "--deobf"]
        process_jadx = await asyncio.create_subprocess_exec(
            *jadx_cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await process_jadx.communicate()
        if process_jadx.returncode != 0:
            logger.error(f"JADX failed: {stderr.decode()}")
            raise RuntimeError(f"JADX failed with return code {process_jadx.returncode}")

        manifest_path = apktool_dir / "AndroidManifest.xml"
        package_name = self._parse_package_name(manifest_path)

        return {
            "apktool_dir": str(apktool_dir),
            "jadx_dir": str(jadx_dir),
            "manifest_path": str(manifest_path),
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
