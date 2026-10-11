import asyncio
import hashlib
import logging
import sys
from importlib.metadata import PackageNotFoundError, version as package_version
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

    @staticmethod
    def _sha256(path: Path) -> str:
        """Hash the input artifact without changing it; fail rather than record a partial digest."""
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    @staticmethod
    async def _tool_version(executable: str, args: tuple[str, ...]) -> dict[str, Any]:
        """Collect a bounded, best-effort version string using argv (never a shell)."""
        process = None
        try:
            process = await asyncio.create_subprocess_exec(
                executable, *args, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT)
            output, _ = await asyncio.wait_for(process.communicate(), timeout=5)
            version = output.decode("utf-8", errors="replace").strip()[:500]
            return {"executable": Path(executable).name, "version": version or None,
                    "version_exit_code": process.returncode}
        except (OSError, asyncio.TimeoutError) as exc:
            if process is not None and process.returncode is None:
                process.kill()
                await process.wait()
            return {"executable": Path(executable).name, "version": None,
                    "version_error": type(exc).__name__}

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
        if not apk_p.is_file():
            raise ValueError("APK path must identify a regular file")

        artifact_sha256 = self._sha256(apk_p)

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
        if self._sha256(apk_p) != artifact_sha256:
            raise RuntimeError("Input APK changed during extraction; refusing to bind scan evidence to a moving artifact")
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
            "package_name": package_name,
            "artifact_provenance": {
                "sha256": artifact_sha256,
                "size_bytes": apk_p.stat().st_size,
                "filename": apk_p.name,
                "mobileag_version": self._mobileag_version(),
                "python_version": sys.version.split()[0],
                "tools": {
                    "apktool": await self._tool_version(self.apktool_path, ("--version",)),
                    "jadx": await self._tool_version(self.jadx_path, ("--version",)),
                },
            },
        }

    @staticmethod
    def _mobileag_version() -> str:
        try:
            return package_version("mobileag")
        except PackageNotFoundError:
            return "source-checkout"

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
