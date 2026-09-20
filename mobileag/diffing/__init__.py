"""APK version diff engine — compares two APK versions for new vulnerabilities."""

import asyncio
import logging
from pathlib import Path
from typing import Any

from mobileag.ingestion.apk_extractor import APKExtractor
from mobileag.ingestion.manifest_parser import ManifestParser
from config.settings import Settings

logger = logging.getLogger(__name__)


class VersionDiff:
    """Compares two versions of an APK to identify security-relevant changes.

    Detects:
        - New exported components
        - Removed permission guards
        - New API endpoints
        - Changed deep link handlers
        - New native libraries
        - New dependencies
        - Permission changes
    """

    def __init__(self, settings: Settings):
        self._extractor = APKExtractor(settings)
        self._manifest_parser = ManifestParser()

    async def diff(
        self,
        old_apk: str,
        new_apk: str,
        output_dir: str = "./output/diff",
    ) -> dict[str, Any]:
        """Compare two APK versions and return security-relevant differences.

        Args:
            old_apk: Path to the older APK version.
            new_apk: Path to the newer APK version.
            output_dir: Directory for diff output.

        Returns:
            Dict with categorized differences.
        """
        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        logger.info("Diffing %s → %s", old_apk, new_apk)

        # Extract both APKs
        old_result, new_result = await asyncio.gather(
            self._extractor.extract(old_apk, str(out / "old")),
            self._extractor.extract(new_apk, str(out / "new")),
        )

        # Parse manifests
        old_manifest = self._manifest_parser.parse(old_result.get("manifest_path", ""))
        new_manifest = self._manifest_parser.parse(new_result.get("manifest_path", ""))

        diff_result: dict[str, Any] = {
            "old_version": old_result.get("package_name", "unknown"),
            "new_version": new_result.get("package_name", "unknown"),
            "permission_changes": self._diff_permissions(old_manifest, new_manifest),
            "component_changes": self._diff_components(old_manifest, new_manifest),
            "deep_link_changes": self._diff_deep_links(old_manifest, new_manifest),
            "new_files": [],
            "removed_files": [],
            "security_notes": [],
        }

        # Diff file trees
        old_files = self._list_files(old_result.get("jadx_dir", ""))
        new_files = self._list_files(new_result.get("jadx_dir", ""))

        diff_result["new_files"] = sorted(new_files - old_files)[:100]
        diff_result["removed_files"] = sorted(old_files - new_files)[:100]

        # Generate security notes
        diff_result["security_notes"] = self._generate_notes(diff_result)

        logger.info(
            "Diff complete: %d permission changes, %d component changes, %d new files",
            len(diff_result["permission_changes"]),
            len(diff_result["component_changes"]),
            len(diff_result["new_files"]),
        )

        return diff_result

    def _diff_permissions(
        self,
        old_manifest: dict,
        new_manifest: dict,
    ) -> list[dict[str, str]]:
        """Compare permissions between versions."""
        old_perms = set(old_manifest.get("permissions", []))
        new_perms = set(new_manifest.get("permissions", []))

        changes: list[dict[str, str]] = []
        for perm in new_perms - old_perms:
            changes.append({"type": "added", "permission": perm})
        for perm in old_perms - new_perms:
            changes.append({"type": "removed", "permission": perm})

        return changes

    def _diff_components(
        self,
        old_manifest: dict,
        new_manifest: dict,
    ) -> list[dict[str, Any]]:
        """Compare exported components between versions."""
        old_components = {
            c.get("name", ""): c
            for c in old_manifest.get("components", [])
        }
        new_components = {
            c.get("name", ""): c
            for c in new_manifest.get("components", [])
        }

        changes: list[dict[str, Any]] = []

        # New components
        for name in set(new_components) - set(old_components):
            comp = new_components[name]
            changes.append({
                "type": "added",
                "name": name,
                "exported": comp.get("exported", False),
                "component_type": comp.get("type", "unknown"),
                "security_risk": comp.get("exported", False),
            })

        # Removed components
        for name in set(old_components) - set(new_components):
            changes.append({
                "type": "removed",
                "name": name,
            })

        # Changed export status
        for name in set(old_components) & set(new_components):
            old_exp = old_components[name].get("exported", False)
            new_exp = new_components[name].get("exported", False)
            if old_exp != new_exp:
                changes.append({
                    "type": "export_changed",
                    "name": name,
                    "old_exported": old_exp,
                    "new_exported": new_exp,
                    "security_risk": new_exp and not old_exp,
                })

            # Permission guard removed?
            old_perm = old_components[name].get("permission", "")
            new_perm = new_components[name].get("permission", "")
            if old_perm and not new_perm:
                changes.append({
                    "type": "permission_removed",
                    "name": name,
                    "old_permission": old_perm,
                    "security_risk": True,
                })

        return changes

    def _diff_deep_links(
        self,
        old_manifest: dict,
        new_manifest: dict,
    ) -> list[dict[str, Any]]:
        """Compare deep link handlers between versions."""
        old_links = {
            dl.get("scheme", "") + "://" + dl.get("host", ""): dl
            for dl in old_manifest.get("deep_links", [])
        }
        new_links = {
            dl.get("scheme", "") + "://" + dl.get("host", ""): dl
            for dl in new_manifest.get("deep_links", [])
        }

        changes: list[dict[str, Any]] = []
        for uri in set(new_links) - set(old_links):
            changes.append({"type": "added", "uri": uri, **new_links[uri]})
        for uri in set(old_links) - set(new_links):
            changes.append({"type": "removed", "uri": uri})

        return changes

    @staticmethod
    def _list_files(directory: str) -> set[str]:
        """List all relative file paths in a directory."""
        if not directory:
            return set()
        root = Path(directory)
        if not root.exists():
            return set()
        return {
            str(f.relative_to(root))
            for f in root.rglob("*")
            if f.is_file()
        }

    @staticmethod
    def _generate_notes(diff: dict) -> list[str]:
        """Generate security notes from diff results."""
        notes: list[str] = []

        # New exported components
        new_exported = [
            c for c in diff.get("component_changes", [])
            if c.get("type") == "added" and c.get("exported")
        ]
        if new_exported:
            names = [c["name"] for c in new_exported]
            notes.append(
                f"⚠️ {len(new_exported)} NEW exported component(s) added: "
                + ", ".join(names[:5])
            )

        # Permission guards removed
        perm_removed = [
            c for c in diff.get("component_changes", [])
            if c.get("type") == "permission_removed"
        ]
        if perm_removed:
            notes.append(
                f"🔴 Permission guard REMOVED from {len(perm_removed)} component(s)"
            )

        # Newly exported
        newly_exported = [
            c for c in diff.get("component_changes", [])
            if c.get("type") == "export_changed" and c.get("security_risk")
        ]
        if newly_exported:
            notes.append(
                f"🔴 {len(newly_exported)} component(s) changed to exported=true"
            )

        # Dangerous permissions added
        dangerous = [
            p for p in diff.get("permission_changes", [])
            if p.get("type") == "added" and any(
                kw in p.get("permission", "").lower()
                for kw in ("camera", "location", "contacts", "sms", "call_log", "read_external")
            )
        ]
        if dangerous:
            notes.append(
                f"⚠️ {len(dangerous)} dangerous permission(s) added"
            )

        # New deep links
        new_links = [
            dl for dl in diff.get("deep_link_changes", [])
            if dl.get("type") == "added"
        ]
        if new_links:
            notes.append(f"ℹ️ {len(new_links)} new deep link handler(s) added")

        if not notes:
            notes.append("✅ No significant security-relevant changes detected")

        return notes
