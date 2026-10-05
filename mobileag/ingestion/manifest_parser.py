import logging
import re
import json
import xml.etree.ElementTree as ET
from typing import Any, Dict, List
from pathlib import Path

logger = logging.getLogger(__name__)

class ManifestParser:
    """
    Parses AndroidManifest.xml to extract app configuration and components.
    """
    
    ANDROID_NS = "http://schemas.android.com/apk/res/android"

    def __init__(self) -> None:
        pass

    def _get_attrib(self, element: ET.Element, name: str) -> str:
        """Helper to get an attribute with the Android namespace."""
        if element is None:
            return ""
        return element.attrib.get(f"{{{self.ANDROID_NS}}}{name}", "")

    def _parse_intent_filters(self, component_elem: ET.Element) -> List[Dict[str, Any]]:
        """Parses intent filters for a component."""
        filters = []
        for filter_elem in component_elem.findall("intent-filter"):
            actions = [self._get_attrib(a, "name") for a in filter_elem.findall("action")]
            categories = [self._get_attrib(c, "name") for c in filter_elem.findall("category")]
            data_elems = filter_elem.findall("data")
            data = []
            for d in data_elems:
                data.append({
                    "scheme": self._get_attrib(d, "scheme"),
                    "host": self._get_attrib(d, "host"),
                    "path": self._get_attrib(d, "path"),
                    "pathPrefix": self._get_attrib(d, "pathPrefix"),
                    "pathPattern": self._get_attrib(d, "pathPattern"),
                    "mimeType": self._get_attrib(d, "mimeType"),
                })
            filters.append({
                "actions": [a for a in actions if a],
                "categories": [c for c in categories if c],
                "data": [d for d in data if any(d.values())]
            })
        return filters

    def _parse_components(self, app_elem: ET.Element, tag: str, target_sdk: str = "") -> List[Dict[str, Any]]:
        """Parses app components like activities, services, etc."""
        components = []
        for elem in app_elem.findall(tag):
            name = self._get_attrib(elem, "name")
            exported = self._get_attrib(elem, "exported")
            permission = self._get_attrib(elem, "permission") or self._get_attrib(app_elem, "permission")
            task_affinity = self._get_attrib(elem, "taskAffinity")
            intent_filters = self._parse_intent_filters(elem)
            
            # Default export logic if not explicitly set
            if not exported:
                if tag == "provider":
                    exported_bool = int(target_sdk) < 17 if target_sdk.isdecimal() else None
                else:
                    exported_bool = bool(intent_filters)
            else:
                exported_bool = exported.lower() == "true"
                
            meta_data = {}
            for meta in elem.findall("meta-data"):
                m_name = self._get_attrib(meta, "name")
                m_res = self._get_attrib(meta, "resource") or self._get_attrib(meta, "value")
                if m_name:
                    meta_data[m_name] = m_res

            components.append({
                "name": name,
                "type": tag.replace("-alias", ""),
                "exported": exported_bool,
                "permission": permission,
                "taskAffinity": task_affinity,
                "intent_filters": intent_filters,
                "meta_data": meta_data,
            })
        return components

    @staticmethod
    def _decoded_metadata(path: Path) -> Dict[str, str]:
        """Read only bounded, simple APKTool scalar metadata; never load YAML objects.

        APKTool moves SDK/version attributes out of decoded XML. Complex YAML,
        aliases and malformed values are deliberately not interpreted.
        """
        metadata = path.parent / "apktool.yml"
        if not metadata.is_file() or metadata.is_symlink() or metadata.stat().st_size > 65536:
            return {}
        values = {}
        section = ""
        for line in metadata.read_text(encoding="utf-8", errors="replace").splitlines():
            if line and not line[0].isspace():
                section = line.rstrip(":") if line in ("versionInfo:", "sdkInfo:") else ""
                continue
            match = re.fullmatch(r"  (versionName|versionCode|minSdkVersion|targetSdkVersion): ([^\n]{1,256})", line)
            if not section or not match:
                continue
            key, value = match.groups()
            if (section == "versionInfo") != (key in ("versionName", "versionCode")):
                continue
            if value.startswith('"'):
                try:
                    value = json.loads(value)
                except (ValueError, TypeError):
                    continue
            elif value.startswith("'") and value.endswith("'"):
                value = value[1:-1].replace("''", "'")
            elif not re.fullmatch(r"[A-Za-z0-9_.+-]+", value):
                continue
            if not isinstance(value, str) or not value or len(value) > 256:
                continue
            if key != "versionName" and not value.isdecimal():
                continue
            values[key] = value
        return values

    def parse(self, manifest_path: str) -> Dict[str, Any]:
        """
        Parses the AndroidManifest.xml and extracts relevant security info.

        Args:
            manifest_path: Path to the AndroidManifest.xml file.

        Returns:
            A dictionary containing structured manifest data.
        """
        path = Path(manifest_path)
        if not path.exists():
            raise FileNotFoundError(f"Manifest not found: {manifest_path}")

        try:
            tree = ET.parse(path)
            root = tree.getroot()
        except ET.ParseError as e:
            logger.error(f"Failed to parse manifest XML: {e}")
            raise ValueError(f"Invalid XML in manifest: {e}")

        ET.register_namespace("android", self.ANDROID_NS)

        package_name = root.attrib.get("package", "")
        
        decoded_metadata = self._decoded_metadata(path)

        # Uses-SDK
        uses_sdk = root.find("uses-sdk")
        min_sdk = self._get_attrib(uses_sdk, "minSdkVersion") if uses_sdk is not None else ""
        target_sdk = self._get_attrib(uses_sdk, "targetSdkVersion") if uses_sdk is not None else ""

        min_sdk = min_sdk or decoded_metadata.get("minSdkVersion", "")
        target_sdk = target_sdk or decoded_metadata.get("targetSdkVersion", "")

        # Permissions requested
        permissions = [self._get_attrib(p, "name") for p in root.findall("uses-permission")]
        permissions = [p for p in permissions if p]

        # Custom permissions declared by the application
        declared_permissions = []
        for perm in root.findall("permission"):
            p_name = self._get_attrib(perm, "name")
            p_prot = self._get_attrib(perm, "protectionLevel") or "normal"
            if p_name:
                declared_permissions.append({"name": p_name, "protectionLevel": p_prot})

        app_elem = root.find("application")
        if app_elem is None:
            logger.warning("No <application> element found in manifest.")
            app_elem = ET.Element("application")

        # Application flags
        allow_backup = self._get_attrib(app_elem, "allowBackup")
        allow_backup_bool = allow_backup.lower() == "true" if allow_backup else True

        debuggable = self._get_attrib(app_elem, "debuggable")
        debuggable_bool = debuggable.lower() == "true" if debuggable else False

        uses_cleartext = self._get_attrib(app_elem, "usesCleartextTraffic")
        uses_cleartext_bool = (uses_cleartext.lower() == "true" if uses_cleartext
                               else int(target_sdk) < 28 if target_sdk.isdecimal() else None)

        # Parse components
        activities = self._parse_components(app_elem, "activity", target_sdk)
        activities.extend(self._parse_components(app_elem, "activity-alias", target_sdk))
        services = self._parse_components(app_elem, "service", target_sdk)
        receivers = self._parse_components(app_elem, "receiver", target_sdk)
        providers = self._parse_components(app_elem, "provider", target_sdk)

        all_components = activities + services + receivers + providers

        # Extract deep links
        deep_links = []
        for comp in all_components:
            for ifilter in comp.get("intent_filters", []):
                for d in ifilter.get("data", []):
                    if d.get("scheme"):
                        deep_links.append({
                            "component": comp["name"],
                            "uri": f"{d.get('scheme')}://{d.get('host') or ''}{d.get('path') or d.get('pathPrefix') or ''}",
                            "scheme": d.get("scheme"),
                            "host": d.get("host"),
                            "path": d.get("path") or d.get("pathPrefix") or d.get("pathPattern")
                        })

        application_dict = {
            "allowBackup": allow_backup_bool,
            "debuggable": debuggable_bool,
            "usesCleartextTraffic": uses_cleartext_bool,
            "activities": activities,
            "services": services,
            "receivers": receivers,
            "providers": providers,
        }

        return {
            "package_name": package_name,
            "version_name": self._get_attrib(root,"versionName") or decoded_metadata.get("versionName"),
            "version_code": self._get_attrib(root,"versionCode") or decoded_metadata.get("versionCode"),
            "package": package_name,
            "min_sdk": min_sdk,
            "target_sdk": target_sdk,
            "permissions": permissions,
            "declared_permissions": declared_permissions,
            "application": application_dict,
            "activities": activities,
            "services": services,
            "receivers": receivers,
            "providers": providers,
            "components": all_components,
            "deep_links": deep_links,
        }
