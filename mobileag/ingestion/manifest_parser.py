import logging
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

    def _parse_components(self, app_elem: ET.Element, tag: str) -> List[Dict[str, Any]]:
        """Parses app components like activities, services, etc."""
        components = []
        for elem in app_elem.findall(tag):
            name = self._get_attrib(elem, "name")
            exported = self._get_attrib(elem, "exported")
            permission = self._get_attrib(elem, "permission")
            task_affinity = self._get_attrib(elem, "taskAffinity")
            intent_filters = self._parse_intent_filters(elem)
            
            # Default export logic if not explicitly set
            if not exported:
                exported_bool = True if intent_filters else False
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
        
        # Uses-SDK
        uses_sdk = root.find("uses-sdk")
        min_sdk = self._get_attrib(uses_sdk, "minSdkVersion") if uses_sdk is not None else ""
        target_sdk = self._get_attrib(uses_sdk, "targetSdkVersion") if uses_sdk is not None else ""

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
        uses_cleartext_bool = uses_cleartext.lower() == "true" if uses_cleartext else False

        # Parse components
        activities = self._parse_components(app_elem, "activity")
        activities.extend(self._parse_components(app_elem, "activity-alias"))
        services = self._parse_components(app_elem, "service")
        receivers = self._parse_components(app_elem, "receiver")
        providers = self._parse_components(app_elem, "provider")

        all_components = activities + services + receivers + providers

        # Extract deep links
        deep_links = []
        for comp in all_components:
            for ifilter in comp.get("intent_filters", []):
                for d in ifilter.get("data", []):
                    if d.get("scheme"):
                        deep_links.append({
                            "component": comp["name"],
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
