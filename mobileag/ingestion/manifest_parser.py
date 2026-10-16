import logging
import re
import json
import os
import stat
import xml.etree.ElementTree as ET
from typing import Any, Dict, List
from pathlib import Path
from mobileag.analysis.bounded_sources import SourceInventory
from mobileag.ingestion.intent_filters import DATA_ATTRIBUTES, inventory_links

logger = logging.getLogger(__name__)

class ManifestParser:
    """
    Parses AndroidManifest.xml to extract app configuration and components.
    """
    
    ANDROID_NS = "http://schemas.android.com/apk/res/android"
    MAX_MANIFEST_XML_BYTES = 8 * 1024 * 1024

    def __init__(self) -> None:
        pass

    def _get_attrib(self, element: ET.Element, name: str) -> str:
        """Helper to get an attribute with the Android namespace."""
        if element is None:
            return ""
        return element.attrib.get(f"{{{self.ANDROID_NS}}}{name}", "")

    @staticmethod
    def _permission_string_resources(manifest_path: Path) -> tuple[dict[str, str], dict[str, Any]]:
        """Read a small, fail-closed subset of decoded `res/values*/` strings."""
        root = manifest_path.parent / "res"
        summary = {"status": "not_available", "resource_files_read": 0,
                   "resource_bytes_read": 0, "ambiguous_names": 0,
                   "limits_reached": False, "limitations": [
                       "Only unique plain <string> literals in bounded Apktool values XML are resolved.",
                       "Resource aliases, binary resource tables, dynamic references and merged-manifest behavior are not resolved.",
                   ]}
        if root.is_symlink() or not root.is_dir():
            return {}, summary
        variants = {}
        files_read = total_bytes = entries = 0
        incomplete = False
        try:
            directories = []
            with os.scandir(root) as iterator:
                root_entries = sorted(iterator, key=lambda item: item.name.casefold())
            for entry in root_entries:
                entries += 1
                if entries > 256:
                    incomplete = True
                    summary["limits_reached"] = True
                    break
                if not re.fullmatch(r"values(?:-[A-Za-z0-9-]{1,64})?", entry.name):
                    continue
                if entry.is_symlink() or not entry.is_dir(follow_symlinks=False):
                    incomplete = True
                    continue
                directories.append(Path(entry.path))
            for directory in directories[:32]:
                if len(directories) > 32:
                    incomplete = True
                    summary["limits_reached"] = True
                with os.scandir(directory) as iterator:
                    directory_entries = sorted(iterator, key=lambda item: item.name.casefold())
                for entry in directory_entries:
                    entries += 1
                    if entries > 2048 or files_read >= 256:
                        incomplete = True
                        summary["limits_reached"] = True
                        break
                    if not entry.name.lower().endswith(".xml"):
                        continue
                    if entry.is_symlink() or not entry.is_file(follow_symlinks=False):
                        incomplete = True
                        continue
                    path = Path(entry.path)
                    try:
                        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                        with os.fdopen(fd, "rb") as stream:
                            file_info = os.fstat(stream.fileno())
                            if not stat.S_ISREG(file_info.st_mode) or file_info.st_size > 64 * 1024:
                                incomplete = True
                                continue
                            data = stream.read(64 * 1024 + 1)
                        if len(data) > 64 * 1024:
                            incomplete = True
                            continue
                    except OSError:
                        incomplete = True
                        continue
                    files_read += 1
                    total_bytes += len(data)
                    if total_bytes > 2 * 1024 * 1024:
                        incomplete = True
                        summary["limits_reached"] = True
                        break
                    upper = data.upper()
                    if b"<!DOCTYPE" in upper or b"<!ENTITY" in upper:
                        incomplete = True
                        continue
                    try:
                        xml_root = ET.fromstring(data)
                    except ET.ParseError:
                        incomplete = True
                        continue
                    if xml_root.tag != "resources":
                        incomplete = True
                        continue
                    for element in list(xml_root):
                        name = element.attrib.get("name", "")
                        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,127}", name):
                            continue
                        if element.tag != "string":
                            continue
                        if list(element):
                            variants.setdefault(name, set()).add(None)
                            continue
                        value = element.text or ""
                        if (not value or value != value.strip() or len(value) > 256
                                or not re.fullmatch(r"[A-Za-z0-9_.]+", value)):
                            variants.setdefault(name, set()).add(None)
                            continue
                        variants.setdefault(name, set()).add(value)
                    if summary["limits_reached"]:
                        break
                if summary["limits_reached"]:
                    break
        except OSError:
            incomplete = True
        resolved = {name: next(iter(values)) for name, values in variants.items()
                    if len(values) == 1 and None not in values}
        summary.update(resource_files_read=files_read, resource_bytes_read=total_bytes,
                       ambiguous_names=sum(len(values) != 1 or None in values for values in variants.values()),
                       status="incomplete" if incomplete else "measured_bounded_values")
        return resolved, summary

    @staticmethod
    def _resolve_permission(value: str | None, origin: str, resources: dict[str, str],
                            package_name: str) -> tuple[str | None, dict[str, str | None]]:
        """Resolve literal or uniquely defined simple string permission names."""
        if not value:
            return None, {"status": "not_declared", "origin": origin, "name": None, "raw_reference": None}
        if value.startswith("@"):
            match = re.fullmatch(r"@(?:([A-Za-z0-9_.]+):)?string/([A-Za-z_][A-Za-z0-9_]{0,127})", value)
            if match and (not match.group(1) or match.group(1) == package_name):
                resolved = resources.get(match.group(2))
                if resolved:
                    return resolved, {"status": "resolved_simple_string_resource", "origin": origin,
                                      "name": resolved, "raw_reference": value[:256]}
        if value.startswith(("@", "?")):
            return value[:256], {"status": "unresolved_resource_reference", "origin": origin,
                                 "name": None, "raw_reference": value[:256]}
        return value[:256], {"status": "literal_name", "origin": origin,
                             "name": value[:256], "raw_reference": None}

    def _parse_intent_filters(self, component_elem: ET.Element) -> List[Dict[str, Any]]:
        """Parses intent filters for a component."""
        filters = []
        for filter_elem in component_elem.findall("intent-filter"):
            actions = [self._get_attrib(a, "name") for a in filter_elem.findall("action")]
            categories = [self._get_attrib(c, "name") for c in filter_elem.findall("category")]
            data_elems = filter_elem.findall("data")
            data = []
            for d in data_elems:
                data.append({name:self._get_attrib(d,name) for name in DATA_ATTRIBUTES})
            relative = [{'allow':self._get_attrib(group,'allow'),
                         'data':[{name:self._get_attrib(d,name) for name in DATA_ATTRIBUTES}
                                 for d in group.findall('data')]}
                        for group in filter_elem.findall('uri-relative-filter-group')]
            filters.append({
                "auto_verify": self._get_attrib(filter_elem,"autoVerify") or None,
                "relative_uri_groups": relative,
                "actions": [a for a in actions if a],
                "categories": [c for c in categories if c],
                "data": [d for d in data if any(d.values())]
            })
        return filters

    def _parse_components(self, app_elem: ET.Element, tag: str, target_sdk: str = "",
                          permission_resources: dict[str, str] | None = None,
                          package_name: str = "") -> List[Dict[str, Any]]:
        """Parses app components like activities, services, etc."""
        components = []
        permission_resources = permission_resources or {}
        app_permission_raw = self._get_attrib(app_elem, "permission")
        app_permission, app_permission_resolution = self._resolve_permission(
            app_permission_raw or None, "application", permission_resources, package_name)
        for elem in app_elem.findall(tag):
            name = self._get_attrib(elem, "name")
            exported = self._get_attrib(elem, "exported")
            component_permission_raw = self._get_attrib(elem, "permission")
            if component_permission_raw:
                permission, interaction_resolution = self._resolve_permission(
                    component_permission_raw, "component", permission_resources, package_name)
                permission_origin = "component"
            else:
                permission = app_permission
                interaction_resolution = dict(app_permission_resolution)
                permission_origin = "application_inherited" if app_permission_raw else "none"
            read_permission = self._get_attrib(elem, "readPermission") if tag == "provider" else ""
            write_permission = self._get_attrib(elem, "writePermission") if tag == "provider" else ""
            affinity_key = f"{{{self.ANDROID_NS}}}taskAffinity"
            task_affinity_raw = elem.attrib.get(affinity_key)
            application_task_affinity = app_elem.attrib.get(affinity_key)
            if task_affinity_raw is not None:
                task_affinity = task_affinity_raw
                task_affinity_origin = "component"
            elif application_task_affinity is not None:
                task_affinity = application_task_affinity
                task_affinity_origin = "application"
            else:
                task_affinity = package_name
                task_affinity_origin = "package_default"
            launch_mode_raw = self._get_attrib(elem, "launchMode")
            launch_mode = launch_mode_raw or "standard"
            intent_filters = self._parse_intent_filters(elem)
            
            # Default export logic is version-dependent. Apps targeting API 31+
            # must explicitly set android:exported on components with intent
            # filters; retain an unknown value rather than report an effective
            # exported surface for an APK that cannot be installed as declared.
            if not exported:
                if tag == "provider":
                    exported_bool = int(target_sdk) < 17 if target_sdk.isdecimal() else None
                elif (intent_filters and target_sdk.isdecimal()
                      and int(target_sdk) >= 31):
                    exported_bool = None
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

            grant_uri_permissions_raw = self._get_attrib(elem, "grantUriPermissions")
            grant_uri_permissions = (grant_uri_permissions_raw.lower() == "true"
                                    if grant_uri_permissions_raw else None)
            grant_paths = [{name: self._get_attrib(grant, name) or None
                            for name in ("path", "pathPrefix", "pathPattern", "pathAdvancedPattern")}
                           for grant in elem.findall("grant-uri-permission")]
            raw_path_permissions = elem.findall("path-permission")
            path_permissions_truncated = len(raw_path_permissions) > 128
            path_permissions = []
            for item in raw_path_permissions[:128]:
                path_generic = self._get_attrib(item, "permission")
                path_read_raw = self._get_attrib(item, "readPermission")
                path_write_raw = self._get_attrib(item, "writePermission")
                if path_read_raw:
                    path_read, path_read_resolution = self._resolve_permission(
                        path_read_raw, "path-readPermission", permission_resources, package_name)
                elif path_generic:
                    path_read, path_read_resolution = self._resolve_permission(
                        path_generic, "path-permission", permission_resources, package_name)
                else:
                    path_read, path_read_resolution = None, {
                        "status": "not_declared", "origin": "path-permission", "name": None,
                        "raw_reference": None}
                if path_write_raw:
                    path_write, path_write_resolution = self._resolve_permission(
                        path_write_raw, "path-writePermission", permission_resources, package_name)
                elif path_generic:
                    path_write, path_write_resolution = self._resolve_permission(
                        path_generic, "path-permission", permission_resources, package_name)
                else:
                    path_write, path_write_resolution = None, {
                        "status": "not_declared", "origin": "path-permission", "name": None,
                        "raw_reference": None}
                path_permissions.append({
                    "path": self._get_attrib(item, "path") or None,
                    "pathPrefix": self._get_attrib(item, "pathPrefix") or None,
                    "pathPattern": self._get_attrib(item, "pathPattern") or None,
                    "permission": path_generic or None,
                    "readPermission": path_read_raw or None,
                    "writePermission": path_write_raw or None,
                    "declared_access_permissions": {"read": path_read, "write": path_write},
                    "permission_resolution": {"read": path_read_resolution,
                                              "write": path_write_resolution},
                })

            if tag == "provider":
                if read_permission:
                    read_value, read_resolution = self._resolve_permission(
                        read_permission, "readPermission", permission_resources, package_name)
                else:
                    read_value, read_resolution = permission, dict(interaction_resolution)
                    read_resolution["origin"] = permission_origin
                if write_permission:
                    write_value, write_resolution = self._resolve_permission(
                        write_permission, "writePermission", permission_resources, package_name)
                else:
                    write_value, write_resolution = permission, dict(interaction_resolution)
                    write_resolution["origin"] = permission_origin
                permission_resolution = {
                    "read": read_resolution,
                    "write": write_resolution,
                }
            else:
                permission_resolution = {"interaction": interaction_resolution}

            components.append({
                "name": name,
                "alias_target": self._get_attrib(elem,"targetActivity") or None,
                "exported_explicit": exported or None,
                "type": tag.replace("-alias", ""),
                "exported": exported_bool,
                "permission": permission,
                "permission_origin": permission_origin,
                "read_permission": read_permission or None,
                "write_permission": write_permission or None,
                # Provider read/write declarations override its generic permission;
                # otherwise that permission (including an inherited application
                # default) is used. This is manifest inventory, not runtime policy.
                "declared_access_permissions": ({
                    "read": read_value or None,
                    "read_origin": ("readPermission" if read_permission else permission_origin),
                    "write": write_value or None,
                    "write_origin": ("writePermission" if write_permission else permission_origin),
                } if tag == "provider" else {
                    "interaction": permission or None,
                    "interaction_origin": permission_origin,
                }),
                "permission_resolution": permission_resolution,
                "taskAffinity": task_affinity,
                "taskAffinityOrigin": task_affinity_origin,
                "declaredTaskAffinity": task_affinity_raw,
                "taskAffinityExplicit": task_affinity_raw is not None,
                "launchMode": launch_mode,
                "launchModeOrigin": "component" if launch_mode_raw else "platform_default",
                "launchModeExplicit": bool(launch_mode_raw),
                "intent_filters": intent_filters,
                "meta_data": meta_data,
                "grant_uri_permissions": grant_uri_permissions,
                "grant_uri_permissions_explicit": grant_uri_permissions_raw or None,
                "grant_uri_permissions_paths": grant_paths,
                "path_permissions": path_permissions,
                "path_permissions_truncated": path_permissions_truncated,
            })
        return components

    @staticmethod
    def _provider_path_inventory(manifest_path: Path, providers: list[dict]) -> dict[str, Any]:
        """Resolve only bounded symbolic FileProvider XML resources under res/xml.

        This inventories path configuration; it does not prove a URI was granted
        or that a caller can read a file. Unknown/dynamic references remain gaps.
        """
        root = manifest_path.parent / "res" / "xml"
        rows = []
        unresolved = 0
        for provider in providers:
            metadata = provider.get("meta_data", {})
            reference = next((metadata.get(key) for key in (
                "android.support.FILE_PROVIDER_PATHS",
                "androidx.core.content.FILE_PROVIDER_PATHS",
            ) if metadata.get(key)), None)
            if not reference:
                continue
            match = re.fullmatch(r"@xml/([A-Za-z0-9_]{1,100})", str(reference))
            if not match:
                unresolved += 1
                rows.append({"provider": provider.get("name", "unknown"), "resource": str(reference)[:128],
                             "status": "unresolved_reference", "entries": []})
                continue
            candidate = root / f"{match.group(1)}.xml"
            try:
                extraction_root = manifest_path.parent.resolve(strict=True)
                resolved_root = root.resolve(strict=True)
                resolved = candidate.resolve(strict=True)
                if (not resolved_root.is_relative_to(extraction_root)
                        or (manifest_path.parent / "res").is_symlink() or root.is_symlink()
                        or not resolved.is_relative_to(resolved_root)
                        or candidate.is_symlink() or not resolved.is_file()):
                    raise ValueError("unsafe or non-file resource")
                fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd, "rb") as stream:
                    details = os.fstat(stream.fileno())
                    if not stat.S_ISREG(details.st_mode) or details.st_size > 65536:
                        raise ValueError("resource exceeds 65536 bytes or is not regular")
                    raw = stream.read(65537)
                if len(raw) > 65536:
                    raise ValueError("resource exceeds 65536 bytes")
                if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
                    raise ValueError("DTD/entity declarations are unsupported")
                xml_root = ET.fromstring(raw)
                entries = [{"type": child.tag, "name": child.attrib.get("name", ""),
                            "path": child.attrib.get("path", "")}
                           for child in list(xml_root)[:100]
                           if child.tag in {"root-path", "files-path", "cache-path", "external-path",
                                            "external-files-path", "external-cache-path", "external-media-path"}]
                rows.append({"provider": provider.get("name", "unknown"), "resource": str(reference),
                             "status": "parsed", "entries": entries,
                             "entries_truncated": len(list(xml_root)) > 100})
            except (OSError, ValueError, ET.ParseError, RuntimeError):
                unresolved += 1
                rows.append({"provider": provider.get("name", "unknown"), "resource": str(reference),
                             "status": "unavailable_or_invalid", "entries": []})
        return {"status": "incomplete" if unresolved else "completed",
                "static_status": "incomplete" if unresolved else "completed",
                "runtime_status": "not_tested", "proof_status": "not_proven",
                "provider_count": len(rows),
                "unresolved_count": unresolved, "providers": rows, "exhaustive": False,
                "limitations": ["Only symbolic @xml/name references and res/xml/name.xml are resolved.",
                                "URI grant flags, provider implementation, runtime caller checks and readable data are not tested."]}

    @staticmethod
    def _backup_rules_inventory(manifest_path: Path, references: dict[str, dict]) -> dict[str, Any]:
        """Summarize bounded decoded backup-rule XML without asserting exposure.

        Only direct ``res/xml/<name>.xml`` resources are considered. Rule paths
        are intentionally not copied into report coverage; domains and include /
        exclude counts are sufficient for inventory while avoiding extra source
        detail in ordinary reports. This does not model OS/transport semantics.
        """
        root = manifest_path.parent / "res" / "xml"
        output = []
        incomplete = False
        for kind, item in sorted(references.items()):
            reference = item.get("reference") if isinstance(item, dict) else None
            if not reference:
                status = item.get("status", "unavailable") if isinstance(item, dict) else "unavailable"
                output.append({"kind": kind, "status": status, "root": None,
                               "include_count": None, "exclude_count": None,
                               "domains": [], "unrecognized_elements": None})
                if status != "literal_or_unset":
                    incomplete = True
                continue
            match = re.fullmatch(r"@xml/([A-Za-z0-9_]{1,100})", reference)
            if not match:
                output.append({"kind": kind, "status": "unresolved_reference", "root": None,
                               "include_count": None, "exclude_count": None,
                               "domains": [], "unrecognized_elements": None})
                incomplete = True
                continue
            candidate = root / f"{match.group(1)}.xml"
            try:
                base = manifest_path.parent.resolve(strict=True)
                resolved_root = root.resolve(strict=True)
                resolved = candidate.resolve(strict=True)
                if (manifest_path.parent.is_symlink() or (manifest_path.parent / "res").is_symlink()
                        or root.is_symlink() or not resolved_root.is_relative_to(base)
                        or not resolved.is_relative_to(resolved_root) or candidate.is_symlink()
                        or not resolved.is_file()):
                    raise ValueError("unsafe backup rules resource")
                fd = os.open(resolved, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
                with os.fdopen(fd, "rb") as stream:
                    details = os.fstat(stream.fileno())
                    if not stat.S_ISREG(details.st_mode) or details.st_size > 65536:
                        raise ValueError("backup rules resource exceeds limits")
                    raw = stream.read(65537)
                if len(raw) > 65536 or b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
                    raise ValueError("unsupported or overlarge backup rules XML")
                xml_root = ET.fromstring(raw)
                all_nodes = list(xml_root.iter())
                if len(all_nodes) > 257:
                    raise ValueError("backup rules element limit exceeded")
                include_count = exclude_count = unknown = 0
                domains = set()
                for node in all_nodes[1:]:
                    if node.tag in {"include", "exclude"}:
                        if node.tag == "include": include_count += 1
                        else: exclude_count += 1
                        domain = node.attrib.get("domain")
                        if domain and len(domain) <= 64:
                            domains.add(domain)
                    elif node.tag not in {"cloud-backup", "device-transfer", "cross-platform-transfer"}:
                        unknown += 1
                expected_roots = ({"full-backup-content"} if kind == "legacy_rules"
                                  else {"data-extraction-rules"})
                root_name = xml_root.tag if isinstance(xml_root.tag, str) else ""
                source_status = "parsed" if root_name in expected_roots else "unexpected_root"
                if source_status != "parsed": incomplete = True
                output.append({"kind": kind, "status": source_status, "root": root_name[:64],
                               "include_count": include_count, "exclude_count": exclude_count,
                               "domains": sorted(domains)[:32], "unrecognized_elements": unknown})
            except (OSError, ValueError, ET.ParseError, RuntimeError):
                output.append({"kind": kind, "status": "unavailable_or_invalid", "root": None,
                               "include_count": None, "exclude_count": None,
                               "domains": [], "unrecognized_elements": None})
                incomplete = True
        return {"status": "incomplete" if incomplete else "completed",
                "static_status": "incomplete" if incomplete else "completed",
                "runtime_status": "not_tested", "proof_status": "not_proven",
                "rules": output, "exhaustive": False,
                "limitations": ["Only bounded decoded @xml/name resources directly under res/xml are summarized.",
                                "Rule paths and application data contents are not analyzed.",
                                "Effective backup, restore, cloud, device-transfer and OS behavior are not established."]}

    @staticmethod
    def _decoded_metadata(path: Path) -> Dict[str, str]:
        """Read only bounded, simple APKTool scalar metadata; never load YAML objects.

        APKTool moves SDK/version attributes out of decoded XML. Complex YAML,
        aliases and malformed values are deliberately not interpreted.
        """
        metadata = path.parent / "apktool.yml"
        if not metadata.is_file() or metadata.is_symlink() or metadata.stat().st_size > 65536:
            return {}
        inventory = SourceInventory(max_entries=100, max_file_bytes=65536, max_total_bytes=65536)
        records = list(inventory.read(metadata.parent, names={metadata.name}))
        raw = next((data for candidate, data in records if candidate == metadata), None)
        if raw is None:
            return {}
        values = {}
        section = ""
        for line in raw.decode("utf-8", errors="replace").splitlines():
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
        try:
            path = Path(manifest_path)
        except (TypeError, ValueError) as e:
            raise ValueError("Invalid manifest path") from e
        try:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        except FileNotFoundError:
            raise FileNotFoundError(f"Manifest not found: {manifest_path}") from None
        except OSError as e:
            raise ValueError("Manifest is unavailable or not a safe regular file") from e
        try:
            with os.fdopen(fd, "rb") as stream:
                file_info = os.fstat(stream.fileno())
                if not stat.S_ISREG(file_info.st_mode):
                    raise ValueError("Manifest is not a regular file")
                if file_info.st_size > self.MAX_MANIFEST_XML_BYTES:
                    raise ValueError("Manifest exceeds XML size limit")
                raw = stream.read(self.MAX_MANIFEST_XML_BYTES + 1)
            if len(raw) > self.MAX_MANIFEST_XML_BYTES:
                raise ValueError("Manifest exceeds XML size limit")
            if b"<!DOCTYPE" in raw.upper() or b"<!ENTITY" in raw.upper():
                raise ValueError("Manifest DTD/entity declarations are unsupported")
            root = ET.fromstring(raw)
        except ET.ParseError as e:
            logger.error(f"Failed to parse manifest XML: {e}")
            raise ValueError(f"Invalid XML in manifest: {e}")

        ET.register_namespace("android", self.ANDROID_NS)

        package_name = root.attrib.get("package", "")
        # A decoded split APK manifest may carry a root `split` attribute.
        # Its absence does not prove that this APK came from a complete install
        # set (nor does it detect an AAB); retain only this local observation.
        split_name = root.attrib.get("split")
        
        decoded_metadata = self._decoded_metadata(path)

        # Uses-SDK
        uses_sdk = root.find("uses-sdk")
        min_sdk = self._get_attrib(uses_sdk, "minSdkVersion") if uses_sdk is not None else ""
        target_sdk = self._get_attrib(uses_sdk, "targetSdkVersion") if uses_sdk is not None else ""

        min_sdk = min_sdk or decoded_metadata.get("minSdkVersion", "")
        target_sdk = target_sdk or decoded_metadata.get("targetSdkVersion", "")

        permission_resources, permission_resource_inventory = self._permission_string_resources(path)

        # Inventory both unconditional and SDK-23-gated request declarations.
        # These are declarations only; install-time/runtime grant state is unknown.
        permission_requests = []
        request_elements = [(element, "uses-permission") for element in root.findall("uses-permission")]
        request_elements.extend((element, "uses-permission-sdk-23")
                                for element in root.findall("uses-permission-sdk-23"))
        permission_requests_truncated = len(request_elements) > 1024
        for element, request_kind in request_elements[:1024]:
            raw_name = self._get_attrib(element, "name")
            name, name_resolution = self._resolve_permission(
                raw_name or None, request_kind, permission_resources, package_name)
            if not name:
                continue
            permission_requests.append({
                "name": name[:256], "raw_name": raw_name[:256],
                "name_resolution": name_resolution,
                "request_element": request_kind,
                "max_sdk_version": self._get_attrib(element, "maxSdkVersion") or None,
                "uses_permission_flags": self._get_attrib(element, "usesPermissionFlags") or None,
            })
        permissions = [request["name"] for request in permission_requests]

        # Custom permissions declared by the application
        declared_permissions = []
        for perm in root.findall("permission"):
            p_name_raw = self._get_attrib(perm, "name")
            p_name, p_name_resolution = self._resolve_permission(
                p_name_raw or None, "permission-declaration", permission_resources, package_name)
            p_prot = self._get_attrib(perm, "protectionLevel") or "normal"
            if p_name:
                declared_permissions.append({"name": p_name, "raw_name": p_name_raw,
                                             "name_resolution": p_name_resolution,
                                             "protectionLevel": p_prot})

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

        # Preserve only manifest resource references here. Resolving Android's
        # versioned backup semantics requires the matching resource and device
        # build; this inventory deliberately does not infer effective behavior.
        backup_rule_references = {}
        for attr, key in (("fullBackupContent", "legacy_rules"),
                          ("dataExtractionRules", "data_extraction_rules")):
            raw = self._get_attrib(app_elem, attr)
            backup_rule_references[key] = {
                "status": "reference_observed" if raw.startswith("@") else
                          "literal_or_unset" if not raw else "non_resource_value",
                "reference": raw[:512] if raw.startswith("@") and len(raw) <= 512 else None,
            }
            if len(raw) > 512:
                backup_rule_references[key]["status"] = "incomplete_overlong_reference"
        backup_rules_inventory = self._backup_rules_inventory(path, backup_rule_references)

        # Parse components
        activities = self._parse_components(app_elem, "activity", target_sdk,
                                            permission_resources, package_name)
        aliases = self._parse_components(app_elem, "activity-alias", target_sdk,
                                         permission_resources, package_name)

        def canonical_component_name(value: str) -> str:
            if value.startswith("."):
                return f"{package_name}{value}"
            if "." not in value:
                return f"{package_name}.{value}" if package_name else value
            return value

        activity_index: dict[str, list[dict[str, Any]]] = {}
        for activity in activities:
            activity_index.setdefault(canonical_component_name(activity["name"]), []).append(activity)
        for alias in aliases:
            target_raw = alias.get("alias_target")
            matches = activity_index.get(canonical_component_name(target_raw), []) if isinstance(target_raw, str) and target_raw else []
            if len(matches) != 1:
                alias["alias_target_resolution"] = "unresolved"
                alias["taskAffinity"] = None
                alias["taskAffinityOrigin"] = "alias_target_unresolved"
                alias["launchMode"] = "unknown"
                alias["launchModeOrigin"] = "alias_target_unresolved"
                continue
            target = matches[0]
            alias["alias_target_resolution"] = "resolved"
            alias["alias_target_resolved_name"] = target["name"]
            # Android specifies that activity-alias attributes absent from its
            # supported subset inherit from the target activity. Do not treat
            # similarly named raw attributes on the alias as effective policy.
            alias["taskAffinity"] = target.get("taskAffinity")
            alias["taskAffinityOrigin"] = "alias_target"
            alias["launchMode"] = target.get("launchMode", "unknown")
            alias["launchModeOrigin"] = "alias_target"
        activities.extend(aliases)
        services = self._parse_components(app_elem, "service", target_sdk,
                                          permission_resources, package_name)
        receivers = self._parse_components(app_elem, "receiver", target_sdk,
                                           permission_resources, package_name)
        providers = self._parse_components(app_elem, "provider", target_sdk,
                                           permission_resources, package_name)
        provider_path_inventory = self._provider_path_inventory(path, providers)

        all_components = activities + services + receivers + providers

        deep_links, link_coverage = inventory_links(all_components)

        application_dict = {
            "allowBackup": allow_backup_bool,
            "taskAffinity": app_elem.attrib.get(f"{{{self.ANDROID_NS}}}taskAffinity"),
            "taskAffinityExplicit": f"{{{self.ANDROID_NS}}}taskAffinity" in app_elem.attrib,
            "backup_rule_references": backup_rule_references,
            "backup_rules_inventory": backup_rules_inventory,
            "debuggable": debuggable_bool,
            "usesCleartextTraffic": uses_cleartext_bool,
            "activities": activities,
            "services": services,
            "receivers": receivers,
            "providers": providers,
        }

        return {
            "package_name": package_name,
            "split_metadata": {
                "status": "manifest_attribute_observed" if split_name else "attribute_absent",
                "split_name": split_name,
                "is_split_manifest": bool(split_name),
                "split_set_completeness": "not_measured",
            },
            "version_name": self._get_attrib(root,"versionName") or decoded_metadata.get("versionName"),
            "version_code": self._get_attrib(root,"versionCode") or decoded_metadata.get("versionCode"),
            "package": package_name,
            "min_sdk": min_sdk,
            "target_sdk": target_sdk,
            "permissions": permissions,
            "permission_requests": permission_requests,
            "permission_request_inventory": {
                "status": "partial" if permission_requests_truncated else "measured_declarations",
                "count": len(permission_requests), "truncated": permission_requests_truncated,
                "runtime_grant_state": "not_tested", "proof_status": "not_proven",
            },
            "declared_permissions": declared_permissions,
            "permission_resource_inventory": permission_resource_inventory,
            "application": application_dict,
            "activities": activities,
            "services": services,
            "receivers": receivers,
            "providers": providers,
            "provider_path_inventory": provider_path_inventory,
            "components": all_components,
            "deep_links": deep_links,
            "deep_link_coverage": link_coverage,
        }
