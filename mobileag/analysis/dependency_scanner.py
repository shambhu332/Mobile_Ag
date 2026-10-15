import asyncio
import csv
import hashlib
import json
import logging
import os
import re
import stat
import tomllib
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime, timezone
from typing import Any
from urllib.parse import quote
import httpx

from mobileag.llm.router import LLMRouter
from mobileag.reporting.finding import Finding, Severity, FindingStatus
from mobileag.reporting.cvss import get_default_cvss_for_cwe
from mobileag.analysis.bounded_sources import SourceInventory
from mobileag.analysis.android_surface import mask_non_code

logger = logging.getLogger(__name__)
_MAX_OSV_RESPONSE_BYTES = 1024 * 1024
_MAX_OSV_VULNS_PER_PACKAGE = 100
_MAX_OSV_FINDINGS_PER_SCAN = 500
_MAX_OSV_SUMMARY_CHARS = 4096
_MAX_PACKAGE_LOCK_ENTRIES = 10_000
_MAX_POM_XML_ELEMENTS = 10_000
_MAX_POM_PROPERTIES = 1_000
_MAX_NATIVE_TREE_ENTRIES = 50_000
_MAX_NATIVE_LIBRARIES = 1_000
_MAX_NATIVE_LIBRARY_BYTES = 128 * 1024 * 1024
_MAX_NATIVE_TOTAL_BYTES = 1024 * 1024 * 1024
_NPM_NAME = re.compile(r"^(?:@[A-Za-z0-9._~-]+/)?[A-Za-z0-9._~-]+$")
_EXACT_NPM_VERSION = re.compile(r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$")
_GRADLE_CATALOG_ACCESSOR = re.compile(
    r"\b(?:implementation|api|compile|compileOnly|runtimeOnly|testImplementation|"
    r"testCompileOnly|testRuntimeOnly|androidTestImplementation|annotationProcessor|kapt|ksp)"
    r"\b\s*\(?\s*(?:(?:platform|enforcedPlatform)\s*\(\s*)?libs\.([A-Za-z0-9_.-]+)"
)
_NATIVE_LIBRARY_NAME = re.compile(r".+\.so(?:\.\d+(?:\.\d+)*)?$", re.IGNORECASE)


def _catalog_accessor(alias: str) -> str:
    """Normalize the documented dotted Gradle accessor separators only."""
    return re.sub(r"[-_.]+", ".", alias)


def _mask_gradle_comments(source: str) -> str:
    """Blank Gradle line/block comments while preserving quoted coordinates and line numbers."""
    chars = list(source)
    index = 0
    length = len(source)

    def blank(start: int, end: int) -> None:
        for position in range(start, end):
            if chars[position] not in "\r\n":
                chars[position] = " "

    while index < length:
        if source.startswith("//", index):
            end = index + 2
            while end < length and source[end] not in "\r\n":
                end += 1
            blank(index, end)
            index = end
            continue
        if source.startswith("/*", index):
            end = source.find("*/", index + 2)
            end = length if end < 0 else end + 2
            blank(index, end)
            index = end
            continue
        if source.startswith("$/", index):
            end = source.find("/$", index + 2)
            if end >= 0:
                blank(index, end + 2)
                index = end + 2
                continue
        if source[index] in "\"'":
            quote = source[index]
            delimiter = quote * 3 if source.startswith(quote * 3, index) else quote
            cursor = index + len(delimiter)
            while cursor < length:
                if source[cursor] == "\\":
                    cursor += 2
                elif source.startswith(delimiter, cursor):
                    cursor += len(delimiter)
                    break
                else:
                    cursor += 1
            index = cursor
            continue
        index += 1
    return "".join(chars)


def _pom_direct_dependencies(content: str, file_path: str) -> tuple[list[tuple[str, str, str, str]], int]:
    """Read only literal direct project dependencies from bounded, DTD-free Maven XML."""
    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", content, flags=re.IGNORECASE):
        raise ET.ParseError("DTD and entity declarations are unsupported")
    root = ET.fromstring(content)
    local = lambda element: element.tag.rsplit("}", 1)[-1] if isinstance(element.tag, str) else ""
    pending = [root]
    visited = 0
    while pending:
        element = pending.pop()
        visited += 1
        if visited > _MAX_POM_XML_ELEMENTS:
            raise ET.ParseError("POM element limit reached")
        pending.extend(list(element))
    if local(root) != "project":
        raise ET.ParseError("POM root must be project")
    dependencies_node = next((child for child in root if local(child) == "dependencies"), None)
    if dependencies_node is None:
        dependencies_node = None
    result = []
    unresolved = 0
    properties: dict[str, str] = {}
    ambiguous_properties: set[str] = set()
    properties_node = next((child for child in root if local(child) == "properties"), None)
    if properties_node is not None:
        for prop in list(properties_node)[:_MAX_POM_PROPERTIES]:
            name = local(prop)
            if list(prop) or not name or len(name) > 256:
                ambiguous_properties.add(name)
                continue
            if name in properties:
                ambiguous_properties.add(name)
            properties[name] = (prop.text or "").strip()
        if len(list(properties_node)) > _MAX_POM_PROPERTIES:
            unresolved += 1

    def resolve(value: str) -> str:
        # Intentionally resolve only whole-value placeholders from this root POM.
        for _ in range(8):
            match = re.fullmatch(r"\$\{([A-Za-z0-9_.-]{1,256})\}", value)
            if not match:
                return value
            key = match.group(1)
            if key in ambiguous_properties or key not in properties or not properties[key]:
                return ""
            value = properties[key]
        return "" if re.fullmatch(r"\$\{[^{}]+\}", value) else value
    for container in root:
        if local(container) == "parent":
            # Parent/effective-model dependencies and managed versions are not resolved.
            unresolved += 1
        if local(container) in {"dependencyManagement", "profiles"}:
            pending = list(container)
            while pending:
                child = pending.pop()
                if local(child) == "dependency":
                    unresolved += 1
                pending.extend(list(child))
    for dependency in list(dependencies_node) if dependencies_node is not None else ():
        if local(dependency) != "dependency":
            continue
        fields: dict[str, list[str]] = {}
        for child in dependency:
            tag = local(child)
            if tag in {"groupId", "artifactId", "version", "scope", "type"}:
                fields.setdefault(tag, []).append((child.text or "").strip())
        if any(len(fields.get(name, [])) > 1 for name in ("groupId", "artifactId", "version")):
            unresolved += 1
            continue
        group = resolve(fields.get("groupId", [""])[0])
        artifact = resolve(fields.get("artifactId", [""])[0])
        version = resolve(fields.get("version", [""])[0])
        scope = fields.get("scope", [""])[0]
        dep_type = fields.get("type", [""])[0]
        literal = (re.fullmatch(r"[A-Za-z0-9_.-]{1,256}", group)
                   and re.fullmatch(r"[A-Za-z0-9_.-]{1,256}", artifact)
                   and re.fullmatch(r"[A-Za-z0-9_.+-]{1,256}", version)
                   and version.upper() not in {"LATEST", "RELEASE"})
        if scope == "import" or dep_type == "pom" or not literal:
            unresolved += 1
            continue
        result.append((group, artifact, version, file_path))
    return result, unresolved


class DependencyScanner:
    """Agent for scanning dependencies for known CVEs via OSV."""

    def __init__(self, router: Optional[LLMRouter] = None):
        """Initialize the dependency scanner with an optional LLM router."""
        self.router = router
        self.dep_pattern = re.compile(r"(?:implementation|api|compile)\s+['\"]([^:]+):([^:]+):([^'\"]+)['\"]")
        self.coverage = {"static_status": "not_analyzed", "runtime_status": "not_tested",
                         "proof_status": "not_proven", "exhaustive": False}
        self._last_native_libraries: list[dict[str, Any]] = []
        self._lookup_results = {"successful": 0, "failed": 0, "oversized_responses": 0,
                                "vulnerability_results_omitted": 0,
                                "malformed_vulnerabilities": 0, "findings_omitted": 0}

    def _sync_find_dependencies(self, base_path: Path) -> list[tuple[str, str, str, str]]:
        """Inventory bounded Maven/Gradle and npm lockfile coordinates offline."""
        dependencies = []
        unresolved_declarations = 0
        metadata_parse_failures = 0
        dependencies_by_source = {"gradle_build": 0, "pom_properties": 0,
                                  "gradle_lockfile": 0, "version_catalog": 0,
                                  "npm_package_lock": 0, "yarn_lock_v1": 0,
                                  "pom_xml": 0}
        seen = set()
        used_catalog_accessors: set[str] = set()
        catalog_candidates: dict[str, list[tuple[str, str, str, str]]] = {}
        invalid_catalog_accessors: set[str] = set()
        inventory = SourceInventory(max_entries=5000, max_file_bytes=1024*1024, max_total_bytes=16*1024*1024)
        source_files = list(inventory.read(
            base_path, names={"pom.properties", "pom.xml", "gradle.lockfile", "libs.versions.toml", "package-lock.json", "yarn.lock"},
            suffixes={"build.gradle", "build.gradle.kts"},
        ))
        for file_path, data in source_files:
            if file_path.name.startswith("build.gradle"):
                source = data.decode("utf-8", errors="ignore")
                masked = mask_non_code(source)
                used_catalog_accessors.update(
                    _catalog_accessor(match.group(1))
                    for match in _GRADLE_CATALOG_ACCESSOR.finditer(masked)
                    if not match.group(1).startswith(("bundles.", "plugins.", "versions."))
                )
        for file_path, data in source_files:
            try:
                content = data.decode("utf-8", errors="ignore")
                rel_path = str(file_path.relative_to(base_path))
                parsed = []
                if file_path.name.startswith("build.gradle"):
                    source_kind = "gradle_build"
                    gradle_source = _mask_gradle_comments(content)
                    # String notation in Groovy/Kotlin DSL, with or without
                    # Kotlin's configuration(...) call syntax.
                    for group, artifact, version in re.findall(
                        r"\b(?:implementation|api|compile)\s*\(?\s*['\"]([^:'\"\s]+):([^:'\"\s]+):([^:'\"\s]+)['\"]",
                        gradle_source,
                    ):
                        if "$" in group + artifact + version:
                            unresolved_declarations += 1
                            continue
                        parsed.append((group, artifact, version, rel_path))
                    # Common single-line Groovy map notation. Do not evaluate
                    # variables, providers, version catalogs, or expressions.
                    for line in gradle_source.splitlines():
                        if not re.search(r"\b(?:implementation|api|compile)\b", line):
                            continue
                        fields = {key: match.group(1) for key in ("group", "name", "version")
                                  if (match := re.search(rf"\b{key}\s*:\s*['\"]([^'\"]+)['\"]", line))}
                        if len(fields) == 3:
                            coordinate = (fields["group"], fields["name"], fields["version"])
                            if any("$" in part for part in coordinate):
                                unresolved_declarations += 1
                            else:
                                parsed.append((*coordinate, rel_path))
                        elif any(re.search(rf"\b{key}\s*:", line) for key in ("group", "name", "version")):
                            unresolved_declarations += 1
                elif file_path.name == "pom.properties":
                    source_kind = "pom_properties"
                    values = {}
                    for line in content.splitlines():
                        clean = line.strip()
                        if clean.startswith(("groupId=", "artifactId=", "version=")):
                            key, value = clean.split("=", 1)
                            values[key] = value.strip()
                    if all(values.get(key) for key in ("groupId", "artifactId", "version")):
                        parsed = [(values["groupId"], values["artifactId"], values["version"], rel_path)]
                elif file_path.name == "pom.xml":
                    source_kind = "pom_xml"
                    path_parts = Path(rel_path).parts
                    if any(path_parts[index:index + 2] == ("META-INF", "maven")
                           for index in range(len(path_parts) - 1)):
                        # Embedded library POMs describe that library's graph,
                        # not proof that the referenced graph is shipped here.
                        continue
                    parsed, unresolved = _pom_direct_dependencies(content, rel_path)
                    unresolved_declarations += unresolved
                elif file_path.name == "gradle.lockfile":
                    source_kind = "gradle_lockfile"
                    for line in content.splitlines():
                        line = line.strip()
                        if not line or line.startswith("#") or line.startswith("empty="):
                            continue
                        coordinate, separator, configurations = line.partition("=")
                        if not separator or not configurations.strip():
                            unresolved_declarations += int(":" in line)
                            continue
                        parts = coordinate.split(":")
                        if (len(parts) != 3 or any(not part or len(part) > 256 for part in parts)
                                or any(char.isspace() for part in parts for char in part)
                                or any(char in parts[2] for char in "[](),*+$")):
                            unresolved_declarations += 1
                            continue
                        parsed.append((*parts, rel_path))
                elif file_path.name == "libs.versions.toml":
                    source_kind = "version_catalog"
                    catalog = tomllib.loads(data.decode("utf-8"))
                    versions = catalog.get("versions", {})
                    libraries = catalog.get("libraries", {})
                    if not isinstance(versions, dict) or not isinstance(libraries, dict):
                        unresolved_declarations += 1
                        libraries = {}
                    for alias, declaration in libraries.items():
                        accessor = _catalog_accessor(alias) if isinstance(alias, str) else ""
                        if not isinstance(declaration, dict):
                            if accessor in used_catalog_accessors:
                                invalid_catalog_accessors.add(accessor)
                            continue
                        module = declaration.get("module")
                        group = declaration.get("group")
                        artifact = declaration.get("name")
                        if isinstance(module, str):
                            coordinates = module.split(":")
                            if len(coordinates) == 2:
                                group, artifact = coordinates
                            else:
                                if accessor in used_catalog_accessors:
                                    invalid_catalog_accessors.add(accessor)
                                continue
                        version = declaration.get("version")
                        if isinstance(version, dict):
                            if isinstance(version.get("ref"), str):
                                version = versions.get(version["ref"])
                            else:
                                version = version.get("strictly")
                        if (not isinstance(group, str) or not isinstance(artifact, str)
                                or not isinstance(version, str) or not group or not artifact
                                or not version or len(group) > 256 or len(artifact) > 256
                                or len(version) > 256 or any(char.isspace() for char in group + artifact + version)
                                or any(char in version for char in "[](),*+$")):
                            if accessor in used_catalog_accessors:
                                invalid_catalog_accessors.add(accessor)
                            continue
                        catalog_candidates.setdefault(accessor, []).append((group, artifact, version, rel_path))
                elif file_path.name == "package-lock.json":
                    source_kind = "npm_package_lock"
                    lock = json.loads(content)
                    lock_version = lock.get("lockfileVersion") if isinstance(lock, dict) else None
                    if type(lock_version) is not int or lock_version not in {1, 2, 3}:
                        unresolved_declarations += 1
                    elif lock_version == 1:
                        root_dependencies = lock.get("dependencies")
                        if not isinstance(root_dependencies, dict):
                            unresolved_declarations += 1
                        else:
                            pending = [root_dependencies]
                            inspected = 0
                            exhausted = False
                            while pending and not exhausted:
                                dependency_map = pending.pop()
                                for name, entry in dependency_map.items():
                                    if inspected >= _MAX_PACKAGE_LOCK_ENTRIES:
                                        inventory.record_limit("npm_package_lock_entry_count")
                                        exhausted = True
                                        break
                                    inspected += 1
                                    if not isinstance(name, str) or not isinstance(entry, dict):
                                        unresolved_declarations += 1
                                        continue
                                    version = entry.get("version")
                                    if (not _NPM_NAME.fullmatch(name) or name in {".", ".."}
                                            or not isinstance(version, str)
                                            or not _EXACT_NPM_VERSION.fullmatch(version)
                                            or entry.get("link") is True):
                                        unresolved_declarations += 1
                                    else:
                                        parsed.append(("npm", name, version, rel_path))
                                    children = entry.get("dependencies", {})
                                    if isinstance(children, dict):
                                        pending.append(children)
                                    elif children is not None:
                                        unresolved_declarations += 1
                    else:
                        packages = lock.get("packages")
                        if not isinstance(packages, dict):
                            unresolved_declarations += 1
                        else:
                            if len(packages) > _MAX_PACKAGE_LOCK_ENTRIES:
                                inventory.record_limit("npm_package_lock_entry_count")
                            for index, (lock_path, entry) in enumerate(packages.items()):
                                if index >= _MAX_PACKAGE_LOCK_ENTRIES:
                                    break
                                if lock_path == "":
                                    continue
                                if not isinstance(lock_path, str) or not isinstance(entry, dict):
                                    unresolved_declarations += 1
                                    continue
                                parts = lock_path.split("node_modules/")
                                if len(parts) < 2:
                                    unresolved_declarations += 1
                                    continue
                                tail = parts[-1].split("/")
                                if tail[0].startswith("@"):
                                    name = "/".join(tail[:2]) if len(tail) >= 2 else ""
                                else:
                                    name = tail[0]
                                version = entry.get("version")
                                if (not _NPM_NAME.fullmatch(name) or name in {".", ".."}
                                        or not isinstance(version, str) or not _EXACT_NPM_VERSION.fullmatch(version)
                                        or entry.get("link") is True):
                                    unresolved_declarations += 1
                                    continue
                                parsed.append(("npm", name, version, rel_path))
                else:
                    source_kind = "yarn_lock_v1"
                    lines = content.splitlines()
                    if not any(line.strip() == "# yarn lockfile v1" for line in lines[:20]):
                        unresolved_declarations += 1
                    else:
                        selectors: list[str] = []
                        resolved_version = None

                        def flush_yarn_entry():
                            nonlocal unresolved_declarations
                            if not selectors:
                                return
                            for selector in selectors:
                                separator = selector.rfind("@") if selector.startswith("@") else selector.find("@")
                                name = selector[:separator] if separator > 0 else ""
                                if (not _NPM_NAME.fullmatch(name) or name in {".", ".."}
                                        or not isinstance(resolved_version, str)
                                        or not _EXACT_NPM_VERSION.fullmatch(resolved_version)):
                                    unresolved_declarations += 1
                                else:
                                    parsed.append(("npm", name, resolved_version, rel_path))

                        selector_entries = 0
                        for line in lines:
                            if not line.strip() or line.lstrip().startswith("#"):
                                continue
                            if not line[0].isspace():
                                flush_yarn_entry()
                                selectors = []
                                resolved_version = None
                                if not line.endswith(":"):
                                    unresolved_declarations += 1
                                    continue
                                try:
                                    selectors = next(csv.reader([line[:-1]], skipinitialspace=True))
                                except csv.Error:
                                    unresolved_declarations += 1
                                    continue
                                selector_entries += len(selectors)
                                if selector_entries > _MAX_PACKAGE_LOCK_ENTRIES:
                                    inventory.record_limit("yarn_lock_entry_count")
                                    selectors = []
                                    break
                            elif selectors:
                                match = re.match(r'^\s+version\s+"?([^"\s]+)"?\s*$', line)
                                if match:
                                    resolved_version = match.group(1)
                        flush_yarn_entry()
                for dep in parsed:
                    identity = dep[:3]
                    if identity not in seen:
                        seen.add(identity)
                        dependencies.append(dep)
                        dependencies_by_source[source_kind] += 1
                    if len(dependencies) >= 500:
                        inventory.record_limit('dependency_coordinate_count')
                        break
            except (OSError, UnicodeError, json.JSONDecodeError,
                    tomllib.TOMLDecodeError, ET.ParseError, RecursionError) as e:
                metadata_parse_failures += 1
                logger.debug("Error reading dependency metadata %s: %s", file_path, e)
        for accessor in sorted(used_catalog_accessors):
            candidates = catalog_candidates.get(accessor, [])
            if accessor in invalid_catalog_accessors or len(candidates) != 1:
                unresolved_declarations += 1
                continue
            dep = candidates[0]
            identity = dep[:3]
            if identity not in seen:
                seen.add(identity)
                dependencies.append(dep)
                dependencies_by_source["version_catalog"] += 1
            if len(dependencies) >= 500:
                inventory.record_limit("dependency_coordinate_count")
                break
        self.coverage = dict(inventory.coverage)
        self.coverage.update(runtime_status="not_tested", proof_status="not_proven", exhaustive=False,
                             dependency_count=len(dependencies), unresolved_dependency_declarations=unresolved_declarations,
                             dependency_metadata_parse_failures=metadata_parse_failures,
                             dependencies_by_source=dependencies_by_source,
                             limits={**inventory.coverage['limits'], 'dependencies':500})
        if metadata_parse_failures or unresolved_declarations or inventory.coverage["limits_reached"]:
            self.coverage["static_status"] = "partial"
        return dependencies

    def _sync_find_native_libraries(self, base_path: Path) -> tuple[list[dict[str, Any]], dict[str, Any]]:
        """Hash bounded ELF ET_DYN .so candidates without following links or buffering binaries."""
        records: list[dict[str, Any]] = []
        coverage: dict[str, Any] = {
            "native_inventory_status": "completed",
            "native_candidate_files": 0,
            "native_elf_candidates": 0,
            "native_non_elf_candidates": 0,
            "native_read_failures": 0,
            "native_symlinks_skipped": 0,
            "native_oversized_files_skipped": 0,
            "native_entries_seen": 0,
            "native_bytes_hashed": 0,
            "native_limits_reached": False,
            "native_inventory_limits": {
                "tree_entries": _MAX_NATIVE_TREE_ENTRIES,
                "libraries": _MAX_NATIVE_LIBRARIES,
                "per_library_bytes": _MAX_NATIVE_LIBRARY_BYTES,
                "total_bytes": _MAX_NATIVE_TOTAL_BYTES,
            },
        }
        root = Path(base_path)
        if root.is_symlink() or not root.is_dir():
            coverage.update(native_inventory_status="invalid", native_read_failures=1)
            return records, coverage

        stopped = False

        def record_walk_error(_error: OSError) -> None:
            coverage["native_read_failures"] += 1

        try:
            for current, dirs, files in os.walk(root, followlinks=False, onerror=record_walk_error):
                current_path = Path(current)
                symlink_dirs = {name for name in dirs if (current_path / name).is_symlink()}
                coverage["native_symlinks_skipped"] += len(symlink_dirs)
                dirs[:] = sorted(name for name in dirs if name not in symlink_dirs)
                coverage["native_entries_seen"] += len(dirs) + len(files)
                if coverage["native_entries_seen"] > _MAX_NATIVE_TREE_ENTRIES:
                    coverage["native_limits_reached"] = True
                    stopped = True
                    break

                for filename in sorted(files):
                    if not _NATIVE_LIBRARY_NAME.fullmatch(filename):
                        continue
                    coverage["native_candidate_files"] += 1
                    candidate = current_path / filename
                    if candidate.is_symlink():
                        coverage["native_symlinks_skipped"] += 1
                        continue
                    if len(records) >= _MAX_NATIVE_LIBRARIES:
                        coverage["native_limits_reached"] = True
                        stopped = True
                        break
                    try:
                        fd = os.open(candidate, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
                                     | getattr(os, "O_NONBLOCK", 0))
                        with os.fdopen(fd, "rb") as stream:
                            details = os.fstat(stream.fileno())
                            if not stat.S_ISREG(details.st_mode):
                                coverage["native_read_failures"] += 1
                                continue
                            if details.st_size > _MAX_NATIVE_LIBRARY_BYTES:
                                coverage["native_oversized_files_skipped"] += 1
                                coverage["native_limits_reached"] = True
                                continue
                            if coverage["native_bytes_hashed"] + details.st_size > _MAX_NATIVE_TOTAL_BYTES:
                                coverage["native_limits_reached"] = True
                                stopped = True
                                break
                            header = stream.read(64)
                            elf_class = header[4] if len(header) > 4 else 0
                            data_encoding = header[5] if len(header) > 5 else 0
                            byte_order = "little" if data_encoding == 1 else "big"
                            required_header = 52 if elf_class == 1 else 64 if elf_class == 2 else 0
                            valid_elf_shared_object = (
                                header.startswith(b"\x7fELF") and elf_class in {1, 2}
                                and data_encoding in {1, 2} and len(header) >= required_header
                                and int.from_bytes(header[16:18], byte_order) == 3
                                and int.from_bytes(header[20:24], byte_order) == 1
                            )
                            if not valid_elf_shared_object:
                                coverage["native_non_elf_candidates"] += 1
                                continue
                            digest = hashlib.sha256()
                            digest.update(header)
                            bytes_read = len(header)
                            while chunk := stream.read(min(1024 * 1024, details.st_size - bytes_read)):
                                digest.update(chunk)
                                bytes_read += len(chunk)
                            after = os.fstat(stream.fileno())
                            if (bytes_read != details.st_size or after.st_size != details.st_size
                                    or after.st_mtime_ns != details.st_mtime_ns):
                                coverage["native_read_failures"] += 1
                                continue
                        relative_path = candidate.relative_to(root).as_posix()
                        purl_path = "/".join(quote(part, safe="._-~") for part in relative_path.split("/"))
                        records.append({"name": filename, "version": None,
                                        "purl": f"pkg:generic/{purl_path}",
                                        "file_path": relative_path,
                                        "sha256": digest.hexdigest(),
                                        "size_bytes": details.st_size,
                                        "elf_class": 32 if elf_class == 1 else 64,
                                        "machine": int.from_bytes(header[18:20], byte_order)})
                        coverage["native_bytes_hashed"] += details.st_size
                        coverage["native_elf_candidates"] += 1
                    except OSError:
                        coverage["native_read_failures"] += 1
                if stopped:
                    break
        except OSError:
            coverage["native_read_failures"] += 1

        if (coverage["native_limits_reached"] or coverage["native_read_failures"]
                or coverage["native_symlinks_skipped"] or coverage["native_oversized_files_skipped"]
                or coverage["native_non_elf_candidates"]):
            coverage["native_inventory_status"] = "partial"
        return records, coverage

    async def _query_osv_package(
        self,
        client: httpx.AsyncClient,
        semaphore: asyncio.Semaphore,
        group: str,
        artifact: str,
        version: str,
        file_path: str
    ) -> list[Finding]:
        """Query OSV API for a single dependency with concurrency limiting."""
        is_npm = group == "npm"
        pkg_name = artifact if is_npm else f"{group}:{artifact}"
        query = {
            "package": {"name": pkg_name, "ecosystem": "npm" if is_npm else "Maven"},
            "version": version
        }
        findings: list[Finding] = []

        async with semaphore:
            try:
                async with client.stream("POST", "https://api.osv.dev/v1/query", json=query,
                                          timeout=10.0) as response:
                    if response.status_code != 200:
                        self._lookup_results["failed"] += 1
                        return findings
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        if not isinstance(chunk, bytes) or len(body) + len(chunk) > _MAX_OSV_RESPONSE_BYTES:
                            self._lookup_results["failed"] += 1
                            self._lookup_results["oversized_responses"] += 1
                            return findings
                        body.extend(chunk)
                    data = json.loads(bytes(body).decode("utf-8"))
                    if not isinstance(data, dict):
                        raise ValueError("OSV response must be an object")
                    vulns = data.get("vulns", [])
                    if not isinstance(vulns, list):
                        raise ValueError("OSV vulnerabilities must be a list")
                    self._lookup_results["successful"] += 1
                    if len(vulns) > _MAX_OSV_VULNS_PER_PACKAGE:
                        self._lookup_results["vulnerability_results_omitted"] += len(vulns) - _MAX_OSV_VULNS_PER_PACKAGE
                        vulns = vulns[:_MAX_OSV_VULNS_PER_PACKAGE]
                    for vuln in vulns:
                        if not isinstance(vuln, dict):
                            self._lookup_results["malformed_vulnerabilities"] += 1
                            continue
                        aliases = vuln.get("aliases")
                        alias = aliases[0] if isinstance(aliases, list) and aliases else None
                        cve_id = alias if isinstance(alias, str) else vuln.get("id", "CVE-Unknown")
                        if not isinstance(cve_id, str):
                            cve_id = "CVE-Unknown"
                        cve_id = "".join(char for char in cve_id[:128] if char.isprintable()) or "CVE-Unknown"
                        summary = vuln.get("summary")
                        if not isinstance(summary, str) or not summary.strip():
                            summary = "Known vulnerability identified in third-party library dependency."
                        summary = "".join(char for char in summary[:_MAX_OSV_SUMMARY_CHARS] if char.isprintable())
                        advisory_id = vuln.get("id")
                        if not isinstance(advisory_id, str):
                            advisory_id = None
                        advisory_id = "".join(char for char in advisory_id[:128] if char.isprintable()) if advisory_id else None
                        published = vuln.get("published")
                        modified = vuln.get("modified")
                        published = "".join(c for c in published[:40] if c.isprintable()) if isinstance(published, str) else None
                        modified = "".join(c for c in modified[:40] if c.isprintable()) if isinstance(modified, str) else None
                        
                        cwe = "CWE-1104"
                        score, vector = get_default_cvss_for_cwe(cwe)
                        findings.append(Finding(
                            title=f"Vulnerable Dependency: {pkg_name} ({version})",
                            description=f"{summary} (Advisory/CVE: {cve_id})",
                            severity=Severity.HIGH,
                            cwe_id=cwe,
                            cvss_score=score,
                            cvss_vector=vector,
                            affected_component=pkg_name,
                            detection_method="DependencyScanner",
                            status=FindingStatus.UNVERIFIED,
                            remediation=f"Upgrade {pkg_name} to a secure version that resolves {cve_id}.",
                            file_path=file_path,
                            metadata={"advisory_source": "OSV API", "package_ecosystem": "npm" if is_npm else "Maven",
                                      "advisory_id": advisory_id,
                                      "advisory_published": published,
                                      "advisory_modified": modified, "proof_state": "not_proven"}
                        ))
            except Exception as e:
                self._lookup_results["failed"] += 1
                logger.debug(f"OSV lookup failed for {pkg_name}:{version} - {e}")

        return findings

    async def scan(self, decompiled_path: str, *, allow_advisory_lookup: bool = False) -> list[Finding]:
        """Inventory locally; query OSV only with explicit per-run authorization."""
        logger.info(f"Starting dependency scan in: {decompiled_path}")
        findings: list[Finding] = []
        base_path = Path(decompiled_path)
        dependencies = await asyncio.to_thread(self._sync_find_dependencies, base_path)
        self._last_dependencies = dependencies
        native_libraries, native_coverage = await asyncio.to_thread(
            self._sync_find_native_libraries, base_path)
        self._last_native_libraries = native_libraries
        self.coverage.update(native_coverage)
        if native_coverage["native_inventory_status"] != "completed":
            self.coverage["static_status"] = "partial"
        offline = bool(getattr(self.router, "_settings", None) and self.router._settings.offline is True)
        self.coverage.update(advisory_source="OSV API", advisory_freshness="not_checked",
                             lookup_status=("skipped_offline" if offline else
                                            "skipped_no_consent" if not allow_advisory_lookup else "not_started"),
                             lookup_authorized=bool(allow_advisory_lookup),
                             advisory_response_limits={
                                 "response_bytes": _MAX_OSV_RESPONSE_BYTES,
                                 "vulnerabilities_per_package": _MAX_OSV_VULNS_PER_PACKAGE,
                                 "findings_per_scan": _MAX_OSV_FINDINGS_PER_SCAN,
                             })
        # Offline mode is a hard egress prohibition. Per-invocation consent is
        # necessary online, but must never override the offline setting.
        if offline:
            self.coverage.setdefault("limitations", []).append(
                "OSV advisory lookup blocked by offline mode; local dependency inventory retained")
            return []
        if not allow_advisory_lookup:
            self.coverage.setdefault("limitations", []).append(
                "OSV advisory lookup requires explicit per-run authorization; local dependency inventory retained")
            return []
        if not dependencies:
            logger.info("No Gradle dependencies identified.")
            self.coverage["lookup_status"] = "not_applicable"
            return findings

        self._lookup_results = {"successful": 0, "failed": 0,
                                "oversized_responses": 0, "vulnerability_results_omitted": 0,
                                "malformed_vulnerabilities": 0, "findings_omitted": 0}
        semaphore = asyncio.Semaphore(10)
        async with httpx.AsyncClient() as client:
            tasks = [
                self._query_osv_package(client, semaphore, grp, art, ver, fp)
                for grp, art, ver, fp in dependencies
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        for res in results:
            if isinstance(res, list):
                available = max(0, _MAX_OSV_FINDINGS_PER_SCAN - len(findings))
                findings.extend(res[:available])
                self._lookup_results["findings_omitted"] += max(0, len(res) - available)
            elif isinstance(res, Exception):
                logger.error(f"Dependency scan task error: {res}")

        self.coverage.update(self._lookup_results)
        incomplete_results = any(self._lookup_results[key] for key in
                                  ("vulnerability_results_omitted", "malformed_vulnerabilities", "findings_omitted"))
        self.coverage["lookup_status"] = ("partial" if incomplete_results or
                                            (self._lookup_results["failed"] and self._lookup_results["successful"]) else
                                            "completed" if not self._lookup_results["failed"] else "failed")
        self.coverage["advisory_freshness"] = (
            "retrieved_at:" + datetime.now(timezone.utc).isoformat()
            if self._lookup_results["successful"] else "not_retrieved")
        if self._lookup_results["failed"]:
            self.coverage.setdefault("limitations", []).append(
                "One or more advisory requests failed; advisory coverage is incomplete")

        logger.info(f"Dependency scan completed: {len(findings)} findings.")
        return findings

    def generate_sbom(self, app_name: str = "MobileApp", app_version: str = "1.0.0") -> Any:
        """Construct a standardized MobileSbomGenerator instance populated from inventoried dependencies."""
        from mobileag.analysis.sbom_generator import MobileSbomGenerator
        generator = MobileSbomGenerator(app_name=app_name, app_version=app_version)
        for grp, art, ver, _ in getattr(self, "_last_dependencies", []):
            purl = f"pkg:maven/{grp}/{art}@{ver}" if grp else f"pkg:npm/{art}@{ver}"
            name = f"{grp}:{art}" if grp else art
            generator.add_component(name=name, version=ver, purl=purl, component_type="library")
        for library in getattr(self, "_last_native_libraries", []):
            generator.add_component(name=library["name"], version=library["version"],
                                    purl=library["purl"], component_type="library",
                                    hashes={"SHA-256": library["sha256"]})
        return generator

