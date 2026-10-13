"""Bounded inventory-only accounting for Android App Bundle ZIP inputs."""
from __future__ import annotations

import hashlib
import re
import zipfile
from pathlib import Path
from typing import Any

from mobileag.security.archives import MAX_EXPANDED, MAX_MEMBERS, validate_android_bundle_archive

_MODULE_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")
_DEX_NAME = re.compile(r"^classes(?:(\d+))?\.dex$")
_NON_MODULE_ROOTS = {"BUNDLE-METADATA", "META-INF"}


def inventory_android_app_bundle(path: str | Path) -> dict[str, Any]:
    """Inventory bounded AAB module/DEX/native member counts without extraction.

    No manifest protobuf is decoded and no APK is synthesized. The result is
    input accounting only; it cannot represent delivered device splits or
    establish that module code was analyzed.
    """
    source = Path(path)
    if not source.is_file():
        raise ValueError("Android App Bundle path must identify a regular file")
    before = _sha256(source)
    validate_android_bundle_archive(source)
    modules: dict[str, dict[str, Any]] = {}

    def module_for(member_name: str) -> dict[str, Any] | None:
        parts = member_name.split("/")
        if len(parts) < 2 or parts[0] in _NON_MODULE_ROOTS:
            return None
        module_name = parts[0]
        if not _MODULE_NAME.fullmatch(module_name):
            return None
        return modules.setdefault(module_name, {
            "name": module_name, "manifest_present": False,
            "dex_member_count": 0, "declared_dex_class_count": 0,
            "dex_class_count_status": "measured", "native_library_member_count": 0,
            "invalid_dex_member_count": 0,
        })

    dex_rows: list[tuple[str, str, zipfile.ZipInfo]] = []
    invalid_module_entries = 0
    try:
        with zipfile.ZipFile(source) as archive:
            members = archive.infolist()
            if not members or len(members) > MAX_MEMBERS:
                raise ValueError("Android App Bundle member count outside limits")
            expanded_bytes = 0
            for member in members:
                expanded_bytes += member.file_size
                if expanded_bytes > MAX_EXPANDED:
                    raise ValueError("Android App Bundle expanded size limit exceeded")
                name = member.filename
                module = module_for(name)
                if module is None:
                    if "/" in name and name.split("/", 1)[0] not in _NON_MODULE_ROOTS:
                        invalid_module_entries += 1
                    continue
                parts = name.split("/")
                if parts == [module["name"], "manifest", "AndroidManifest.xml"]:
                    module["manifest_present"] = True
                if len(parts) >= 3 and parts[1] == "dex":
                    dex_name = "/".join(parts[2:])
                    dex_match = _DEX_NAME.fullmatch(dex_name)
                    suffix = dex_match.group(1) if dex_match else None
                    canonical_dex_name = (dex_match is not None and
                                          (suffix is None or (len(suffix) <= 9 and int(suffix) >= 2
                                                              and str(int(suffix)) == suffix)))
                    if "/" not in dex_name and canonical_dex_name:
                        module["dex_member_count"] += 1
                        dex_rows.append((module["name"], name, member))
                    elif dex_name.lower().endswith(".dex"):
                        module["invalid_dex_member_count"] += 1
                        module["dex_class_count_status"] = "incomplete_or_unsupported_member_name"
                if len(parts) >= 4 and parts[1] == "lib" and name.lower().endswith(".so"):
                    module["native_library_member_count"] += 1

            if len(dex_rows) > MAX_MEMBERS:
                raise ValueError("Android App Bundle DEX inventory exceeds member limit")
            for module_name, _member_name, member in dex_rows:
                from mobileag.ingestion.apk_extractor import APKExtractor
                parsed = APKExtractor._dex_class_definition_count(archive, member)
                state = modules[module_name]
                if parsed.get("status") != "measured_dex_header":
                    state["dex_class_count_status"] = "incomplete_or_unsupported_dex"
                elif state["dex_class_count_status"] == "measured":
                    state["declared_dex_class_count"] += parsed["count"]

            if invalid_module_entries:
                for state in modules.values():
                    state["module_inventory_status"] = "incomplete_invalid_module_path"
            for state in modules.values():
                if "module_inventory_status" not in state:
                    state["module_inventory_status"] = (
                        "complete_within_inventory_limits" if state["manifest_present"]
                        else "incomplete_module_manifest_missing")
                if state["dex_member_count"] == 0 and state["dex_class_count_status"] == "measured":
                    state["dex_class_count_status"] = "not_applicable_no_dex_member"
                elif state["dex_class_count_status"] == "measured":
                    state["dex_class_count_status"] = "measured_dex_headers"
                elif state["dex_class_count_status"] == "incomplete_or_unsupported_member_name":
                    pass
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError) as exc:
        raise ValueError(f"Unable to read bounded Android App Bundle inventory ({type(exc).__name__})") from None

    after = _sha256(source)
    if before != after:
        raise ValueError("Android App Bundle changed during inventory")
    ordered = [modules[name] for name in sorted(modules)]
    complete = (not invalid_module_entries and all(
        row["module_inventory_status"] == "complete_within_inventory_limits"
        and row["invalid_dex_member_count"] == 0
        and row["dex_class_count_status"] in {"measured_dex_headers", "not_applicable_no_dex_member"}
        for row in ordered
    ))
    return {
        "inventory_schema_version": 1,
        "format": "android_app_bundle",
        "artifact_sha256": before,
        "size_bytes": source.stat().st_size,
        "zip_member_count": len(members),
        "expanded_bytes": expanded_bytes,
        "module_count": len(ordered),
        "module_manifest_count": sum(row["manifest_present"] for row in ordered),
        "dex_member_count": len(dex_rows),
        "native_library_member_count": sum(row["native_library_member_count"] for row in ordered),
        "modules": ordered,
        "inventory_status": "complete_within_limits" if complete else "partial",
        "analysis_state": "input_inventory_only_not_analyzed",
        "bundle_manifest_protobuf_decoded": False,
        "split_delivery_set_status": "not_measured",
        "runtime_status": "not_tested",
        "proof_status": "not_proven",
        "security_verdict": "not_established",
        "limitations": [
            "Module manifests are counted but protobuf contents and effective merged manifest are not decoded.",
            "DEX counts are header class-definition counts only; code is not decompiled or analyzed.",
            "Device-specific APK split generation, delivery selection, installation, and runtime behavior are not assessed.",
            "Archive member content checksums/CRC are not verified by this metadata-only inventory.",
        ],
    }


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()
