"""Sanitize installed-package permission snapshots into bounded observations.

This module records device state only. Permission names or grants are not
classified as vulnerabilities without app-flow and user-consent context.
"""
from __future__ import annotations

import re
from typing import Any

_PERMISSION = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$")
_MAX_PERMISSIONS = 512


def _permission_set(value: Any, field: str) -> set[str]:
    if not isinstance(value, list) or len(value) > _MAX_PERMISSIONS:
        raise ValueError(f"{field} inventory is missing or exceeds bounds")
    if any(not isinstance(item, str) or len(item) > 256 or not _PERMISSION.fullmatch(item) for item in value):
        raise ValueError(f"{field} inventory contains malformed permission names")
    return set(value)


def summarize_runtime_package(package_name: str, info: dict[str, Any],
                               static_permissions: list[str] | None = None) -> dict[str, Any]:
    """Return names/counts only; omit code/data paths and never infer safety."""
    if not isinstance(package_name, str) or not re.fullmatch(r"[A-Za-z_][\w]*(?:\.[A-Za-z_][\w]*)+", package_name):
        raise ValueError("Invalid package name")
    if not isinstance(info, dict) or info.get("package_name") != package_name:
        raise ValueError("Runtime package identity differs from the approved package")
    requested = _permission_set(info.get("requested_permissions"), "requested")
    granted = _permission_set(info.get("granted_permissions"), "granted")
    static_status = "not_recorded"
    static_delta: dict[str, list[str]] = {"runtime_only": [], "static_only": []}
    if static_permissions is not None:
        static = _permission_set(static_permissions, "static")
        static_status = "matched" if static == requested else "different_review_required"
        static_delta = {"runtime_only": sorted(requested - static),
                        "static_only": sorted(static - requested)}
    return {
        "status": "observed",
        "package_name": package_name,
        "version_name": str(info.get("version_name", "Unknown"))[:128],
        "version_code": str(info.get("version_code", "Unknown"))[:32],
        "target_sdk": str(info.get("target_sdk", "Unknown"))[:16],
        "requested_permission_count": len(requested),
        "granted_permission_count": len(granted),
        "granted_requested_permissions": sorted(requested & granted),
        "requested_not_granted_permissions": sorted(requested - granted),
        "granted_not_requested_permissions": sorted(granted - requested),
        "static_comparison_status": static_status,
        "static_delta": static_delta,
        "evidence_type": "runtime_package_permission_snapshot",
        "proof_status": "not_proven",
        "limitations": [
            "ADB package-manager output is a diagnostic observation, not ordinary-app access proof.",
            "Permission grants are not vulnerabilities without reachability, consent, purpose and data-flow review.",
            "Static/runtime manifest differences need platform/build-context review.",
        ],
    }
