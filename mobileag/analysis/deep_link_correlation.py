"""Correlate URI-flow candidates with same-class exported manifest routes.

This is a bounded identity join, not reachability, control-flow, or exploit proof.
"""
from __future__ import annotations

from typing import Any


_URI_SOURCES = {"URI_QUERY_PARAM", "URI_COMPONENT"}
_QUALIFIED_IDENTITY_KINDS = {
    "package_and_explicit_import_canonicalization_only",  # legacy analysis records
    "package_import_and_same_source_type_lexical_canonicalization_only",
}
MAX_COMPONENTS = 5_000
MAX_ROUTES = 5_000
MAX_FINDINGS = 10_000


def _component_class(name: Any, package: Any) -> str | None:
    if not isinstance(name, str) or not name or len(name) > 512:
        return None
    package = package if isinstance(package, str) and len(package) <= 256 else ""
    if name.startswith("."):
        return f"{package}{name}" if package else None
    if "." not in name:
        return f"{package}.{name}" if package else None
    return name


def _bounded_route_value(value: Any) -> str | int | bool | None:
    if isinstance(value, str):
        return value[:256]
    if type(value) in (int, bool) or value is None:
        return value
    return None


def correlate_manifest_deep_link_flows(findings: list, manifest: dict[str, Any]) -> dict[str, Any]:
    """Annotate URI-flow candidates whose AST owner matches an exported route class.

    Only fully package-qualified AST owner identities are joined. Lexical/simple
    class names are intentionally left uncorrelated to avoid basename guesses.
    """
    if not isinstance(manifest, dict) or not isinstance(manifest.get("components"), list):
        return {"status": "unavailable", "uri_flow_candidates": 0,
                "correlated_flows": 0, "unmatchable_flows": 0,
                "proof_status": "not_proven", "runtime_status": "not_tested"}

    package = manifest.get("package_name") or manifest.get("package")
    components = manifest["components"]
    routes = manifest.get("deep_links", [])
    routes = routes if isinstance(routes, list) else []
    components_truncated = len(components) > MAX_COMPONENTS
    routes_truncated = len(routes) > MAX_ROUTES
    findings_truncated = len(findings) > MAX_FINDINGS
    component_by_name = {}
    for component in components[:MAX_COMPONENTS]:
        if isinstance(component, dict) and isinstance(component.get("name"), str):
            component_by_name.setdefault(component["name"], component)
    route_by_owner: dict[str, list[dict[str, Any]]] = {}
    for route in routes[:MAX_ROUTES]:
        if not isinstance(route, dict) or route.get("exported") is not True:
            continue
        route_class = _component_class(route.get("component"), package)
        if route_class:
            route_by_owner.setdefault(route_class, []).append(route)
        component = component_by_name.get(route.get("component"))
        # An exported activity-alias forwards entry to its declared target class.
        if component and component.get("type") == "activity-alias":
            target = _component_class(component.get("alias_target"), package)
            if target:
                route_by_owner.setdefault(target, []).append(route)

    uri_flows = correlated = unmatchable = 0
    for finding in findings[:MAX_FINDINGS]:
        metadata = getattr(finding, "metadata", None)
        if not isinstance(metadata, dict):
            continue
        trace = metadata.get("source_sink_trace")
        if not isinstance(trace, dict):
            continue
        source = trace.get("source")
        if not isinstance(source, dict) or source.get("kind") not in _URI_SOURCES:
            continue
        uri_flows += 1
        identity = source.get("source_qualified_method_identity")
        identity_kind = source.get("source_qualified_identity_kind")
        owner = identity.split("#", 1)[0] if isinstance(identity, str) and "#" in identity else None
        if (identity_kind not in _QUALIFIED_IDENTITY_KINDS
                or not owner or owner not in route_by_owner):
            unmatchable += 1
            continue
        matched = route_by_owner[owner]
        metadata["manifest_route_correlation"] = {
            "status": "same_ast_owner_as_exported_manifest_uri_route",
            "component_class": owner,
            "matched_route_count": len(matched),
            "routes": [{key: _bounded_route_value(route.get(key)) for key in
                        ("component", "filter_index", "scheme", "host", "port", "path", "path_kind", "uri")}
                       for route in matched[:10]],
            "identity_basis": identity_kind,
            "entrypoint_reachability": "not_established",
            "guards_and_control_flow": "not_resolved",
            "runtime_verified": False,
            "proof_status": "not_proven",
        }
        correlated += 1

    return {
        "status": "partial" if components_truncated or routes_truncated or findings_truncated else "bounded_same_class_join_completed",
        "uri_flow_candidates": uri_flows,
        "correlated_flows": correlated,
        "unmatchable_flows": unmatchable,
        "exported_manifest_uri_routes": sum(len(items) for items in route_by_owner.values()),
        "inventory_limits": {"components": MAX_COMPONENTS, "routes": MAX_ROUTES,
                             "findings": MAX_FINDINGS},
        "components_seen": min(len(components), MAX_COMPONENTS),
        "routes_seen": min(len(routes), MAX_ROUTES),
        "findings_seen": min(len(findings), MAX_FINDINGS),
        "components_omitted_by_limit": max(0, len(components) - MAX_COMPONENTS),
        "routes_omitted_by_limit": max(0, len(routes) - MAX_ROUTES),
        "findings_omitted_by_limit": max(0, len(findings) - MAX_FINDINGS),
        "inventory_truncated": components_truncated or routes_truncated or findings_truncated,
        "proof_status": "not_proven",
        "runtime_status": "not_tested",
        "limitations": [
            "Only explicit-import-qualified AST owner identities are joined; lexical/simple names are not guessed.",
            "Same-class route declaration does not prove the method is invoked by that route, reachable, or unguarded.",
            "Intent-filter matching semantics, aliases beyond the direct target, URI normalization and runtime dispatch are not analyzed.",
            "Component, route, and finding inventories are bounded; omitted entries make correlation coverage partial.",
        ],
    }
