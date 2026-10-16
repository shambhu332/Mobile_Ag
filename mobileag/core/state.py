"""LangGraph state schema for the MobileAg scan pipeline."""

from typing import TypedDict, Any


class ScanState(TypedDict):
    """Complete state object passed through the LangGraph pipeline.

    Each agent reads from and writes to specific fields in this state.
    The orchestrator persists a JSON snapshot in the scan output directory.
    """

    # ── Scan Identity ──
    scan_id: str
    apk_path: str
    artifact_provenance: dict[str, Any]
    package_name: str
    output_dir: str

    # ── Ingestion Results ──
    manifest_data: dict[str, Any]
    manifest_path: str
    resource_path: str
    smali_path: str
    coverage: dict[str, Any]
    assessment_coverage: str
    coverage_gaps: list[str]
    json_report_path: str
    sarif_path: str
    decompiled_path: str
    framework_info: dict[str, Any]
    il2cpp_analysis: dict[str, Any]
    obfuscation_info: dict[str, Any]

    # ── Extracted Assets ──
    components: list[dict[str, Any]]       # Exported activities, services, etc.
    deep_links: list[dict[str, Any]]       # URI schemes and app links
    api_endpoints: list[dict[str, Any]]    # Extracted API routes
    secrets_found: list[dict[str, Any]]    # Hardcoded secrets, keys
    native_libraries: list[dict[str, Any]] # .so files with metadata
    dependencies: list[dict[str, Any]]     # Third-party libraries

    # ── Findings Pipeline ──
    raw_findings: list[dict[str, Any]]         # Pre-filter findings
    filtered_findings: list[dict[str, Any]]    # Retained unverified review candidates (legacy field name)

    # ── Generated Outputs ──
    generated_frida_scripts: list[dict[str, Any]]  # Frida hooks (text files)
    generated_poc_guides: list[dict[str, Any]]     # PoC step-by-step guides

    # ── State Tracking ──
    graph_populated: bool
    report_path: str
    errors: list[str]
    current_phase: str


def create_initial_state(
    scan_id: str,
    apk_path: str,
    output_dir: str = "./output",
) -> ScanState:
    """Create a fresh scan state with empty defaults."""
    return ScanState(
        scan_id=scan_id,
        apk_path=apk_path,
        artifact_provenance={},
        package_name="",
        output_dir=output_dir,
        manifest_data={},
        manifest_path="",
        decompiled_path="",
        resource_path="",
        smali_path="",
        coverage={"android_surface":{
            "categories":{name:{"static_status":"not_started","runtime_status":"not_tested","proof_status":"not_proven"}
                          for name in ("deep_links","webview","intent")},
            "exhaustive":False,"automatic_exploit_proof":False},
            **{name: {"static_status": "not_started", "runtime_status": "not_tested",
                      "proof_status": "not_proven", "exhaustive": False}
               for name in ("auth_session", "firebase", "secrets", "code_review", "api_mapping", "data_safety",
                            "native", "dependencies", "taint", "nsc", "binary_protection", "react_native", "il2cpp")}},
        assessment_coverage="not_assessed",
        coverage_gaps=[],
        json_report_path="",
        sarif_path="",
        framework_info={},
        il2cpp_analysis={},
        obfuscation_info={},
        components=[],
        deep_links=[],
        api_endpoints=[],
        secrets_found=[],
        native_libraries=[],
        dependencies=[],
        raw_findings=[],
        filtered_findings=[],
        generated_frida_scripts=[],
        generated_poc_guides=[],
        graph_populated=False,
        report_path="",
        errors=[],
        current_phase="initialized",
    )
