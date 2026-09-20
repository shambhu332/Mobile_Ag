"""LangGraph state schema for the MobileAg scan pipeline."""

from typing import TypedDict, Any


class ScanState(TypedDict):
    """Complete state object passed through the LangGraph pipeline.

    Each agent reads from and writes to specific fields in this state.
    LangGraph persists this to PostgreSQL for crash recovery.
    """

    # ── Scan Identity ──
    scan_id: str
    apk_path: str
    package_name: str
    output_dir: str

    # ── Ingestion Results ──
    manifest_data: dict[str, Any]
    decompiled_path: str
    framework_info: dict[str, Any]
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
    filtered_findings: list[dict[str, Any]]    # Post 5-layer filter

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
        package_name="",
        output_dir=output_dir,
        manifest_data={},
        decompiled_path="",
        framework_info={},
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
