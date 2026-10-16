"""LangGraph orchestrator — wires all agents into a state-machine pipeline."""

import asyncio
import logging
import uuid
import json
from mobileag.security.privacy import redact
from mobileag.reporting.report_engine import ReportEngine
from pathlib import Path
from typing import Optional, Any

from config.settings import Settings, get_settings
from config.llm_config import TaskType
from mobileag.core.state import ScanState, create_initial_state
from mobileag.llm.router import LLMRouter
from mobileag.llm.consensus import ConsensusVoter
from mobileag.ingestion.apk_extractor import APKExtractor
from mobileag.ingestion.manifest_parser import ManifestParser
from mobileag.ingestion.framework_detector import FrameworkDetector
from mobileag.ingestion.packer_detector import PackerDetector
from mobileag.ingestion.obfuscation import ObfuscationAnalyzer
from mobileag.analysis.api_mapper import APIMapper
from mobileag.analysis.bounded_sources import SourceInventory
from mobileag.analysis.binary_protection_auditor import BinaryProtectionAuditor
from mobileag.analysis.call_graph import SmaliCallGraphEngine
from mobileag.analysis.android_surface import AndroidSurfaceAnalyzer
from mobileag.analysis.deep_link_correlation import correlate_manifest_deep_link_flows
from mobileag.analysis.auth_session_auditor import AuthSessionAuditor
from mobileag.analysis.firebase_auditor import FirebaseAuditor
from mobileag.analysis.code_reviewer import CodeReviewer
from mobileag.analysis.dependency_scanner import DependencyScanner
from mobileag.analysis.manifest_auditor import ManifestAuditor
from mobileag.analysis.native_analyzer import NativeAnalyzer
from mobileag.analysis.network_security_config_auditor import NetworkSecurityConfigAuditor
from mobileag.analysis.react_native_scanner import ReactNativeScanner
from mobileag.analysis.secret_scanner import SecretScanner
from mobileag.analysis.taint_engine import TaintEngine
from mobileag.filters.pipeline import FilterPipeline
from mobileag.generators.frida_generator import FridaGenerator
from mobileag.generators.poc_generator import PoCGenerator
from mobileag.reporting.finding import Finding, FindingStatus
from mobileag.reporting.sarif_exporter import SARIFExporter
from mobileag.analysis.pending_intent_auditor import PendingIntentAuditor
from mobileag.analysis.intent_redirection_auditor import IntentRedirectionAuditor
from mobileag.analysis.flutter_engine import FlutterEngineAnalyzer
from mobileag.analysis.native_jni_bridge import NativeJniAnalyzer
from mobileag.analysis.hermes_analyzer import HermesBytecodeAnalyzer
from mobileag.analysis.il2cpp_auditor import Il2CppAuditor
from mobileag.analysis.privacy_manifest_auditor import PrivacyManifestAuditor
from mobileag.analysis.rasp_resilience_auditor import RaspResilienceAuditor
from mobileag.analysis.fileprovider_auditor import FileProviderAuditor

logger = logging.getLogger(__name__)


class Orchestrator:
    """Main scan orchestrator that coordinates all agents through a pipeline.

    Pipeline stages:
        1. Ingestion — APK extraction, manifest parsing, framework/packer detection
        2. Analysis — 6 parallel agents scan for vulnerabilities
        3. Candidate ranking — optional heuristic signals; no automatic finding confirmation
        4. Generation — Frida scripts + PoC guides for candidate findings
        5. Reporting — Final report assembly
    """

    def __init__(self, settings: Optional[Settings] = None):
        self._settings = settings or get_settings()
        self._router = LLMRouter(self._settings)
        self._voter = ConsensusVoter(self._router, min_votes=self._settings.consensus_min_votes)

        # Ingestion agents
        self._extractor = APKExtractor(self._settings)
        self._manifest_parser = ManifestParser()
        self._framework_detector = FrameworkDetector()
        self._packer_detector = PackerDetector()
        self._obfuscation_analyzer = ObfuscationAnalyzer()

        # Analysis agents
        self._manifest_auditor = ManifestAuditor(self._router)
        self._secret_scanner = SecretScanner(self._router, self._settings.entropy_threshold)
        self._code_reviewer = CodeReviewer(self._router)
        self._api_mapper = APIMapper(self._router)
        self._native_analyzer = NativeAnalyzer(self._router, self._settings.GHIDRA_PATH)
        self._dependency_scanner = DependencyScanner(self._router)
        self._android_surface = AndroidSurfaceAnalyzer()
        self._auth_session_auditor = AuthSessionAuditor()
        self._firebase_auditor = FirebaseAuditor()
        self._call_graph_engine = SmaliCallGraphEngine()
        self._taint_engine = TaintEngine()
        self._nsc_auditor = NetworkSecurityConfigAuditor()
        self._bin_protection = BinaryProtectionAuditor()
        self._rn_scanner = ReactNativeScanner(self._settings.entropy_threshold)
        self._pending_intent_auditor = PendingIntentAuditor()
        self._intent_redirection_auditor = IntentRedirectionAuditor()
        self._flutter_engine = FlutterEngineAnalyzer()
        self._native_jni_analyzer = NativeJniAnalyzer()
        self._hermes_analyzer = HermesBytecodeAnalyzer()
        self._il2cpp_auditor = Il2CppAuditor()
        self._privacy_manifest_auditor = PrivacyManifestAuditor()
        self._rasp_auditor = RaspResilienceAuditor()
        self._fileprovider_auditor = FileProviderAuditor()

        # Filter pipeline
        self._filter_pipeline = FilterPipeline(
            router=self._router,
            consensus_voter=self._voter,
            settings=self._settings,
        )

        # Generators
        self._frida_generator = FridaGenerator(self._router)
        self._poc_generator = PoCGenerator(self._router)

    async def scan(
        self,
        apk_path: str,
        output_dir: Optional[str] = None,
        scan_id: Optional[str] = None,
        progress_callback: Optional[Any] = None,
        allow_advisory_lookup: bool = False,
    ) -> ScanState:
        """Run a full security scan on an APK.

        Args:
            apk_path: Path to the APK file.
            output_dir: Directory for scan output (default from settings).
            scan_id: Optional pre-assigned scan ID.
            progress_callback: Optional async callback taking (stage, message, progress_pct, finding).

        Returns:
            Complete ScanState with all findings and generated outputs.
        """
        sid = scan_id or str(uuid.uuid4())[:8]
        output = output_dir or self._settings.OUTPUT_DIR
        output_path = Path(output) / sid
        output_path.mkdir(parents=True, exist_ok=True)

        state = create_initial_state(sid, apk_path, str(output_path))
        state["allow_advisory_lookup"] = bool(allow_advisory_lookup)
        logger.info("Starting scan %s on %s", sid, apk_path)

        async def _notify(stage: str, msg: str, pct: int, finding: Optional[dict[str, Any]] = None) -> None:
            if progress_callback:
                try:
                    res = progress_callback(stage, msg, pct, finding)
                    if asyncio.iscoroutine(res):
                        await res
                except Exception as cb_err:
                    logger.debug("Progress callback error: %s", cb_err)

        await _notify("APK Extraction", "Decompiling DEX and resources via JADX / APKTool...", 10)

        # === Stage 1: Ingestion ===
        state = await self._run_ingestion(state)

        if not state["decompiled_path"] or state["errors"]:
            state["errors"].append("Ingestion failed — cannot continue scan")
            logger.error("Ingestion failed for %s", apk_path)
            await _notify("Ingestion Error", "Failed to decompile APK resources.", 100)
            state["current_phase"] = "failed"
            return state

        pkg = state.get("package_name") or "UnknownApp"
        framework = state.get("framework_info", {}).get("framework", "Native")
        await _notify("Ingestion Complete", f"Parsed manifest for {pkg} (Framework: {framework})", 25)

        # === Stage 2: Analysis ===
        await _notify("Static Analysis", "Running static review engines and Android surface coverage checks...", 40)
        state = await self._run_analysis(state)

        raw_count = len(state.get("raw_findings", []))
        await _notify("SAST Completed", f"Discovered {raw_count} raw potential security findings", 75)

        # Broadcast each discovered raw finding if callback is present
        if progress_callback and state.get("raw_findings"):
            for f in state["raw_findings"][:15]:  # stream preview
                await _notify("Finding Discovered", f.get("title", "Security Finding"), 78, f)

        # === Stage 3: Filtering ===
        await _notify("Candidate Ranking", "Ranking review candidates with available heuristic signals (not exploit proof)...", 85)
        state = await self._run_filtering(state)

        candidate_count = len(state.get("filtered_findings", []))
        await _notify("Filtering Complete", f"Retained {candidate_count} unverified review candidates", 92)

        # === Stage 4: Generation ===
        await _notify("Generators", "Synthesizing Frida hooks and Markdown PoC guides...", 95)
        state = await self._run_generation(state)

        # === Stage 5: Save outputs ===
        await self._save_outputs(state)

        state["current_phase"] = "partial" if state["errors"] else "complete"
        (output_path / "state.json").write_text(json.dumps(redact(state), indent=2, default=str))
        await _notify("Scan Complete", f"Scan {sid} complete: {candidate_count} unverified review candidates.", 98)
        logger.info(
            "Scan %s complete: %d candidate findings",
            sid, len(state["filtered_findings"]),
        )
        return state

    async def _run_ingestion(self, state: ScanState) -> ScanState:
        """Stage 1: Extract, parse, detect framework/packing/obfuscation."""
        state["current_phase"] = "ingestion"
        logger.info("[Stage 1] Ingestion — extracting APK...")

        try:
            extraction = await self._extractor.extract(
                state["apk_path"], state["output_dir"]
            )
            state["decompiled_path"] = extraction.get("jadx_dir", "")
            state["resource_path"] = extraction.get("apktool_dir", "")
            state["smali_path"] = extraction.get("apktool_dir", "")
            inventory = SourceInventory(max_entries=20000)
            file_counts = {"java": 0, "kotlin": 0, "smali": 0}
            for path in inventory.paths(state["decompiled_path"], {".java", ".kt"}):
                if path.suffix.lower() == ".java": file_counts["java"] += 1
                elif path.suffix.lower() == ".kt": file_counts["kotlin"] += 1
            smali_inventory = SourceInventory(max_entries=20000)
            file_counts["smali"] = sum(1 for _ in smali_inventory.paths(state["smali_path"], {".smali"}))
            state["coverage"].update({
                "java_files": file_counts["java"],
                "kotlin_files": file_counts["kotlin"],
                "smali_files": file_counts["smali"],
                "ingestion_inventory": {"source": dict(inventory.coverage), "smali": dict(smali_inventory.coverage)},
                "resources": bool(state["resource_path"]),
                "dependency_lookup": ("authorized" if state.get("allow_advisory_lookup") else
                                       "skipped_offline" if self._settings.offline else "skipped_no_consent"),
                "historical_learning": "not_configured",
                "android_surface": AndroidSurfaceAnalyzer().scan(None,{} )["coverage"],
            })
            state["package_name"] = extraction.get("package_name", "")
            state["artifact_provenance"] = extraction.get("artifact_provenance", {})
            archive_inventory = state["artifact_provenance"].get("archive_inventory", {})
            state["coverage"].setdefault("ingestion_inventory", {})["apk_archive"] = dict(archive_inventory)
            decompiler_diagnostics = state["artifact_provenance"].get("decompiler_diagnostics", {})
            if isinstance(decompiler_diagnostics, dict):
                state["coverage"]["decompiler_diagnostics"] = {
                    "static_status": ("partial" if decompiler_diagnostics.get("review_state") == "partial"
                                      else "completed" if decompiler_diagnostics.get("review_state") == "completed"
                                      else "incomplete"),
                    "runtime_status": "not_tested",
                    "proof_status": "not_proven",
                    "marker_line_counts": decompiler_diagnostics.get("marker_line_counts"),
                    "unsupported_construct_count": None,
                    "omitted_file_count": None,
                    "limits_reached": decompiler_diagnostics.get("status") == "bounded_diagnostics_incomplete",
                    "exhaustive": False,
                    "limitations": decompiler_diagnostics.get("limitations", []),
                }

            # Parse manifest
            manifest_path = extraction.get("manifest_path", "")
            state["manifest_path"] = str(manifest_path)
            if manifest_path:
                state["manifest_data"] = self._manifest_parser.parse(manifest_path)
                state["coverage"]["split_manifest"] = dict(
                    state["manifest_data"].get("split_metadata", {})
                )
                state["artifact_provenance"].setdefault("app", {}).update({
                    key: state["manifest_data"].get(key)
                    for key in ("version_name", "version_code", "min_sdk", "target_sdk")
                })
                # Extract components and deep links from manifest
                state["components"] = state["manifest_data"].get("components", [])
                state["deep_links"] = state["manifest_data"].get("deep_links", [])

            # Detect framework
            state["framework_info"] = self._framework_detector.detect(
                state["resource_path"]
            )

            # Detect packer
            packer_info = self._packer_detector.detect(
                state["apk_path"], state["decompiled_path"]
            )
            state["obfuscation_info"]["packer"] = packer_info

            # Analyze obfuscation
            obf_info = self._obfuscation_analyzer.analyze(state["decompiled_path"])
            state["obfuscation_info"]["obfuscation"] = obf_info

            logger.info(
                "[Stage 1] Done — package: %s, framework: %s",
                state["package_name"],
                state["framework_info"].get("framework", "native"),
            )
        except Exception as exc:
            logger.error("[Stage 1] Ingestion error: %s", exc)
            state["errors"].append(f"Ingestion error: {exc}")

        return state

    async def _run_analysis(self, state: ScanState) -> ScanState:
        """Stage 2: Run all enterprise analysis agents in parallel."""
        state["current_phase"] = "analysis"
        logger.info("[Stage 2] Analysis — running analysis agents in parallel...")

        all_findings: list[Finding] = []
        manifest_data = state.get("manifest_data", {})
        target_sdk_raw = manifest_data.get("target_sdk") if isinstance(manifest_data, dict) else None
        target_sdk = None
        if isinstance(target_sdk_raw, int) and not isinstance(target_sdk_raw, bool):
            target_sdk = target_sdk_raw
        elif isinstance(target_sdk_raw, str) and target_sdk_raw.isdecimal():
            target_sdk = int(target_sdk_raw)

        # Run all agents concurrently
        tasks = {
            "auth_session": self._auth_session_auditor.analyze(state["decompiled_path"]),
            "firebase": self._firebase_auditor.analyze(state["decompiled_path"], state["resource_path"]),
            "android_surface": self._android_surface.analyze(state["decompiled_path"],state["manifest_data"]),
            "manifest": self._manifest_auditor.audit(
                state["manifest_data"], state["package_name"]
            ),
            "secrets": self._secret_scanner.scan(state["output_dir"]),
            "code_review": self._code_reviewer.review(
                state["decompiled_path"], state["manifest_data"]
            ),
            "api_mapping": self._api_mapper.map_apis(state["decompiled_path"]),
            "native": self._native_analyzer.analyze(state["resource_path"]),
            "dependencies": self._dependency_scanner.scan(
                state["resource_path"], allow_advisory_lookup=state.get("allow_advisory_lookup", False)),
            "taint": self._taint_engine.analyze_directory_async(state["decompiled_path"]) if self._settings.enable_deep_taint else asyncio.sleep(0, result=[]),
            "nsc": self._nsc_auditor.audit_directory_async(state["resource_path"]),
            "binary_protection": self._bin_protection.audit_directory_async(state["resource_path"]),
            "react_native": self._rn_scanner.scan_directory_async(state["resource_path"]),
            "pending_intent": asyncio.to_thread(
                self._pending_intent_auditor.audit_directory, state["decompiled_path"], target_sdk=target_sdk),
            "intent_redirection": asyncio.to_thread(self._intent_redirection_auditor.audit_directory, state["decompiled_path"]),
            "native_jni": asyncio.to_thread(self._native_jni_analyzer.audit_package_libraries, state["resource_path"]),
            "hermes": asyncio.to_thread(self._hermes_analyzer.audit_package_bundles, state["resource_path"]),
            "il2cpp": asyncio.to_thread(self._il2cpp_auditor.audit_package, state["resource_path"]),
            "flutter": asyncio.to_thread(self._flutter_engine.analyze_package_directory, state["resource_path"]),
            "fileprovider": asyncio.to_thread(self._fileprovider_auditor.audit_resource_directory, state["resource_path"]),
            "data_safety": asyncio.to_thread(
                self._privacy_manifest_auditor.audit_android_data_safety_package,
                state.get("manifest_path", ""), state["resource_path"],
            ),
        }

        results = await asyncio.gather(
            *tasks.values(), return_exceptions=True
        )

        engines=state.setdefault("coverage",{}).setdefault("engines",{})
        agent_names = list(tasks.keys())
        for i, result in enumerate(results):
            name = agent_names[i]
            if isinstance(result, Exception):
                logger.error("[Stage 2] %s agent failed: %s", name, result)
                state["errors"].append(f"{name} agent error: {result}")
                engines[name]="incomplete"
                if name in {"auth_session", "firebase"}:
                    state["coverage"][name].update(static_status="incomplete", runtime_status="not_tested", proof_status="not_proven")
                if name == "manifest":
                    state["coverage"][name] = {
                        "static_status": "incomplete", "runtime_status": "not_tested",
                        "proof_status": "not_proven", "exhaustive": False,
                        "limitations": ["manifest auditor failed; component review is incomplete"],
                    }
                if name in {"secrets", "code_review", "api_mapping", "native", "dependencies", "taint", "nsc", "binary_protection", "react_native", "fileprovider", "intent_redirection", "pending_intent", "data_safety", "il2cpp"}:
                    state["coverage"][name] = {
                        "static_status": "incomplete", "runtime_status": "not_tested",
                        "proof_status": "not_proven", "exhaustive": False,
                        "limitations": ["analysis engine failed; findings and coverage are incomplete"],
                    }
                    if name == "taint":
                        state["coverage"][name]["serialization"] = {
                            "static_status": "incomplete", "runtime_status": "not_tested",
                            "proof_status": "not_proven", "candidate_count": None,
                            "exhaustive": False,
                        }
                        state["coverage"][name]["webview"] = {
                            "static_status": "incomplete", "runtime_status": "not_tested",
                            "proof_status": "not_proven", "candidate_count": None,
                            "exhaustive": False,
                        }
                if name=="android_surface":
                    for category in state["coverage"].get("android_surface",{}).get("categories",{}).values():
                        category["static_status"]="incomplete"
                continue

            engines[name]="skipped_disabled" if name=="taint" and not self._settings.enable_deep_taint else "completed_heuristically"
            if name == "dependencies" and self._settings.offline:
                engines[name] = "skipped_offline"
                state["coverage"]["dependencies"] = dict(self._dependency_scanner.coverage)
            if name in {"auth_session", "firebase"}:
                all_findings.extend(result["findings"])
                state["coverage"][name] = result["coverage"]
                engines[name] = result["coverage"]["static_status"]
            elif name=="android_surface":
                all_findings.extend(result["findings"])
                state["coverage"]["android_surface"]=result["coverage"]
                engines[name]=result["coverage"]["categories"]["webview"]["static_status"]
            elif name == "api_mapping":
                # API mapper returns (endpoints, findings)
                endpoints, findings = result
                state["api_endpoints"] = [
                    ep if isinstance(ep, dict) else ep.__dict__
                    for ep in endpoints
                ]
                all_findings.extend(findings)
                state["coverage"][name] = dict(self._api_mapper.coverage)
            elif name == "native_jni":
                for lib_res in result:
                    all_findings.extend(lib_res.findings)
            elif name == "flutter":
                if getattr(result, "is_flutter_app", False):
                    for ep in getattr(result, "api_endpoints", []):
                        state.setdefault("api_endpoints", []).append({"url": ep, "method": "GET"})
            elif name == "hermes":
                for h_res in (result or []):
                    if getattr(h_res, "is_hermes", False):
                        for ep in getattr(h_res, "api_endpoints", []):
                            state.setdefault("api_endpoints", []).append({"url": ep, "method": "GET"})
            elif name == "il2cpp":
                state["il2cpp_analysis"] = {
                    "scan_status": getattr(result, "scan_status", "unknown"),
                    "is_il2cpp": bool(getattr(result, "is_il2cpp", False)),
                    "metadata_version": getattr(result, "metadata_version", None),
                    "metadata_tables_status": getattr(result, "metadata_tables_status", "unknown"),
                    "metadata_definitions_status": getattr(result, "metadata_definitions_status", "unknown"),
                    "type_definitions_count": int(getattr(result, "type_definitions_count", 0) or 0),
                    "method_definitions_count": int(getattr(result, "method_definitions_count", 0) or 0),
                    "reconstructed_classes": list(getattr(result, "reconstructed_classes", []))[:50],
                    "reconstructed_fields": list(getattr(result, "reconstructed_fields", []))[:100],
                    "reconstructed_methods": list(getattr(result, "reconstructed_methods", []))[:100],
                    "tree_entries_scanned": int(getattr(result, "tree_entries_scanned", 0) or 0),
                    "metadata_bytes_scanned": int(getattr(result, "metadata_bytes_scanned", 0) or 0),
                    "metadata_truncated": bool(getattr(result, "metadata_truncated", False)),
                    "candidate_output_truncated": bool(getattr(result, "candidate_output_truncated", False)),
                    "scan_errors": list(getattr(result, "scan_errors", []))[:20],
                    "evidence_kind": "bounded_static_metadata_candidates",
                    "runtime_status": "not_tested",
                    "proof_status": "not_proven",
                    "exhaustive": False,
                }
                state["coverage"]["il2cpp"] = {
                    "static_status": "partial" if getattr(result, "scan_status", "") != "complete"
                    or getattr(result, "metadata_truncated", False)
                    or getattr(result, "candidate_output_truncated", False)
                    else "analyzed_heuristically",
                    "runtime_status": "not_tested", "proof_status": "not_proven",
                    "exhaustive": False,
                    "metadata_definitions_status": getattr(result, "metadata_definitions_status", "unknown"),
                    "candidate_count": len(getattr(result, "reconstructed_classes", []))
                    + len(getattr(result, "reconstructed_fields", []))
                    + len(getattr(result, "reconstructed_methods", [])),
                    "limitations": ["bounded metadata names are review candidates, not source reconstruction or exploit proof"],
                }
                if getattr(result, "is_il2cpp", False):
                    for ep in getattr(result, "api_endpoints", []):
                        state.setdefault("api_endpoints", []).append({"url": ep, "method": "GET"})
            elif name == "fileprovider":
                for fp_res in (result or []):
                    all_findings.extend(fp_res.findings)
                state["coverage"][name] = dict(self._fileprovider_auditor.coverage)
            elif name == "data_safety":
                all_findings.extend(result.get("findings", []))
                details = dict(result.get("coverage", {}))
                complete_inputs = (details.get("manifest_parse") == "parsed"
                                   and details.get("source_tree") == "complete")
                static_status = ("partial" if not complete_inputs or details.get("limits_reached")
                                 or details.get("errors") else "analyzed_heuristically")
                state["coverage"][name] = {
                    **details, "static_status": static_status,
                    "runtime_status": "not_tested", "proof_status": "not_proven",
                    "candidate_count": len(result.get("findings", [])), "exhaustive": False,
                    "limitations": [
                        "Play Console declarations are unavailable in the APK/source tree",
                        "permission and SDK fingerprints do not prove data collection, execution, or sharing",
                    ],
                }
                engines[name] = static_status
            elif name == "intent_redirection":
                all_findings.extend(result)
                state["coverage"][name] = dict(self._intent_redirection_auditor.coverage)
            elif name == "pending_intent":
                all_findings.extend(result)
                state["coverage"][name] = dict(self._pending_intent_auditor.coverage)
            elif isinstance(result, list):
                all_findings.extend(result)
                if name == "manifest":
                    manifest = state.get("manifest_data", {})
                    manifest_ready = isinstance(manifest, dict) and isinstance(manifest.get("components"), list)
                    provider_inventory = dict(manifest.get("provider_path_inventory", {})) if isinstance(manifest, dict) else {}
                    if provider_inventory:
                        provider_inventory["candidate_count"] = sum(
                            1 for finding in result
                            if getattr(finding, "metadata", {}).get("analysis_kind") == "provider_path_configuration")
                    else:
                        provider_inventory = {
                            "static_status": "incomplete", "runtime_status": "not_tested",
                            "proof_status": "not_proven", "exhaustive": False,
                            "limitations": ["provider path resource inventory unavailable"],
                        }
                    state["coverage"]["manifest"] = {
                        "static_status": "completed" if manifest_ready else "incomplete",
                        "runtime_status": "not_tested",
                        "proof_status": "not_proven",
                        "exhaustive": False,
                        "component_count": len(manifest.get("components", [])) if manifest_ready else 0,
                        "exported_component_count": sum(1 for component in manifest.get("components", [])
                                                         if component.get("exported") is True) if manifest_ready else 0,
                        "candidate_count": sum(1 for finding in result
                                               if getattr(finding, "detection_method", "") == "ManifestAuditor"),
                        "backup_rule_references": dict(manifest.get("application", {}).get(
                            "backup_rule_references", {})) if isinstance(manifest.get("application"), dict) else {},
                        "backup_rules_inventory": dict(manifest.get("application", {}).get(
                            "backup_rules_inventory", {})) if isinstance(manifest.get("application"), dict) else {},
                        "provider_path_inventory": provider_inventory,
                        "limitations": [
                            "bounded parsed-manifest audit only; merged installed manifest and runtime caller authorization are not verified",
                            "exported declarations and candidate findings do not establish attacker reachability or impact",
                        ],
                    }
                    backup_inventory = state["coverage"]["manifest"].get("backup_rules_inventory")
                    if isinstance(backup_inventory, dict):
                        backup_inventory["candidate_count"] = sum(
                            1 for finding in result
                            if getattr(finding, "metadata", {}).get("check_id") == "manifest_allow_backup")
                elif name == "secrets":
                    state["coverage"][name] = dict(self._secret_scanner.coverage)
                    engines[name] = self._secret_scanner.coverage.get("static_status", "incomplete")
                elif name == "code_review":
                    state["coverage"][name] = dict(self._code_reviewer.coverage)
                    engines[name] = self._code_reviewer.coverage.get("static_status", "incomplete")
                elif name in {"native", "dependencies", "taint", "nsc", "binary_protection", "react_native"}:
                    if name == "taint" and not self._settings.enable_deep_taint:
                        state["coverage"][name] = {
                            "static_status": "skipped_disabled", "runtime_status": "not_tested",
                            "proof_status": "not_proven", "exhaustive": False,
                            "limitations": ["deep taint scan is disabled by configuration"],
                        }
                        state["coverage"][name]["serialization"] = {
                            "static_status": "skipped_disabled", "runtime_status": "not_tested",
                            "proof_status": "not_proven", "candidate_count": None,
                            "exhaustive": False,
                        }
                        state["coverage"][name]["webview"] = {
                            "static_status": "skipped_disabled", "runtime_status": "not_tested",
                            "proof_status": "not_proven", "candidate_count": None,
                            "exhaustive": False,
                        }
                    else:
                        analyzer = {
                            "native": self._native_analyzer, "dependencies": self._dependency_scanner,
                            "taint": self._taint_engine, "nsc": self._nsc_auditor,
                            "binary_protection": self._bin_protection, "react_native": self._rn_scanner,
                        }[name]
                        state["coverage"][name] = dict(getattr(analyzer, "coverage", {}))

            f_count = 0
            if name in {"android_surface", "auth_session", "firebase"} and isinstance(result, dict):
                f_count = len(result.get("findings", []))
            elif isinstance(result, tuple):
                f_count = len(result[1]) if len(result) > 1 and hasattr(result[1], "__len__") else 0
            elif isinstance(result, list):
                f_count = len(result)
            elif hasattr(result, "findings"):
                f_count = len(getattr(result, "findings", []))
            logger.info("[Stage 2] %s: %d findings", name, f_count)

        # Deterministic Smali Call Graph reachability audit
        try:
            smali_findings = self._call_graph_engine.audit_smali_directory(state["smali_path"])
            all_findings.extend(smali_findings)
            state["coverage"]["smali_call_graph"] = dict(self._call_graph_engine.coverage)
            engines["smali_call_graph"]="completed_heuristically"
            logger.info("[Stage 2] Smali Call Graph: %d reachability findings", len(smali_findings))
        except Exception as e:
            engines["smali_call_graph"]="incomplete"
            state["coverage"]["smali_call_graph"] = {
                "static_status": "incomplete", "runtime_status": "not_tested",
                "proof_status": "not_proven", "exhaustive": False,
            }
            state["errors"].append("Smali call graph review incomplete")
            logger.warning("[Stage 2] Smali Call Graph audit warning: %s", e)

        try:
            route_correlation = correlate_manifest_deep_link_flows(
                all_findings, state.get("manifest_data", {}))
        except Exception as e:
            route_correlation = {
                "status": "incomplete", "uri_flow_candidates": None,
                "correlated_flows": None, "unmatchable_flows": None,
                "proof_status": "not_proven", "runtime_status": "not_tested",
                "limitations": ["bounded manifest-route correlation failed"],
            }
            logger.warning("[Stage 2] Deep-link route correlation incomplete: %s", e)
        state["coverage"]["deep_link_flow_correlation"] = route_correlation
        deep_link_coverage = (state.get("coverage", {}).get("android_surface", {})
                              .get("categories", {}).get("deep_links"))
        if isinstance(deep_link_coverage, dict):
            deep_link_coverage["uri_flow_manifest_route_correlation"] = route_correlation

        for finding in all_findings:
            finding.status = FindingStatus.UNVERIFIED
        state["raw_findings"] = redact([f.model_dump(mode="json") for f in all_findings])
        logger.info("[Stage 2] Done — %d raw findings total", len(all_findings))
        return state

    async def _run_filtering(self, state: ScanState) -> ScanState:
        """Stage 3: rank and annotate unverified candidate findings."""
        state["current_phase"] = "filtering"
        logger.info("[Stage 3] Candidate ranking — findings remain unverified...")

        raw_findings = [
            Finding(**f) for f in state["raw_findings"]
        ]

        review_candidates = await self._filter_pipeline.filter_findings(
            raw_findings, state["decompiled_path"]
        )

        state["filtered_findings"] = [f.model_dump() for f in review_candidates]
        logger.info(
            "[Stage 3] Done — %d/%d findings retained",
            len(review_candidates), len(raw_findings),
        )
        return state

    async def _run_generation(self, state: ScanState) -> ScanState:
        """Stage 4: Generate Frida scripts and PoC guides."""
        state["current_phase"] = "generation"
        logger.info("[Stage 4] Generation — Frida scripts + PoC guides...")

        review_candidates = [Finding(**f) for f in state["filtered_findings"]]
        app_info = {
            "package_name": state["package_name"],
            "framework": state["framework_info"].get("framework", "native"),
            "scan_id": state["scan_id"],
        }

        # Generate Frida scripts
        try:
            frida_results = await self._frida_generator.generate_batch(
                review_candidates, app_info
            )
            state["generated_frida_scripts"] = frida_results
            logger.info("[Stage 4] Generated %d Frida scripts", len(frida_results))
        except Exception as exc:
            logger.error("[Stage 4] Frida generation error: %s", exc)
            state["errors"].append(f"Frida generation error: {exc}")

        # Generate PoC guides
        try:
            poc_results = await self._poc_generator.generate_batch(
                review_candidates, app_info
            )
            state["generated_poc_guides"] = poc_results
            logger.info("[Stage 4] Generated %d PoC guides", len(poc_results))
        except Exception as exc:
            logger.error("[Stage 4] PoC generation error: %s", exc)
            state["errors"].append(f"PoC generation error: {exc}")

        return state

    async def _save_outputs(self, state: ScanState) -> None:
        """Save generated Frida scripts and PoC guides to disk."""
        output = Path(state["output_dir"])
        await ReportEngine().generate_reports(state)

        # Save Frida scripts
        frida_dir = output / "frida_scripts"
        frida_dir.mkdir(exist_ok=True)
        for item in state.get("generated_frida_scripts", []):
            fp = frida_dir / Path(item["filename"]).name
            fp.write_text(redact(item["script"]))
            logger.info("Saved Frida script: %s", fp)

        # Save PoC guides
        poc_dir = output / "poc_guides"
        poc_dir.mkdir(exist_ok=True)
        for item in state.get("generated_poc_guides", []):
            fp = poc_dir / Path(item["filename"]).name
            fp.write_text(redact(item["poc_guide"]))
            logger.info("Saved PoC guide: %s", fp)

        # Save OASIS SARIF v2.1.0 report for CI/CD integration
        try:
            sarif_path = output / f"report_{state['scan_id']}.sarif"
            SARIFExporter.export_to_file(
                findings=state.get("filtered_findings", []),
                output_path=sarif_path,
                target_name=state.get("package_name", "mobile_target"),
                scan_id=state.get("scan_id", "scan-001"),
                artifact={
                    "artifact_sha256": state.get("artifact_provenance", {}).get("sha256"),
                    "package_name": state.get("package_name"),
                    "app_version": state.get("manifest_data", {}).get("version_name") or state.get("version"),
                },
                coverage=state.get("coverage", {}),
            )
            state["sarif_path"] = str(sarif_path)
            logger.info("Saved SARIF report: %s", sarif_path)
        except Exception as exc:
            logger.warning("Failed exporting SARIF: %s", exc)

        # Save CycloneDX v1.5 SBOM
        try:
            from mobileag.analysis.sbom_generator import MobileSbomGenerator
            sbom_gen = MobileSbomGenerator(
                app_name=state.get("package_name") or "mobile_target",
                app_version=state.get("manifest_data", {}).get("version_name") or "1.0.0",
            )
            for dep in state.get("dependencies", []):
                sbom_gen.add_component(
                    name=dep.get("name", "dependency"),
                    version=dep.get("version", "unknown"),
                    purl=dep.get("purl", f"pkg:generic/{dep.get('name', 'dependency')}"),
                )
            sbom_path = output / f"sbom_{state['scan_id']}_cyclonedx.json"
            sbom_gen.save_cyclonedx(sbom_path)
            state["sbom_path"] = str(sbom_path)
            logger.info("Saved CycloneDX SBOM: %s", sbom_path)
        except Exception as exc:
            logger.warning("Failed exporting CycloneDX SBOM: %s", exc)
