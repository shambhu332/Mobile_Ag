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
from mobileag.analysis.binary_protection_auditor import BinaryProtectionAuditor
from mobileag.analysis.call_graph import SmaliCallGraphEngine
from mobileag.analysis.android_surface import AndroidSurfaceAnalyzer
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

logger = logging.getLogger(__name__)


class Orchestrator:
    """Main scan orchestrator that coordinates all agents through a pipeline.

    Pipeline stages:
        1. Ingestion — APK extraction, manifest parsing, framework/packer detection
        2. Analysis — 6 parallel agents scan for vulnerabilities
        3. Filtering — 5-layer false positive elimination
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
        await _notify("5-Layer Filter", "Prioritizing candidates using heuristic reachability and optional consensus (not exploit proof)...", 85)
        state = await self._run_filtering(state)

        confirmed_count = len(state.get("filtered_findings", []))
        await _notify("Filtering Complete", f"Retained {confirmed_count} review candidates", 92)

        # === Stage 4: Generation ===
        await _notify("Generators", "Synthesizing Frida hooks and Markdown PoC guides...", 95)
        state = await self._run_generation(state)

        # === Stage 5: Save outputs ===
        await self._save_outputs(state)

        state["current_phase"] = "partial" if state["errors"] else "complete"
        (output_path / "state.json").write_text(json.dumps(redact(state), indent=2, default=str))
        await _notify("Scan Complete", f"Scan {sid} complete: {confirmed_count} candidate findings.", 98)
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
            state["coverage"] = {
                "java_files": len(list(Path(state["decompiled_path"]).rglob("*.java"))) if state["decompiled_path"] else 0,
                "kotlin_files": len(list(Path(state["decompiled_path"]).rglob("*.kt"))) if state["decompiled_path"] else 0,
                "smali_files": len(list(Path(state["smali_path"]).rglob("*.smali"))) if state["smali_path"] else 0,
                "resources": bool(state["resource_path"]),
                "dependency_lookup": "skipped_offline" if self._settings.offline else "enabled",
                "historical_learning": "not_configured",
                "android_surface": AndroidSurfaceAnalyzer().scan(None,{} )["coverage"],
            }
            state["package_name"] = extraction.get("package_name", "")

            # Parse manifest
            manifest_path = extraction.get("manifest_path", "")
            if manifest_path:
                state["manifest_data"] = self._manifest_parser.parse(manifest_path)
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
            "dependencies": self._dependency_scanner.scan(state["resource_path"]),
            "taint": self._taint_engine.analyze_directory_async(state["decompiled_path"]) if self._settings.enable_deep_taint else asyncio.sleep(0, result=[]),
            "nsc": self._nsc_auditor.audit_directory_async(state["resource_path"]),
            "binary_protection": self._bin_protection.audit_directory_async(state["resource_path"]),
            "react_native": self._rn_scanner.scan_directory_async(state["resource_path"]),
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
                if name=="android_surface":
                    for category in state["coverage"].get("android_surface",{}).get("categories",{}).values():
                        category["static_status"]="incomplete"
                continue

            engines[name]="skipped_disabled" if name=="taint" and not self._settings.enable_deep_taint else "completed_heuristically"
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
            elif isinstance(result, list):
                all_findings.extend(result)

            logger.info("[Stage 2] %s: %d findings",
                        name,
                        len(result["findings"]) if name in {"android_surface", "auth_session", "firebase"} else len(result) if not isinstance(result, tuple) else len(result[1]))

        # Deterministic Smali Call Graph reachability audit
        try:
            smali_findings = self._call_graph_engine.audit_smali_directory(state["smali_path"])
            all_findings.extend(smali_findings)
            engines["smali_call_graph"]="completed_heuristically"
            logger.info("[Stage 2] Smali Call Graph: %d reachability findings", len(smali_findings))
        except Exception as e:
            engines["smali_call_graph"]="incomplete"
            state["errors"].append("Smali call graph review incomplete")
            logger.warning("[Stage 2] Smali Call Graph audit warning: %s", e)

        for finding in all_findings:
            finding.status = FindingStatus.UNVERIFIED
        state["raw_findings"] = redact([f.model_dump(mode="json") for f in all_findings])
        logger.info("[Stage 2] Done — %d raw findings total", len(all_findings))
        return state

    async def _run_filtering(self, state: ScanState) -> ScanState:
        """Stage 3: Filter findings through 5-layer pipeline."""
        state["current_phase"] = "filtering"
        logger.info("[Stage 3] Filtering — 5-layer FP elimination...")

        raw_findings = [
            Finding(**f) for f in state["raw_findings"]
        ]

        confirmed = await self._filter_pipeline.filter_findings(
            raw_findings, state["decompiled_path"]
        )

        state["filtered_findings"] = [f.model_dump() for f in confirmed]
        logger.info(
            "[Stage 3] Done — %d/%d findings retained",
            len(confirmed), len(raw_findings),
        )
        return state

    async def _run_generation(self, state: ScanState) -> ScanState:
        """Stage 4: Generate Frida scripts and PoC guides."""
        state["current_phase"] = "generation"
        logger.info("[Stage 4] Generation — Frida scripts + PoC guides...")

        confirmed = [Finding(**f) for f in state["filtered_findings"]]
        app_info = {
            "package_name": state["package_name"],
            "framework": state["framework_info"].get("framework", "native"),
            "scan_id": state["scan_id"],
        }

        # Generate Frida scripts
        try:
            frida_results = await self._frida_generator.generate_batch(
                confirmed, app_info
            )
            state["generated_frida_scripts"] = frida_results
            logger.info("[Stage 4] Generated %d Frida scripts", len(frida_results))
        except Exception as exc:
            logger.error("[Stage 4] Frida generation error: %s", exc)
            state["errors"].append(f"Frida generation error: {exc}")

        # Generate PoC guides
        try:
            poc_results = await self._poc_generator.generate_batch(
                confirmed, app_info
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
            )
            state["sarif_path"] = str(sarif_path)
            logger.info("Saved SARIF report: %s", sarif_path)
        except Exception as exc:
            logger.warning("Failed exporting SARIF: %s", exc)
