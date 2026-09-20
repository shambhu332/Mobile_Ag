"""LangGraph orchestrator — wires all agents into a state-machine pipeline."""

import asyncio
import logging
import uuid
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
from mobileag.analysis.manifest_auditor import ManifestAuditor
from mobileag.analysis.secret_scanner import SecretScanner
from mobileag.analysis.code_reviewer import CodeReviewer
from mobileag.analysis.api_mapper import APIMapper
from mobileag.analysis.native_analyzer import NativeAnalyzer
from mobileag.analysis.dependency_scanner import DependencyScanner
from mobileag.filters.pipeline import FilterPipeline
from mobileag.generators.frida_generator import FridaGenerator
from mobileag.generators.poc_generator import PoCGenerator
from mobileag.reporting.finding import Finding

logger = logging.getLogger(__name__)


class Orchestrator:
    """Main scan orchestrator that coordinates all agents through a pipeline.

    Pipeline stages:
        1. Ingestion — APK extraction, manifest parsing, framework/packer detection
        2. Analysis — 6 parallel agents scan for vulnerabilities
        3. Filtering — 5-layer false positive elimination
        4. Generation — Frida scripts + PoC guides for confirmed findings
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

        # Filter pipeline
        self._filter_pipeline = FilterPipeline(
            router=self._router,
            consensus_voter=self._voter,
            settings=self._settings,
        )

        # Generators
        self._frida_generator = FridaGenerator(self._router)
        self._poc_generator = PoCGenerator(self._router)

    async def scan(self, apk_path: str, output_dir: Optional[str] = None) -> ScanState:
        """Run a full security scan on an APK.

        Args:
            apk_path: Path to the APK file.
            output_dir: Directory for scan output (default from settings).

        Returns:
            Complete ScanState with all findings and generated outputs.
        """
        scan_id = str(uuid.uuid4())[:8]
        output = output_dir or self._settings.OUTPUT_DIR
        output_path = Path(output) / scan_id
        output_path.mkdir(parents=True, exist_ok=True)

        state = create_initial_state(scan_id, apk_path, str(output_path))
        logger.info("Starting scan %s on %s", scan_id, apk_path)

        # === Stage 1: Ingestion ===
        state = await self._run_ingestion(state)

        if not state["decompiled_path"]:
            state["errors"].append("Ingestion failed — cannot continue scan")
            logger.error("Ingestion failed for %s", apk_path)
            return state

        # === Stage 2: Analysis ===
        state = await self._run_analysis(state)

        # === Stage 3: Filtering ===
        state = await self._run_filtering(state)

        # === Stage 4: Generation ===
        state = await self._run_generation(state)

        # === Stage 5: Save outputs ===
        await self._save_outputs(state)

        state["current_phase"] = "complete"
        logger.info(
            "Scan %s complete: %d confirmed findings",
            scan_id, len(state["filtered_findings"]),
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
                state["decompiled_path"]
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
        """Stage 2: Run all 6 analysis agents in parallel."""
        state["current_phase"] = "analysis"
        logger.info("[Stage 2] Analysis — running 6 agents in parallel...")

        all_findings: list[Finding] = []

        # Run all agents concurrently
        tasks = {
            "manifest": self._manifest_auditor.audit(
                state["manifest_data"], state["package_name"]
            ),
            "secrets": self._secret_scanner.scan(state["decompiled_path"]),
            "code_review": self._code_reviewer.review(
                state["decompiled_path"], state["manifest_data"]
            ),
            "api_mapping": self._api_mapper.map_apis(state["decompiled_path"]),
            "native": self._native_analyzer.analyze(state["decompiled_path"]),
            "dependencies": self._dependency_scanner.scan(state["decompiled_path"]),
        }

        results = await asyncio.gather(
            *tasks.values(), return_exceptions=True
        )

        agent_names = list(tasks.keys())
        for i, result in enumerate(results):
            name = agent_names[i]
            if isinstance(result, Exception):
                logger.error("[Stage 2] %s agent failed: %s", name, result)
                state["errors"].append(f"{name} agent error: {result}")
                continue

            if name == "api_mapping":
                # API mapper returns (endpoints, findings)
                endpoints, findings = result
                state["api_endpoints"] = [
                    ep if isinstance(ep, dict) else ep.__dict__
                    for ep in endpoints
                ]
                all_findings.extend(findings)
            else:
                all_findings.extend(result)

            logger.info("[Stage 2] %s: %d findings",
                        name,
                        len(result) if not isinstance(result, tuple) else len(result[1]))

        state["raw_findings"] = [f.model_dump() for f in all_findings]
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
            "[Stage 3] Done — %d/%d findings confirmed",
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

        # Save Frida scripts
        frida_dir = output / "frida_scripts"
        frida_dir.mkdir(exist_ok=True)
        for item in state.get("generated_frida_scripts", []):
            fp = frida_dir / item["filename"]
            fp.write_text(item["script"])
            logger.info("Saved Frida script: %s", fp)

        # Save PoC guides
        poc_dir = output / "poc_guides"
        poc_dir.mkdir(exist_ok=True)
        for item in state.get("generated_poc_guides", []):
            fp = poc_dir / item["filename"]
            fp.write_text(item["poc_guide"])
            logger.info("Saved PoC guide: %s", fp)
