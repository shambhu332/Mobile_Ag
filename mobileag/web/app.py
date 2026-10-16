"""FastAPI web application for MobileAg AppSec Dashboard with Live WebSockets & Neo4j."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from dotenv import load_dotenv
load_dotenv(override=False)
import secrets
import re
import hashlib
import shutil
import time
from mobileag import __version__
from mobileag.web.repository import ScanRepository, private_write
from mobileag.web.jobs import isolated_analysis, CANCELLED, PROCESSES
import uuid
from mobileag.web.security import SecurityMiddleware, authorized, check_device
from mobileag.security.archives import validate_archive, MAX_UPLOAD
from mobileag.security.network import scoped_request
from mobileag.security.privacy import redact
from mobileag.reporting.validation import ConfirmationEvidence, EvidenceError
from mobileag.assessments.test_plan import TestPlanInput as TestPlanRequest
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional, Literal

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(application):
    # Direct uvicorn launches must also announce the local access mechanism.
    if not getattr(application.state,'token_announced',False):
        if os.environ.get('MOBILEAG_API_TOKEN'):
            print('MobileAg uses configured MOBILEAG_API_TOKEN; enter that local access key, not a GitHub/app/API credential.',flush=True)
        else:
            print('Session access token (paste into dashboard): '+application.state.auth_token,flush=True)
        application.state.token_announced=True
    await recover_interrupted_jobs()
    automation_service().store().recover()
    assessment_service().store().recover()
    yield
    if api_capture_proxy is not None:
        await api_capture_proxy.stop()
    CANCELLED.update(PROCESSES)
    assessments=assessment_service()
    for task in list(assessments.tasks.values()):task.cancel()
    if assessments.tasks:await asyncio.gather(*list(assessments.tasks.values()),return_exceptions=True)
    service=automation_service()
    for rid in list(service.tasks):
        try:service.cancel(rid)
        except ValueError:pass
    for task in list(service.tasks.values()):task.cancel()
    if service.tasks:await asyncio.gather(*list(service.tasks.values()),return_exceptions=True)

from fastapi import Request, BackgroundTasks, Query, FastAPI, HTTPException, WebSocket, WebSocketDisconnect, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.exceptions import RequestValidationError
from pydantic import BaseModel, Field
import httpx

from config.settings import get_settings
def Orchestrator(settings):
    # Compatibility injection boundary for unit tests; production static work is
    # isolated and never uses this constructor in the API process.
    from mobileag.core.orchestrator import Orchestrator as Engine
    return Engine(settings)
from mobileag.analysis.ios_analyzer import IOSSecurityAnalyzer
from mobileag.analysis.taint_engine import TaintEngine
from mobileag.dast import (
    ADBManager,
    ConnectedDevice,
    DeepLinkFuzzer,
    FridaRunner,
    HTTPTransaction,
    IntentFuzzer,
    LogcatAuditor,
    MemoryForensicsAuditor,
    ProviderAuditor,
    StorageAuditor,
    TrafficAuditor,
    UICrawler,
)
from mobileag.knowledge.neo4j_graph import AttackGraph
from mobileag.reporting.cvss import get_default_cvss_for_cwe
from mobileag.reporting.finding import Finding, FindingStatus, Severity
from mobileag.reporting.evidence_contract import prepare_scan, prepare_observation
from mobileag.reporting.sarif_exporter import SARIFExporter

logger = logging.getLogger(__name__)

# Initialize DAST & Knowledge subsystems
adb_manager = ADBManager()
logcat_auditor = LogcatAuditor()
traffic_auditor = TrafficAuditor()
api_capture_proxy = None
storage_auditor = StorageAuditor(adb=adb_manager)
provider_auditor = ProviderAuditor(adb=adb_manager)
deeplink_fuzzer = DeepLinkFuzzer(adb=adb_manager)
frida_runner = FridaRunner(adb=adb_manager)
ui_crawler = UICrawler(adb=adb_manager)
memory_auditor = MemoryForensicsAuditor(adb=adb_manager)
taint_engine = TaintEngine()

intent_fuzzer = IntentFuzzer(
    adb=adb_manager,
    auditor=logcat_auditor,
    storage_auditor=storage_auditor,
    provider_auditor=provider_auditor,
    deeplink_fuzzer=deeplink_fuzzer,
    ui_crawler=ui_crawler,
    memory_auditor=memory_auditor,
)


REPO_ROOT = Path(__file__).resolve().parent.parent.parent
DATA_ROOT = Path(os.environ.get("MOBILEAG_DATA_DIR", Path.cwd())).resolve()
OUTPUT_DIR = DATA_ROOT / "output"
TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
UPLOAD_DIR = DATA_ROOT / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)

app = FastAPI(
    title="MobileAg — AppSec Dashboard",
    description="Local, scoped mobile security research workbench",
    version=__version__,
    lifespan=lifespan,
)

app.state.session_deadline = time.monotonic() + 8*3600
app.state.auth_token = os.environ.get("MOBILEAG_API_TOKEN") or secrets.token_urlsafe(32)
app.add_middleware(SecurityMiddleware, owner=app)
app.mount("/static", StaticFiles(directory=Path(__file__).parent / "static"), name="static")

@app.exception_handler(RequestValidationError)
async def safe_validation_error(request: Request, exc: RequestValidationError):
    # Pydantic errors may include entire rejected credentials in input/ctx.
    return JSONResponse(status_code=422, content={'detail': [
        {'loc': error['loc'], 'type': error['type'], 'msg': 'Invalid request field'}
        for error in exc.errors()
    ]})

# Global in-memory data store for scans and runtime settings
DEMO_SCAN_CACHE: Optional[dict[str, Any]] = None
ACTIVE_SCANS: dict[str, dict[str, Any]] = {}
_db_settings = get_settings()
attack_graph = AttackGraph(_db_settings.NEO4J_URI, _db_settings.NEO4J_USER, _db_settings.NEO4J_PASSWORD)
RUNTIME_FINDINGS: list[dict[str, Any]] = []
DAST_JOBS: set[str] = set()

def remember_findings(findings):
    RUNTIME_FINDINGS.extend(redact([prepare_observation(f) for f in findings]))
    del RUNTIME_FINDINGS[:-1000]

RUNTIME_SETTINGS: dict[str, Any] = {}


# =============================================================================
# WebSocket Real-Time Telemetry Manager
# =============================================================================
class ConnectionManager:
    """Manages real-time WebSocket subscriber connections for telemetry streaming."""

    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []
        self.pending = 0
        self.sessions = {}
        self.subscriptions: dict[WebSocket, str | None] = {}

    async def connect(self, websocket: WebSocket, scan_id: str | None = None) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)
        self.subscriptions[websocket] = scan_id
        logger.info("WebSocket subscriber connected (%d active)", len(self.active_connections))

    def disconnect(self, websocket: WebSocket) -> None:
        self.sessions.pop(websocket,None)
        self.subscriptions.pop(websocket, None)
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info("WebSocket subscriber disconnected (%d remaining)", len(self.active_connections))

    async def broadcast(self, message: dict[str, Any]) -> None:
        for connection in list(self.active_connections):
            try:
                subscribed_scan = self.subscriptions.get(connection)
                if subscribed_scan is not None and message.get("scan_id") != subscribed_scan:
                    continue
                if time.monotonic() >= app.state.session_deadline or not authorized(self.sessions.get(connection),app.state.auth_token):
                    await connection.close(code=1008)
                    self.disconnect(connection)
                    continue
                await asyncio.wait_for(connection.send_json(redact(message)), timeout=2)
            except Exception:
                self.disconnect(connection)


manager = ConnectionManager()


@app.websocket("/ws/telemetry")
async def websocket_telemetry(websocket: WebSocket) -> None:
    """Authenticated legacy stream for all dashboard telemetry events."""
    await _telemetry_stream(websocket)


@app.websocket("/ws/scans/{scan_id}/telemetry")
async def websocket_scan_telemetry(websocket: WebSocket, scan_id: str) -> None:
    """Authenticated scan-specific stream; never delivers another scan's events."""
    await _telemetry_stream(websocket, scan_id=scan_id)


async def _telemetry_stream(websocket: WebSocket, scan_id: str | None = None) -> None:
    if len(manager.active_connections) + manager.pending >= 32:
        await websocket.close(code=1013)
        return
    manager.pending += 1
    try:
        await websocket.accept()
        auth = await asyncio.wait_for(websocket.receive_json(), timeout=5)
        if time.monotonic() >= app.state.session_deadline or not isinstance(auth, dict) or not authorized(auth.get("token"), app.state.auth_token):
            await websocket.close(code=1008)
            return
    except Exception:
        await websocket.close(code=1008)
        return
    finally:
        manager.pending -= 1
    if scan_id is not None:
        try:
            await get_scan_details(scan_id)
        except HTTPException:
            await websocket.close(code=1008)
            return
    manager.active_connections.append(websocket)
    manager.sessions[websocket] = auth["token"]
    manager.subscriptions[websocket] = scan_id
    try:
        await websocket.send_json({
            "type": "connection_established",
            "message": "Connected to MobileAg Live Telemetry Stream",
            **({"scan_id": scan_id} if scan_id is not None else {}),
            "timestamp": datetime.now().isoformat(),
            "neo4j_online": attack_graph._connected,
        })
        while True:
            if time.monotonic() >= app.state.session_deadline or not authorized(auth.get('token'),app.state.auth_token):
                await websocket.close(code=1008)
                break
            try:
                data = await asyncio.wait_for(websocket.receive_text(),timeout=30)
            except asyncio.TimeoutError:
                continue
            if data == "ping":
                await websocket.send_json({"type": "pong", "timestamp": datetime.now().isoformat()})
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.warning("WebSocket disconnected")
    finally:
        manager.disconnect(websocket)


# =============================================================================
# Demo & Scan Data Utilities
# =============================================================================
def get_initial_demo_scan():
    raise HTTPException(404, "Demo results are not available in the live workbench")



def validate_scan_id(scan_id: str) -> None:
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', scan_id):
        raise HTTPException(400, 'Invalid scan identifier')


def repository() -> ScanRepository:
    return ScanRepository(OUTPUT_DIR)


app.state.scope_repository = repository

def repository_import_legacy() -> None:
    repo = repository()
    for file in OUTPUT_DIR.glob('*/dashboard.json'):
        sid = file.parent.name
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,128}', sid) or repo.get(sid) or repo.purged(sid):
            continue
        if not file.resolve().is_relative_to(OUTPUT_DIR.resolve()) or file.stat().st_size > 16*1024*1024:
            continue
        try:
            document = json.loads(file.read_text())
            if isinstance(document, dict) and document.get('scan_id') == sid:
                repo.save(document)
        except (ValueError, OSError):
            logger.warning('Could not import legacy scan %s', sid)


def effective_runtime_settings() -> dict[str, Any]:
    names = {'entropy_threshold', 'enable_deep_taint', 'enable_reachability_filter',
             'enable_consensus_voting', 'offline'}
    settings = get_settings()
    values = {name: getattr(settings, name) for name in names}
    values.update({k:v for k,v in repository().get_settings().items() if k in names})
    values.update({k:v for k,v in RUNTIME_SETTINGS.items() if k in names})
    values['approved_llm_providers'] = settings.approved_llm_providers
    values['offline'] = True
    values['web_cloud_supported'] = False
    return values


def find_latest_reports() -> list[dict[str, Any]]:
    repository_import_legacy()
    return repository().page(0, 100)[0]



# =============================================================================
# REST Endpoints
# =============================================================================
async def recover_interrupted_jobs():
    def recover():
        repo = repository()
        with repo.connection() as db:
            rows = db.execute("SELECT document FROM scans WHERE status IN ('running','queued','cancelling')").fetchall()
        for row in rows:
            scan = json.loads(row[0])
            scan.update(status='interrupted', errors=['Server restarted; retry explicitly. No device action was resumed'])
            repo.save(scan)
    await asyncio.to_thread(recover)


@app.post("/api/scans/{scan_id}/cancel")
async def cancel_scan(scan_id: str):
    validate_scan_id(scan_id)
    scan = ACTIVE_SCANS.get(scan_id)
    if not scan or scan.get('status') != 'running':
        raise HTTPException(409, 'Only an active job can be cancelled')
    CANCELLED.add(scan_id)
    return {'status':'cancellation_requested','scan_id':scan_id}


@app.post("/api/scans/{scan_id}/retry")
async def retry_scan(scan_id: str, background_tasks: BackgroundTasks):
    scan = await get_scan_details(scan_id)
    if scan.get('status') not in {'error','partial','cancelled','interrupted'}:
        raise HTTPException(409, 'Only an incomplete job can be retried')
    request = scan.get('request', {})
    path = Path(request.get('apk_path', ''))
    if not path.is_file() or hash_file(path) != scan.get('artifact_sha256'):
        raise HTTPException(409, 'Original archive is unavailable or changed; upload it again')
    return await trigger_scan(RunScanRequest(**request),background_tasks)


@app.get("/", response_class=HTMLResponse)
async def get_dashboard() -> HTMLResponse:
    """Serve the single-page MobileAg Enterprise Dashboard."""
    index_path = TEMPLATES_DIR / "index.html"
    if not index_path.exists():
        raise HTTPException(status_code=404, detail="Dashboard template not found.")
    return HTMLResponse(content=index_path.read_text())


@app.get("/api/status")
async def get_system_status() -> dict[str, Any]:
    """Return framework readiness, Neo4j connectivity, and configuration."""
    settings = get_settings()
    return {
        "status": "online",
        "engine": "MobileAg static review heuristics",
        "version": __version__,
        "timestamp": datetime.now().isoformat(),
        "configured_llm_providers": settings.enabled_providers,
        "active_scans_count": len(ACTIVE_SCANS),
        "websocket_subscribers": len(manager.active_connections),
        "neo4j_connected": attack_graph._connected,
        "neo4j_uri": attack_graph.uri,
    }


@app.get("/api/readiness")
async def get_readiness():
    from mobileag.web.jobs import sandbox_command, resource_command, manager_environment
    import sys
    def probe():
        import subprocess
        # Same mount/network namespace as production, with harmless /usr/bin/true.
        # No device, upload parser, model or external target is contacted.
        try:
            command = sandbox_command(OUTPUT_DIR.resolve(), Path(__file__).resolve())
            command = command[:-3]+['/usr/bin/true']
            result = subprocess.run(resource_command(command,'readiness-'+uuid.uuid4().hex), env=manager_environment(),capture_output=True,timeout=5)
            return result.returncode == 0
        except Exception:
            return False
    OUTPUT_DIR.mkdir(parents=True,exist_ok=True,mode=0o700)
    isolated = await asyncio.to_thread(probe)
    jar = Path(os.environ.get('MOBILEAG_SANDBOX_APKTOOL_JAR','/snap/apktool/current/apktool.jar'))
    return {'local_operator_only':True,'sandbox_probe':isolated,
            'android_tools':{'jadx':Path('/usr/bin/jadx').is_file(),'apktool':Path('/usr/bin/apktool').is_file() or jar.is_file()},
            'aggregate_worker_limits':{'memory':'3GiB','swap':'512MiB','tasks':128,'cpu':'one core','wall_seconds':360},
            'web_static_network':'denied', 'cloud_web_worker':'offline; optional separate aggregate-only broker',
            'python':sys.version.split()[0], 'production_device_validation':'not_performed',
            'multiuser_deployment':'unsupported', 'offline_ui_assets':True}


@app.get("/api/graph/status")
async def get_graph_status() -> dict[str, Any]:
    """Check Neo4j graph database connectivity status."""
    is_online = await attack_graph.verify_connection()
    return {
        "neo4j_connected": is_online,
        "neo4j_uri": attack_graph.uri,
        "mode": "neo4j_live" if is_online else "embedded_fallback",
    }


@app.get("/api/scans")
async def list_scans(offset: int = Query(0, ge=0), limit: int = Query(25, ge=1, le=100),
                     summaries: bool = False):
    snapshots = list(ACTIVE_SCANS.values())
    def read():
        repository_import_legacy()
        for scan in snapshots:
            repository().save(scan)
        rows, total = repository().page(offset, limit)
        if summaries:
            rows = [{k:s.get(k) for k in ('scan_id','app_name','package_name','version','created_at','status','progress','stats','revision','artifact_sha256','coverage','errors')} for s in rows]
            return {'items': rows, 'total': total, 'offset': offset, 'limit': limit}
        return [redact(prepare_scan(s)) for s in rows]  # Presentation only; preserve stored triage.
    return await asyncio.to_thread(read)



@app.get("/api/scans/{scan_id}")
async def get_scan_details(scan_id: str) -> dict[str, Any]:
    validate_scan_id(scan_id)
    if scan_id in ACTIVE_SCANS and ACTIVE_SCANS[scan_id].get('status') == 'running':
        return redact(prepare_scan(ACTIVE_SCANS[scan_id]))
    def read():
        repo = repository()
        scan = repo.get(scan_id)
        if not scan and not repo.purged(scan_id):
            file = OUTPUT_DIR / scan_id / 'dashboard.json'
            if file.is_file() and file.resolve().is_relative_to(OUTPUT_DIR.resolve()) and file.stat().st_size <= 16*1024*1024:
                document = json.loads(file.read_text())
                if isinstance(document, dict) and document.get('scan_id') == scan_id:
                    scan = repo.save(document)
        return scan
    scan = await asyncio.to_thread(read)
    if scan is None:
        raise HTTPException(404, 'Scan not found')
    return redact(prepare_scan(scan))


@app.get("/api/scans/{scan_id}/comparison/{baseline_scan_id}")
async def compare_scan_to_baseline(scan_id: str, baseline_scan_id: str) -> dict[str, Any]:
    """Read-only comparison; never marks findings fixed or changes scan history."""
    validate_scan_id(scan_id)
    validate_scan_id(baseline_scan_id)
    current, baseline = await asyncio.gather(get_scan_details(scan_id),
                                             get_scan_details(baseline_scan_id))
    from mobileag.reporting.scan_comparison import compare_scans
    try:
        return compare_scans(baseline, current)
    except ValueError as exc:
        raise HTTPException(409, str(exc))


@app.get("/api/scans/{scan_id}/planned-comparison")
async def compare_scan_to_planned_baseline(scan_id: str) -> dict[str, Any]:
    """Compare only against the artifact-bound baseline saved in this scan's test plan."""
    validate_scan_id(scan_id)
    current = await get_scan_details(scan_id)
    plan = await asyncio.to_thread(repository().get_test_plan, scan_id)
    if plan is None:
        raise HTTPException(404, 'No test plan is recorded for this scan')
    binding = plan.get('retest_baseline_binding')
    if not isinstance(binding, dict) or not isinstance(binding.get('scan_id'), str):
        raise HTTPException(409, 'No artifact-bound retest baseline is recorded in the test plan')
    baseline = await get_scan_details(binding['scan_id'])
    provenance = baseline.get('artifact_provenance')
    provenance = provenance if isinstance(provenance, dict) else {}
    current_hash = baseline.get('artifact_sha256') or provenance.get('sha256')
    app_info = baseline.get('app_info') if isinstance(baseline.get('app_info'), dict) else {}
    current_version = baseline.get('version') or app_info.get('version_name')
    if (baseline.get('package_name') != binding.get('package_name')
            or not isinstance(current_hash, str)
            or current_hash.lower() != binding.get('artifact_sha256')
            or current_version != binding.get('app_version')):
        raise HTTPException(409, 'Recorded retest baseline no longer matches its saved artifact binding')
    from mobileag.reporting.scan_comparison import compare_scans
    try:
        result = compare_scans(baseline, current)
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    result['plan_binding'] = {
        'plan_revision': plan.get('plan_revision'),
        'baseline_scan_id': binding['scan_id'],
        'baseline_artifact_sha256': binding['artifact_sha256'],
        'status': 'artifact_binding_matches',
    }
    return result



@app.get("/api/scans/{scan_id}/graph")
async def get_scan_graph(scan_id: str) -> dict[str, Any]:
    """Retrieve graph topology, dynamically querying Neo4j if available, or falling back to embedded data."""
    if attack_graph._connected:
        try:
            neo4j_data = await attack_graph.export_visjs_graph(scan_id)
            if neo4j_data and neo4j_data.get("nodes"):
                return {
                    "source": "neo4j",
                    "scan_id": scan_id,
                    "graph": neo4j_data,
                }
        except Exception as e:
            logger.warning("Neo4j graph query failed, using embedded fallback: %s", e)

    scan = await get_scan_details(scan_id)
    return {
        "source": "embedded",
        "scan_id": scan_id,
        "graph": scan.get("attack_surface_graph", {"nodes": [], "edges": []}),
    }


@app.get("/api/scans/{scan_id}/sarif")
async def get_scan_sarif(scan_id: str) -> dict[str, Any]:
    """Export scan findings in standard OASIS SARIF v2.1.0 format."""
    scan = await get_scan_details(scan_id)
    findings = scan.get("findings", [])
    target_name = scan.get("package_name") or scan.get("app_name", "target_app")
    provenance = scan.get("artifact_provenance", {})
    artifact = {
        "artifact_sha256": provenance.get("sha256") or scan.get("artifact_sha256"),
        "package_name": scan.get("package_name"),
        "app_version": scan.get("version") or scan.get("app_info", {}).get("version_name"),
    }
    return SARIFExporter.generate_sarif(findings, target_name=target_name, scan_id=scan_id,
                                        artifact=artifact, coverage=scan.get("coverage", {}))


@app.get("/api/scans/{scan_id}/apis")
async def get_scan_apis(scan_id: str) -> dict[str, Any]:
    """Retrieve all discovered REST & GraphQL API endpoints for the specified scan."""
    scan = await get_scan_details(scan_id)
    apis = scan.get("api_endpoints", [])

    return {
        "scan_id": scan_id,
        "endpoints": apis,
        "total": len(apis),
        "vulnerable_count": 0,
        "candidate_count": len([e for e in apis if e.get("status") == "VULNERABLE"]),
        "assessment": "Discovered routes are unverified; no server authorization proof",
    }


@app.get("/api/scans/{scan_id}/resilience")
async def get_scan_resilience(scan_id: str) -> dict[str, Any]:
    """Return heuristic resilience inventory and its bounded-input coverage."""
    scan = await get_scan_details(scan_id)
    out_dir = OUTPUT_DIR / scan_id
    from mobileag.analysis.bounded_sources import SourceInventory

    # Prefer the two known apktool layouts. The compatibility fallback is
    # bounded and refuses ambiguous roots instead of materializing an
    # unbounded recursive glob and arbitrarily choosing its first result.
    known_roots = [out_dir / "apktool_out" / "smali", out_dir / "apktool" / "smali"]

    def has_symlink_component(path: Path) -> bool:
        current = path
        while current != OUTPUT_DIR and current != current.parent:
            if current.is_symlink():
                return True
            current = current.parent
        return OUTPUT_DIR.is_symlink()

    unsafe_scan_root = has_symlink_component(out_dir)
    smali_roots = ([] if unsafe_scan_root else
                   [p for p in known_roots if not has_symlink_component(p) and p.is_dir()])
    discovery = {"status": "not_analyzed_symlink_root" if unsafe_scan_root else "known_layout",
                 "roots_found": len(smali_roots),
                 "entries_examined": 0, "limits_reached": False}
    if unsafe_scan_root:
        pass
    elif len(smali_roots) > 1:
        discovery["status"] = "not_analyzed_multiple_known_roots"
    elif not smali_roots:
        inventory = SourceInventory(max_entries=5000, max_file_bytes=1,
                                    max_total_bytes=1)
        roots = set()
        for path in inventory.paths(out_dir, {".smali"}):
            for parent in path.parents:
                if parent == out_dir:
                    break
                if parent.name == "smali" or re.fullmatch(r"smali_classes\d+", parent.name):
                    roots.add(parent)
                    break
        discovery = {"status": "bounded_fallback", "roots_found": len(roots),
                     "entries_examined": inventory.coverage["entries_examined"],
                     "limits_reached": inventory.coverage["limits_reached"]}
        if len(roots) == 1 and not inventory.coverage["limits_reached"]:
            smali_roots = list(roots)
        else:
            if inventory.coverage["limits_reached"]:
                discovery["status"] = "not_analyzed_incomplete_inventory"
            else:
                discovery["status"] = "not_analyzed_ambiguous_roots" if roots else "not_analyzed_no_root"

    from mobileag.analysis.rasp_resilience_auditor import RaspResilienceAuditor
    auditor = RaspResilienceAuditor()
    res = auditor.audit_package(smali_roots[0]) if len(smali_roots) == 1 else auditor.audit_package(None)
    if discovery["status"] != "known_layout":
        res.coverage["root_discovery"] = discovery
        if discovery["status"] != "bounded_fallback":
            res.coverage["static_status"] = "not_analyzed"
            res.coverage["exhaustive"] = False

    return {
        "scan_id": scan_id,
        "overall_score": res.overall_score,
        "grade": res.grade,
        "coverage": res.coverage,
        "vectors": {
            k: {
                "name": v.vector_name,
                "category": v.masvs_category,
                "score": v.score,
                "passed": v.passed,
                "indicators": v.detected_indicators,
            }
            for k, v in res.vectors.items()
        },
    }


@app.get("/api/scans/{scan_id}/cyclonedx")
async def get_scan_cyclonedx(scan_id: str) -> dict[str, Any]:
    """Export CycloneDX v1.5 SBOM."""
    scan = await get_scan_details(scan_id)
    from mobileag.analysis.sbom_generator import MobileSbomGenerator
    app_name = scan.get("app_name") or scan.get("package_name") or "MobileApp"
    version = scan.get("version") or "1.0.0"
    gen = MobileSbomGenerator(app_name=app_name, app_version=version)

    deps = scan.get("dependencies", [])
    for d in deps:
        gen.add_component(
            name=d.get("name", "library"),
            version=d.get("version", "unknown"),
            purl=d.get("purl", f"pkg:generic/{d.get('name', 'library')}"),
        )
    if not deps:
        gen.add_component(
            name=app_name,
            version=version,
            purl=f"pkg:apk/{app_name}@{version}",
            component_type="application",
        )
    return gen.generate_cyclonedx_json()


@app.get("/api/scans/{scan_id}/cyclonedx.xml")
async def get_scan_cyclonedx_xml(scan_id: str) -> Response:
    """Export CycloneDX v1.5 XML SBOM."""
    scan = await get_scan_details(scan_id)
    from mobileag.analysis.sbom_generator import MobileSbomGenerator
    app_name = scan.get("app_name") or scan.get("package_name") or "MobileApp"
    version = scan.get("version") or "1.0.0"
    gen = MobileSbomGenerator(app_name=app_name, app_version=version)

    deps = scan.get("dependencies", [])
    for d in deps:
        gen.add_component(
            name=d.get("name", "library"),
            version=d.get("version", "unknown"),
            purl=d.get("purl", f"pkg:generic/{d.get('name', 'library')}"),
        )
    if not deps:
        gen.add_component(
            name=app_name,
            version=version,
            purl=f"pkg:apk/{app_name}@{version}",
            component_type="application",
        )
    return Response(content=gen.generate_cyclonedx_xml(), media_type="application/xml")


@app.get("/api/scans/{scan_id}/spdx")
async def get_scan_spdx(scan_id: str) -> dict[str, Any]:
    """Export SPDX 2.3 SBOM."""
    scan = await get_scan_details(scan_id)
    from mobileag.analysis.sbom_generator import MobileSbomGenerator
    app_name = scan.get("app_name") or scan.get("package_name") or "MobileApp"
    version = scan.get("version") or "1.0.0"
    gen = MobileSbomGenerator(app_name=app_name, app_version=version)

    deps = scan.get("dependencies", [])
    for d in deps:
        gen.add_component(
            name=d.get("name", "library"),
            version=d.get("version", "unknown"),
            purl=d.get("purl", f"pkg:generic/{d.get('name', 'library')}"),
        )
    if not deps:
        gen.add_component(
            name=app_name,
            version=version,
            purl=f"pkg:apk/{app_name}@{version}",
            component_type="application",
        )
    return gen.generate_spdx_json()


@app.get("/api/scans/{scan_id}/openapi")
async def get_scan_openapi(scan_id: str) -> dict[str, Any]:
    """Export discovered mobile APIs in OpenAPI 3.0 format."""
    scan = await get_scan_details(scan_id)
    from mobileag.dast.api_cataloger import MobileApiCataloger, CapturedRequest
    app_name = scan.get("app_name") or scan.get("package_name") or "MobileApp"
    cataloger = MobileApiCataloger(title=f"{app_name} APIs", version="1.0.0")

    apis = scan.get("api_endpoints", [])
    for ep in apis:
        url = ep.get("url") or f"https://api.example.com{ep.get('path', '/')}"
        method = ep.get("method", "GET")
        cataloger.ingest_request(CapturedRequest(method=method, url=url))

    return cataloger.export_openapi_json()


@app.get("/api/scans/{scan_id}/har")
async def get_scan_har(scan_id: str) -> dict[str, Any]:
    """Export intercepted mobile HTTP/HTTPS traffic in HAR 1.2 format."""
    scan = await get_scan_details(scan_id)
    from mobileag.dast.api_cataloger import MobileApiCataloger, CapturedRequest
    app_name = scan.get("app_name") or scan.get("package_name") or "MobileApp"
    cataloger = MobileApiCataloger(title=f"{app_name} APIs", version="1.0.0")

    apis = scan.get("api_endpoints", [])
    for ep in apis:
        url = ep.get("url") or f"https://api.example.com{ep.get('path', '/')}"
        method = ep.get("method", "GET")
        cataloger.ingest_request(CapturedRequest(method=method, url=url))

    return cataloger.export_har_json()


@app.get("/api/scans/{scan_id}/tokens/audit")
async def audit_scan_tokens(scan_id: str) -> dict[str, Any]:
    """Audit captured authentication tokens and session lifecycle."""
    scan = await get_scan_details(scan_id)
    from mobileag.dast.token_session_auditor import MobileTokenSessionAuditor
    from mobileag.dast.api_cataloger import CapturedRequest

    auditor = MobileTokenSessionAuditor()
    apis = scan.get("api_endpoints", [])
    captured = [
        CapturedRequest(
            method=ep.get("method", "GET"),
            url=ep.get("url") or f"https://api.example.com{ep.get('path', '/')}",
            headers=ep.get("headers", {}),
            query_params=ep.get("query_params", {}),
            response_status=ep.get("status_code", 200),
        )
        for ep in apis
    ]
    findings = auditor.audit_transactions(captured)
    return {
        "scan_id": scan_id,
        "token_findings_count": len(findings),
        "findings": [f.model_dump() for f in findings],
    }


@app.get("/api/scans/{scan_id}/findings/{finding_id}/poc")
async def get_finding_poc(scan_id: str, finding_id: str) -> dict[str, Any]:
    """Generate Kotlin exploit PoC and ADB command for a finding."""
    scan = await get_scan_details(scan_id)
    findings = scan.get("findings", [])
    finding_dict = next((f for f in findings if f.get("id") == finding_id), None)
    if not finding_dict:
        raise HTTPException(404, f"Finding {finding_id} not found in scan {scan_id}")

    from mobileag.generators.poc_apk_synthesizer import ExploitPocSynthesizer
    from mobileag.reporting.finding import Finding, Severity, FindingStatus

    try:
        sev = Severity(finding_dict.get("severity", "MEDIUM"))
    except Exception:
        sev = Severity.MEDIUM
    try:
        st = FindingStatus(finding_dict.get("status", "UNVERIFIED"))
    except Exception:
        st = FindingStatus.UNVERIFIED

    f_obj = Finding(
        id=finding_dict.get("id", finding_id),
        title=finding_dict.get("title", ""),
        description=finding_dict.get("description", ""),
        severity=sev,
        status=st,
        cwe_id=finding_dict.get("cwe_id"),
        file_path=finding_dict.get("file_path", ""),
        metadata=finding_dict.get("metadata", {}),
    )

    pkg = scan.get("package_name") or "com.target.mobile.app"
    synthesizer = ExploitPocSynthesizer()
    poc = synthesizer.synthesize(f_obj, target_package=pkg)

    if not poc:
        return {
            "finding_id": finding_id,
            "available": False,
            "message": "Automated standalone exploit generator not applicable for this finding category.",
        }

    return {
        "finding_id": finding_id,
        "available": True,
        "vulnerability_type": poc.vulnerability_type,
        "adb_command": poc.adb_command,
        "kotlin_exploit_code": poc.kotlin_exploit_code,
        "explanation": poc.explanation,
    }


class FeedbackRequest(BaseModel):
    verdict: Literal['CONFIRMED', 'FALSE_POSITIVE', 'DUPLICATE', 'UNVERIFIED']
    notes: str = Field(default='', max_length=10000)
    evidence: Optional[ConfirmationEvidence] = None
    revision: Optional[int] = Field(default=None, ge=0)



@app.post("/api/findings/{finding_id}/feedback")
async def submit_feedback(finding_id: str, feedback: FeedbackRequest) -> dict[str, Any]:
    # Compatibility endpoint: never silently fan out across scans or runtime rings.
    if feedback.verdict == 'CONFIRMED' and not feedback.notes.strip():
        raise HTTPException(422, 'Confirmation requires observed validation evidence')
    raise HTTPException(409, 'Scan identity is required; use /api/scans/{scan_id}/findings/{finding_id}/feedback')


@app.post('/api/scans/{scan_id}/findings/{finding_id}/feedback')
async def submit_scan_feedback(scan_id: str, finding_id: str, feedback: FeedbackRequest):
    validate_scan_id(scan_id)
    if feedback.verdict == 'CONFIRMED' and not feedback.notes.strip():
        raise HTTPException(422, 'Confirmation requires observed validation evidence')
    await get_scan_details(scan_id)  # Import legacy documents on first access.
    try:
        scan = await asyncio.to_thread(repository().triage, scan_id, finding_id,
                                      feedback.verdict, feedback.notes, feedback.revision,
                                      feedback.evidence.model_dump() if feedback.evidence else None)
    except KeyError as exc:
        raise HTTPException(404, str(exc))
    except EvidenceError as exc:
        raise HTTPException(422, str(exc))
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    if scan_id in ACTIVE_SCANS:
        ACTIVE_SCANS[scan_id] = scan
    effective = next(f for f in prepare_scan(scan)['findings'] if f['id'] == finding_id)
    return {'status': 'saved', 'scan_id': scan_id, 'finding_id': finding_id,
            'finding': redact(effective),
            'revision': scan['revision'], 'verdict': feedback.verdict,
            'confirmation_basis': 'analyst_attested_not_independently_verified' if feedback.verdict=='CONFIRMED' else None,
            'validation_evidence': next(f for f in scan['findings'] if f['id']==finding_id).get('validation_evidence'),
            'validation_notes': next(f for f in scan['findings'] if f['id']==finding_id).get('validation_notes'),
            'persistence': 'local_sqlite'}


@app.get('/api/scans/{scan_id}/decisions')
async def scan_decisions(scan_id: str):
    await get_scan_details(scan_id)
    return {'scan_id': scan_id, 'decisions': await asyncio.to_thread(repository().history, scan_id)}


@app.get('/api/scans/{scan_id}/test-plan')
async def get_scan_test_plan(scan_id: str):
    validate_scan_id(scan_id)
    await get_scan_details(scan_id)  # Import legacy scan snapshots consistently.
    plan = await asyncio.to_thread(repository().get_test_plan, scan_id)
    if plan is None:
        raise HTTPException(404, 'No test plan is recorded for this scan')
    return redact(plan)


@app.put('/api/scans/{scan_id}/test-plan')
async def save_scan_test_plan(scan_id: str, request: TestPlanRequest):
    validate_scan_id(scan_id)
    if request.retest_of_scan_id:
        validate_scan_id(request.retest_of_scan_id)
    scan = await get_scan_details(scan_id)
    from mobileag.assessments.test_plan import build_plan
    try:
        document = build_plan(scan, request, revision=0)
        saved = await asyncio.to_thread(repository().save_test_plan, scan_id, document,
                                        request.expected_revision)
    except KeyError as exc:
        raise HTTPException(404, str(exc))
    except ValueError as exc:
        raise HTTPException(409, str(exc))
    return redact(saved)


class CopilotRequest(BaseModel):
    prompt: str = Field(max_length=10000)
    scan_id: Optional[str] = None


@app.post("/api/copilot")
async def query_copilot(req: CopilotRequest) -> dict[str, Any]:
    if not req.scan_id:
        raise HTTPException(422, "Select a scan; contextual assistance never invents a target")
    scan = await get_scan_details(req.scan_id)
    findings = scan.get("findings", [])
    response = "# Evidence summary — not runtime verification\n\n"
    response += f"Scan {scan['scan_id']}: {len(findings)} review candidates.\n"
    response += "Generated procedures are suggestions, not observed results. Root/shell/hook results do not prove ordinary-app exploitation.\n\n"
    for f in findings[:20]:
        response += f"- {f.get('title', 'Candidate')} [{f.get('status', 'UNVERIFIED')}] at {f.get('file_path', 'unknown')}:{f.get('line_number', '?')}\n"
    if scan.get('errors'):
        response += "\nCoverage is incomplete; inspect the scan errors."
    return {"status": "success", "mode": "local_evidence_summary", "response": redact(response), "scan_id": req.scan_id}



@app.get("/api/agents")
async def list_agents() -> list[dict[str, Any]]:
    names = [("manifest", "Manifest auditor"), ("secrets", "Credential pattern scanner"),
             ("code_review", "Java/Kotlin heuristic review"), ("api_mapping", "API route discovery"),
             ("native", "Native analysis"), ("dependencies", "Dependency advisory lookup"),
             ("taint", "Straight-line taint analysis"), ("nsc", "Network configuration"),
             ("binary_protection", "ELF protections"), ("react_native", "React Native strings"),
             ("smali", "Smali call graph")]
    return [{"id": key, "name": name, "status": "CAPABILITY", "findings_count": None,
             "last_runtime": None, "description": "Runs as part of a scan; inspect that scan's measured coverage. Individual execution is not implemented."}
            for key, name in names]



@app.get("/api/scope")
async def get_scope():
    from mobileag.web.security import configured_list
    return {'policy':repository().get_policy(), 'ceilings':{
        'devices':sorted(configured_list('MOBILEAG_ALLOWED_DEVICES')),
        'origins':sorted(configured_list('MOBILEAG_ALLOWED_ORIGINS'))},
        'boundary':'single local operator; shell, root and Frida approval is device-wide'}


@app.post("/api/scope")
async def save_scope(value: dict):
    from mobileag.web.policy import validate_policy
    try:
        policy = validate_policy(value)
    except ValueError as exc:
        raise HTTPException(422,str(exc))
    repository().save_policy(policy)
    return {'status':'saved','policy':policy}


@app.post("/api/session/rotate")
async def rotate_session():
    app.state.auth_token = secrets.token_urlsafe(32)
    app.state.session_deadline = time.monotonic()+8*3600
    for ws in list(manager.active_connections):
        await ws.close(code=1008)
        manager.disconnect(ws)
    return {'token':app.state.auth_token,'expires_in':8*3600}


@app.post("/api/session/logout")
async def logout_session():
    app.state.auth_token = secrets.token_urlsafe(32)
    app.state.session_deadline = time.monotonic()+8*3600
    for ws in list(manager.active_connections):
        await ws.close(code=1008)
        manager.disconnect(ws)
    print('MobileAg new local session token (after logout): '+app.state.auth_token, flush=True)
    return {'status':'logged_out','reconnect':'Use the new token displayed in the server terminal'}


@app.get("/api/scans/{scan_id}/retention")
async def retention_preview(scan_id: str):
    scan = await get_scan_details(scan_id)
    return {'scan_id':scan_id,'revision':scan.get('revision',0),
            'confirmation':scan_id, 'artifact_sha256':scan.get('artifact_sha256'),
            'deletes':['scan output','scan metadata','analyst decisions','manual test-plan records'],
            'preserves':['uploaded original archive; may be shared by other scans'],
            'allowed':scan.get('status') not in {'running','queued','cancelling'}}


class PurgeRequest(BaseModel):
    confirmation: str
    revision: int


@app.post("/api/scans/{scan_id}/purge")
async def purge_scan(scan_id: str, request: PurgeRequest):
    scan = await get_scan_details(scan_id)
    if scan.get('status') in {'running','queued','cancelling'} or request.revision != scan.get('revision',0) or request.confirmation != scan_id:
        raise HTTPException(409, 'Job active, changed, or confirmation incorrect; preview again')
    root = OUTPUT_DIR.resolve()
    directory = OUTPUT_DIR / scan_id
    if directory.is_symlink() or not directory.resolve().is_relative_to(root):
        raise HTTPException(409, 'Unsafe evidence path; manual operator review required')
    # Tombstone prevents preserved legacy snapshots from being re-imported.
    try:
        repository().purge(scan_id,scan.get('artifact_sha256'),request.revision)
    except ValueError as exc:
        raise HTTPException(409,str(exc))
    ACTIVE_SCANS.pop(scan_id,None)
    if directory.exists():
        await asyncio.to_thread(shutil.rmtree,directory)
    return {'status':'purged','original_archive':'preserved'}


@app.get("/api/settings")
async def get_settings_config() -> dict[str, Any]:
    return await asyncio.to_thread(effective_runtime_settings)



@app.post("/api/settings")
async def update_settings_config(settings: dict[str, Any]) -> dict[str, Any]:
    supported = {"entropy_threshold", "enable_deep_taint", "enable_reachability_filter", "enable_consensus_voting", "offline"}
    if set(settings) - supported:
        raise HTTPException(422, "Unsupported setting; credentials must stay in the server environment")
    merged = {**effective_runtime_settings(), **settings}
    try:
        if isinstance(merged['entropy_threshold'], bool) or not 0 <= float(merged['entropy_threshold']) <= 8:
            raise ValueError()
        if any(type(v) is not bool for k,v in settings.items() if k != 'entropy_threshold'):
            raise ValueError()
        if merged.get('offline') is False:
            raise ValueError('Web static workers are offline-only. Cloud execution requires a separate credential broker; use the explicitly approved CLI flow instead')
    except (ValueError, TypeError) as exc:
        raise HTTPException(422, str(exc) or "Invalid runtime settings")
    if 'entropy_threshold' in settings:
        settings['entropy_threshold'] = float(settings['entropy_threshold'])
    RUNTIME_SETTINGS.update(settings)
    saved = {k:merged[k] for k in supported}
    await asyncio.to_thread(repository().save_settings, saved)
    return {"status": "saved", "settings": effective_runtime_settings(), "persistence": "local_sqlite"}



# =============================================================================
# DAST (Dynamic Application Security Testing) Endpoints
# =============================================================================
class DeviceConnectRequest(BaseModel):
    host_port: str = "127.0.0.1:5555"


class DeviceActionRequest(BaseModel):
    serial: str


class InstallApkRequest(BaseModel):
    serial: str
    apk_path: str
    grant_permissions: bool = False


class LaunchActivityRequest(BaseModel):
    serial: str
    component: str


class DispatchDeeplinkRequest(BaseModel):
    serial: str
    package_name: str
    uri: str


class StorageAuditRequest(BaseModel):
    serial: str
    package_name: str


class ProviderAuditRequest(BaseModel):
    serial: str
    package_name: str
    authorities: list[str] = Field(max_length=30)


class DastFuzzRequest(BaseModel):
    serial: str
    package_name: str
    apk_path: Optional[str] = None
    activities: Optional[list[str]] = Field(default=None,max_length=30)
    deeplinks: Optional[list[str]] = Field(default=None,max_length=30)
    authorities: Optional[list[str]] = Field(default=None,max_length=30)
    targeted_extras: Optional[dict[str, list[str]]] = None
    audit_storage: bool = True
    audit_memory: bool = False
    crawl_ui: bool = False


class DeepLinkAuditRequest(BaseModel):
    serial: str
    package_name: str
    deep_links: list[str] = Field(max_length=30)


class MemoryAuditRequest(BaseModel):
    serial: str
    package_name: str


class UICrawlRequest(BaseModel):
    serial: str
    package_name: str
    max_steps: int = Field(default=5, ge=1, le=20)


class FridaDeployRequest(BaseModel):
    serial: str
    package_name: str
    script_type: Literal["unpinning", "crypto", "root_bypass", "all", "unified"] = "unpinning"  # "unpinning", "crypto", "root_bypass", "unified"


class TaintAnalyzeRequest(BaseModel):
    source_code: str = Field(max_length=262144)
    file_path: str = Field(default="VulnerableActivity.java", max_length=512)


class CapturedTransaction(BaseModel):
    model_config = {'extra': 'forbid'}
    url: str = Field(max_length=8192)
    method: Literal['GET','POST','PUT','PATCH','DELETE','HEAD','OPTIONS'] = 'GET'
    request_headers: dict[str, str] = Field(default_factory=dict, max_length=100)
    response_status: int = Field(default=200, ge=100, le=599)
    response_headers: dict[str, str] = Field(default_factory=dict, max_length=100)
    request_body: Optional[str] = Field(default=None, max_length=262144)
    response_body: Optional[str] = Field(default=None, max_length=262144)

class DeclaredApiEndpoint(BaseModel):
    model_config = {"extra": "forbid"}
    url: str = Field(max_length=8192)
    method: Optional[Literal["GET", "PUT", "POST", "DELETE", "OPTIONS", "HEAD", "PATCH", "TRACE"]] = None


class TrafficAuditRequest(BaseModel):
    transactions: list[CapturedTransaction] = Field(default_factory=list, max_length=100)
    declared_endpoints: list[str | DeclaredApiEndpoint] = Field(default_factory=list, max_length=1000)



class ExecuteAdbRequest(BaseModel):
    serial: str
    command: str


class ApiTestRequest(BaseModel):
    url: str
    method: str = "GET"
    headers: Optional[dict[str, str]] = None
    body: Optional[str] = None
    timeout: float = 4.0


class ApiFuzzRequest(BaseModel):
    url: str
    method: str = "GET"
    headers: Optional[dict[str, str]] = None
    body: Optional[str] = None
    response_status: int = 200
    response_headers: Optional[dict[str, str]] = None
    response_body: Optional[str] = None





def require_current_session(request: Request):
    token = request.state.authenticated_token
    if time.monotonic() >= app.state.session_deadline or not authorized(token, app.state.auth_token):
        raise HTTPException(401, "Session expired or revoked")


from mobileag.dashboard.routes import build_router as build_dashboard_router
app.include_router(build_dashboard_router(require_current_session))


@app.get("/api/dast/devices")
async def get_dast_devices(request: Request) -> dict[str, Any]:
    """Observe host ADB inventory; do not query device shell/root or choose a target."""
    require_current_session(request)
    avail = await adb_manager.is_adb_available()
    require_current_session(request)
    state = "unavailable"
    devices = []
    if avail:
        try:
            devices = await adb_manager.discover_devices()
            state = "checked"
        except Exception:
            state = "unknown"
    require_current_session(request)
    return {
        "adb_available": avail, "adb_path": adb_manager.adb_bin,
        "inventory_state": state, "device_count": len(devices),
        "devices": [{"serial": d.serial, "status": d.status, "model": d.model,
            "android_version": d.android_version, "sdk_level": d.sdk_level,
            "is_emulator": d.is_emulator, "is_rooted": False, "root_checked": False,
            "allowed": check_device(d.serial)} for d in devices],
    }


@app.get("/api/preflight")
async def get_preflight(request: Request):
    """Local readiness only. Never authorize targets, execute jobs or call a model."""
    from mobileag.llm.broker import catalog
    require_current_session(request)
    host, devices = await asyncio.gather(get_readiness(), get_dast_devices(request))
    require_current_session(request)
    scope = await get_scope()
    return {"checked_at": datetime.now(timezone.utc).isoformat(), "host": host,
            "devices": devices, "scope": scope, "providers": catalog(),
            "automatic_actions": ["harmless local sandbox probe", "host ADB inventory", "configuration inspection"],
            "device_selection": "explicit_only", "model_contacted": False,
            "target_testing_started": False}


@app.get("/api/dast/frida/status")
async def get_frida_status(request: Request, serial: str = Query(min_length=1, max_length=128)):
    """Approved ordinary-shell process observation, NOT attachment or server startup."""
    from mobileag.web.policy import check_action
    from mobileag.dast import frida_runner as native
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}", serial):
        raise HTTPException(422, "Invalid device serial")
    def guard():
        require_current_session(request)
        if not check_device(serial) or not check_action(repository().get_policy(), "frida_status", {"serial": serial}):
            raise HTTPException(403, "Read-only device process observation is not approved")
    guard()
    try:
        code, stdout, _ = await adb_manager._exec_cmd(
            ["-s", serial, "shell", "ps", "-A"], timeout=4.0, output_limit=65536)
        observed = any(line.split() and line.split()[-1].rsplit("/", 1)[-1] == "frida-server"
                       for line in stdout.decode("utf-8", errors="replace").splitlines())
        state = ("observed" if observed else "not_observed") if code == 0 else "unknown"
    except Exception:
        state = "unknown"
    guard()
    return {"serial": serial, "process_state": state, "native_dependency": native.HAS_NATIVE_FRIDA,
            "attach_verified": False, "compatibility": "not_checked",
            "checked_at": datetime.now(timezone.utc).isoformat(),
            "boundary": "device-wide ordinary ADB shell process observation; not ordinary-app exploit proof"}


@app.get("/api/frida/presets/{script_type}")
async def preview_frida_preset(script_type: Literal["crypto", "root_bypass", "unpinning"]):
    """Generate preview text only. Never use the execution route for previews."""
    generators = {"crypto": frida_runner.generate_crypto_monitor_script,
                  "root_bypass": frida_runner.generate_root_bypass_script,
                  "unpinning": frida_runner.generate_unpinning_script}
    return {"script": generators[script_type](), "executed": False}


@app.post("/api/dast/connect")
async def connect_dast_device(req: DeviceConnectRequest) -> dict[str, Any]:
    """Connect to a local or remote emulator/device over TCP/IP."""
    res = await adb_manager.connect_device(req.host_port)
    return res


@app.post("/api/dast/root")
async def restart_dast_root(req: DeviceActionRequest) -> dict[str, Any]:
    """Restart adbd with root privileges on the selected device."""
    res = await adb_manager.restart_root(req.serial)
    return res


@app.post("/api/dast/install")
async def install_dast_apk(req: InstallApkRequest) -> dict[str, Any]:
    """Install an explicitly selected APK; permission grants are opt-in."""
    path = Path(req.apk_path).resolve()
    if not path.is_relative_to(UPLOAD_DIR.resolve()):
        raise HTTPException(400, "Install an archive uploaded to this dashboard")
    try:
        if validate_archive(path) != "android":
            raise ValueError("Expected Android APK")
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    res = await adb_manager.install_apk(req.serial, str(path), req.grant_permissions)
    return res


@app.post("/api/dast/launch")
async def launch_dast_activity(req: LaunchActivityRequest) -> dict[str, Any]:
    """Launch an Android component or exported activity via am start."""
    res = await adb_manager.launch_activity(req.serial, req.component)
    return res


@app.post("/api/dast/deeplink")
async def dispatch_dast_deeplink(req: DispatchDeeplinkRequest, request: Request) -> dict[str, Any]:
    """Dispatch a custom URI scheme or deep-link to the target device."""
    def guard():
        from mobileag.web.policy import check_action
        if (time.monotonic() >= app.state.session_deadline or
            not authorized(request.state.authenticated_token, app.state.auth_token) or
            not check_device(req.serial) or
            not check_action(repository().get_policy(), "deeplink", req.model_dump())):
            raise HTTPException(403, "Deep-link approval expired or revoked")
    res = await intent_fuzzer.exercise_component(
        serial=req.serial,
        package_name=req.package_name,
        component_name="",
        action="android.intent.action.VIEW",
        data_uri=req.uri,
        guard=guard,
    )
    return {
        "status": "success" if not res.get("crashed") else "crashed",
        "result": res,
    }


@app.post("/api/dast/execute_adb")
async def execute_adb_command(req: ExecuteAdbRequest) -> dict[str, Any]:
    """Execute an ADB shell command directly on the connected BYOD device."""
    res = await adb_manager.execute_shell(req.serial, req.command)
    return res


@app.get("/api/dast/logcat")
async def get_dast_logcat(serial: str, package_name: Optional[str] = None, lines: int = Query(200, ge=1, le=1000)) -> dict[str, Any]:
    """Return only exact target-process log records for an approved package."""
    if not package_name:
        raise HTTPException(status_code=422, detail="package_name is required for scoped log capture")
    # PID filtering happens at logcat collection time, so stale Process markers
    # cannot cause the shared buffer to expose a different process reusing a PID.
    pids = await adb_manager.get_process_pids(serial, package_name)
    raw_lines = []
    for pid in pids:
        raw_lines.extend(await adb_manager.get_logcat_dump(serial=serial, lines=lines, pid=pid))
    findings = logcat_auditor.audit_lines(raw_lines, package_name=package_name, process_pids=pids)
    return {
        "serial": serial,
        "lines": redact(raw_lines),
        "line_count": len(raw_lines),
        "findings": redact([f.to_dict() for f in findings]),
    }


@app.post("/api/dast/logcat/clear")
async def clear_dast_logcat(req: DeviceActionRequest, request: Request) -> dict[str, Any]:
    """Clear device logcat buffer."""
    require_current_session(request)
    success = await adb_manager.clear_logcat(req.serial)
    require_current_session(request)
    return {"status": "success" if success else "failed"}


@app.post("/api/dast/screenshot")
async def capture_dast_screenshot(req: DeviceActionRequest, request: Request) -> dict[str, Any]:
    """Capture a live screenshot of the device screen."""
    require_current_session(request)
    png_bytes = await adb_manager.capture_screenshot(req.serial)
    require_current_session(request)
    if png_bytes:
        import base64
        b64 = base64.b64encode(png_bytes).decode("utf-8")
        return {"status": "success", "image_b64": f"data:image/png;base64,{b64}"}
    return {"status": "error", "message": "Screenshot capture failed"}


@app.post("/api/dast/storage")
async def audit_dast_storage(req: StorageAuditRequest, request: Request) -> dict[str, Any]:
    """Audit local sandbox storage (SharedPreferences, SQLite DBs, and cache) post-execution."""
    require_current_session(request)
    def guard():
        from mobileag.web.policy import check_action
        require_current_session(request)
        if not check_device(req.serial) or not check_action(repository().get_policy(), 'storage', req.model_dump()):
            raise HTTPException(403, 'Storage diagnostic scope revoked')
    report = await storage_auditor.audit_all_storage(req.serial, req.package_name, guard=guard)
    guard()
    remember_findings(report.get("findings", []))
    return {"status": "success", "report": redact(report)}


@app.post("/api/dast/providers")
async def audit_dast_providers(req: ProviderAuditRequest, request: Request) -> dict[str, Any]:
    """Audit exported Content Providers for unauthorized access and SQL syntax leakage."""
    def guard():
        from mobileag.web.policy import check_action
        if (time.monotonic() >= app.state.session_deadline or
            not authorized(request.state.authenticated_token, app.state.auth_token) or
            not check_device(req.serial) or
            not check_action(repository().get_policy(), "providers", req.model_dump())):
            raise PermissionError("Provider approval expired or revoked")
    try:
        results, findings = await provider_auditor.audit_providers(req.serial, req.package_name, req.authorities, guard=guard)
    except PermissionError as exc:
        raise HTTPException(403, str(exc))
    f_dicts = redact([f.to_dict() for f in findings])
    remember_findings(f_dicts)
    return {"status": "success", "results": results, "findings": f_dicts}


@app.post("/api/dast/deeplinks")
async def audit_dast_deeplinks(req: DeepLinkAuditRequest, request: Request) -> dict[str, Any]:
    """Explicit synthetic link diagnostics; no automatic exploit proof."""
    from mobileag.web.policy import check_action
    def guard():
        require_current_session(request)
        if not check_device(req.serial) or not check_action(repository().get_policy(),'deeplinks',req.model_dump()):
            raise HTTPException(403,'Deep-link diagnostic scope revoked')
    guard()
    results, findings = await deeplink_fuzzer.fuzz_deep_links(req.serial, req.package_name, req.deep_links,guard=guard)
    guard()
    f_dicts = redact([f.to_dict() for f in findings])
    remember_findings(f_dicts)
    return {"status": "success", "results": results, "findings": f_dicts}


@app.post("/api/dast/memory")
async def audit_dast_memory(req: MemoryAuditRequest, request: Request) -> dict[str, Any]:
    """Audit volatile process RAM for cleartext passwords and lingering bearer tokens (CWE-316)."""
    require_current_session(request)
    def guard():
        from mobileag.web.policy import check_action
        require_current_session(request)
        if not check_device(req.serial) or not check_action(repository().get_policy(), 'memory', req.model_dump()):
            raise HTTPException(403, 'Memory diagnostic scope revoked')
    guard()
    report = await memory_auditor.run_memory_audit(req.serial, req.package_name, guard=guard)
    guard()
    remember_findings(report.get("findings", []))
    return {"status": "success", "report": redact(report)}


@app.post("/api/dast/crawl")
async def crawl_dast_ui(req: UICrawlRequest, request: Request) -> dict[str, Any]:
    """Autonomously navigate UI views with UIAutomator to expand dynamic coverage."""
    require_current_session(request)
    from mobileag.web.policy import check_action
    if not check_device(req.serial) or not check_action(repository().get_policy(), 'crawl', req.model_dump()):
        raise HTTPException(403, 'UI observation scope is not approved')
    def guard():
        require_current_session(request)
        if not check_device(req.serial) or not check_action(repository().get_policy(), 'crawl', req.model_dump()):
            raise HTTPException(403, 'UI observation scope revoked')
    report = await ui_crawler.crawl_app(req.serial, req.package_name, max_steps=req.max_steps, guard=guard)
    require_current_session(request)
    if not check_device(req.serial) or not check_action(repository().get_policy(), 'crawl', req.model_dump()):
        raise HTTPException(403, 'UI observation scope revoked')
    return {"status": "success", "report": redact(report)}


@app.post("/api/dast/frida")
async def deploy_dast_frida(req: FridaDeployRequest, request: Request) -> dict[str, Any]:
    """Generate or deploy dynamic Frida runtime scripts (SSL unpinning, crypto monitor, root bypass, unified)."""
    require_current_session(request)
    from mobileag.web.policy import check_action
    if not check_device(req.serial) or not check_action(repository().get_policy(), 'frida', req.model_dump()):
        raise HTTPException(403, 'Frida device-wide diagnostic action is not approved')
    if req.script_type == "crypto":
        script = frida_runner.generate_crypto_monitor_script()
    elif req.script_type == "root_bypass":
        script = frida_runner.generate_root_bypass_script()
    elif req.script_type in ("all", "unified"):
        script = frida_runner.generate_all_in_one_agent_script()
    else:
        script = frida_runner.generate_unpinning_script()
    res = await frida_runner.execute_script_payload(req.serial, req.package_name, script)
    require_current_session(request)
    if not check_device(req.serial) or not check_action(repository().get_policy(), 'frida', req.model_dump()):
        raise HTTPException(403, 'Frida device-wide diagnostic action was revoked')
    return {"status": res.get("status", "error"), "result": res, "script": script}


@app.post("/api/dast/traffic/audit")
async def audit_dast_traffic(req: TrafficAuditRequest) -> dict[str, Any]:
    """Audit supplied captured traffic; never sends network requests."""
    txs = [HTTPTransaction(**item.model_dump()) for item in req.transactions]
    findings = traffic_auditor.audit_transactions(txs)
    declared = [
        item.model_dump(exclude_none=True) if isinstance(item, DeclaredApiEndpoint) else item
        for item in req.declared_endpoints
    ]
    shadow_findings = (traffic_auditor.find_shadow_apis(txs, declared) if declared else [])
    return {
        "status": "success",
        "findings_count": len(findings),
        "findings": redact([f.to_dict() for f in findings]),
        "shadow_api_review_status": ("unverified_review_leads" if declared else "not_requested"),
        "shadow_api_findings_count": len(shadow_findings),
        "shadow_api_findings": redact([f.to_dict() for f in shadow_findings]),
        "live_requests_sent": 0,
    }


@app.post("/api/dast/api-capture/start")
async def start_api_capture(request: Request) -> dict[str, Any]:
    """Start authenticated loopback HTTP capture; HTTPS CONNECT is unsupported."""
    global api_capture_proxy
    from mobileag.web.policy import check_action
    require_current_session(request)
    policy = repository().get_policy()
    if not check_action(policy, 'api_capture', {}):
        raise HTTPException(403, 'API capture is not enabled in the operator scope policy')
    if not policy.get('origins') or not policy.get('methods'):
        raise HTTPException(403, 'API capture requires explicitly scoped origins and methods')
    from mobileag.dast.mitm_proxy import AsyncMITMProxy
    if (api_capture_proxy is not None and api_capture_proxy.is_running and
            (api_capture_proxy.allowed_origins != set(policy['origins']) or
             api_capture_proxy.allowed_methods != {m.upper() for m in policy['methods']})):
        raise HTTPException(409, 'Stop the running capture proxy before changing its scope')
    if api_capture_proxy is None:
        api_capture_proxy = AsyncMITMProxy(host='127.0.0.1', port=8082,
            auditor=traffic_auditor, allowed_origins=policy['origins'],
            allowed_methods=policy['methods'])
    try:
        await api_capture_proxy.start()
    except (ValueError, OSError) as exc:
        raise HTTPException(503, str(exc))
    require_current_session(request)
    return {'status': 'listening', 'host': '127.0.0.1', 'port': 8082,
            'https_interception': False, 'scope_origins': policy['origins'],
            'scope_methods': policy['methods'],
            'note': 'Configure a researcher-controlled client to use the authenticated local proxy; no APK/device is changed.'}


@app.post("/api/dast/api-capture/stop")
async def stop_api_capture(request: Request) -> dict[str, Any]:
    global api_capture_proxy
    require_current_session(request)
    count = len(api_capture_proxy.get_transactions()) if api_capture_proxy else 0
    if api_capture_proxy:
        await api_capture_proxy.stop()
    require_current_session(request)
    return {'status': 'stopped', 'captured_transactions': count}


@app.get("/api/dast/api-capture/transactions")
async def get_api_capture_transactions(request: Request) -> dict[str, Any]:
    require_current_session(request)
    txs = api_capture_proxy.get_transactions() if api_capture_proxy else []
    capture_stats = api_capture_proxy.get_capture_stats() if api_capture_proxy else {
        'transaction_count': 0, 'stored_bytes_estimate': 0, 'omitted_transactions': 0}
    require_current_session(request)
    return {'count': len(txs), 'capture_stats': capture_stats,
            'transactions': redact([tx.__dict__ if hasattr(tx, '__dict__') else {
        'url': tx.url, 'method': tx.method, 'request_headers': tx.request_headers,
        'response_status': tx.response_status, 'response_headers': tx.response_headers,
        'request_body': tx.request_body, 'response_body': tx.response_body,
    } for tx in txs])}


def _captured_api_catalog(txs, title: str):
    """Build an inventory/export model from observed transactions, not guesses."""
    from mobileag.dast.api_cataloger import MobileApiCataloger, CapturedRequest
    catalog = MobileApiCataloger(title=title)
    for tx in txs:
        catalog.ingest_request(CapturedRequest(
            method=tx.method, url=tx.url, headers=tx.request_headers,
            body=tx.request_body,
            response_status=tx.response_status, response_body=tx.response_body,
        ))
    return catalog


@app.get("/api/dast/api-capture/openapi")
async def get_api_capture_openapi(request: Request) -> dict[str, Any]:
    """Export an OpenAPI inventory based solely on captured, redacted requests."""
    require_current_session(request)
    txs = api_capture_proxy.get_transactions() if api_capture_proxy else []
    catalog = _captured_api_catalog(txs, 'Observed Mobile API Traffic')
    result = catalog.export_openapi_json()
    if api_capture_proxy:
        result['x-mobileag-capture-limits']['omittedRequests'] += api_capture_proxy.omitted_transactions
    require_current_session(request)
    result['x-mobileag-evidence-state'] = 'observed_capture_inventory'
    result['x-mobileag-proof-state'] = 'not_proven'
    return result


@app.get("/api/dast/api-capture/har")
async def get_api_capture_har(request: Request) -> dict[str, Any]:
    """Export current in-memory capture as redacted HAR 1.2."""
    require_current_session(request)
    txs = api_capture_proxy.get_transactions() if api_capture_proxy else []
    result = _captured_api_catalog(txs, 'Observed Mobile API Traffic').export_har_json()
    result['log']['x-mobileag-capture-stats'] = (
        api_capture_proxy.get_capture_stats() if api_capture_proxy else {
            'transaction_count': 0, 'stored_bytes_estimate': 0, 'omitted_transactions': 0})
    require_current_session(request)
    return result


@app.post("/api/dast/api-capture/audit")
async def audit_api_capture(request: Request) -> dict[str, Any]:
    require_current_session(request)
    txs = api_capture_proxy.get_transactions() if api_capture_proxy else []
    findings = traffic_auditor.audit_transactions(txs)
    require_current_session(request)
    return {'status': 'capture_analysis', 'transactions_reviewed': len(txs),
            'findings': redact([finding.to_dict() for finding in findings]),
            'live_requests_sent': 0}


@app.post("/api/analysis/taint")
async def analyze_taint(req: TaintAnalyzeRequest) -> dict[str, Any]:
    """Find potential straight-line source-to-sink flows; results require manual validation."""
    findings = await asyncio.wait_for(asyncio.to_thread(taint_engine.analyze_source_content, req.source_code, req.file_path), timeout=15)
    f_dicts = redact([f.to_dict() for f in findings])
    return {"status": "success", "findings": f_dicts}


@app.post("/api/apis/test")
async def test_api_endpoint(req: ApiTestRequest) -> dict[str, Any]:
    """Replay a request only within the operator-configured scope."""
    from mobileag.web.policy import check_replay
    if not check_replay(repository().get_policy(), req.url.strip(), req.method.upper()):
        raise HTTPException(403, 'API request is not approved in the UI scope policy')
    try:
        result = await scoped_request(req.url.strip(), req.method.upper(), req.headers,
                                      req.body.encode() if req.body else None, req.timeout)
        return {"status":"success", "mode":"live", "reachable":True, **redact(result)}
    except PermissionError as exc:
        raise HTTPException(403, str(exc))
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    except Exception:
        raise HTTPException(502, "Target request failed; no simulated result was generated")


@app.post("/api/apis/fuzz")
async def fuzz_api_endpoint(req: ApiFuzzRequest) -> dict[str, Any]:
    """Run an autonomous OWASP API Security Top 10 (2023) audit on the given endpoint."""
    url = req.url.strip()
    method = req.method.strip().upper()
    req_headers = req.headers or {}
    resp_headers = req.response_headers or {}
    resp_body = req.response_body

    tx = HTTPTransaction(
        url=url,
        method=method,
        request_headers=req_headers,
        response_status=req.response_status,
        response_headers=resp_headers,
        request_body=req.body,
        response_body=resp_body,
    )

    findings = traffic_auditor.audit_transactions([tx])

    # Request paths and absent headers alone cannot establish an authorization bypass.
    for finding in findings:
        finding.status = FindingStatus.UNVERIFIED

    f_dicts = redact([f.to_dict() for f in findings])
    return {
        "status": "success",
        "url": url,
        "method": method,
        "findings_count": len(findings),
        "findings": f_dicts,
        "risk_summary": "CANDIDATES" if findings else "NOT_ASSESSED",
        "mode": "capture_analysis",
        "limitations": "No live request or server authorization verification was performed",
    }


async def run_dast_background_task(req: DastFuzzRequest, token: str) -> None:
    """Execute dynamic fuzzing, IPC audits, and storage forensics with WebSocket telemetry."""
    serial = req.serial
    pkg = req.package_name

    def guard():
        from mobileag.web.policy import check_action
        if time.monotonic() >= app.state.session_deadline or not authorized(token, app.state.auth_token):
            raise HTTPException(401, 'Session expired or revoked')
        if not check_device(serial) or not check_action(repository().get_policy(), 'fuzz', req.model_dump()):
            raise HTTPException(403, 'Dynamic assessment scope was revoked')

    guard()

    await manager.broadcast({
        "type": "dast_progress",
        "stage": "DAST Initialized",
        "message": f"Starting dynamic assessment on {serial} for {pkg}...",
        "progress": 5,
        "timestamp": datetime.now().isoformat(),
    })

    # Device verification
    guard()
    devs = await adb_manager.discover_devices()
    target_dev = next((d for d in devs if d.serial == serial), None)
    if target_dev is None or target_dev.status != 'device':
        raise HTTPException(409, 'Selected device is not online')

    await manager.broadcast({
        "type": "dast_progress",
        "stage": "Device Verified",
        "message": f"Device {serial} is online; root status was not probed.",
        "progress": 20,
        "timestamp": datetime.now().isoformat(),
    })

    # Optional APK installation
    if req.apk_path:
        await manager.broadcast({
            "type": "dast_progress",
            "stage": "APK Installation",
            "message": f"Installing {req.apk_path} without automatic permission grants...",
            "progress": 35,
            "timestamp": datetime.now().isoformat(),
        })
        guard()
        await adb_manager.install_apk(serial, req.apk_path, grant_permissions=False)

    # Activity intent fuzzing (with targeted extras if provided)
    acts = req.activities or []
    await manager.broadcast({
        "type": "dast_progress",
        "stage": "Intent Exercising",
        "message": f"Exercising {len(acts)} activities with boundary payloads...",
        "progress": 50,
        "timestamp": datetime.now().isoformat(),
    })

    guard()
    _, findings = await intent_fuzzer.fuzz_activity_intents(
        serial, pkg, acts, targeted_extras=req.targeted_extras, guard=guard
    )

    # Deep-link fuzzing
    if req.deeplinks:
        await manager.broadcast({
            "type": "dast_progress",
            "stage": "Deep Link Fuzzing",
            "message": f"Invoking {len(req.deeplinks)} deep links and URI schemes...",
            "progress": 65,
            "timestamp": datetime.now().isoformat(),
        })
        guard()
        _, dl_findings = await intent_fuzzer.fuzz_deeplinks(serial, pkg, req.deeplinks, guard=guard)
        findings.extend(dl_findings)

    # Content Provider Auditing
    if req.authorities:
        await manager.broadcast({
            "type": "dast_progress",
            "stage": "Content Provider Auditing",
            "message": f"Auditing {len(req.authorities)} Content Provider authorities via IPC...",
            "progress": 80,
            "timestamp": datetime.now().isoformat(),
        })
        guard()
        _, prov_findings = await provider_auditor.audit_providers(serial, pkg, req.authorities, guard=guard)
        findings.extend(prov_findings)

    # Sandbox Storage Forensics (SharedPreferences, SQLite, Cache)
    if req.audit_storage:
        await manager.broadcast({
            "type": "dast_progress",
            "stage": "Sandbox Storage Forensics",
            "message": "Inspecting SharedPreferences, SQLite databases, and disk cache on device...",
            "progress": 85,
            "timestamp": datetime.now().isoformat(),
        })
        guard()
        storage_res = await storage_auditor.audit_all_storage(serial, pkg, guard=guard)
        for sf in storage_res.get("findings", []):
            findings.append(Finding(**sf))

    # Autonomous UI Crawling (if requested)
    if req.crawl_ui:
        await manager.broadcast({
            "type": "dast_progress",
            "stage": "Autonomous UI Crawling",
            "message": "Observing the intended package UI without taps or consent...",
            "progress": 90,
            "timestamp": datetime.now().isoformat(),
        })
        guard()
        crawl_res = await ui_crawler.crawl_app(serial, pkg, max_steps=5, guard=guard)
        await manager.broadcast({
            "type": "dast_progress",
            "stage": "UI Crawl Complete",
            "message": f"Explored {crawl_res.get('screens_explored', 0)} screens, dismissed {crawl_res.get('dialogs_dismissed', 0)} dialogs.",
            "progress": 92,
            "timestamp": datetime.now().isoformat(),
        })

    # Volatile Process Memory Forensics (if requested)
    if req.audit_memory:
        await manager.broadcast({
            "type": "dast_progress",
            "stage": "Volatile Memory Forensics",
            "message": "Auditing active process heap and RAM for lingering cleartext secrets (CWE-316)...",
            "progress": 95,
            "timestamp": datetime.now().isoformat(),
        })
        guard()
        mem_res = await memory_auditor.run_memory_audit(serial, pkg, guard=guard)
        for mf in mem_res.get("findings", []):
            findings.append(Finding(**mf))

    # Append to active findings
    guard()
    for f in findings:
        f_dict = redact(prepare_observation(f.to_dict()))
        remember_findings([f_dict])
        await manager.broadcast({
            "type": "dast_finding",
            "finding": f_dict,
            "message": f"Dynamic review candidate: {f.title}",
            "timestamp": datetime.now().isoformat(),
        })

    crashes = len([f for f in findings if f.cwe_id == "CWE-755"])
    leaks = len([f for f in findings if f.cwe_id in ("CWE-532", "CWE-312")])
    provs = len([f for f in findings if f.cwe_id in ("CWE-926", "CWE-89")])

    await manager.broadcast({
        "type": "dast_progress",
        "stage": "DAST Complete",
        "message": f"Dynamic diagnostics completed. Recorded {len(findings)} unverified candidates ({crashes} crash observations, {leaks} storage/log observations, {provs} IPC observations). Privileged device results are not ordinary-app exploit proof.",
        "progress": 100,
        "timestamp": datetime.now().isoformat(),
    })



@app.post("/api/dast/fuzz")
async def trigger_dast_fuzzer(req: DastFuzzRequest, background_tasks: BackgroundTasks, request: Request) -> dict[str, Any]:
    """Trigger dynamic activity intent fuzzing and crash monitoring."""
    if req.serial in DAST_JOBS or len(DAST_JOBS) >= 2:
        raise HTTPException(429, "Device job concurrency limit reached")
    DAST_JOBS.add(req.serial)
    token = request.state.authenticated_token
    async def bounded_job():
        try:
            await asyncio.wait_for(run_dast_background_task(req, token), timeout=180)
        except Exception as exc:
            await manager.broadcast({"type":"dast_progress", "stage":"DAST failed", "message":redact(str(exc)), "progress":100})
        finally:
            DAST_JOBS.discard(req.serial)
    background_tasks.add_task(bounded_job)
    return {
        "status": "initiated",
        "device": req.serial,
        "package_name": req.package_name,
        "message": f"DAST execution started on {req.serial}. Streaming on /ws/telemetry",
    }


@app.post("/api/upload/apk")
async def upload_apk(file: UploadFile = File(...)) -> dict[str, Any]:
    """Store a validated application archive using an exclusive opaque identifier."""
    filename = file.filename or "target.apk"
    if Path(filename).name != filename or "\\" in filename or filename in {".", ".."}:
        raise HTTPException(400, "Invalid upload filename")
    suffix = Path(filename).suffix.lower()
    if suffix not in {".apk", ".ipa", ".zip"}:
        raise HTTPException(400, "Only .apk, .ipa, or .zip application archives are supported.")
    existing = [p for p in UPLOAD_DIR.iterdir() if p.is_file()]
    if len(existing) >= 100 or sum(p.stat().st_size for p in existing) + MAX_UPLOAD > 1024 * 1024 * 1024:
        raise HTTPException(429, "Upload storage quota reached; archive or remove old uploads locally")
    target_path = UPLOAD_DIR / (uuid.uuid4().hex + suffix)
    total = 0
    try:
        with os.fdopen(os.open(target_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output:
            while chunk := await file.read(65536):
                total += len(chunk)
                if total > MAX_UPLOAD:
                    raise HTTPException(413, "Upload size limit exceeded")
                output.write(chunk)
        platform = await asyncio.to_thread(validate_archive, target_path)
    except Exception as exc:
        target_path.unlink(missing_ok=True)
        if isinstance(exc, HTTPException):
            raise
        raise HTTPException(400, str(exc))
    finally:
        await file.close()
    return {"status":"success", "filename":filename, "file_path":str(target_path.resolve()),
            "size_mb":round(total / (1024*1024),2), "platform":platform}


class RunScanRequest(BaseModel):
    apk_path: str
    output_dir: Optional[str] = None
    auto_dast: bool = False
    auto_taint: bool = True
    bypass_root: bool = False
    bypass_ssl: bool = False
    serial: Optional[str] = None


async def live_scan_telemetry_worker(scan_id: str, apk_name: str, req: Optional[RunScanRequest] = None) -> None:
    """Run real analysis and publish only canonical final results, never simulated findings."""
    scan = ACTIVE_SCANS[scan_id]
    try:
        if req is None:
            raise ValueError("Missing scan request")
        platform = await asyncio.to_thread(validate_archive, req.apk_path)
        setting_names = {"entropy_threshold", "enable_deep_taint", "enable_reachability_filter", "enable_consensus_voting", "offline"}
        effective = await asyncio.to_thread(effective_runtime_settings)
        updates = {k:v for k,v in effective.items() if k in setting_names}
        updates["enable_deep_taint"] = req.auto_taint and updates.get("enable_deep_taint", True)
        settings = get_settings().model_copy(update=updates)
        scan['analysis_policy'] = {**updates, 'approved_llm_providers': settings.approved_llm_providers}
        async def progress(stage, message, pct, finding=None):
            scan["progress"] = min(pct,99)
            scan.setdefault("events", []).append({"sequence":scan.get("event_sequence",0)+1,"stage":str(stage)[:256],"message":str(redact(message))[:1024],"progress":scan["progress"]})
            scan["event_sequence"] = scan["events"][-1]["sequence"]
            del scan["events"][:-100]
            await asyncio.to_thread(repository().save, scan)
            # Raw findings stay out of the final-results UI.
            await manager.broadcast({"type":"agent_progress", "scan_id":scan_id,
                                     "stage":stage, "message":message, "progress":scan["progress"]})
        # Web uploads are hostile parser inputs: never process them in the API process.
        # Cloud execution needs a credential broker, not network access in this worker.
        settings = settings.model_copy(update={'offline':True, 'approved_llm_providers':[]})
        scan['analysis_policy'].update(offline=True, approved_llm_providers=[], execution='isolated_offline')
        state = await isolated_analysis(req.apk_path, req.output_dir, scan_id, settings, progress)
        if state.get("errors"):
            scan["errors"] = ["Static analysis incomplete; review coverage and tool readiness"]
        scan["package_name"] = state.get("package_name", apk_name)
        scan["version"] = state.get("app_version") or state.get("manifest_data",{}).get("version_name")
        scan["execution_environment"] = state.get("execution_environment",{})
        scan["findings"] = redact(state.get("filtered_findings", []))
        for finding in scan["findings"]:
            finding["status"] = "UNVERIFIED"
        scan["components"] = state.get("components", [])
        scan["deep_links"] = state.get("deep_links", [])
        scan["api_endpoints"] = state.get("api_endpoints", [])
        scan["coverage"] = state.get("coverage", {})
        scan["framework"] = state.get("framework_info", {}).get("framework", platform)
        if req.auto_dast:
            if platform != "android" or not check_device(req.serial):
                raise ValueError("DAST requires an explicitly scoped Android device")
            if req.bypass_root or req.bypass_ssl:
                raise ValueError("Automatic bypass is unsupported; use the explicit Frida workbench and verify its result")
            activities = [c["name"] for c in scan["components"] if c.get("type") == "activity" and c.get("exported")]
            links = [d["uri"] for d in scan["deep_links"] if d.get("uri")]
            dynamic = await intent_fuzzer.run_full_dast_suite(serial=req.serial, package_name=scan["package_name"],
                apk_path=req.apk_path, activities=activities, deeplinks=links, audit_storage=False, audit_memory=False)
            if dynamic.get("status") != "completed":
                raise RuntimeError("DAST failed or incomplete")
            scan["findings"].extend(redact([prepare_observation(f) for f in dynamic.get("findings", [])]))
        scan["stats"] = {level:sum(f.get("severity", "").lower() == level for f in scan["findings"])
                         for level in ("critical","high","medium","low","info")}
        scan["stats"]["total"] = len(scan["findings"])

        # Dynamically build interactive Vis.js Attack Surface Graph
        nodes = [{"id": "app", "label": scan["package_name"] or apk_name, "group": "app", "shape": "dot", "size": 32, "color": "#0ea5e9"}]
        edges = []
        seen_nodes = {"app"}
        for c in (scan["components"] or [])[:15]:
            c_name = c.get("name", "Component")
            c_id = f"comp_{c_name}"
            if c_id not in seen_nodes:
                seen_nodes.add(c_id)
                nodes.append({
                    "id": c_id, "label": c_name.split(".")[-1], "group": "component",
                    "shape": "dot", "size": 18, "color": "#10b981" if not c.get("exported") else "#f59e0b"
                })
                edges.append({"from": "app", "to": c_id, "label": "component"})
        for ep in (scan["api_endpoints"] or [])[:15]:
            ep_url = ep.get("url") if isinstance(ep, dict) else getattr(ep, "url", str(ep))
            ep_id = f"api_{ep_url}"
            if ep_id not in seen_nodes:
                seen_nodes.add(ep_id)
                nodes.append({
                    "id": ep_id, "label": ep_url[:30], "group": "api",
                    "shape": "dot", "size": 16, "color": "#06b6d4"
                })
                edges.append({"from": "app", "to": ep_id, "label": "calls"})
        for f in (scan["findings"] or [])[:20]:
            f_id = f.get("id", str(id(f)))
            if f_id not in seen_nodes:
                seen_nodes.add(f_id)
                sev = f.get("severity", "MEDIUM").upper()
                f_color = "#ef4444" if sev in {"CRITICAL", "HIGH"} else "#f59e0b" if sev == "MEDIUM" else "#3b82f6"
                nodes.append({
                    "id": f_id, "label": (f.get("title") or "Finding")[:25], "group": "vulnerability",
                    "shape": "diamond", "size": 20, "color": f_color
                })
                edges.append({"from": "app", "to": f_id, "label": "has_vuln"})
        scan["attack_surface_graph"] = {"nodes": nodes, "edges": edges}

        from mobileag.reporting.report_engine import ReportEngine
        state.update(scan_id=scan_id, output_dir=str(Path(req.output_dir) / scan_id),
                     filtered_findings=scan["findings"], package_name=scan["package_name"])
        await ReportEngine().generate_reports(state)
        SARIFExporter.export_to_file(scan["findings"], Path(state["output_dir"]) / f"report_{scan_id}.sarif")
        scan["status"], scan["progress"] = ("partial" if scan.get("errors") and scan["findings"] else "error" if scan.get("errors") else "completed"), 100
    except Exception as exc:
        if isinstance(exc,TimeoutError):
            exc = RuntimeError("Worker wall-clock budget exceeded; retry after reviewing tool readiness")
        scan["status"], scan["progress"], scan["errors"] = ("cancelled" if scan_id in CANCELLED or "cancelled" in str(exc) else "error"), 100, ["Analysis incomplete: " + str(redact(str(exc)))[:512]]
    finally:
        # Transactional authoritative metadata; preserve an original final snapshot.
        await asyncio.to_thread(repository().save, scan)
        await asyncio.to_thread(private_write, OUTPUT_DIR / scan_id / 'dashboard.json', scan)
        await manager.broadcast({"type":"scan_complete", "scan_id":scan_id, "status":scan["status"], "progress":100})


@app.post("/api/scans/run")
async def trigger_scan(request: RunScanRequest, background_tasks: BackgroundTasks) -> dict[str, Any]:
    """Trigger a new asynchronous security scan with live WebSocket telemetry."""
    apk_file = Path(request.apk_path).resolve()
    if not apk_file.is_relative_to(UPLOAD_DIR.resolve()):
        raise HTTPException(400, "Select an archive uploaded to this dashboard")
    try:
        platform = await asyncio.to_thread(validate_archive, apk_file)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    if request.auto_dast:
        raise HTTPException(422, "Static jobs never execute device actions. Use explicitly scoped diagnostics after reviewing results")
    if request.auto_dast and (platform != "android" or not check_device(request.serial)):
        raise HTTPException(403, "DAST requires an explicit authorized Android device")
    if request.bypass_root or request.bypass_ssl:
        raise HTTPException(422, "Automatic bypass is unsupported; use explicit Frida validation")
    output = Path(request.output_dir or OUTPUT_DIR).resolve()
    if output != OUTPUT_DIR.resolve():
        raise HTTPException(400, "Web job outputs use the configured output directory only")
    request.output_dir = str(output)
    artifact_hash = await asyncio.to_thread(hash_file, apk_file)
    # Reservation below is synchronous until ACTIVE_SCANS insertion: no await
    # between capacity check and reservation in the supported single event loop.
    if sum(s.get("status") == "running" for s in ACTIVE_SCANS.values()) >= 2:
        raise HTTPException(429, "Scan concurrency limit reached")
    if len(ACTIVE_SCANS) >= 100:
        completed = next((k for k,v in ACTIVE_SCANS.items() if v.get("status") != "running"), None)
        if completed:
            del ACTIVE_SCANS[completed]
    scan_id = "scan_" + uuid.uuid4().hex
    
    scan_obj = {
        "scan_id": scan_id,
        "app_name": apk_file.stem,
        "package_name": None,
        "version": None,
        "revision": 0,
        "artifact_sha256": artifact_hash,
        "request": {"apk_path":str(apk_file), "auto_taint":request.auto_taint},
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "running",
        "progress": 5,
        "framework": "Not assessed",
        "obfuscation_level": "Assessing...",
        "stats": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
        "findings": [],
        "agent_telemetry": [],
        "api_endpoints": [],
        "components": [],
        "deep_links": [],
        "attack_surface_graph": {
            "nodes": [{"id": "app", "label": apk_file.stem, "group": "app", "shape": "dot", "size": 32, "color": "#0ea5e9"}],
            "edges": [],
        },
    }
    ACTIVE_SCANS[scan_id] = scan_obj
    await asyncio.to_thread(repository().save, scan_obj)

    # Launch live telemetry stream in background with full configuration
    background_tasks.add_task(live_scan_telemetry_worker, scan_id, apk_file.stem, request)

    return {
        "status": "initiated",
        "scan_id": scan_id,
        "auto_dast": request.auto_dast,
        "auto_taint": request.auto_taint,
        "bypass_root": request.bypass_root,
        "bypass_ssl": request.bypass_ssl,
        "message": f"Scan initiated for {apk_file.name}. Live telemetry active on /ws/telemetry",
    }


def hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as source:
        for chunk in iter(lambda: source.read(65536), b''):
            digest.update(chunk)
    return digest.hexdigest()



def automation_service():
    if not hasattr(app.state,'automation_service'):
        from mobileag.automation.engine import AutomationService
        from mobileag.automation.android import AndroidDriver
        app.state.automation_service=AutomationService(
            output=lambda:OUTPUT_DIR,policy=lambda:repository().get_policy(),
            session_valid=lambda token:time.monotonic()<app.state.session_deadline and authorized(token,app.state.auth_token),
            driver_factory=lambda serial,package:AndroidDriver(adb_manager,serial,package))
    return app.state.automation_service

from mobileag.automation.routes import build_router as build_automation_router
app.include_router(build_automation_router(automation_service,lambda request:request.state.authenticated_token))

def assessment_service():
    if not hasattr(app.state,'assessment_service'):
        from mobileag.assessments.service import AssessmentService
        from mobileag.llm.broker import LLMBroker
        async def static_runner(apk,linked):
            background=BackgroundTasks()
            result=await trigger_scan(RunScanRequest(apk_path=str(apk),auto_dast=False,auto_taint=True),background)
            await linked(result['scan_id'])
            await background()
            return repository().get(result['scan_id'])
        app.state.assessment_service=AssessmentService(lambda:OUTPUT_DIR,lambda:UPLOAD_DIR,repository,
            lambda token:time.monotonic()<app.state.session_deadline and authorized(token,app.state.auth_token),
            static_runner,automation_service,adb_manager,LLMBroker(),hash_file)
    return app.state.assessment_service

from mobileag.assessments.routes import build_router as build_assessment_router
app.include_router(build_assessment_router(assessment_service,lambda request:request.state.authenticated_token))


def run_server(host: str = "127.0.0.1", port: int = 8080) -> None:
    """Entrypoint to launch the web dashboard."""
    import uvicorn
    print(f"\n=======================================================")
    print(f"[*] Starting MobileAg Enterprise AppSec Dashboard")
    print(f"[*] Live WebSockets:  ws://{host}:{port}/ws/telemetry")
    print(f"[*] Neo4j Status:     {'Connected' if attack_graph._connected else 'Embedded Fallback'}")
    print(f"[*] Web Interface:    http://{host}:{port}")
    print(f"=======================================================\n")
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValueError("This release supports loopback only; remote/shared deployment requires a separate identity/TLS design")
    if not os.environ.get("MOBILEAG_API_TOKEN"):
        print(f"Session access token (paste into dashboard): {app.state.auth_token}")
    else:
        print("Using configured MOBILEAG_API_TOKEN; enter that local workbench access key.")
    app.state.token_announced=True
    uvicorn.run(app, host=host, port=port, log_level="info", ws_max_size=65536)


if __name__ == "__main__":
    run_server()
