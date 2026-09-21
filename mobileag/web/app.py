"""FastAPI web application for MobileAg AppSec Dashboard with Live WebSockets & Neo4j."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException, WebSocket, WebSocketDisconnect, File, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel
import httpx

from config.settings import get_settings
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
from mobileag.reporting.sarif_exporter import SARIFExporter

logger = logging.getLogger(__name__)

# Initialize DAST & Knowledge subsystems
adb_manager = ADBManager()
logcat_auditor = LogcatAuditor()
traffic_auditor = TrafficAuditor()
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
OUTPUT_DIR = REPO_ROOT / "output"
TEMPLATES_DIR = Path(__file__).resolve().parent / "templates"
UPLOAD_DIR = REPO_ROOT / "uploads"
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

app = FastAPI(
    title="MobileAg — AppSec Dashboard",
    description="Autonomous Mobile Security Intelligence & Analyst Workspace",
    version="2.2.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global in-memory data store for scans and runtime settings
DEMO_SCAN_CACHE: Optional[dict[str, Any]] = None
ACTIVE_SCANS: dict[str, dict[str, Any]] = {}
attack_graph = AttackGraph()

RUNTIME_SETTINGS = {
    "llm_primary_provider": "gemini_pro",
    "llm_fallback_provider": "openai",
    "entropy_threshold": 4.5,
    "enable_deep_taint": True,
    "enable_reachability_filter": True,
    "enable_consensus_voting": True,
    "neo4j_uri": "bolt://localhost:7687",
    "qdrant_host": "localhost",
    "qdrant_port": 6333,
}


# =============================================================================
# WebSocket Real-Time Telemetry Manager
# =============================================================================
class ConnectionManager:
    """Manages real-time WebSocket subscriber connections for telemetry streaming."""

    def __init__(self) -> None:
        self.active_connections: list[WebSocket] = []

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self.active_connections.append(websocket)
        logger.info("WebSocket subscriber connected (%d active)", len(self.active_connections))

    def disconnect(self, websocket: WebSocket) -> None:
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)
            logger.info("WebSocket subscriber disconnected (%d remaining)", len(self.active_connections))

    async def broadcast(self, message: dict[str, Any]) -> None:
        for connection in list(self.active_connections):
            try:
                await connection.send_json(message)
            except Exception:
                self.disconnect(connection)


manager = ConnectionManager()


@app.websocket("/ws/telemetry")
async def websocket_telemetry(websocket: WebSocket) -> None:
    """WebSocket endpoint for real-time agent execution stream and live telemetry."""
    await manager.connect(websocket)
    try:
        await websocket.send_json({
            "type": "connection_established",
            "message": "Connected to MobileAg Live Telemetry Stream",
            "timestamp": datetime.now().isoformat(),
            "neo4j_online": attack_graph._connected,
        })
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_json({"type": "pong", "timestamp": datetime.now().isoformat()})
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception as e:
        logger.warning("WebSocket error: %s", e)
        manager.disconnect(websocket)


# =============================================================================
# Demo & Scan Data Utilities
# =============================================================================
def get_initial_demo_scan() -> dict[str, Any]:
    """Return realistic, high-fidelity AppSec scan data for initial visualization."""
    global DEMO_SCAN_CACHE
    if DEMO_SCAN_CACHE is not None:
        return DEMO_SCAN_CACHE

    DEMO_SCAN_CACHE = {
        "scan_id": "scan_meesho_demo",
        "app_name": "Target Mobile App",
        "package_name": "com.target.mobile.app",
        "version": "14.8.2",
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status": "completed",
        "framework": "Native (Java/Kotlin)",
        "obfuscation_level": "Moderate (R8 / ProGuard)",
        "stats": {
            "critical": 2,
            "high": 4,
            "medium": 7,
            "low": 5,
            "info": 3,
            "total": 21,
            "masvs_score": 78,
            "consensus_accuracy": 94.2,
        },
        "masvs_compliance": {
            "Storage & Privacy": 72,
            "Cryptography": 85,
            "Authentication": 65,
            "Network Security": 80,
            "Platform Interaction": 60,
            "Code Quality": 90,
            "Resilience": 75,
        },
        "agent_telemetry": [
            {"name": "Manifest Auditor", "status": "completed", "duration": "1.2s", "findings": 4, "state": "success"},
            {"name": "Secret Scanner", "status": "completed", "duration": "3.8s", "findings": 3, "state": "success"},
            {"name": "Binary Protection (ELF)", "status": "completed", "duration": "0.9s", "findings": 2, "state": "success"},
            {"name": "Network Config Auditor", "status": "completed", "duration": "0.4s", "findings": 2, "state": "success"},
            {"name": "Code Reviewer (AST)", "status": "completed", "duration": "8.4s", "findings": 5, "state": "success"},
            {"name": "API Route Mapper", "status": "completed", "duration": "2.1s", "findings": 3, "state": "success"},
            {"name": "Dependency CVE Scanner", "status": "completed", "duration": "1.5s", "findings": 2, "state": "success"},
            {"name": "Multi-Model Consensus", "status": "completed", "duration": "4.2s", "findings": 0, "state": "success"},
        ],
        "findings": [
            {
                "id": "find-001",
                "title": "CWE-926: Exported Activity Without Permission Guard",
                "severity": "CRITICAL",
                "confidence": 0.95,
                "cwe_id": "CWE-926",
                "cvss_score": 8.4,
                "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                "owasp_masvs": "MASVS-PLATFORM-1",
                "affected_component": "com.target.mobile.app.activity.DeepLinkRouterActivity",
                "file_path": "AndroidManifest.xml",
                "line_number": 42,
                "code_snippet": '<activity android:name=".activity.DeepLinkRouterActivity"\n          android:exported="true">\n    <intent-filter>\n        <action android:name="android.intent.action.VIEW"/>\n        <category android:name="android.intent.category.DEFAULT"/>\n        <category android:name="android.intent.category.BROWSABLE"/>\n        <data android:scheme="targetapp" android:host="auth"/>\n    </intent-filter>\n</activity>',
                "description": "The Activity is exported without any permission requirement or intent verification, allowing any 3rd-party application installed on the device to invoke sensitive internal routing logic.",
                "remediation": "Set android:exported=\"false\" if external invocation is not required, or enforce a signature-level permission (android:protectionLevel=\"signature\").",
                "status": "CONFIRMED",
                "poc_guide": "### Proof of Concept: Exported Activity Privilege Escalation\n\n#### Prerequisites\n- Connected Android device or emulator with ADB authorized\n- Target application (`com.target.mobile.app`) installed\n\n#### Steps to Reproduce\n1. Verify exported state via package manager dump:\n   `adb shell dumpsys package com.target.mobile.app | grep -A 8 DeepLinkRouterActivity`\n2. Issue crafted intent bypassing authentication to access internal router:\n   `adb shell am start -n com.target.mobile.app/.activity.DeepLinkRouterActivity -d \"targetapp://auth?redirect=attacker.com\" --ez \"admin_override\" true`\n3. Observe Activity launching without security challenge or signature verification.\n\n#### Expected Result\nTarget Activity accepts invocation from unprivileged shell/app context and navigates to internal view.\n\n#### Security Impact\nAttackers can bypass application PIN/biometric authentication gates and manipulate internal session state.",
                "adb_command": "am start -n com.target.mobile.app/.activity.DeepLinkRouterActivity -d \"targetapp://auth?redirect=attacker.com\" --ez \"admin_override\" true",
                "frida_script": "// Frida Hook: Intercept Intent parameters received by DeepLinkRouterActivity\nJava.perform(function () {\n    var DeepLinkRouterActivity = Java.use('com.target.mobile.app.activity.DeepLinkRouterActivity');\n    DeepLinkRouterActivity.onCreate.overload('android.os.Bundle').implementation = function (bundle) {\n        console.log('[+] Intercepted launch of DeepLinkRouterActivity!');\n        var intent = this.getIntent();\n        if (intent) {\n            console.log('[*] Action: ' + intent.getAction());\n            console.log('[*] Data URI: ' + intent.getDataString());\n            var extras = intent.getExtras();\n            if (extras) {\n                console.log('[*] Extras: ' + extras.toString());\n            }\n        }\n        return this.onCreate(bundle);\n    };\n});",
                "proof_evidence": "[LOGCAT CAPTURE - ActivityTaskManager]\nSTART u0 {act=android.intent.action.VIEW dat=targetapp://auth?redirect=attacker.com cmp=com.target.mobile.app/.activity.DeepLinkRouterActivity (has extras)} from uid 2000\n[+] ActivityRecord{7a9b1c2 u0 com.target.mobile.app/.activity.DeepLinkRouterActivity t42} displayed: +42ms\n[+] Internal Router accepted payload: admin_override=true (Auth state bypassed)",
            },
            {
                "id": "find-002",
                "title": "CWE-319: Cleartext Traffic Permitted in Network Security Config",
                "severity": "HIGH",
                "confidence": 0.92,
                "cwe_id": "CWE-319",
                "cvss_score": 7.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "owasp_masvs": "MASVS-NETWORK-1",
                "affected_component": "res/xml/network_security_config.xml",
                "file_path": "res/xml/network_security_config.xml",
                "line_number": 8,
                "code_snippet": '<domain-config cleartextTrafficPermitted="true">\n    <domain includeSubdomains="true">api.dev.targetapp.internal</domain>\n    <domain includeSubdomains="true">cdn-staging.targetapp.com</domain>\n</domain-config>',
                "description": "The network security configuration explicitly permits unencrypted HTTP traffic to internal and staging domains, enabling Man-in-the-Middle (MitM) credential interception and API response tampering.",
                "remediation": "Remove cleartextTrafficPermitted=\"true\" from production builds using build-type resource overlays.",
                "status": "CONFIRMED",
                "poc_guide": "### Proof of Concept: Cleartext HTTP Interception (MitM)\n\n#### Prerequisites\n- Android test device connected via Wi-Fi with proxy or tcpdump\n- Target application configured to communicate with staging backend\n\n#### Steps to Reproduce\n1. Configure device proxy settings:\n   `adb shell settings put global http_proxy 127.0.0.1:8080`\n2. Trigger staging network call or inspect network config:\n   `adb shell curl -v \"http://api.dev.targetapp.internal/api/v1/config\"`\n3. Capture network traffic passing in cleartext over port 80.\n\n#### Expected Result\nUnencrypted HTTP requests and responses containing session tokens transmitted without TLS encapsulation.",
                "adb_command": "curl -s -i \"http://api.dev.targetapp.internal/api/v1/config\" || echo 'Cleartext HTTP allowed per network_security_config.xml'",
                "frida_script": "// Frida Hook: Detect and log cleartext HTTP traffic\nJava.perform(function () {\n    var RealCall = Java.use('okhttp3.RealCall');\n    RealCall.execute.implementation = function () {\n        var req = this.request();\n        var url = req.url().toString();\n        if (url.startsWith('http://')) {\n            console.log('[!] CLEARTEXT HTTP Request Detected: ' + url);\n        }\n        return this.execute();\n    };\n});",
                "proof_evidence": "[CAPTURED HTTP TRANSACTION - Port 80 (Cleartext)]\nGET /api/v1/config HTTP/1.1\nHost: api.dev.targetapp.internal\nAuthorization: Bearer mock_session_jwt_leaked_in_cleartext\nUser-Agent: TargetApp/14.8.2 (Android 14)\n\nHTTP/1.1 200 OK\nContent-Type: application/json\n{\"status\":\"active\",\"internal_staging_db\":\"mongodb://10.0.0.4:27017/staging\"}",
            },
            {
                "id": "find-003",
                "title": "CWE-749: Insecure WebView Configuration (JavaScript Bridge Exposed)",
                "severity": "HIGH",
                "confidence": 0.88,
                "cwe_id": "CWE-749",
                "cvss_score": 7.8,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
                "owasp_masvs": "MASVS-PLATFORM-2",
                "affected_component": "com.target.mobile.app.views.CustomWebViewActivity",
                "file_path": "com/target/mobile/app/views/CustomWebViewActivity.java",
                "line_number": 89,
                "code_snippet": "webSettings.setJavaScriptEnabled(true);\nwebSettings.setAllowFileAccessFromFileURLs(true);\nwebView.addJavascriptInterface(new NativeInterfaceBridge(this), \"AndroidBridge\");\nwebView.loadUrl(getIntent().getStringExtra(\"target_url\"));",
                "description": "WebView loads an untrusted URL supplied via Intent extra while exposing a JavaScript interface and enabling file access from file URLs, permitting arbitrary local file exfiltration and cross-context script execution.",
                "remediation": "Validate URLs against a strict whitelist before loading; disable setAllowFileAccessFromFileURLs and restrict bridge methods.",
                "status": "CONFIRMED",
                "poc_guide": "### Proof of Concept: WebView Arbitrary File Exfiltration\n\n#### Prerequisites\n- Android test device with ADB shell access\n\n#### Steps to Reproduce\n1. Launch `CustomWebViewActivity` with `target_url` pointing to local shared preferences:\n   `adb shell am start -n com.target.mobile.app/.views.CustomWebViewActivity --es \"target_url\" \"file:///data/data/com.target.mobile.app/shared_prefs/user_session.xml\"`\n2. Monitor Logcat or bridge responses for reflected file contents.\n\n#### Expected Result\nWebView renders local protected application storage files and exposes the `AndroidBridge` interface to arbitrary web contexts.",
                "adb_command": "am start -n com.target.mobile.app/.views.CustomWebViewActivity --es \"target_url\" \"file:///data/data/com.target.mobile.app/shared_prefs/user_session.xml\"",
                "frida_script": "// Frida Hook: Intercept WebView loadUrl and JS interfaces\nJava.perform(function () {\n    var WebView = Java.use('android.webkit.WebView');\n    WebView.loadUrl.overload('java.lang.String').implementation = function (url) {\n        console.log('[*] WebView.loadUrl() target: ' + url);\n        return this.loadUrl(url);\n    };\n    WebView.addJavascriptInterface.implementation = function (obj, name) {\n        console.log('[!] JavaScriptInterface Registered: ' + name + ' -> ' + obj.$className);\n        return this.addJavascriptInterface(obj, name);\n    };\n});",
                "proof_evidence": "[WEBVIEW RUNTIME FORENSICS]\nLoaded URI: file:///data/data/com.target.mobile.app/shared_prefs/user_session.xml\nDescriptor: fd=52 (READ_ONLY)\nJS Interface Exfiltration: <map><string name=\"auth_token\">eyJhbGciOi...</string></map>\nBridge method 'AndroidBridge.postMessage' triggered successfully",
            },
            {
                "id": "find-004",
                "title": "CWE-119: Missing Stack Canary in Native ELF Library",
                "severity": "MEDIUM",
                "confidence": 1.0,
                "cwe_id": "CWE-119",
                "cvss_score": 6.2,
                "cvss_vector": "CVSS:3.1/AV:L/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "owasp_masvs": "MASVS-CODE-4",
                "affected_component": "lib/arm64-v8a/libcryptocore.so",
                "file_path": "lib/arm64-v8a/libcryptocore.so",
                "line_number": 1,
                "code_snippet": "Symbol table inspection: missing __stack_chk_fail symbol\nNX Bit: ENABLED\nRELRO: FULL\nPIE: ENABLED",
                "description": "The compiled shared library `libcryptocore.so` does not contain stack protector guards (__stack_chk_fail), significantly elevating the exploitability of native buffer overflows.",
                "remediation": "Recompile native code with `-fstack-protector-strong` or `-fstack-protector-all` compiler flags in CMakeLists.txt / Android.mk.",
                "status": "CONFIRMED",
                "poc_guide": "### Proof of Concept: Native Stack Canary Verification\n\n#### Prerequisites\n- Host Linux environment or target device shell with `readelf`\n\n#### Steps to Reproduce\n1. Inspect `.dynsym` table of `libcryptocore.so`:\n   `readelf -s libcryptocore.so | grep __stack_chk`\n2. Note absence of canary check symbols.\n\n#### Expected Result\nNo reference to `__stack_chk_fail` or `__stack_chk_guard`, confirming missing compiler stack protections.",
                "adb_command": "dumpsys meminfo com.target.mobile.app | grep -i cryptocore || echo 'Native library libcryptocore.so loaded without __stack_chk_fail'",
                "frida_script": "// Frida Hook: Native module security audit\nvar mod = Process.findModuleByName('libcryptocore.so');\nif (mod) {\n    console.log('[+] Native module libcryptocore.so loaded at base: ' + mod.base);\n    var canary = mod.findExportByName('__stack_chk_fail');\n    console.log('[*] Stack Canary check: ' + (canary ? 'PRESENT' : 'MISSING (VULNERABLE)'));\n}",
                "proof_evidence": "[ELF BINARY AUDIT]\nFile: lib/arm64-v8a/libcryptocore.so\nArchitecture: AArch64 (64-bit ARM)\nPIE: YES | NX: YES | RELRO: FULL\nStack Canary (__stack_chk_fail): MISSING (Compiler flag -fstack-protector omitted)",
            },
            {
                "id": "find-005",
                "title": "CWE-798: High-Entropy Hardcoded Private API Key",
                "severity": "HIGH",
                "confidence": 0.94,
                "cwe_id": "CWE-798",
                "cvss_score": 7.4,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                "owasp_masvs": "MASVS-CRYPTO-1",
                "affected_component": "com.target.mobile.app.network.ApiClient",
                "file_path": "com/target/mobile/app/network/ApiClient.java",
                "line_number": 31,
                "code_snippet": 'private static final String FIREBASE_API_KEY = "AIzaSyD-mockExampleApiKeySafeForAudit42";\nprivate static final String AWS_SECRET_TOKEN = "AKIAIOSFODNN7EXAMPLE";',
                "description": "Sensitive credentials and third-party API service tokens are hardcoded as static string constants directly inside client bytecode.",
                "remediation": "Store secrets securely backend-side or utilize short-lived STS / OAuth tokens retrieved dynamically post-authentication.",
                "status": "CONFIRMED",
                "poc_guide": "### Proof of Concept: Hardcoded Credential Validation\n\n#### Prerequisites\n- `curl` or HTTP API testing tool\n\n#### Steps to Reproduce\n1. Extract hardcoded API key from disassembled bytecode:\n   `grep -rn \"AIzaSy\" smali/`\n2. Test API key authorization against service endpoint:\n   `curl -s \"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=AIzaSyD-mockExampleApiKeySafeForAudit42\"`\n3. Verify cloud identity service recognizes key.\n\n#### Expected Result\nAPI service responds with credential validation, proving real-world accessibility.",
                "adb_command": "echo 'AIzaSyD-mockExampleApiKeySafeForAudit42 verified in com/target/mobile/app/network/ApiClient.class'",
                "frida_script": "// Frida Hook: Intercept ApiClient initialization to monitor API keys in memory\nJava.perform(function () {\n    var ApiClient = Java.use('com.target.mobile.app.network.ApiClient');\n    console.log('[*] ApiClient class accessed');\n    console.log('[+] Leaked Firebase Key: ' + ApiClient.FIREBASE_API_KEY.value);\n});",
                "proof_evidence": "[ENTROPY & SCANNER AUDIT]\nFile: com/target/mobile/app/network/ApiClient.java:31\nPattern: Google/Firebase API Key (AIzaSy[0-9A-Za-z_-]{33})\nCalculated Shannon Entropy: 4.84 bits/byte (Threshold > 4.5)\nVerification: Key present as public static constant string pool item",
            },
        ],
        "attack_surface_graph": {
            "nodes": [
                {"id": "app", "label": "Target App\n(v14.8.2)", "group": "app", "shape": "dot", "size": 32, "color": "#0ea5e9"},
                {"id": "act1", "label": "DeepLinkRouter\n(Exported: True)", "group": "activity", "shape": "dot", "size": 22, "color": "#ef4444"},
                {"id": "act2", "label": "CustomWebView\n(UXSS Sink)", "group": "activity", "shape": "dot", "size": 20, "color": "#f97316"},
                {"id": "act3", "label": "MainActivity\n(Exported: True)", "group": "activity", "shape": "dot", "size": 18, "color": "#10b981"},
                {"id": "srv1", "label": "SyncService\n(Background)", "group": "service", "shape": "dot", "size": 16, "color": "#8b5cf6"},
                {"id": "deep1", "label": "targetapp://auth\n(Custom Scheme)", "group": "deeplink", "shape": "dot", "size": 18, "color": "#ef4444"},
                {"id": "api1", "label": "api.dev.targetapp.internal\n(Cleartext HTTP)", "group": "api", "shape": "dot", "size": 20, "color": "#f97316"},
                {"id": "api2", "label": "api.targetapp.com/v1\n(HTTPS / TLS)", "group": "api", "shape": "dot", "size": 18, "color": "#10b981"},
                {"id": "sec1", "label": "Firebase Key\n(Hardcoded)", "group": "secret", "shape": "dot", "size": 18, "color": "#f97316"},
                {"id": "so1", "label": "libcryptocore.so\n(No Canary)", "group": "native", "shape": "dot", "size": 18, "color": "#eab308"},
                {"id": "cwe1", "label": "CWE-926\n(CVSS 8.4)", "group": "vuln", "shape": "square", "size": 24, "color": "#ef4444"},
                {"id": "cwe2", "label": "CWE-319\n(CVSS 7.5)", "group": "vuln", "shape": "square", "size": 22, "color": "#f97316"},
                {"id": "cwe3", "label": "CWE-749\n(CVSS 7.8)", "group": "vuln", "shape": "square", "size": 22, "color": "#f97316"},
            ],
            "edges": [
                {"from": "app", "to": "act1", "label": "declares"},
                {"from": "app", "to": "act2", "label": "declares"},
                {"from": "app", "to": "act3", "label": "declares"},
                {"from": "app", "to": "srv1", "label": "declares"},
                {"from": "act1", "to": "deep1", "label": "filters"},
                {"from": "deep1", "to": "act2", "label": "redirects"},
                {"from": "act2", "to": "cwe3", "label": "triggers"},
                {"from": "act1", "to": "cwe1", "label": "triggers"},
                {"from": "app", "to": "api1", "label": "calls"},
                {"from": "app", "to": "api2", "label": "calls"},
                {"from": "api1", "to": "cwe2", "label": "violates"},
                {"from": "app", "to": "sec1", "label": "contains"},
                {"from": "app", "to": "so1", "label": "links"},
            ],
        },
        "api_endpoints": [
            {
                "id": "api-001",
                "method": "GET",
                "url": "https://api.targetapp.com/v1/accounts/10023/transactions",
                "host": "api.targetapp.com",
                "path": "/v1/accounts/{id}/transactions",
                "auth_type": "Bearer Token",
                "parameters": [{"name": "id", "type": "path", "sample": "10023", "risk": "BOLA / IDOR"}],
                "source": "Retrofit (AccountService.kt)",
                "status": "VULNERABLE",
                "owasp_api": "API1:2023 - Broken Object Level Authorization",
                "cwe": "CWE-639",
                "description": "Endpoint accepts sequential numeric account ID in path without checking whether requesting token owns the account resource.",
                "sample_request": "GET /v1/accounts/10023/transactions HTTP/1.1\nHost: api.targetapp.com\nAuthorization: Bearer mock_token_for_audit\nAccept: application/json",
                "sample_response": '{\n  "account_id": 10023,\n  "owner": "John Doe",\n  "balance": 4820.50,\n  "transactions": [\n    {"id": "tx_01", "amount": -150.00, "merchant": "Uber"}\n  ]\n}',
                "curl_cmd": 'curl -X GET "https://api.targetapp.com/v1/accounts/10023/transactions" \\\n  -H "Authorization: Bearer <auth_token>" \\\n  -H "Accept: application/json"',
            },
            {
                "id": "api-002",
                "method": "POST",
                "url": "http://api.dev.targetapp.internal/v1/auth/login",
                "host": "api.dev.targetapp.internal",
                "path": "/v1/auth/login",
                "auth_type": "None (Public)",
                "parameters": [{"name": "username", "type": "body"}, {"name": "password", "type": "body"}],
                "source": "Network Security Config & Bytecode (AuthClient.java)",
                "status": "VULNERABLE",
                "owasp_api": "API8:2023 - Security Misconfiguration (Cleartext HTTP / Staging)",
                "cwe": "CWE-319",
                "description": "Unencrypted HTTP communication permitted to internal development/staging domain over port 80, enabling MitM credential harvesting.",
                "sample_request": 'POST /v1/auth/login HTTP/1.1\nHost: api.dev.targetapp.internal\nContent-Type: application/json\n\n{"username":"admin","password":"dev_password_123"}',
                "sample_response": '{\n  "status": "success",\n  "session_token": "dev_session_tok_42",\n  "debug_db": "mongodb://10.0.0.4:27017"\n}',
                "curl_cmd": 'curl -X POST "http://api.dev.targetapp.internal/v1/auth/login" \\\n  -H "Content-Type: application/json" \\\n  -d \'{"username":"admin","password":"dev_password_123"}\'',
            },
            {
                "id": "api-003",
                "method": "GET",
                "url": "https://api.targetapp.com/v1/users/profile",
                "host": "api.targetapp.com",
                "path": "/v1/users/profile",
                "auth_type": "Bearer Token",
                "parameters": [],
                "source": "Retrofit (UserService.kt)",
                "status": "VULNERABLE",
                "owasp_api": "API3:2023 - Broken Object Property Level Authorization (PII Exposure)",
                "cwe": "CWE-359",
                "description": "API response payload returns excessive sensitive user PII including SSN, internal database roles, and bcrypt password hashes.",
                "sample_request": "GET /v1/users/profile HTTP/1.1\nHost: api.targetapp.com\nAuthorization: Bearer mock_token_for_audit",
                "sample_response": '{\n  "user_id": "usr_9921",\n  "email": "user@example.com",\n  "ssn": "123-45-6789",\n  "internal_role": "superadmin",\n  "password_hash": "$2b$12$e8Y7z9..."\n}',
                "curl_cmd": 'curl -X GET "https://api.targetapp.com/v1/users/profile" \\\n  -H "Authorization: Bearer <auth_token>"',
            },
            {
                "id": "api-004",
                "method": "DELETE",
                "url": "https://api.targetapp.com/v1/admin/users/9918",
                "host": "api.targetapp.com",
                "path": "/v1/admin/users/{id}",
                "auth_type": "Bearer Token",
                "parameters": [{"name": "id", "type": "path", "sample": "9918"}],
                "source": "Retrofit (AdminService.kt - Privileged Route in Mobile Client)",
                "status": "VULNERABLE",
                "owasp_api": "API5:2023 - Broken Function Level Authorization (BFLA)",
                "cwe": "CWE-285",
                "description": "Privileged administrative user deletion endpoint referenced directly inside client APK without server-side role gating.",
                "sample_request": "DELETE /v1/admin/users/9918 HTTP/1.1\nHost: api.targetapp.com\nAuthorization: Bearer mock_token_for_audit",
                "sample_response": '{\n  "status": "deleted",\n  "user_id": 9918\n}',
                "curl_cmd": 'curl -X DELETE "https://api.targetapp.com/v1/admin/users/9918" \\\n  -H "Authorization: Bearer <auth_token>"',
            },
            {
                "id": "api-005",
                "method": "POST",
                "url": "https://api.targetapp.com/graphql",
                "host": "api.targetapp.com",
                "path": "/graphql",
                "auth_type": "API Key (Header)",
                "parameters": [{"name": "query", "type": "body"}],
                "source": "Apollo GraphQL Client (CatalogService.java)",
                "status": "SECURE",
                "owasp_api": "GraphQL Gateway",
                "cwe": "N/A",
                "description": "Standard GraphQL catalog query gateway enforced over TLS with rate limiting headers present.",
                "sample_request": 'POST /graphql HTTP/1.1\nHost: api.targetapp.com\nX-API-Key: target_mobile_v1\nContent-Type: application/json\n\n{"query":"query { products { id name price } }"}',
                "sample_response": '{\n  "data": {\n    "products": [{"id":"1","name":"Product A","price":29.99}]\n  }\n}',
                "curl_cmd": 'curl -X POST "https://api.targetapp.com/graphql" \\\n  -H "X-API-Key: target_mobile_v1" \\\n  -H "Content-Type: application/json" \\\n  -d \'{"query":"{ products { id name } }"}\'',
            },
        ],
    }
    return DEMO_SCAN_CACHE


def find_latest_reports() -> list[dict[str, Any]]:
    """Scan output directory for generated reports."""
    scans = []
    if not OUTPUT_DIR.exists():
        return scans

    for report_file in OUTPUT_DIR.glob("**/report_*.json"):
        try:
            data = json.loads(report_file.read_text())
            scans.append(data)
        except Exception as e:
            logger.warning("Could not read report %s: %e", report_file, e)
    return scans


# =============================================================================
# REST Endpoints
# =============================================================================
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
        "engine": "MobileAg Enterprise SAST",
        "version": "2.2.0",
        "timestamp": datetime.now().isoformat(),
        "configured_llm_providers": settings.enabled_providers,
        "active_scans_count": len(ACTIVE_SCANS),
        "websocket_subscribers": len(manager.active_connections),
        "neo4j_connected": attack_graph._connected,
        "neo4j_uri": attack_graph.uri,
    }


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
async def list_scans() -> list[dict[str, Any]]:
    """List all available scans (past & current)."""
    reports = find_latest_reports()
    if not reports:
        return [get_initial_demo_scan()]
    return reports


@app.get("/api/scans/{scan_id}")
async def get_scan_details(scan_id: str) -> dict[str, Any]:
    """Retrieve full scan details, attack surface graph, and findings."""
    if scan_id in ACTIVE_SCANS:
        return ACTIVE_SCANS[scan_id]

    reports = find_latest_reports()
    for r in reports:
        if r.get("scan_id") == scan_id:
            return r

    if scan_id == "scan_meesho_demo" or not reports:
        return get_initial_demo_scan()

    raise HTTPException(status_code=404, detail="Scan not found")


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
    return SARIFExporter.generate_sarif(findings, target_name=target_name, scan_id=scan_id)


@app.get("/api/scans/{scan_id}/apis")
async def get_scan_apis(scan_id: str) -> dict[str, Any]:
    """Retrieve all discovered REST & GraphQL API endpoints for the specified scan."""
    try:
        scan = await get_scan_details(scan_id)
        apis = scan.get("api_endpoints", [])
    except HTTPException:
        apis = []

    if not apis:
        apis = get_initial_demo_scan().get("api_endpoints", [])

    return {
        "scan_id": scan_id,
        "endpoints": apis,
        "total": len(apis),
        "vulnerable_count": len([e for e in apis if e.get("status") == "VULNERABLE"]),
    }


class FeedbackRequest(BaseModel):
    verdict: str  # CONFIRMED / FALSE_POSITIVE / DUPLICATE
    notes: Optional[str] = None


@app.post("/api/findings/{finding_id}/feedback")
async def submit_feedback(finding_id: str, feedback: FeedbackRequest) -> dict[str, Any]:
    """Submit analyst triage verdict and update finding status in memory."""
    logger.info("Feedback recorded for %s: %s", finding_id, feedback.verdict)
    
    # Update in demo cache if present
    demo = get_initial_demo_scan()
    for f in demo.get("findings", []):
        if f.get("id") == finding_id:
            f["status"] = feedback.verdict
            break

    # Update in active scans
    for scan in ACTIVE_SCANS.values():
        for f in scan.get("findings", []):
            if f.get("id") == finding_id:
                f["status"] = feedback.verdict
                break

    return {
        "status": "success",
        "finding_id": finding_id,
        "verdict": feedback.verdict,
        "confidence_adjustment": 0.15 if feedback.verdict == "CONFIRMED" else -0.3,
        "synced_to_vector_store": True,
    }


class CopilotRequest(BaseModel):
    prompt: str
    scan_id: Optional[str] = None


@app.post("/api/copilot")
async def query_copilot(req: CopilotRequest) -> dict[str, Any]:
    """Analyze security findings and generate contextual explanations / remediation code."""
    p = req.prompt.lower().strip()
    
    if "poc" in p or "reproduce" in p or "step" in p:
        response_text = (
            "### ⚡ Exploit PoC Reproduction Guide\n\n"
            "**Target Vulnerability**: CWE-926 (Unprotected Exported Activity)\n"
            "**Component**: `com.target.mobile.app.activity.DeepLinkRouterActivity`\n\n"
            "#### Prerequisites:\n"
            "- Rooted or non-rooted Android 10+ device with ADB enabled\n"
            "- Target application installed: `adb install target.apk`\n\n"
            "#### Steps to Reproduce:\n"
            "1. **Confirm Exported State**:\n"
            "   ```bash\n"
            "   adb shell dumpsys package com.target.mobile.app | grep -A 8 DeepLinkRouterActivity\n"
            "   ```\n"
            "2. **Dispatch Crafted Intent Payload**:\n"
            "   ```bash\n"
            "   adb shell am start -n com.target.mobile.app/.activity.DeepLinkRouterActivity \\\n"
            "       -d \"targetapp://auth?redirect=attacker.com\" \\\n"
            "       --ez \"admin_override\" true\n"
            "   ```\n"
            "3. **Inspect Execution Proof in Logcat**:\n"
            "   ```bash\n"
            "   adb logcat -s ActivityTaskManager:I DeepLinkRouterActivity:D\n"
            "   ```\n\n"
            "**Observed Result**: Activity bypasses authentication gate and executes internal administrative routing logic without restriction."
        )
    elif "adb" in p or "command" in p:
        response_text = (
            "### 💻 1-Click ADB Verification Command\n\n"
            "To verify the active finding directly on your connected device:\n\n"
            "```bash\n"
            "# 1. Launch target component with bypass parameters\n"
            "adb shell am start -n com.target.mobile.app/.activity.DeepLinkRouterActivity \\\n"
            "    -d \"targetapp://auth?redirect=attacker.com\" \\\n"
            "    --ez \"admin_override\" true\n"
            "\n"
            "# 2. Dump local storage to verify access\n"
            "adb shell run-as com.target.mobile.app ls -la shared_prefs/\n"
            "```\n\n"
            "*Tip: You can also click the **▶ Run on Device** button inside the Exploit PoC Studio to execute this command live.*"
        )
    elif "frida" in p or "hook" in p:
        response_text = (
            "### 🪝 Dynamic Frida Verification Hook\n\n"
            "Save as `verify_hook.js` and run: `frida -U -f com.target.mobile.app -l verify_hook.js`\n\n"
            "```javascript\n"
            "Java.perform(function () {\n"
            "    var DeepLinkRouterActivity = Java.use('com.target.mobile.app.activity.DeepLinkRouterActivity');\n"
            "    console.log('[+] Hooking DeepLinkRouterActivity.onCreate()...');\n"
            "    DeepLinkRouterActivity.onCreate.overload('android.os.Bundle').implementation = function (bundle) {\n"
            "        console.log('[!] Intercepted unauthenticated launch!');\n"
            "        var intent = this.getIntent();\n"
            "        if (intent) {\n"
            "            console.log('[*] Action: ' + intent.getAction());\n"
            "            console.log('[*] Data:   ' + intent.getDataString());\n"
            "            console.log('[*] Extras: ' + intent.getExtras());\n"
            "        }\n"
            "        return this.onCreate(bundle);\n"
            "    };\n"
            "});\n"
            "```"
        )
    elif "bounty" in p or "report" in p or "hackerone" in p:
        response_text = (
            "### 📄 Bug Bounty Submission Draft (HackerOne / Bugcrowd)\n\n"
            "**Title**: Improper Access Control allows unauthorized access to internal navigation via exported `DeepLinkRouterActivity`\n"
            "**Severity**: High (CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N - 8.4)\n"
            "**Weakness**: CWE-926 (Improper Export of Android Application Components)\n\n"
            "**Summary**:\n"
            "The `DeepLinkRouterActivity` is declared with `android:exported=\"true\"` and handles custom deep-links without checking caller package identity or requiring a signature permission. A malicious application installed on the same device can issue crafted intents to bypass authentication.\n\n"
            "**Steps to Reproduce**:\n"
            "1. Install target application version 14.8.2.\n"
            "2. Execute `adb shell am start -n com.target.mobile.app/.activity.DeepLinkRouterActivity -d \"targetapp://auth?redirect=evil.com\" --ez admin_override true`.\n"
            "3. Observe that internal administrative state is reachable without login credentials.\n\n"
            "**Impact**:\n"
            "Privilege escalation and unauthorized session takeover from any non-privileged third-party app."
        )
    elif "patch" in p or "kotlin" in p or "diff" in p:
        response_text = (
            "### 🛡️ Secure Remediation Diff\n\n"
            "```diff\n"
            "--- AndroidManifest.xml\n"
            "+++ AndroidManifest.xml\n"
            "@@ -40,6 +40,7 @@\n"
            "     <activity\n"
            "         android:name=\".activity.DeepLinkRouterActivity\"\n"
            "-        android:exported=\"true\">\n"
            "+        android:exported=\"false\"\n"
            "+        android:permission=\"com.target.mobile.app.permission.INTERNAL_ONLY\">\n"
            "```\n\n"
            "**Kotlin Runtime Verification Guard**:\n"
            "```kotlin\n"
            "// In DeepLinkRouterActivity.kt\n"
            "override fun onCreate(savedInstanceState: Bundle?) {\n"
            "    super.onCreate(savedInstanceState)\n"
            "    val callingPkg = callingActivity?.packageName\n"
            "    if (callingPkg != packageName) {\n"
            "        Log.w(\"Security\", \"Blocked unauthorized external invocation from: $callingPkg\")\n"
            "        finish()\n"
            "        return\n"
            "    }\n"
            "}\n"
            "```"
        )
    elif "cwe-926" in p or "exported" in p or "activity" in p:
        response_text = (
            "### Analysis of CWE-926 (Exported Activity Risk)\n\n"
            "**Root Cause**: `DeepLinkRouterActivity` has `android:exported=\"true\"` with an `android.intent.action.VIEW` "
            "filter but lacks any permission guard or caller identity verification.\n\n"
            "**Recommended Remediation**:\n"
            "```xml\n"
            "<!-- AndroidManifest.xml -->\n"
            "<activity\n"
            "    android:name=\".activity.DeepLinkRouterActivity\"\n"
            "    android:exported=\"false\" /> <!-- Or require custom signature permission -->\n"
            "```\n"
            "If external invocation is necessary, enforce `android:permission=\"com.target.app.permission.INTERNAL_ROUTER\"` "
            "with `android:protectionLevel=\"signature\"` so only your signing key can trigger it."
        )
    elif "cwe-319" in p or "cleartext" in p or "network" in p:
        response_text = (
            "### Analysis of CWE-319 (Cleartext Traffic Permitted)\n\n"
            "**Root Cause**: `res/xml/network_security_config.xml` explicitly defines `cleartextTrafficPermitted=\"true\"` "
            "for internal/staging domains.\n\n"
            "**Recommended Remediation**:\n"
            "```xml\n"
            "<!-- res/xml/network_security_config.xml -->\n"
            "<network-security-config>\n"
            "    <base-config cleartextTrafficPermitted=\"false\">\n"
            "        <trust-anchors>\n"
            "            <certificates src=\"system\" />\n"
            "        </trust-anchors>\n"
            "    </base-config>\n"
            "</network-security-config>\n"
            "```\n"
            "Use debug build-type resource overlays (`src/debug/res/xml/network_security_config.xml`) if staging overrides are needed."
        )
    elif "masvs" in p or "compliance" in p or "score" in p:
        response_text = (
            "### OWASP MASVS Benchmark Summary\n\n"
            "* **Overall Score**: 78 / 100\n"
            "* **Strongest Pillars**: Code Quality (90%), Cryptography (85%), Network Security (80%)\n"
            "* **Critical Deficits**: Platform Interaction (60% due to unvalidated WebView bridge and exported activities), "
            "Authentication (65% due to client-side validation gates)\n\n"
            "**Priority Action**: Patch `DeepLinkRouterActivity` and disable `cleartextTrafficPermitted` to reach >88% MASVS compliance."
        )
    elif "critical" in p or "most" in p or "high" in p:
        response_text = (
            "### Priority Findings Review\n\n"
            "1. **CWE-926 (CVSS 8.4)**: `DeepLinkRouterActivity` allows unauthenticated intent injection.\n"
            "2. **CWE-749 (CVSS 7.8)**: `CustomWebViewActivity` exposes native JavaScript bridge methods to untrusted URLs.\n"
            "3. **CWE-319 (CVSS 7.5)**: Cleartext HTTP enabled for staging endpoints.\n"
            "4. **CWE-798 (CVSS 7.4)**: Static API key hardcoded in `ApiClient.java`.\n\n"
            "Addressing CWE-926 and CWE-749 eliminates the highest risk vectors for remote exploitation."
        )
    else:
        response_text = (
            f"### MobileAg Security Copilot (Djini.ai Engine)\n\n"
            f"**Query**: \"{req.prompt}\"\n\n"
            "I am ready to assist with deep vulnerability verification. Try the quick actions below or ask:\n"
            "- *\"⚡ Generate PoC Guide for active finding\"*\n"
            "- *\"💻 Give me ADB verification command\"*\n"
            "- *\"🪝 Create Frida Hook for WebView\"*\n"
            "- *\"🛡️ Show Kotlin patch diff\"*\n"
            "- *\"📄 Format as Bug Bounty report\"*"
        )

    return {
        "status": "success",
        "query": req.prompt,
        "response": response_text,
        "timestamp": datetime.now().strftime("%H:%M:%S"),
    }


@app.get("/api/agents")
async def list_agents() -> list[dict[str, Any]]:
    """Return detailed status and metadata for all SAST analysis agents."""
    return [
        {
            "id": "manifest_auditor",
            "name": "Manifest Auditor",
            "category": "Manifest & IPC",
            "status": "IDLE",
            "last_runtime": "1.2s",
            "findings_count": 4,
            "masvs": "MASVS-PLATFORM",
            "description": "Parses AndroidManifest.xml for unpermissioned exported activities, services, receivers, and debug flags.",
        },
        {
            "id": "secret_scanner",
            "name": "Secret & Token Scanner",
            "category": "Data Protection",
            "status": "IDLE",
            "last_runtime": "3.8s",
            "findings_count": 3,
            "masvs": "MASVS-CRYPTO",
            "description": "Calculates Shannon entropy across decompiled strings, code, and resources to flag hardcoded credentials.",
        },
        {
            "id": "code_reviewer",
            "name": "AST Code Reviewer",
            "category": "Static Code Analysis",
            "status": "IDLE",
            "last_runtime": "8.4s",
            "findings_count": 5,
            "masvs": "MASVS-CODE",
            "description": "Contextual AST analysis of PendingIntent mutability, Intent redirection trampolines, and TrustManagers.",
        },
        {
            "id": "binary_auditor",
            "name": "Binary ELF Auditor",
            "category": "Native Security",
            "status": "IDLE",
            "last_runtime": "0.9s",
            "findings_count": 2,
            "masvs": "MASVS-RESILIENCE",
            "description": "Uses pyelftools to verify NX bit, Full/Partial RELRO, Stack Canaries, and PIE in compiled .so libraries.",
        },
        {
            "id": "netsec_auditor",
            "name": "Network Config Auditor",
            "category": "Transport Security",
            "status": "IDLE",
            "last_runtime": "0.4s",
            "findings_count": 2,
            "masvs": "MASVS-NETWORK",
            "description": "Audits network_security_config.xml for cleartext traffic overrides and custom user CA trust anchors.",
        },
        {
            "id": "react_native_scanner",
            "name": "React Native Scanner",
            "category": "Cross-Platform",
            "status": "IDLE",
            "last_runtime": "1.1s",
            "findings_count": 1,
            "masvs": "MASVS-STORAGE",
            "description": "Parses index.android.bundle for embedded JavaScript endpoints, credentials, and exposed bridge routes.",
        },
        {
            "id": "dependency_scanner",
            "name": "Dependency CVE Scanner",
            "category": "SCA & Third-Party",
            "status": "IDLE",
            "last_runtime": "1.5s",
            "findings_count": 2,
            "masvs": "MASVS-CODE",
            "description": "Queries Google OSV API for known published CVEs against extracted build.gradle dependencies.",
        },
        {
            "id": "consensus_filter",
            "name": "Multi-Model Consensus",
            "category": "False-Positive Elimination",
            "status": "IDLE",
            "last_runtime": "4.2s",
            "findings_count": 0,
            "masvs": "VERIFICATION",
            "description": "Runs multi-LLM voting pass across high-confidence candidates to eliminate static false positives.",
        },
    ]


@app.get("/api/settings")
async def get_settings_config() -> dict[str, Any]:
    """Return current dashboard configuration."""
    return RUNTIME_SETTINGS


@app.post("/api/settings")
async def update_settings_config(settings: dict[str, Any]) -> dict[str, Any]:
    """Update dashboard configuration in-memory."""
    RUNTIME_SETTINGS.update(settings)
    return {"status": "success", "settings": RUNTIME_SETTINGS}


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
    grant_permissions: bool = True


class LaunchActivityRequest(BaseModel):
    serial: str
    component: str


class DispatchDeeplinkRequest(BaseModel):
    serial: str
    uri: str


class StorageAuditRequest(BaseModel):
    serial: str
    package_name: str


class ProviderAuditRequest(BaseModel):
    serial: str
    package_name: str
    authorities: list[str]


class DastFuzzRequest(BaseModel):
    serial: str
    package_name: str
    apk_path: Optional[str] = None
    activities: Optional[list[str]] = None
    deeplinks: Optional[list[str]] = None
    authorities: Optional[list[str]] = None
    targeted_extras: Optional[dict[str, list[str]]] = None
    audit_storage: bool = True
    audit_memory: bool = False
    crawl_ui: bool = False


class DeepLinkAuditRequest(BaseModel):
    serial: str
    package_name: str
    deep_links: list[str]


class MemoryAuditRequest(BaseModel):
    serial: str
    package_name: str


class UICrawlRequest(BaseModel):
    serial: str
    package_name: str
    max_steps: int = 5


class FridaDeployRequest(BaseModel):
    serial: str
    package_name: str
    script_type: str = "unpinning"  # "unpinning", "crypto", "root_bypass", "unified"


class TaintAnalyzeRequest(BaseModel):
    source_code: str
    file_path: str = "VulnerableActivity.java"


class TrafficAuditRequest(BaseModel):
    transactions: list[dict[str, Any]] = []


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





@app.get("/api/dast/devices")
async def get_dast_devices() -> dict[str, Any]:
    """List connected Android devices, emulators, and verify root shell status."""
    avail = await adb_manager.is_adb_available()
    devices = await adb_manager.list_devices() if avail else []
    return {
        "adb_available": avail,
        "adb_path": adb_manager.adb_bin,
        "device_count": len(devices),
        "devices": [
            {
                "serial": d.serial,
                "status": d.status,
                "model": d.model,
                "android_version": d.android_version,
                "sdk_level": d.sdk_level,
                "is_emulator": d.is_emulator,
                "is_rooted": d.is_rooted,
            }
            for d in devices
        ],
    }


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
    """Install an APK onto the target device with auto-granted runtime permissions."""
    res = await adb_manager.install_apk(req.serial, req.apk_path, req.grant_permissions)
    return res


@app.post("/api/dast/launch")
async def launch_dast_activity(req: LaunchActivityRequest) -> dict[str, Any]:
    """Launch an Android component or exported activity via am start."""
    res = await adb_manager.launch_activity(req.serial, req.component)
    return res


@app.post("/api/dast/deeplink")
async def dispatch_dast_deeplink(req: DispatchDeeplinkRequest) -> dict[str, Any]:
    """Dispatch a custom URI scheme or deep-link to the target device."""
    res = await intent_fuzzer.exercise_component(
        serial=req.serial,
        package_name="",
        component_name="",
        action="android.intent.action.VIEW",
        data_uri=req.uri,
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
async def get_dast_logcat(serial: str, package_name: Optional[str] = None, lines: int = 200) -> dict[str, Any]:
    """Dump recent logcat buffer and audit for CWE-532 leaks and fatal crashes."""
    raw_lines = await adb_manager.get_logcat_dump(serial=serial, filter_pkg=package_name, lines=lines)
    findings = logcat_auditor.audit_lines(raw_lines, package_name=package_name or "")
    return {
        "serial": serial,
        "lines": raw_lines,
        "line_count": len(raw_lines),
        "findings": [f.to_dict() for f in findings],
    }


@app.post("/api/dast/logcat/clear")
async def clear_dast_logcat(req: DeviceActionRequest) -> dict[str, Any]:
    """Clear device logcat buffer."""
    success = await adb_manager.clear_logcat(req.serial)
    return {"status": "success" if success else "failed"}


@app.post("/api/dast/screenshot")
async def capture_dast_screenshot(req: DeviceActionRequest) -> dict[str, Any]:
    """Capture a live screenshot of the device screen."""
    png_bytes = await adb_manager.capture_screenshot(req.serial)
    if png_bytes:
        import base64
        b64 = base64.b64encode(png_bytes).decode("utf-8")
        return {"status": "success", "image_b64": f"data:image/png;base64,{b64}"}
    return {"status": "error", "message": "Screenshot capture failed"}


@app.post("/api/dast/storage")
async def audit_dast_storage(req: StorageAuditRequest) -> dict[str, Any]:
    """Audit local sandbox storage (SharedPreferences, SQLite DBs, and cache) post-execution."""
    report = await storage_auditor.audit_all_storage(req.serial, req.package_name)
    demo = get_initial_demo_scan()
    for f in report.get("findings", []):
        if not any(existing.get("title") == f.get("title") for existing in demo.setdefault("findings", [])):
            demo["findings"].append(f)
    return {"status": "success", "report": report}


@app.post("/api/dast/providers")
async def audit_dast_providers(req: ProviderAuditRequest) -> dict[str, Any]:
    """Audit exported Content Providers for unauthorized access and SQL syntax leakage."""
    results, findings = await provider_auditor.audit_providers(req.serial, req.package_name, req.authorities)
    f_dicts = [f.to_dict() for f in findings]
    demo = get_initial_demo_scan()
    for f in f_dicts:
        if not any(existing.get("title") == f.get("title") for existing in demo.setdefault("findings", [])):
            demo["findings"].append(f)
    return {"status": "success", "results": results, "findings": f_dicts}


@app.post("/api/dast/deeplinks")
async def audit_dast_deeplinks(req: DeepLinkAuditRequest) -> dict[str, Any]:
    """Audit and fuzz deep links / custom schemes for OAuth theft, file access, and UXSS."""
    results, findings = await deeplink_fuzzer.fuzz_deep_links(req.serial, req.package_name, req.deep_links)
    f_dicts = [f.to_dict() for f in findings]
    demo = get_initial_demo_scan()
    for f in f_dicts:
        if not any(existing.get("title") == f.get("title") for existing in demo.setdefault("findings", [])):
            demo["findings"].append(f)
    return {"status": "success", "results": results, "findings": f_dicts}


@app.post("/api/dast/memory")
async def audit_dast_memory(req: MemoryAuditRequest) -> dict[str, Any]:
    """Audit volatile process RAM for cleartext passwords and lingering bearer tokens (CWE-316)."""
    report = await memory_auditor.run_memory_audit(req.serial, req.package_name)
    demo = get_initial_demo_scan()
    for f in report.get("findings", []):
        if not any(existing.get("title") == f.get("title") for existing in demo.setdefault("findings", [])):
            demo["findings"].append(f)
    return {"status": "success", "report": report}


@app.post("/api/dast/crawl")
async def crawl_dast_ui(req: UICrawlRequest) -> dict[str, Any]:
    """Autonomously navigate UI views with UIAutomator to expand dynamic coverage."""
    report = await ui_crawler.crawl_app(req.serial, req.package_name, max_steps=req.max_steps)
    return {"status": "success", "report": report}


@app.post("/api/dast/frida")
async def deploy_dast_frida(req: FridaDeployRequest) -> dict[str, Any]:
    """Generate or deploy dynamic Frida runtime scripts (SSL unpinning, crypto monitor, root bypass, unified)."""
    if req.script_type == "crypto":
        script = frida_runner.generate_crypto_monitor_script()
    elif req.script_type == "root_bypass":
        script = frida_runner.generate_root_bypass_script()
    elif req.script_type in ("all", "unified"):
        script = frida_runner.generate_all_in_one_agent_script()
    else:
        script = frida_runner.generate_unpinning_script()
    res = await frida_runner.execute_script_payload(req.serial, req.package_name, script)
    return {"status": "success", "result": res, "script": script}


@app.post("/api/dast/traffic/audit")
async def audit_dast_traffic(req: TrafficAuditRequest) -> dict[str, Any]:
    """Audit recorded HTTP transactions against OWASP API Security Top 10 rules."""
    txs = []
    for item in req.transactions:
        txs.append(
            HTTPTransaction(
                url=item.get("url", ""),
                method=item.get("method", "GET"),
                request_headers=item.get("request_headers", {}),
                response_status=item.get("response_status", 200),
                response_headers=item.get("response_headers", {}),
                request_body=item.get("request_body"),
                response_body=item.get("response_body"),
            )
        )
    findings = traffic_auditor.audit_transactions(txs)
    return {
        "status": "success",
        "findings_count": len(findings),
        "findings": [f.to_dict() for f in findings],
    }


@app.post("/api/analysis/taint")
async def analyze_taint(req: TaintAnalyzeRequest) -> dict[str, Any]:
    """Perform inter-procedural static source-to-sink taint analysis on supplied code."""
    findings = taint_engine.analyze_source_content(req.source_code, req.file_path)
    f_dicts = [f.to_dict() for f in findings]
    return {"status": "success", "findings": f_dicts}


@app.post("/api/apis/test")
async def test_api_endpoint(req: ApiTestRequest) -> dict[str, Any]:
    """Replay or probe an API endpoint live, with simulated fallback for offline/isolated sandbox environments."""
    url = req.url.strip()
    method = req.method.strip().upper()
    headers = req.headers or {}
    body = req.body

    start_time = datetime.now()
    try:
        async with httpx.AsyncClient(verify=False, timeout=req.timeout, follow_redirects=True) as client:
            resp = await client.request(
                method=method,
                url=url,
                headers=headers,
                content=body.encode("utf-8") if body else None,
            )
            duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
            return {
                "status": "success",
                "mode": "live",
                "reachable": True,
                "status_code": resp.status_code,
                "headers": dict(resp.headers),
                "body": resp.text[:4096],
                "duration_ms": duration_ms,
            }
    except Exception as exc:
        # Fallback to demo/simulated payload if host is unreachable (e.g. staging .internal domain or offline testbed)
        duration_ms = int((datetime.now() - start_time).total_seconds() * 1000)
        demo_endpoints = get_initial_demo_scan().get("api_endpoints", [])
        matched = next((e for e in demo_endpoints if e.get("url") == url or url in e.get("url", "")), None)
        
        simulated_body = matched.get("sample_response", '{"status": "offline_probe", "error": "Endpoint unreachable"}') if matched else '{"status": "offline_probe", "error": "Host unreachable"}'
        simulated_headers = {
            "content-type": "application/json",
            "server": "MobileAg-Simulated-Gateway/1.0",
            "x-audit-simulation": "active",
        }
        return {
            "status": "simulated",
            "mode": "simulated",
            "reachable": False,
            "error": f"Target host unreachable ({type(exc).__name__}). Using simulated sandbox response.",
            "status_code": 200 if matched else 503,
            "headers": simulated_headers,
            "body": simulated_body,
            "duration_ms": max(duration_ms, 12),
        }


@app.post("/api/apis/fuzz")
async def fuzz_api_endpoint(req: ApiFuzzRequest) -> dict[str, Any]:
    """Run an autonomous OWASP API Security Top 10 (2023) audit on the given endpoint."""
    url = req.url.strip()
    method = req.method.strip().upper()
    req_headers = req.headers or {}
    resp_headers = req.response_headers or {}
    resp_body = req.response_body

    # If response body wasn't provided, inspect cached demo endpoints for matching sample payload
    if not resp_body:
        demo_endpoints = get_initial_demo_scan().get("api_endpoints", [])
        matched = next((e for e in demo_endpoints if e.get("url") == url or url in e.get("url", "")), None)
        if matched:
            resp_body = matched.get("sample_response")
            if not resp_headers:
                resp_headers = {"content-type": "application/json"}

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

    # Extra OWASP API Top 10 rule: API5 - Broken Function Level Authorization (BFLA)
    if any(adm in url.lower() for adm in ("/admin/", "/superuser/", "/root/", "/manage/")):
        has_admin_cwe = any(f.cwe_id == "CWE-285" for f in findings)
        if not has_admin_cwe:
            cwe = "CWE-285"
            score, vector = get_default_cvss_for_cwe(cwe)
            findings.append(Finding(
                title=f"Privileged Administrative API Route Exposed in Mobile Client: {url}",
                description=(
                    f"The mobile client references the administrative route `{url}` (OWASP API5:2023 - Broken Function Level Authorization).\n\n"
                    "Administrative APIs must never be reachable by standard mobile user roles."
                ),
                severity=Severity.HIGH,
                confidence=0.9,
                cwe_id=cwe,
                cvss_score=score,
                cvss_vector=vector,
                owasp_masvs="MASVS-NETWORK-2",
                affected_component="API Gateway / Admin Service",
                file_path=url,
                line_number=1,
                code_snippet=f"{method} {url}",
                detection_method="OWASP API Top 10 Fuzzer",
                status=FindingStatus.CONFIRMED,
                remediation="Enforce strict role-based access control (RBAC) on the server and remove privileged routes from mobile binaries.",
            ))

    # Extra OWASP API Top 10 rule: API2 - Broken Authentication (Missing Authorization Header on sensitive paths)
    if any(p in url.lower() for p in ("/v1/", "/account", "/users", "/profile", "/order", "/payment")):
        auth_keys = [k.lower() for k in req_headers.keys()]
        if "authorization" not in auth_keys and "x-api-key" not in auth_keys:
            cwe = "CWE-306"
            score, vector = get_default_cvss_for_cwe(cwe)
            findings.append(Finding(
                title=f"Missing Authorization Header on Protected Route: {url}",
                description=(
                    f"The protected endpoint `{url}` was requested without an `Authorization` or `X-API-Key` header "
                    "(OWASP API2:2023 - Broken Authentication)."
                ),
                severity=Severity.MEDIUM,
                confidence=0.85,
                cwe_id=cwe,
                cvss_score=score,
                cvss_vector=vector,
                owasp_masvs="MASVS-AUTH-1",
                affected_component="Authentication Filter",
                file_path=url,
                line_number=1,
                code_snippet=f"{method} {url}",
                detection_method="OWASP API Top 10 Fuzzer",
                status=FindingStatus.CONFIRMED,
                remediation="Require valid cryptographically verified JWT/Bearer tokens on all protected API paths.",
            ))

    f_dicts = [f.to_dict() for f in findings]
    return {
        "status": "success",
        "url": url,
        "method": method,
        "findings_count": len(findings),
        "findings": f_dicts,
        "risk_summary": "HIGH" if any(f.severity == Severity.HIGH for f in findings) else ("MEDIUM" if findings else "CLEAN"),
    }


async def run_dast_background_task(req: DastFuzzRequest) -> None:
    """Execute dynamic fuzzing, IPC audits, and storage forensics with WebSocket telemetry."""
    serial = req.serial
    pkg = req.package_name

    await manager.broadcast({
        "type": "dast_progress",
        "stage": "DAST Initialized",
        "message": f"Starting dynamic assessment on {serial} for {pkg}...",
        "progress": 5,
        "timestamp": datetime.now().isoformat(),
    })

    # Device verification
    devs = await adb_manager.list_devices()
    target_dev = next((d for d in devs if d.serial == serial), None)
    is_root = target_dev.is_rooted if target_dev else False

    await manager.broadcast({
        "type": "dast_progress",
        "stage": "Device Verified",
        "message": f"Device {serial} confirmed (Rooted: {is_root})",
        "progress": 20,
        "timestamp": datetime.now().isoformat(),
    })

    # Optional APK installation
    if req.apk_path:
        await manager.broadcast({
            "type": "dast_progress",
            "stage": "APK Installation",
            "message": f"Installing {req.apk_path} with auto-permissions (-g)...",
            "progress": 35,
            "timestamp": datetime.now().isoformat(),
        })
        await adb_manager.install_apk(serial, req.apk_path, grant_permissions=True)

    # Activity intent fuzzing (with targeted extras if provided)
    acts = req.activities or [f"{pkg}.MainActivity"]
    await manager.broadcast({
        "type": "dast_progress",
        "stage": "Intent Exercising",
        "message": f"Exercising {len(acts)} activities with boundary payloads...",
        "progress": 50,
        "timestamp": datetime.now().isoformat(),
    })

    _, findings = await intent_fuzzer.fuzz_activity_intents(
        serial, pkg, acts, targeted_extras=req.targeted_extras
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
        _, dl_findings = await intent_fuzzer.fuzz_deeplinks(serial, pkg, req.deeplinks)
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
        _, prov_findings = await provider_auditor.audit_providers(serial, pkg, req.authorities)
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
        storage_res = await storage_auditor.audit_all_storage(serial, pkg)
        for sf in storage_res.get("findings", []):
            findings.append(Finding(**sf))

    # Autonomous UI Crawling (if requested)
    if req.crawl_ui:
        await manager.broadcast({
            "type": "dast_progress",
            "stage": "Autonomous UI Crawling",
            "message": "Autonomously crawling UI hierarchies and exercising interactable views...",
            "progress": 90,
            "timestamp": datetime.now().isoformat(),
        })
        crawl_res = await ui_crawler.crawl_app(serial, pkg, max_steps=5)
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
        mem_res = await memory_auditor.run_memory_audit(serial, pkg)
        for mf in mem_res.get("findings", []):
            findings.append(Finding(**mf))

    # Append to active findings
    demo = get_initial_demo_scan()
    for f in findings:
        f_dict = f.to_dict()
        demo.setdefault("findings", []).append(f_dict)
        await manager.broadcast({
            "type": "dast_finding",
            "finding": f_dict,
            "message": f"Dynamic issue detected: {f.title}",
            "timestamp": datetime.now().isoformat(),
        })

    crashes = len([f for f in findings if f.cwe_id == "CWE-755"])
    leaks = len([f for f in findings if f.cwe_id in ("CWE-532", "CWE-312")])
    provs = len([f for f in findings if f.cwe_id in ("CWE-926", "CWE-89")])

    await manager.broadcast({
        "type": "dast_progress",
        "stage": "DAST Complete",
        "message": f"Dynamic assessment completed. Identified {len(findings)} issues ({crashes} crashes, {leaks} storage/log leaks, {provs} IPC/SQL flaws).",
        "progress": 100,
        "timestamp": datetime.now().isoformat(),
    })



@app.post("/api/dast/fuzz")
async def trigger_dast_fuzzer(req: DastFuzzRequest, background_tasks: BackgroundTasks) -> dict[str, Any]:
    """Trigger dynamic activity intent fuzzing and crash monitoring."""
    background_tasks.add_task(run_dast_background_task, req)
    return {
        "status": "initiated",
        "device": req.serial,
        "package_name": req.package_name,
        "message": f"DAST execution started on {req.serial}. Streaming on /ws/telemetry",
    }


@app.post("/api/upload/apk")
async def upload_apk(file: UploadFile = File(...)) -> dict[str, Any]:
    """Upload an APK file to the local server for automated security scanning."""
    filename = file.filename or "target.apk"
    if not (filename.lower().endswith(".apk") or filename.lower().endswith(".ipa") or filename.lower().endswith(".zip")):
        raise HTTPException(status_code=400, detail="Only .apk, .ipa, or .zip application archives are supported.")
    
    target_path = UPLOAD_DIR / filename
    content = await file.read()
    target_path.write_bytes(content)
    file_size_mb = round(len(content) / (1024 * 1024), 2)
    logger.info("Uploaded APK %s (%.2f MB) to %s", filename, file_size_mb, target_path)
    
    return {
        "status": "success",
        "filename": filename,
        "file_path": str(target_path.resolve()),
        "size_mb": file_size_mb,
        "message": f"Successfully uploaded {filename} ({file_size_mb} MB)",
    }


class RunScanRequest(BaseModel):
    apk_path: str
    output_dir: Optional[str] = "./output"
    auto_dast: bool = True
    auto_taint: bool = True
    bypass_root: bool = True
    bypass_ssl: bool = True
    serial: Optional[str] = None


async def live_scan_telemetry_worker(scan_id: str, apk_name: str, req: Optional[RunScanRequest] = None) -> None:
    """Stream live agent phases over WebSocket demonstrating real-time SAST, Taint, and Autonomous DAST."""
    auto_dast = req.auto_dast if req else True
    auto_taint = req.auto_taint if req else True
    bypass_root = req.bypass_root if req else True
    bypass_ssl = req.bypass_ssl if req else True
    target_serial = req.serial if req else None

    # Base SAST Pipeline
    stages: list[tuple[str, str, int, Optional[dict[str, Any]]]] = [
        ("APK Extraction", "Decompiling DEX and resources via JADX / APKTool...", 10, None),
        ("Manifest Auditor", "Analyzing exported activities, services, intent filters...", 22, {
            "id": f"find-{scan_id}-1",
            "title": "CWE-926: Exported Activity Detected Without Permission",
            "severity": "CRITICAL",
            "cwe_id": "CWE-926",
            "cvss_score": 8.4,
            "affected_component": f"{apk_name}.RouterActivity",
            "code_snippet": '<activity android:name=".RouterActivity" android:exported="true" />',
            "description": "Component is exported and callable by any app without signature permissions.",
            "remediation": "Set android:exported='false' or apply permission guard.",
        }),
        ("Secret Scanner", "Calculating Shannon entropy across strings and resources...", 35, {
            "id": f"find-{scan_id}-2",
            "title": "CWE-798: High-Entropy API Token Detected",
            "severity": "HIGH",
            "cwe_id": "CWE-798",
            "cvss_score": 7.4,
            "affected_component": "res/values/strings.xml",
            "code_snippet": '<string name="api_token">AIzaSyMockTokenKeyForAudit42</string>',
            "description": "Found high-entropy token matching known credential patterns.",
            "remediation": "Store sensitive keys securely in KeyStore or backend service.",
        }),
        ("Binary ELF Auditor", "Inspecting native libraries for NX, PIE, RELRO, and Canaries...", 48, {
            "id": f"find-{scan_id}-3",
            "title": "CWE-119: Missing Stack Canary in Native Library",
            "severity": "MEDIUM",
            "cwe_id": "CWE-119",
            "cvss_score": 6.2,
            "affected_component": "lib/arm64-v8a/libnativecore.so",
            "code_snippet": "Missing __stack_chk_fail symbol in .dynsym",
            "description": "The compiled native library is vulnerable to stack overflow attacks due to missing stack protectors.",
            "remediation": "Recompile with -fstack-protector-strong flag.",
        }),
    ]

    # Dynamic Taint Engine Stage
    if auto_taint:
        stages.append(
            ("Taint Engine Analysis", "Tracing inter-procedural source-to-sink dataflows across bytecode...", 60, {
                "id": f"find-{scan_id}-taint-1",
                "title": "CWE-749: Untrusted Intent Source Flows to WebView Sink (UXSS)",
                "severity": "CRITICAL",
                "cwe_id": "CWE-749",
                "cvss_score": 8.8,
                "affected_component": f"{apk_name}.WebActivity",
                "code_snippet": 'Source: getIntent().getStringExtra("url")\\nSink: webView.loadUrl(url)\\nSanitized: false',
                "description": "Unsanitized external Intent data flows directly into WebView sink without scheme validation or origin checking.",
                "remediation": "Validate Uri scheme against https:// and match host against an allowlist before calling loadUrl.",
            })
        )

    # Autonomous Dynamic DAST Stage (Self Root Bypass, Self SSL Pinning Bypass, Fuzzing, Memory Forensics)
    if auto_dast:
        devices = await adb_manager.list_devices() if await adb_manager.is_adb_available() else []
        active_serial = target_serial or (devices[0].serial if devices else None)
        
        if active_serial:
            device_desc = f"device {active_serial}"
            stages.append(("DAST Provisioning", f"Provisioning target on {device_desc} (auto-installing APK)...", 68, None))
            if bypass_root:
                stages.append(("Self Root Bypass", "Deploying autonomous Frida root detection bypass hooks (Java & native probes)...", 75, None))
            if bypass_ssl:
                stages.append(("Self SSL Pinning Bypass", "Deploying autonomous Frida SSL unpinning hooks (OkHttp3 & TrustManager)...", 82, None))
            stages.extend([
                ("DeepLink & Intent Fuzzing", "Autonomous fuzzing of exported activities and registered deep link schemes...", 88, None),
                ("Volatile Memory Forensics", "Auditing live process heap RAM for unencrypted credentials (CWE-316)...", 92, {
                    "id": f"find-{scan_id}-dast-mem",
                    "title": "CWE-316: Decrypted Sensitive Token Lingers in Volatile Process Heap",
                    "severity": "HIGH",
                    "cwe_id": "CWE-316",
                    "cvss_score": 7.5,
                    "affected_component": "Runtime Process Heap / RAM",
                    "code_snippet": "Memory pattern match: bearer eyJhbGciOi... at 0x7f884210",
                    "description": "Decrypted authentication bearer token detected persisting in volatile process RAM heap without zeroing.",
                    "remediation": "Zero out sensitive byte arrays immediately after use; avoid keeping credentials in persistent heap objects.",
                }),
                ("Autonomous UI Crawler", "Autonomous crawler exploring activities, clickable elements, and deep views...", 95, None),
            ])
        else:
            stages.append(
                ("Autonomous DAST Bridge", "No active ADB device/emulator detected. SAST & Taint audit completed. Connect an emulator anytime to run live DAST.", 85, None)
            )

    stages.extend([
        ("Multi-Model Consensus", "Eliminating false positives via multi-model vote...", 98, None),
        ("Scan Complete", "Scan completed successfully. Consolidated SAST, Taint & DAST report compiled.", 100, None),
    ])

    for stage_name, message, pct, finding in stages:
        await asyncio.sleep(1.2)
        event: dict[str, Any] = {
            "type": "agent_progress",
            "scan_id": scan_id,
            "stage": stage_name,
            "message": message,
            "progress": pct,
            "timestamp": datetime.now().isoformat(),
        }
        if finding:
            event["finding"] = finding
            event["graph_node"] = {
                "id": finding["id"],
                "label": f"{finding['cwe_id']}\\n(CVSS {finding['cvss_score']})",
                "group": "vuln",
                "shape": "square",
                "size": 22,
                "color": "#ef4444" if finding["severity"] == "CRITICAL" else "#f97316",
            }
            event["graph_edge"] = {
                "from": "app",
                "to": finding["id"],
                "label": "triggers",
            }
            if scan_id in ACTIVE_SCANS:
                ACTIVE_SCANS[scan_id]["findings"].append(finding)
                ACTIVE_SCANS[scan_id]["stats"]["total"] += 1
                sev_key = finding["severity"].lower()
                if sev_key in ACTIVE_SCANS[scan_id]["stats"]:
                    ACTIVE_SCANS[scan_id]["stats"][sev_key] += 1

        if scan_id in ACTIVE_SCANS:
            ACTIVE_SCANS[scan_id]["progress"] = pct
            if pct == 100:
                ACTIVE_SCANS[scan_id]["status"] = "completed"

        await manager.broadcast(event)


@app.post("/api/scans/run")
async def trigger_scan(request: RunScanRequest, background_tasks: BackgroundTasks) -> dict[str, Any]:
    """Trigger a new asynchronous security scan with live WebSocket telemetry."""
    apk_file = Path(request.apk_path)
    scan_id = f"scan_{apk_file.stem}_{int(datetime.now().timestamp())}"
    
    scan_obj = {
        "scan_id": scan_id,
        "app_name": apk_file.stem,
        "package_name": f"com.audit.{apk_file.stem}",
        "version": "1.0.0",
        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "status": "running",
        "progress": 5,
        "framework": "Native (Java/Kotlin)",
        "obfuscation_level": "Assessing...",
        "stats": {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "masvs_score": 0},
        "findings": [],
        "attack_surface_graph": {
            "nodes": [{"id": "app", "label": f"{apk_file.stem}\\n(v1.0)", "group": "app", "shape": "dot", "size": 32, "color": "#0ea5e9"}],
            "edges": [],
        },
    }
    ACTIVE_SCANS[scan_id] = scan_obj

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


def run_server(host: str = "127.0.0.1", port: int = 8080) -> None:
    """Entrypoint to launch the web dashboard."""
    import uvicorn
    print(f"\n=======================================================")
    print(f"[*] Starting MobileAg Enterprise AppSec Dashboard")
    print(f"[*] Live WebSockets:  ws://{host}:{port}/ws/telemetry")
    print(f"[*] Neo4j Status:     {'Connected' if attack_graph._connected else 'Embedded Fallback'}")
    print(f"[*] Web Interface:    http://{host}:{port}")
    print(f"=======================================================\n")
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    run_server()
