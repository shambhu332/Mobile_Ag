"""Unit tests for Advanced DAST & Taint modules:
- FridaRunner (SSL unpinning, crypto telemetry parsing, root bypass)
- DeepLinkFuzzer (OAuth redirect, file disclosure, UXSS, parameter pollution)
- TaintEngine (inter-procedural static source-to-sink dataflow tracking)
- UICrawler (UI hierarchy parsing, dialog handling, form filling)
- MemoryForensicsAuditor (process memory scraping, CWE-316 detection)
- Associated FastAPI endpoints
"""

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from mobileag.analysis.taint_engine import TaintEngine
from mobileag.dast.adb_manager import ADBManager
from mobileag.dast.deeplink_fuzzer import DeepLinkFuzzer
from mobileag.dast.frida_runner import FridaRunner
from mobileag.dast.memory_forensics import MemoryForensicsAuditor
from mobileag.dast.ui_crawler import UICrawler
from mobileag.web.app import app


@pytest.fixture
def client():
    return TestClient(app)


# =============================================================================
# 1. FridaRunner Tests
# =============================================================================
def test_frida_runner_script_generation():
    runner = FridaRunner()
    unpin_script = runner.generate_unpinning_script()
    crypto_script = runner.generate_crypto_monitor_script()
    root_script = runner.generate_root_bypass_script()

    assert "TrustManager" in unpin_script
    assert "CertificatePinner" in unpin_script
    assert "javax.crypto.Cipher" in crypto_script
    assert "File.exists" in root_script


def test_frida_runner_crypto_telemetry_parsing():
    runner = FridaRunner()
    logs = [
        "[CRYPTO_AUDIT] Algorithm: AES/ECB/PKCS5Padding | Mode: ENCRYPT_MODE | Key: AES (RAW)",
        "[CRYPTO_AUDIT] Algorithm: AES/CBC/PKCS5Padding | Mode: ENCRYPT_MODE | IV: 00 00 00 00 00 00 00 00",
        "Normal log line from activity",
    ]
    findings = runner.parse_crypto_telemetry(logs, package_name="com.test.app")
    assert len(findings) == 2
    cwes = {f.cwe_id for f in findings}
    assert "CWE-327" in cwes  # Insecure ECB mode
    assert "CWE-329" in cwes  # Static IV


@pytest.mark.asyncio
async def test_frida_runner_execution():
    mock_adb = ADBManager()
    mock_adb._exec_cmd = AsyncMock(return_value=(0, b"frida-server 1234\n", b""))

    runner = FridaRunner(adb=mock_adb)
    is_running = await runner.is_frida_server_running("emulator-5554")
    assert is_running is True

    res = await runner.execute_script_payload("emulator-5554", "com.test.app", "console.log('test');")
    assert res["status"] == "deployed"
    assert res["package_name"] == "com.test.app"


# =============================================================================
# 2. DeepLinkFuzzer Tests
# =============================================================================
def test_deeplink_fuzzer_manifest_extraction_and_payloads():
    fuzzer = DeepLinkFuzzer()
    manifest_data = {
        "activities": [
            {
                "name": "com.test.app.RouterActivity",
                "intent_filters": [
                    {
                        "actions": ["android.intent.action.VIEW"],
                        "categories": ["android.intent.category.BROWSABLE"],
                        "data": [{"scheme": "testapp", "host": "auth"}],
                    }
                ],
            }
        ]
    }

    links = fuzzer.extract_deep_links_from_manifest(manifest_data)
    assert len(links) == 1
    assert links[0]["scheme"] == "testapp"
    assert links[0]["uri"] == "testapp://auth"

    payloads = fuzzer.generate_fuzz_payloads("testapp://auth", "com.test.app")
    assert len(payloads) >= 4
    cwes = {p["cwe"] for p in payloads}
    assert "CWE-601" in cwes  # Open Redirect
    assert "CWE-22" in cwes   # File Traversal
    assert "CWE-749" in cwes  # WebView Script Injection


@pytest.mark.asyncio
async def test_deeplink_fuzzer_runtime_fuzz():
    mock_adb = ADBManager()
    mock_adb.clear_logcat = AsyncMock(return_value=True)
    mock_adb._exec_cmd = AsyncMock(return_value=(0, b"Starting: Intent { act=android.intent.action.VIEW }\n", b""))
    mock_adb.get_logcat_dump = AsyncMock(return_value=[
        "09-21 11:00:00.000 1234 1234 E AndroidRuntime: FATAL EXCEPTION: main",
        "java.lang.NullPointerException: Null query parameter in DeepLinkActivity",
    ])

    fuzzer = DeepLinkFuzzer(adb=mock_adb)
    results, findings = await fuzzer.fuzz_deep_links("emulator-5554", "com.test.app", ["testapp://router"])
    assert len(results) >= 4
    assert len(findings) >= 1
    assert findings[0].cwe_id == "CWE-755"


# =============================================================================
# 3. TaintEngine Tests (Static Source-to-Sink Dataflow)
# =============================================================================
def test_taint_engine_webview_uxss():
    engine = TaintEngine()
    source_code = """
    package com.target.app;
    import android.content.Intent;
    import android.webkit.WebView;

    public class VulnActivity {
        public void onCreate(Intent intent, WebView webView) {
            String targetUrl = intent.getStringExtra("url_param");
            String intermediate = targetUrl;
            webView.loadUrl(intermediate);
        }
    }
    """
    findings = engine.analyze_source_content(source_code, "VulnActivity.java")
    assert len(findings) == 1
    assert findings[0].cwe_id == "CWE-749"
    assert "UXSS" in findings[0].title
    assert "targetUrl" in findings[0].description


def test_taint_engine_sql_and_intent_redirection():
    engine = TaintEngine()
    source_code = """
    package com.target.app;
    import android.content.Intent;
    import android.database.sqlite.SQLiteDatabase;

    public class SqlAndRedirectActivity {
        public void handle(Intent incoming, SQLiteDatabase db) {
            String userInput = incoming.getStringExtra("query");
            db.rawQuery("SELECT * FROM users WHERE name = '" + userInput + "'", null);

            Intent forwarded = (Intent) incoming.getParcelableExtra("extra_intent");
            startActivity(forwarded);
        }
    }
    """
    findings = engine.analyze_source_content(source_code, "SqlAndRedirectActivity.java")
    assert len(findings) == 2
    cwes = {f.cwe_id for f in findings}
    assert "CWE-89" in cwes   # SQL Injection
    assert "CWE-927" in cwes  # Intent Redirection


# =============================================================================
# 4. UICrawler Tests
# =============================================================================
def test_ui_crawler_parsing_and_dialog_handling():
    crawler = UICrawler()
    sample_xml = """<?xml version="1.0" encoding="utf-8"?>
    <hierarchy rotation="0">
      <node index="0" text="" resource-id="" class="android.widget.FrameLayout" bounds="[0,0][1080,2400]">
        <node index="0" text="Allow Notifications" resource-id="com.android.permissioncontroller:id/permission_allow_button" class="android.widget.Button" clickable="true" bounds="[100,500][400,600]" />
        <node index="1" text="" resource-id="com.target.app:id/email_field" class="android.widget.EditText" clickable="true" bounds="[100,700][900,850]" />
        <node index="2" text="Log In" resource-id="com.target.app:id/login_button" class="android.widget.Button" clickable="true" bounds="[100,900][900,1050]" />
      </node>
    </hierarchy>
    """
    elements = crawler.parse_ui_elements(sample_xml)
    assert len(elements) == 3

    # Check center calculation
    assert elements[0]["center"] == (250, 550)
    assert elements[0]["clickable"] is True


@pytest.mark.asyncio
async def test_ui_crawler_crawl_flow():
    mock_adb = ADBManager()
    mock_adb._exec_cmd = AsyncMock(return_value=(0, b"""<?xml version="1.0" encoding="utf-8"?>
    <hierarchy rotation="0">
      <node text="OK" class="android.widget.Button" clickable="true" bounds="[100,200][300,400]" />
    </hierarchy>""", b""))

    crawler = UICrawler(adb=mock_adb)
    res = await crawler.crawl_app("emulator-5554", "com.test.app", max_steps=2)
    assert res["status"] == "completed"
    assert res["screens_explored"] >= 1


# =============================================================================
# 5. MemoryForensicsAuditor Tests
# =============================================================================
@pytest.mark.asyncio
async def test_memory_forensics_secret_detection():
    mock_adb = ADBManager()

    async def mock_exec(cmd, timeout=3.0):
        cmd_str = " ".join(cmd)
        if "pidof" in cmd_str:
            return (0, b"4567\n", b"")
        if "strings" in cmd_str:
            return (0, b"header\nAuthorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.sec123\npassword=\"SuperSecretPass!\"\n", b"")
        return (0, b"", b"")

    mock_adb._exec_cmd = mock_exec
    auditor = MemoryForensicsAuditor(adb=mock_adb)

    pid, findings = await auditor.audit_process_memory("emulator-5554", "com.test.app")
    assert pid == 4567
    assert len(findings) >= 2
    cwes = {f.cwe_id for f in findings}
    assert "CWE-316" in cwes


# =============================================================================
# 6. Web API Endpoints Tests
# =============================================================================
def test_web_deeplinks_endpoint(client):
    with patch("mobileag.web.app.deeplink_fuzzer.fuzz_deep_links") as mock_fuzz:
        mock_fuzz.return_value = (
            [{"scheme_uri": "testapp://", "status_code": 0}],
            [],
        )
        response = client.post("/api/dast/deeplinks", json={
            "serial": "emulator-5554",
            "package_name": "com.test.app",
            "deep_links": ["testapp://"],
        })
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert len(data["results"]) == 1


def test_web_memory_endpoint(client):
    with patch("mobileag.web.app.memory_auditor.run_memory_audit") as mock_mem:
        mock_mem.return_value = {
            "package_name": "com.test.app",
            "device_serial": "emulator-5554",
            "pid": 1234,
            "memory_findings_count": 1,
            "findings": [{
                "title": "Cleartext Secret in Volatile Memory: JWT Bearer Token",
                "cwe_id": "CWE-316",
                "severity": "HIGH",
            }],
        }
        response = client.post("/api/dast/memory", json={
            "serial": "emulator-5554",
            "package_name": "com.test.app",
        })
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["report"]["memory_findings_count"] == 1


def test_web_crawl_endpoint(client):
    with patch("mobileag.web.app.ui_crawler.crawl_app") as mock_crawl:
        mock_crawl.return_value = {
            "package_name": "com.test.app",
            "screens_explored": 3,
            "dialogs_dismissed": 1,
            "inputs_filled": 2,
            "buttons_clicked": 2,
            "status": "completed",
        }
        response = client.post("/api/dast/crawl", json={
            "serial": "emulator-5554",
            "package_name": "com.test.app",
            "max_steps": 3,
        })
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert data["report"]["screens_explored"] == 3


def test_web_frida_endpoint(client):
    with patch("mobileag.web.app.frida_runner.execute_script_payload") as mock_frida:
        mock_frida.return_value = {
            "status": "deployed",
            "frida_server_running": True,
            "script_path": "/data/local/tmp/test.js",
        }
        response = client.post("/api/dast/frida", json={
            "serial": "emulator-5554",
            "package_name": "com.test.app",
            "script_type": "crypto",
        })
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert "javax.crypto.Cipher" in data["script"]


def test_web_taint_endpoint(client):
    source = """
    public void test(Intent i, WebView w) {
        String u = i.getStringExtra("u");
        w.loadUrl(u);
    }
    """
    response = client.post("/api/analysis/taint", json={
        "source_code": source,
        "file_path": "Test.java",
    })
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "success"
    assert len(data["findings"]) == 1
    assert data["findings"][0]["cwe_id"] == "CWE-749"
