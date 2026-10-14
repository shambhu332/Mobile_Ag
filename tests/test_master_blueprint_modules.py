"""Tests for newly implemented blueprint modules: FileProvider, Unpinning, CryptoHarvester, ProviderFuzzer, and BolaFuzzer."""
import pytest
from mobileag.analysis.fileprovider_auditor import FileProviderAuditor
from mobileag.dast.unpinning_engine import UnpinningEngine, UnpinningConfig
from mobileag.dast.crypto_harvester import CryptoHarvester
from mobileag.dast.provider_fuzzer import ContentProviderFuzzer
from mobileag.dast.bola_fuzzer import BolaFuzzer


def test_fileprovider_auditor_detects_dangerous_root_path():
    xml_content = """<?xml version="1.0" encoding="utf-8"?>
    <paths xmlns:android="http://schemas.android.com/apk/res/android">
        <root-path name="root" path="." />
        <external-path name="ext" path="." />
        <files-path name="internal_files" path="safe_dir/" />
    </paths>
    """
    auditor = FileProviderAuditor()
    result = auditor.audit_xml_content(xml_content, "res/xml/file_paths.xml")

    assert len(result.entries) == 3
    assert len(result.findings) == 2  # root-path and external-path with "."
    assert any(f.metadata.get("tag") == "root-path" and f.severity == "HIGH" for f in result.findings)
    assert any(f.metadata.get("tag") == "external-path" and f.severity == "MEDIUM" for f in result.findings)


def test_unpinning_engine_generates_multi_layer_script():
    engine = UnpinningEngine()
    config = UnpinningConfig(target_package="com.example.bank", bypass_java=True, bypass_boringssl=True, bypass_flutter=True)
    script = engine.generate_script(config)

    assert "com.example.bank" in script
    assert "javax.net.ssl.TrustManager" in script
    assert "SSL_CTX_set_custom_verify" in script
    assert "libflutter.so" in script


def test_crypto_harvester_script_and_event_parsing():
    harvester = CryptoHarvester()
    script = harvester.generate_hook_script()
    assert "javax.crypto.Cipher" in script
    assert "SecretKeySpec" in script
    assert "net.sqlcipher.database.SQLiteDatabase" in script

    event = harvester.parse_event({
        "type": "crypto_event",
        "operation": "ENCRYPT",
        "algorithm": "AES/CBC/PKCS5Padding",
        "key": "00112233445566778899aabbccddeeff",
        "iv": "0102030405060708090a0b0c0d0e0f10",
    })
    assert event is not None
    assert event.operation == "ENCRYPT"
    assert event.algorithm == "AES/CBC/PKCS5Padding"
    assert event.key_hex == "00112233445566778899aabbccddeeff"

    sqlcipher_event = harvester.parse_event({
        "type": "crypto_event",
        "operation": "SQLCIPHER_KEY",
        "algorithm": "SQLCipher-256",
        "key": "SecretDbPassword123",
    })
    assert sqlcipher_event is not None
    assert sqlcipher_event.operation == "SQLCIPHER_KEY"
    assert sqlcipher_event.key_hex == "SecretDbPassword123"



def test_provider_fuzzer_traversal_and_sqli_payloads():
    fuzzer = ContentProviderFuzzer(adb_path="echo")
    results = fuzzer.fuzz_provider_traversal("com.example.provider", "com.example.app")
    assert len(results) == len(ContentProviderFuzzer.TRAVERSAL_PAYLOADS)
    assert any("databases" in r.target_uri for r in results)

    sqli_results = fuzzer.fuzz_provider_sqli("com.example.provider")
    assert len(sqli_results) == len(ContentProviderFuzzer.SQLI_PROBES)


def test_bola_fuzzer_candidate_extraction_and_discrepancy():
    fuzzer = BolaFuzzer()
    url = "https://api.example.com/v1/users/usr_98472/orders?account_id=acc_1122"
    candidates = fuzzer.extract_resource_candidates(url)
    assert "usr_98472" in candidates
    assert "acc_1122" in candidates

    # Positive test: User B receives User A's data
    res_vuln = fuzzer.evaluate_response_discrepancy(
        endpoint="/v1/users/usr_98472",
        method="GET",
        resource_id="usr_98472",
        status_code=200,
        response_body='{"user_id": "usr_98472", "email": "victim@example.com"}',
        user_a_marker="victim@example.com",
    )
    assert res_vuln.is_vulnerable is True

    # Negative test: 403 Forbidden
    res_safe = fuzzer.evaluate_response_discrepancy(
        endpoint="/v1/users/usr_98472",
        method="GET",
        resource_id="usr_98472",
        status_code=403,
        response_body='{"error": "Forbidden"}',
    )
    assert res_safe.is_vulnerable is False


def test_poc_synthesizer_task_hijacking_and_provider_sqli():
    from mobileag.generators.poc_apk_synthesizer import ExploitPocSynthesizer
    from mobileag.reporting.finding import Finding, Severity

    synth = ExploitPocSynthesizer()

    # 1. Task Hijacking
    f_task = Finding(
        id="TASK_AFFINITY_HIJACK",
        title="Task Affinity Hijacking Risk: com.example.app.LoginActivity",
        description="Task affinity mismatch",
        severity=Severity.HIGH,
        cwe_id="CWE-1021",
        affected_component="com.example.app.LoginActivity",
        metadata={"task_affinity": "com.example.target.affinity"}
    )
    poc_task = synth.synthesize(f_task, "com.example.target")
    assert poc_task is not None
    assert "StrandHoggActivity" in poc_task.kotlin_exploit_code
    assert "com.example.target.affinity" in poc_task.kotlin_exploit_code
    assert "adb shell am start" in poc_task.adb_command

    # 2. ContentProvider SQL Injection
    f_sqli = Finding(
        id="CONTENT_PROVIDER_SQLI",
        title="ContentProvider SQL Injection Vulnerability",
        description="Unsanitized query projection",
        severity=Severity.HIGH,
        cwe_id="CWE-89",
        affected_component="com.example.target.DataProvider",
        metadata={"authority": "com.example.target.provider"}
    )
    poc_sqli = synth.synthesize(f_sqli, "com.example.target")
    assert poc_sqli is not None
    assert "ProviderSqliExploit" in poc_sqli.kotlin_exploit_code
    assert "content://com.example.target.provider/query" in poc_sqli.kotlin_exploit_code
    assert "adb shell content query" in poc_sqli.adb_command


def test_traffic_auditor_catalog_and_shadow_api():
    from mobileag.dast.traffic_auditor import TrafficAuditor, HTTPTransaction

    auditor = TrafficAuditor()
    txs = [
        HTTPTransaction(
            url="https://api.example.com/v1/users/me?include_orders=true",
            method="GET",
            request_headers={"Authorization": "Bearer sample_token"},
            response_status=200,
        ),
        HTTPTransaction(
            url="https://api.example.com/v1/hidden/debug",
            method="POST",
            request_headers={},
            response_status=200,
        ),
    ]

    cataloger = auditor.catalog_traffic(txs, title="Sample App APIs")
    openapi = cataloger.export_openapi_json()
    assert openapi["openapi"] == "3.0.0"
    assert "/v1/users/me" in openapi["paths"]
    assert "/v1/hidden/debug" in openapi["paths"]

    # Detect shadow API not declared in static attack surface
    declared = ["https://api.example.com/v1/users/me"]
    shadow_findings = auditor.find_shadow_apis(txs, declared)
    assert len(shadow_findings) == 1
    assert "/v1/hidden/debug" in shadow_findings[0].affected_component


def test_dependency_scanner_sbom_generation():
    from mobileag.analysis.dependency_scanner import DependencyScanner

    scanner = DependencyScanner()
    scanner._last_dependencies = [
        ("com.squareup.okhttp3", "okhttp", "4.9.3", "build.gradle"),
        ("com.google.code.gson", "gson", "2.8.9", "build.gradle"),
    ]

    generator = scanner.generate_sbom("BankingApp", "2.1.0")
    cyclone = generator.generate_cyclonedx_json()
    assert cyclone["bomFormat"] == "CycloneDX"
    assert len(cyclone["components"]) == 2
    purls = [c["purl"] for c in cyclone["components"]]
    assert "pkg:maven/com.squareup.okhttp3/okhttp@4.9.3" in purls
    assert "pkg:maven/com.google.code.gson/gson@2.8.9" in purls


def test_call_graph_and_taint_pending_intent():
    from mobileag.analysis.call_graph import SMALI_SINKS, SMALI_SOURCES
    from mobileag.analysis.taint_engine import _SINK_SPECS, _SOURCE_PATTERNS

    assert "Landroid/app/PendingIntent;->send" in SMALI_SINKS
    assert "Landroid/content/Intent;->getScheme" in SMALI_SOURCES
    assert "Landroid/net/Uri;->getScheme" in SMALI_SOURCES

    sink_types = [s["type"] for s in _SINK_SPECS]
    assert "PENDING_INTENT_FORWARDING" in sink_types

    source_names = [s[0] for s in _SOURCE_PATTERNS]
    assert "JS_INTERFACE_BRIDGE" in source_names


def test_cyclonedx_xml_generation(tmp_path):
    from mobileag.analysis.sbom_generator import MobileSbomGenerator
    import xml.etree.ElementTree as ET

    gen = MobileSbomGenerator(app_name="SecureBank", app_version="3.5.0")
    gen.add_component(
        name="okhttp",
        version="4.9.3",
        purl="pkg:maven/com.squareup.okhttp3/okhttp@4.9.3",
        hashes={"SHA-256": "abc123def456"},
        licenses=["Apache-2.0"],
    )

    xml_text = gen.generate_cyclonedx_xml()
    assert "bom" in xml_text
    assert '<bom xmlns="http://cyclonedx.org/schema/bom/1.5"' in xml_text
    assert "<name>SecureBank</name>" in xml_text
    assert "<name>okhttp</name>" in xml_text
    assert "<purl>pkg:maven/com.squareup.okhttp3/okhttp@4.9.3</purl>" in xml_text
    assert '<hash alg="SHA-256">abc123def456</hash>' in xml_text
    assert "<id>Apache-2.0</id>" in xml_text

    # Verify parseability
    root = ET.fromstring(xml_text)
    assert root.tag.endswith("bom")
    assert root.attrib.get("version") == "1"

    # Test file saving
    xml_file = tmp_path / "sbom.xml"
    gen.save_cyclonedx_xml(xml_file)
    assert xml_file.is_file()
    assert xml_file.stat().st_size > 0


def test_har_exporter(tmp_path):
    from mobileag.dast.api_cataloger import MobileApiCataloger, CapturedRequest
    import json

    cataloger = MobileApiCataloger(title="Payment APIs", version="2.0.0")
    req = CapturedRequest(
        method="POST",
        url="https://api.payment.com/v2/charge",
        headers={"Content-Type": "application/json", "Authorization": "Bearer tok_123"},
        query_params={"dry_run": "false"},
        body='{"amount": 5000, "currency": "USD"}',
        response_status=201,
        response_body='{"status": "success", "charge_id": "ch_9841"}',
    )
    cataloger.ingest_request(req)

    har_data = cataloger.export_har_json()
    assert har_data["log"]["version"] == "1.2"
    assert har_data["log"]["creator"]["name"] == "MobileAg Dynamic Traffic Auditor"
    assert len(har_data["log"]["entries"]) == 1

    entry = har_data["log"]["entries"][0]
    assert entry["request"]["method"] == "POST"
    assert entry["request"]["url"] == "https://api.payment.com/v2/charge"
    assert entry["request"]["postData"]["text"] == '{"amount": 5000, "currency": "USD"}'
    assert entry["response"]["status"] == 201
    assert "ch_9841" in entry["response"]["content"]["text"]

    # Test saving HAR
    har_file = tmp_path / "traffic.har"
    cataloger.save_har(har_file)
    assert har_file.is_file()
    with open(har_file, "r", encoding="utf-8") as f:
        loaded = json.load(f)
    assert loaded["log"]["version"] == "1.2"


def test_web_export_endpoints_cyclonedx_xml_spdx_har():
    from fastapi.testclient import TestClient
    from mobileag.web.app import app, ACTIVE_SCANS
    import xml.etree.ElementTree as ET

    scan_id = "test_scan_export_001"
    ACTIVE_SCANS[scan_id] = {
        "id": scan_id,
        "scan_id": scan_id,
        "app_name": "DemoApp",
        "version": "1.0.0",
        "status": "running",
        "findings": [],
        "stats": {},
        "agent_telemetry": [],
        "api_endpoints": [
            {"method": "GET", "url": "https://api.demo.com/v1/profile"}
        ],
        "components": [],
        "deep_links": [],
        "attack_surface_graph": {},
        "dependencies": [
            {"name": "retrofit", "version": "2.9.0", "purl": "pkg:maven/com.squareup.retrofit2/retrofit@2.9.0"}
        ],
    }

    client = TestClient(app, headers={"Authorization": "Bearer " + app.state.auth_token})

    # 1. CycloneDX XML
    res_xml = client.get(f"/api/scans/{scan_id}/cyclonedx.xml")
    assert res_xml.status_code == 200
    assert "application/xml" in res_xml.headers.get("content-type", "")
    root = ET.fromstring(res_xml.text)
    assert root.tag.endswith("bom")
    assert "retrofit" in res_xml.text

    # 2. SPDX JSON
    res_spdx = client.get(f"/api/scans/{scan_id}/spdx")
    assert res_spdx.status_code == 200
    spdx_json = res_spdx.json()
    assert spdx_json["spdxVersion"] == "SPDX-2.3"
    assert spdx_json["name"] == "DemoApp SBOM"

    # 3. HAR JSON
    res_har = client.get(f"/api/scans/{scan_id}/har")
    assert res_har.status_code == 200
    har_json = res_har.json()
    assert har_json["log"]["version"] == "1.2"
    assert len(har_json["log"]["entries"]) == 1
    assert har_json["log"]["entries"][0]["request"]["url"] == "https://api.demo.com/v1/profile"


def test_token_session_auditor_jwt_claims_and_entropy():
    import base64
    import json
    from mobileag.dast.token_session_auditor import MobileTokenSessionAuditor

    auditor = MobileTokenSessionAuditor()

    # 1. JWT with 'none' algorithm and missing exp
    hdr_none = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT"}).encode()).decode().rstrip("=")
    pay_plain = base64.urlsafe_b64encode(json.dumps({"sub": "user123", "password": "supersecretpassword"}).encode()).decode().rstrip("=")
    jwt_insecure = f"{hdr_none}.{pay_plain}.sig"

    findings = auditor.audit_token(jwt_insecure)
    cwe_ids = [f.cwe_id for f in findings]
    assert "CWE-347" in cwe_ids  # alg none
    assert "CWE-613" in cwe_ids  # missing exp
    assert "CWE-312" in cwe_ids  # password in payload

    # 2. Low entropy token
    low_ent_findings = auditor.audit_token("aaaaaaaaaaaaaaaa")
    assert any(f.cwe_id == "CWE-330" for f in low_ent_findings)


def test_token_session_auditor_transactions_and_logout_reuse():
    from mobileag.dast.token_session_auditor import MobileTokenSessionAuditor
    from mobileag.dast.api_cataloger import CapturedRequest

    auditor = MobileTokenSessionAuditor()
    txs = [
        # 1. Cleartext HTTP transmission with token
        CapturedRequest(
            method="GET",
            url="http://insecure.example.com/api/profile",
            headers={"Authorization": "Bearer secret_session_token_xyz_123"},
        ),
        # 2. Token in query parameter
        CapturedRequest(
            method="GET",
            url="https://api.example.com/data?auth_token=super_secret_query_tok_123",
        ),
        # 3. Logout request
        CapturedRequest(
            method="POST",
            url="https://api.example.com/logout",
            headers={"Authorization": "Bearer tok_to_revoke_123"},
            response_status=200,
        ),
        # 4. Token reused after logout
        CapturedRequest(
            method="GET",
            url="https://api.example.com/v1/dashboard",
            headers={"Authorization": "Bearer tok_to_revoke_123"},
            response_status=200,
        ),
    ]

    findings = auditor.audit_transactions(txs)
    cwe_ids = [f.cwe_id for f in findings]
    assert "CWE-319" in cwe_ids  # Cleartext HTTP
    assert "CWE-598" in cwe_ids  # Query token
    assert "CWE-613" in cwe_ids  # Logout reuse


def test_api_security_tester_get_token_auditor():
    from mobileag.dast.api_security_tester import APISecurityTester
    from mobileag.dast.token_session_auditor import MobileTokenSessionAuditor

    tester = APISecurityTester()
    auditor = tester.get_token_auditor()
    assert isinstance(auditor, MobileTokenSessionAuditor)


def test_sbom_vulnerability_attachment():
    from mobileag.analysis.sbom_generator import MobileSbomGenerator
    import xml.etree.ElementTree as ET

    gen = MobileSbomGenerator(app_name="VulnApp", app_version="1.0.0")
    gen.add_component(
        name="okhttp",
        version="3.12.0",
        purl="pkg:maven/com.squareup.okhttp3/okhttp@3.12.0",
    )
    gen.add_vulnerability(
        vuln_id="CVE-2021-0341",
        purl="pkg:maven/com.squareup.okhttp3/okhttp@3.12.0",
        description="Certificate hostname verification bypass vulnerability.",
        severity="high",
        cwe_ids=["CWE-295"],
    )

    # Check CycloneDX JSON
    cdx_json = gen.generate_cyclonedx_json()
    assert "vulnerabilities" in cdx_json
    assert cdx_json["vulnerabilities"][0]["id"] == "CVE-2021-0341"
    assert cdx_json["vulnerabilities"][0]["ratings"][0]["severity"] == "high"

    # Check CycloneDX XML
    cdx_xml = gen.generate_cyclonedx_xml()
    assert "<vulnerabilities>" in cdx_xml
    assert "<id>CVE-2021-0341</id>" in cdx_xml
    root = ET.fromstring(cdx_xml)
    assert any(child.tag.endswith("vulnerabilities") for child in root)


def test_web_endpoint_token_audit():
    from fastapi.testclient import TestClient
    from mobileag.web.app import app, ACTIVE_SCANS

    scan_id = "test_scan_tokens_002"
    ACTIVE_SCANS[scan_id] = {
        "id": scan_id,
        "scan_id": scan_id,
        "status": "running",
        "app_name": "TokenTestApp",
        "api_endpoints": [
            {
                "method": "GET",
                "url": "http://api.insecure.com/users",
                "headers": {"Authorization": "Bearer weak_cleartext_token_abc"},
            }
        ],
    }

    client = TestClient(app, headers={"Authorization": "Bearer " + app.state.auth_token})
    res = client.get(f"/api/scans/{scan_id}/tokens/audit")
    assert res.status_code == 200
    data = res.json()
    assert data["token_findings_count"] >= 1
    assert any(f["cwe_id"] == "CWE-319" for f in data["findings"])




