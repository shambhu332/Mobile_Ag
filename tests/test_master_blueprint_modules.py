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

    # A root-relative subdirectory is not the whole filesystem and should not
    # inherit the broad-root finding solely because of its tag.
    narrow = '<paths><root-path name="limited" path="cache/mobileag/" /></paths>'
    assert FileProviderAuditor().audit_xml_content(narrow).findings == []
    first_id = result.findings[0].id
    second_id = auditor.audit_xml_content(xml_content, "res/xml/file_paths.xml").findings[0].id
    assert first_id == second_id


def test_fileprovider_resource_scan_is_bounded_unique_and_reports_parse_errors(tmp_path):
    xml_dir = tmp_path / "res" / "xml"
    xml_dir.mkdir(parents=True)
    (xml_dir / "paths.xml").write_text('<paths><root-path name="root" path="." /></paths>')
    (xml_dir / "broken.xml").write_text('<paths><root-path name="broken"')
    # This non-FileProvider file must not consume matching-file byte budget.
    unrelated = tmp_path / "assets" / "xml"
    unrelated.mkdir(parents=True)
    (unrelated / "ignored.xml").write_text('x' * (2 * 1024 * 1024 + 1))

    auditor = FileProviderAuditor()
    results = auditor.audit_resource_directory(str(tmp_path))

    assert len(results) == 2  # No recursive/direct-glob duplicates.
    broken = next(result for result in results if result.xml_path.endswith("broken.xml"))
    assert broken.parse_status == "invalid"
    assert broken.error_code == "xml_parse_error"
    paths_result = next(result for result in results if result.xml_path.endswith("paths.xml"))
    assert len(paths_result.findings) == 1
    assert auditor.coverage["static_status"] == "analyzed_heuristically"
    assert auditor.coverage["fileprovider_xml_candidates"] == 2
    assert auditor.coverage["fileprovider_xml_parse_errors"] == 1
    assert auditor.coverage["fileprovider_xml_error_codes"] == {"xml_parse_error": 1}


def test_fileprovider_resource_scan_reports_oversized_candidate_as_partial(tmp_path):
    xml_dir = tmp_path / "res" / "xml"
    xml_dir.mkdir(parents=True)
    (xml_dir / "huge.xml").write_bytes(b"<paths>" + b"x" * (2 * 1024 * 1024))

    auditor = FileProviderAuditor()
    assert auditor.audit_resource_directory(str(tmp_path)) == []
    assert auditor.coverage["static_status"] == "partial"
    assert auditor.coverage["source_file_skip_reasons"]["file_size_limit"] == 1


def test_fileprovider_parser_bounds_direct_xml_input_and_validates_root():
    auditor = FileProviderAuditor()
    too_large = auditor.audit_xml_content(" " * (FileProviderAuditor.MAX_XML_CHARS + 1))
    assert too_large.parse_status == "invalid"
    assert too_large.error_code == "xml_size_limit"
    wrong_root = auditor.audit_xml_content('<not-paths><root-path name="root" path="." /></not-paths>')
    assert wrong_root.parse_status == "invalid"
    assert wrong_root.error_code == "unexpected_root_element"


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
    assert res_vuln.marker_observed is True
    assert "victim@example.com" not in res_vuln.evidence_reason
    assert res_vuln.response_body_preview == ""
    assert len(res_vuln.response_sha256) == 64

    # Negative test: 403 Forbidden
    res_safe = fuzzer.evaluate_response_discrepancy(
        endpoint="/v1/users/usr_98472",
        method="GET",
        resource_id="usr_98472",
        status_code=403,
        response_body='{"error": "Forbidden"}',
    )
    assert res_safe.is_vulnerable is False

    # HTTP 200 with arbitrary response content is not enough to prove BOLA.
    ambiguous = fuzzer.evaluate_response_discrepancy(
        endpoint="/v1/orders/order_123", method="GET", resource_id="order_123",
        status_code=200, response_body='{"status":"ok","id":"order_123"}',
    )
    assert ambiguous.is_vulnerable is False
    assert ambiguous.marker_observed is False
    assert "ownership and confidentiality are unverified" in ambiguous.evidence_reason


def test_provider_fuzzer_success_is_observation_not_vulnerability(monkeypatch):
    from types import SimpleNamespace
    import mobileag.dast.provider_fuzzer as provider_module

    monkeypatch.setattr(
        provider_module.subprocess, "run",
        lambda *a, **k: SimpleNamespace(returncode=0, stdout="Row: 0 _id=1 name=synthetic", stderr=""),
    )
    fuzzer = ContentProviderFuzzer(adb_path="adb")
    traversal = fuzzer.fuzz_provider_traversal("com.example.provider", "com.example.app")
    sql = fuzzer.fuzz_provider_sqli("com.example.provider")
    assert traversal[0].status == "OBSERVED_READABLE"
    assert sql[0].status == "QUERY_RESULT_OBSERVED"
    assert all("VULNERABLE" not in item.status for item in traversal + sql)


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


def test_openapi_catalog_keeps_hosts_separate_and_drops_userinfo():
    import json
    from mobileag.dast.api_cataloger import CapturedRequest, MobileApiCataloger

    catalog = MobileApiCataloger()
    catalog.ingest_request(CapturedRequest("GET", "https://alice:secret@api-one.example/v1/items"))
    catalog.ingest_request(CapturedRequest("GET", "https://api-two.example/v1/items"))
    spec = catalog.export_openapi_json()
    operation = spec["paths"]["/v1/items"]["get"]
    assert operation["servers"] == [
        {"url": "https://api-one.example"}, {"url": "https://api-two.example"}
    ]
    assert "alice" not in json.dumps(spec)
    assert "secret" not in json.dumps(spec)


def test_openapi_catalog_templates_identifier_paths_and_keeps_query_signatures():
    import json
    from mobileag.dast.api_cataloger import CapturedRequest, MobileApiCataloger

    catalog = MobileApiCataloger()
    catalog.ingest_request(CapturedRequest(
        "GET", "https://api.example.test/v1/orders/94821?expand=items&page=1"))
    catalog.ingest_request(CapturedRequest(
        "GET", "https://api.example.test/v1/orders/550e8400-e29b-41d4-a716-446655440000?expand=items&page=2"))
    # A distinct query signature is retained for deduplication, then merged into
    # the single OpenAPI operation with the union of observed parameter names.
    catalog.ingest_request(CapturedRequest(
        "GET", "https://api.example.test/v1/orders/31415?sort=recent"))

    spec = catalog.export_openapi_json()
    operation = spec["paths"]["/v1/orders/{id1}"]["get"]
    assert {p["name"] for p in operation["parameters"] if p["in"] == "query"} == {
        "expand", "page", "sort",
    }
    path_params = [p for p in operation["parameters"] if p["in"] == "path"]
    assert path_params == [{"name": "id1", "in": "path", "required": True,
                            "schema": {"type": "string"}}]
    encoded = json.dumps(spec)
    assert "94821" not in encoded
    assert "550e8400-e29b-41d4-a716-446655440000" not in encoded
    assert "31415" not in encoded



def test_openapi_catalog_redacts_token_shaped_opaque_path_segments():
    import json
    from mobileag.dast.api_cataloger import CapturedRequest, MobileApiCataloger

    sample_a = "AbCdEf0123456789GhIjKlMnOpQrStUv"
    sample_b = "ZaYxWv9876543210UtSrQpOnMlKjIhGf"
    catalog = MobileApiCataloger()
    catalog.ingest_request(CapturedRequest("GET", f"https://api.example.test/v1/sessions/{sample_a}"))
    catalog.ingest_request(CapturedRequest("GET", f"https://api.example.test/v1/sessions/{sample_b}"))

    spec = catalog.export_openapi_json()
    assert "/v1/sessions/{id1}" in spec["paths"]
    encoded = json.dumps(spec)
    assert sample_a not in encoded and sample_b not in encoded


def test_captured_traffic_can_be_exported_as_observed_openapi_inventory():
    import json
    from mobileag.web.app import _captured_api_catalog
    from mobileag.dast.traffic_auditor import HTTPTransaction

    txs = [
        HTTPTransaction(url="https://api-a.example.test/v1/items?limit=2", method="POST",
                        request_body='{"account":"synthetic-private-marker","enabled":true}',
                        response_status=200, response_body='{"ok":true,"count":4}'),
        HTTPTransaction(url="https://api-b.example.test/v1/items?limit=3", method="POST",
                        response_status=403, response_body='{}'),
    ]
    spec = _captured_api_catalog(txs, "Synthetic observed traffic").export_openapi_json()
    operation = spec["paths"]["/v1/items"]["post"]
    assert spec["openapi"] == "3.0.0"
    assert len(operation["servers"]) == 2
    assert set(operation["responses"]) == {"200", "403"}
    assert operation["x-mobileag-inferred-from-capture"] is True
    req_schema = operation["requestBody"]["content"]["application/json"]["schema"]
    assert req_schema["properties"]["account"]["type"] == "string"
    assert req_schema["properties"]["enabled"]["type"] == "boolean"
    assert "synthetic-private-marker" not in json.dumps(spec)


def test_openapi_export_is_normatively_validated_and_rejects_invalid_documents():
    import pytest
    from openapi_spec_validator import validate
    from openapi_spec_validator.validation.exceptions import OpenAPIValidationError
    from mobileag.dast.api_cataloger import CapturedRequest, MobileApiCataloger

    catalog = MobileApiCataloger("Synthetic API", "1.0.0")
    catalog.ingest_request(CapturedRequest("GET", "https://api.example.test/v1/items"))
    document = catalog.export_openapi_json()
    validate(document)

    with pytest.raises(OpenAPIValidationError):
        validate({"openapi": "3.0.0", "info": {"title": "missing version"}, "paths": {}})


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
    from mobileag.analysis.call_graph import SMALI_DERIVED_SOURCES, SMALI_SINKS, SMALI_SOURCES
    from mobileag.analysis.taint_engine import _SINK_SPECS, _SOURCE_PATTERNS

    assert "Landroid/app/PendingIntent;->send" in SMALI_SINKS
    assert "Landroid/content/Intent;->getScheme" in SMALI_DERIVED_SOURCES
    assert "Landroid/content/Intent;->getStringExtra" in SMALI_DERIVED_SOURCES
    assert "Landroid/content/Intent;->getStringExtra" not in SMALI_SOURCES
    assert "Landroid/net/Uri;->getScheme" in SMALI_DERIVED_SOURCES

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
    assert "tok_123" not in json.dumps(entry)
    assert any(h["name"] == "Authorization" and h["value"] == "[REDACTED]" for h in entry["request"]["headers"])
    assert entry["response"]["status"] == 201
    assert "ch_9841" in entry["response"]["content"]["text"]

    # Test saving HAR
    har_file = tmp_path / "traffic.har"
    cataloger.save_har(har_file)
    assert har_file.is_file()
    with open(har_file, "r", encoding="utf-8") as f:
        loaded = json.load(f)
    assert loaded["log"]["version"] == "1.2"


def test_har_exporter_redacts_auth_fields_in_url_and_bodies():
    import json
    from mobileag.dast.api_cataloger import CapturedRequest, MobileApiCataloger

    catalog = MobileApiCataloger()
    catalog.ingest_request(CapturedRequest(
        method="POST",
        url="https://api.example.test/path?access_token=syntheticUrlSecret",
        headers={"Authorization": "Bearer syntheticBearerCredential"},
        query_params={"refresh_token": "syntheticRefreshSecret", "page": "1"},
        body='{"password":"syntheticPassword","amount":3}',
        response_body='{"access_token":"syntheticResponseToken","ok":true}',
    ))
    har = catalog.export_har_json()
    exported = json.dumps(har)
    for secret in ("syntheticUrlSecret", "syntheticBearerCredential", "syntheticRefreshSecret",
                   "syntheticPassword", "syntheticResponseToken"):
        assert secret not in exported
    entry = har["log"]["entries"][0]
    assert json.loads(entry["request"]["postData"]["text"])["amount"] == 3
    assert {q["name"]: q["value"] for q in entry["request"]["queryString"]}["page"] == "1"


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
    hdr_none = base64.urlsafe_b64encode(json.dumps({"alg": "none", "typ": "JWT",
        "jwk": {"k": "synthetic-header-secret-123"}}).encode()).decode().rstrip("=")
    pay_plain = base64.urlsafe_b64encode(json.dumps({"sub": "user123", "password": "supersecretpassword"}).encode()).decode().rstrip("=")
    jwt_insecure = f"{hdr_none}.{pay_plain}.sig"

    findings = auditor.audit_token(jwt_insecure,
                                   context_url="https://researcher:pass@api.example.test/me?sessionid=query-secret-123#frag-secret")
    cwe_ids = [f.cwe_id for f in findings]
    assert "CWE-347" in cwe_ids  # alg none
    assert "CWE-613" in cwe_ids  # missing exp
    assert "CWE-312" in cwe_ids  # password in payload
    serialized = json.dumps([finding.model_dump(mode="json") for finding in findings])
    assert "synthetic-header-secret-123" not in serialized
    assert "supersecretpassword" not in serialized
    assert "query-secret-123" not in serialized
    assert "frag-secret" not in serialized
    assert "researcher:pass" not in serialized
    assert "api.example.test/me" in serialized
    alg_finding = next(f for f in findings if f.cwe_id == "CWE-347")
    assert alg_finding.status.value == "UNVERIFIED"
    assert "Verification Not Established" in alg_finding.title
    assert "jwk" not in json.dumps(alg_finding.metadata)
    assert "raw_token" not in auditor.decode_jwt(jwt_insecure)
    decoded = auditor.decode_jwt(jwt_insecure)
    assert decoded["header"] == {"alg": "none"}
    assert decoded["payload"]["sensitive_claim_names"] == ["password"]
    assert "supersecretpassword" not in json.dumps(decoded)
    assert auditor._safe_context_url(
        "https://api.example.test/reset/abCDef01234567890123456789012345?x=secret#frag") == (
            "https://api.example.test/reset/[REDACTED]")

    # 2. Low entropy token
    low_ent_findings = auditor.audit_token("aaaaaaaaaaaaaaaa")
    assert any(f.cwe_id == "CWE-330" for f in low_ent_findings)

    # Malformed claim roots and excessive attacker-controlled token strings
    # are treated as non-decodable input rather than raising or parsing as JWT.
    json_list = base64.urlsafe_b64encode(b"[]").decode().rstrip("=")
    valid_object = base64.urlsafe_b64encode(b"{}").decode().rstrip("=")
    assert auditor.decode_jwt(f"{json_list}.{valid_object}.sig") is None
    assert auditor.decode_jwt(f"{valid_object}.{json_list}.sig") is None
    assert auditor.audit_token("x" * (auditor.MAX_TOKEN_CHARS + 1)) == []

    # A present but non-numeric exp is not misreported as an absent claim.
    pay_invalid_exp = base64.urlsafe_b64encode(json.dumps({"exp": True}).encode()).decode().rstrip("=")
    invalid_exp = auditor.audit_token(f"{valid_object}.{pay_invalid_exp}.sig")
    assert not any(f.title == "JWT Token Missing Expiration Claim" for f in invalid_exp)


def test_token_session_auditor_opt_in_hmac_verification_is_local_and_bounded():
    import base64
    import hashlib
    import hmac
    import json
    from mobileag.dast.token_session_auditor import MobileTokenSessionAuditor

    auditor = MobileTokenSessionAuditor()
    def encode(value):
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

    for alg, digest in (("HS256", hashlib.sha256), ("HS384", hashlib.sha384), ("HS512", hashlib.sha512)):
        key = b"synthetic-research-only-hmac-key".ljust(digest().digest_size, b"x")
        header = encode(json.dumps({"alg": alg, "typ": "JWT"}, separators=(",", ":")).encode())
        payload = encode(json.dumps({"sub": "synthetic"}, separators=(",", ":")).encode())
        signing_input = f"{header}.{payload}".encode("ascii")
        signature = encode(hmac.new(key, signing_input, digest).digest())
        token = f"{header}.{payload}.{signature}"

        verified = auditor.verify_hmac_jwt_signature(token, key)
        assert verified == {
            "status": "valid_for_supplied_key", "algorithm": alg,
            "key_source": "researcher_supplied", "server_acceptance": "not_tested",
        }
        wrong_key = b"different-synthetic-key".ljust(digest().digest_size, b"y")
        assert auditor.verify_hmac_jwt_signature(token, wrong_key)["status"] == "invalid_for_supplied_key"
        assert auditor.verify_hmac_jwt_signature(token, None)["status"] == "not_tested"

        altered_payload = encode(b'{"sub":"changed"}')
        altered = f"{header}.{altered_payload}.{signature}"
        assert auditor.verify_hmac_jwt_signature(altered, key)["status"] == "invalid_for_supplied_key"
        assert auditor.verify_hmac_jwt_signature(token, b"short")["status"] == "key_too_short"

    unsupported_header = encode(b'{"alg":"RS256"}')
    payload = encode(b'{"sub":"synthetic"}')
    assert auditor.verify_hmac_jwt_signature(
        f"{unsupported_header}.{payload}.AA", key
    )["status"] == "unsupported_algorithm"
    assert auditor.verify_hmac_jwt_signature(f"{unsupported_header}.{payload}.", key)["status"] == "unsupported_algorithm"
    assert auditor.verify_hmac_jwt_signature(f"{unsupported_header}.{payload}.AA", b"x" * 4097)["status"] == "invalid_key"
    assert auditor.verify_hmac_jwt_signature("not.a.jwt", key)["status"] == "invalid_compact_token"
    hs256_header = encode(b'{"alg":"HS256"}')
    min_key = b"k" * hashlib.sha256().digest_size
    assert auditor.verify_hmac_jwt_signature(f"{hs256_header}.{payload}.", min_key)["status"] == "missing_signature"
    critical_header = encode(b'{"alg":"HS256","crit":["b64"],"b64":false}')
    assert auditor.verify_hmac_jwt_signature(
        f"{critical_header}.{payload}.AA", min_key
    )["status"] == "unsupported_header_parameters"
    duplicate_header = encode(b'{"alg":"HS256","alg":"HS512"}')
    assert auditor.verify_hmac_jwt_signature(
        f"{duplicate_header}.{payload}.AA", min_key
    )["status"] == "unsupported_header_parameters"
    assert "synthetic-research-only-hmac-key" not in json.dumps(
        auditor.verify_hmac_jwt_signature(token, key)
    )


def test_token_session_hmac_verifier_matches_rfc7515_hs256_vector():
    import base64
    from mobileag.dast.token_session_auditor import MobileTokenSessionAuditor

    # RFC 7515 Appendix A.1 JWS example; fixed public test vector, not a secret.
    key_b64 = "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"
    key = base64.urlsafe_b64decode(key_b64 + "=" * (-len(key_b64) % 4))
    token = (
        "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9."
        "eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFt"
        "cGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
        "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    )
    result = MobileTokenSessionAuditor().verify_hmac_jwt_signature(token, key)
    assert result["status"] == "valid_for_supplied_key"
    assert result["algorithm"] == "HS256"
    assert result["server_acceptance"] == "not_tested"


def test_token_session_auditor_transactions_and_logout_reuse():
    import json
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
    serialized = json.dumps([finding.model_dump(mode="json") for finding in findings])
    assert "secret_session_token_xyz_123" not in serialized
    assert "super_secret_query_tok_123" not in serialized


def test_token_session_auditor_does_not_call_unauthorized_responses_successful_reuse():
    from mobileag.dast.token_session_auditor import MobileTokenSessionAuditor
    from mobileag.dast.api_cataloger import CapturedRequest

    token = "synthetic-session-token-98765"
    transactions = [
        CapturedRequest(method="POST", url="https://api.example.test/logout",
                        headers={"Authorization": f"Bearer {token}"}, response_status=204),
        CapturedRequest(method="GET", url="https://api.example.test/account",
                        headers={"AUTHORIZATION": f"Bearer {token}"}, response_status=401),
    ]
    findings = MobileTokenSessionAuditor().audit_transactions(transactions)
    assert not any(f.cwe_id == "CWE-613" for f in findings)


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
    component_ref = cdx_json["components"][0]["bom-ref"]
    assert cdx_json["vulnerabilities"][0]["affects"][0]["ref"] == component_ref

    # Check CycloneDX XML
    cdx_xml = gen.generate_cyclonedx_xml()
    assert "<vulnerabilities>" in cdx_xml
    assert "<id>CVE-2021-0341</id>" in cdx_xml
    root = ET.fromstring(cdx_xml)
    assert any(child.tag.endswith("vulnerabilities") for child in root)
    component = next(el for el in root.iter() if el.tag.endswith("component") and el.get("type") == "library")
    target_ref = next(el.text for el in root.iter() if el.tag.endswith("ref"))
    assert target_ref == component.get("bom-ref")
    assert "<scope>required</scope>" in cdx_xml


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




