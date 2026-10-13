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

