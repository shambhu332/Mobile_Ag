"""Unit test suite for newly implemented static analysis, resilience, and SBOM modules."""
import json
import os
import tempfile
from pathlib import Path

from mobileag.analysis.symbol_resolver import SymbolResolver
from mobileag.analysis.pending_intent_auditor import PendingIntentAuditor
from mobileag.analysis.intent_redirection_auditor import IntentRedirectionAuditor
from mobileag.analysis.flutter_engine import FlutterEngineAnalyzer
from mobileag.analysis.rasp_resilience_auditor import RaspResilienceAuditor
from mobileag.analysis.sbom_generator import MobileSbomGenerator


def test_symbol_resolver():
    with tempfile.TemporaryDirectory() as tmp_dir:
        java_code = """
        package com.example.app;
        import java.util.List;

        public class PaymentService {
            public void processPayment(String cardToken, int amount) {
                // payment logic
            }
        }
        """
        file_path = os.path.join(tmp_dir, "PaymentService.java")
        with open(file_path, "w") as f:
            f.write(java_code)

        resolver = SymbolResolver()
        count = resolver.index_directory(tmp_dir)
        assert count == 1
        assert "com.example.app.PaymentService" in resolver.classes

        cls = resolver.resolve_class("PaymentService")
        assert cls is not None
        assert cls.fqcn == "com.example.app.PaymentService"

        methods = resolver.resolve_method("PaymentService", "processPayment")
        assert len(methods) == 1
        assert methods[0].name == "processPayment"


def test_pending_intent_auditor():
    with tempfile.TemporaryDirectory() as tmp_dir:
        java_code = """
        package com.example.app;
        import android.app.PendingIntent;
        import android.content.Intent;

        public class AlarmManagerHelper {
            public void setAlarm() {
                Intent i = new Intent();
                PendingIntent pi1 = PendingIntent.getActivity(ctx, 0, i, 0);
                PendingIntent pi2 = PendingIntent.getBroadcast(ctx, 1, i, PendingIntent.FLAG_IMMUTABLE);
                PendingIntent pi3 = PendingIntent.getService(ctx, 2, i, PendingIntent.FLAG_MUTABLE);
            }
        }
        """
        file_path = os.path.join(tmp_dir, "AlarmManagerHelper.java")
        with open(file_path, "w") as f:
            f.write(java_code)

        auditor = PendingIntentAuditor()
        findings = auditor.audit_file(file_path)

        assert len(findings) >= 2
        # pi1 should be flagged for missing mutability flags
        unspecified = [f for f in findings if "PENDING_INTENT_MUTABLE_UNSPECIFIED" in f.id]
        assert len(unspecified) == 1

        # pi3 should be flagged for explicit FLAG_MUTABLE
        mutable = [f for f in findings if "PENDING_INTENT_EXPLICIT_MUTABLE" in f.id]
        assert len(mutable) == 1


def test_intent_redirection_auditor():
    with tempfile.TemporaryDirectory() as tmp_dir:
        java_code = """
        package com.example.app;
        import android.app.Activity;
        import android.content.Intent;
        import android.os.Bundle;

        public class ProxyActivity extends Activity {
            protected void onCreate(Bundle savedInstanceState) {
                super.onCreate(savedInstanceState);
                Intent forwardIntent = getIntent().getParcelableExtra("redirect_intent");
                startActivity(forwardIntent);
            }
        }
        """
        file_path = os.path.join(tmp_dir, "ProxyActivity.java")
        with open(file_path, "w") as f:
            f.write(java_code)

        auditor = IntentRedirectionAuditor()
        findings = auditor.audit_file(file_path)

        assert len(findings) == 1
        assert "INTENT_REDIRECTION" in findings[0].id
        assert findings[0].cwe_id == "CWE-926"


def test_flutter_engine_analyzer():
    with tempfile.TemporaryDirectory() as tmp_dir:
        lib_dir = os.path.join(tmp_dir, "lib", "arm64-v8a")
        os.makedirs(lib_dir)

        # Simulate libapp.so with embedded strings
        dummy_content = b"\x00" * 100 + b"https://api.example.com/v1/auth" + b"\x00" * 50 + b"/dashboard" + b"\x00"
        with open(os.path.join(lib_dir, "libapp.so"), "wb") as f:
            f.write(dummy_content)

        analyzer = FlutterEngineAnalyzer()
        res = analyzer.analyze_package_directory(tmp_dir)

        assert res.is_flutter_app is True
        assert res.libapp_present is True
        assert "https://api.example.com/v1/auth" in res.api_endpoints
        assert "/dashboard" in res.named_routes


def test_rasp_resilience_auditor():
    with tempfile.TemporaryDirectory() as tmp_dir:
        smali_content = """
        .class public La/b/c;
        .super Ljava/lang/Object;

        .method public static checkRoot()Z
            const-string v0, "/system/bin/su"
            const-string v1, "magisk"
            const-string v2, "isDebuggerConnected"
            const-string v3, "GET_SIGNATURES"
            return v0
        .end method
        """
        with open(os.path.join(tmp_dir, "c.smali"), "w") as f:
            f.write(smali_content)

        auditor = RaspResilienceAuditor()
        res = auditor.audit_package(tmp_dir)

        assert "obfuscation" in res.vectors
        assert "root_detection" in res.vectors
        assert "/system/bin/su" in res.vectors["root_detection"].detected_indicators
        assert "isDebuggerConnected" in res.vectors["anti_debugging"].detected_indicators
        assert res.overall_score >= 0.0


def test_mobile_sbom_generator():
    generator = MobileSbomGenerator(app_name="SecureBankApp", app_version="2.4.0")
    generator.add_component(
        name="okhttp",
        version="4.10.0",
        purl="pkg:maven/com.squareup.okhttp3/okhttp@4.10.0",
        licenses=["Apache-2.0"],
    )
    generator.add_component(
        name="libnativecrypto.so",
        version="1.0.0",
        purl="pkg:generic/libnativecrypto.so@1.0.0",
        component_type="operating-system",
    )

    cyclonedx = generator.generate_cyclonedx_json()
    assert cyclonedx["bomFormat"] == "CycloneDX"
    assert cyclonedx["specVersion"] == "1.5"
    assert len(cyclonedx["components"]) == 2

    spdx = generator.generate_spdx_json()
    assert spdx["spdxVersion"] == "SPDX-2.3"
    assert len(spdx["packages"]) == 2


def test_exploit_poc_synthesizer():
    from mobileag.reporting.finding import Finding, Severity, FindingStatus
    from mobileag.generators.poc_apk_synthesizer import ExploitPocSynthesizer

    finding = Finding(
        id="INTENT_REDIRECTION_10",
        title="Unsafe Intent Redirection",
        description="Nested Intent proxying flaw",
        severity=Severity.HIGH,
        status=FindingStatus.UNVERIFIED,
        cwe_id="CWE-926",
        file_path="VulnerableActivity.java",
        line_number=10,
        metadata={"component_name": "com.target.app.ProxyActivity"},
    )

    synthesizer = ExploitPocSynthesizer()
    poc = synthesizer.synthesize(finding, target_package="com.target.app")

    assert poc is not None
    assert poc.vulnerability_type == "Intent Redirection"
    assert "adb shell am start" in poc.adb_command
    assert "class ExploitActivity" in poc.kotlin_exploit_code
    assert "com.target.app" in poc.kotlin_exploit_code


def test_deeplink_fuzzer_mutations():
    from mobileag.dast.deeplink_intent_fuzzer import DeepLinkIntentFuzzer

    fuzzer = DeepLinkIntentFuzzer()
    mutations = fuzzer.generate_mutations("myapp://oauth/callback?code=123&redirect=home")

    assert len(mutations) > 5
    assert any("https://attacker.com" in m for m in mutations)
    assert any("javascript:" in m for m in mutations)


def test_mobile_api_cataloger():
    from mobileag.dast.api_cataloger import MobileApiCataloger, CapturedRequest

    cataloger = MobileApiCataloger(title="TestApp Backend", version="2.0")
    req1 = CapturedRequest(
        method="GET",
        url="https://api.testapp.com/v1/users?page=1",
        query_params={"page": "1"},
        response_status=200,
    )
    req2 = CapturedRequest(
        method="POST",
        url="https://api.testapp.com/v1/auth/login",
        body='{"username": "admin"}',
        response_status=200,
    )

    cataloger.ingest_request(req1)
    cataloger.ingest_request(req2)

    spec = cataloger.export_openapi_json()
    assert spec["openapi"] == "3.0.0"
    assert "/v1/users" in spec["paths"]
    assert "get" in spec["paths"]["/v1/users"]
    assert "/v1/auth/login" in spec["paths"]
    assert "post" in spec["paths"]["/v1/auth/login"]

