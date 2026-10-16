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
from mobileag.reporting.finding import Severity


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
        assert auditor.coverage["static_status"] == "analyzed_heuristically"
        # pi1 should be flagged for missing mutability flags
        unspecified = [f for f in findings if "PENDING_INTENT_MUTABLE_UNSPECIFIED" in f.id]
        assert len(unspecified) == 1

        # pi3 should be flagged for explicit FLAG_MUTABLE
        mutable = [f for f in findings if "PENDING_INTENT_EXPLICIT_MUTABLE" in f.id]
        assert len(mutable) == 1


def test_pending_intent_parser_handles_multiline_nested_calls_and_ignores_comments(tmp_path):
    path = tmp_path / "Sample.kt"
    path.write_text('''
        // PendingIntent.getActivity(ctx, 0, intent, 0) -- comment only
        val text = "PendingIntent.getActivity(ctx, 0, i, 0)"
        val missing = PendingIntent.getActivity(
            ctx,
            requestCode,
            Intent(ctx, Target::class.java).apply { putExtra("x", nested(1, 2)) },
            0
        )
        val immutable = PendingIntent.getBroadcast(ctx, 0, intent,
            PendingIntent.FLAG_IMMUTABLE)
    ''')
    findings = PendingIntentAuditor().audit_file(path)
    assert len(findings) == 1
    assert findings[0].line_number == 4
    assert PendingIntentAuditor().audit_file(tmp_path / "missing.kt") == []


def test_pending_intent_review_uses_parsed_target_sdk_without_claiming_exploitability(tmp_path):
    path = tmp_path / "Pending.java"
    path.write_text("PendingIntent p = PendingIntent.getActivity(ctx, 0, intent, 0);")
    auditor = PendingIntentAuditor()
    current_target = auditor.audit_file(path, target_sdk=35)
    legacy_target = auditor.audit_file(path, target_sdk=30)
    unknown_target = auditor.audit_file(path)

    assert len(current_target) == len(legacy_target) == len(unknown_target) == 1
    assert current_target[0].severity == Severity.INFO
    assert current_target[0].cwe_id == "CWE-Unknown"
    assert current_target[0].metadata == {"target_sdk": 35, "review_kind": "compatibility_lead"}
    assert "not evidence that a mutable token was created or exploitable" in current_target[0].description
    assert legacy_target[0].cwe_id == "CWE-927"
    assert legacy_target[0].metadata["target_sdk"] == 30
    assert unknown_target[0].metadata["target_sdk"] is None


def test_pending_intent_directory_scan_is_bounded_and_skips_symlinks(tmp_path):
    outside = tmp_path.parent / "pending-intent-outside.java"
    outside.write_text("PendingIntent.getActivity(ctx, 0, intent, 0);")
    (tmp_path / "Link.java").symlink_to(outside)
    (tmp_path / "Large.kt").write_bytes(b"x" * (2 * 1024 * 1024 + 1))
    (tmp_path / "Local.java").write_text("PendingIntent.getBroadcast(ctx, 0, intent, 0);")

    auditor = PendingIntentAuditor()
    findings = auditor.audit_directory(tmp_path)

    assert len(findings) == 1
    assert findings[0].file_path.endswith("Local.java")
    assert auditor.coverage["static_status"] == "partial"
    assert auditor.coverage["source_files_skipped"] == 2
    assert auditor.coverage["source_file_skip_reasons"] == {
        "symlink_entry": 1, "file_size_limit": 1,
    }


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
        assert findings[0].severity == "INFO"
        assert findings[0].metadata["method_scope"] == "not_resolved"
        assert "does not resolve" in findings[0].description
        assert auditor.coverage["static_status"] == "analyzed_heuristically"


def test_intent_redirection_does_not_match_launch_before_later_extraction(tmp_path):
    source = tmp_path / "WrongOrder.java"
    source.write_text('''class Proxy {
        void launchFirst() { startActivity(forwardIntent); }
        void extractLater() { Intent forwardIntent = getIntent().getParcelableExtra("nested"); }
    }''')

    auditor = IntentRedirectionAuditor()
    assert auditor.audit_file(source) == []
    assert auditor.audit_file(tmp_path / "missing.java") == []


def test_intent_redirection_directory_scan_is_bounded_and_skips_symlinks(tmp_path):
    target = tmp_path.parent / "intent-redirection-outside.java"
    target.write_text('''class Outside {
      void open() { Intent next = getIntent().getParcelableExtra("next"); startActivity(next); }
    }''')
    (tmp_path / "link.java").symlink_to(target)
    (tmp_path / "large.java").write_bytes(b"x" * (2 * 1024 * 1024 + 1))

    auditor = IntentRedirectionAuditor()
    assert auditor.audit_directory(tmp_path) == []
    assert auditor.coverage["static_status"] == "partial"
    assert auditor.coverage["source_files_skipped"] == 2
    assert auditor.coverage["source_file_skip_reasons"] == {
        "symlink_entry": 1, "file_size_limit": 1,
    }


def test_flutter_engine_analyzer():
    with tempfile.TemporaryDirectory() as tmp_dir:
        lib_dir = os.path.join(tmp_dir, "lib", "arm64-v8a")
        os.makedirs(lib_dir)

        # Simulate libapp.so with embedded strings
        dummy_content = (b"\x00" * 100 + b"https://api.example.com/v1/auth" + b"\x00" * 50
                         + b"/dashboard" + b"\x00" + b'apiKey: "synthetic-secret-value-123"')
        with open(os.path.join(lib_dir, "libapp.so"), "wb") as f:
            f.write(dummy_content)

        analyzer = FlutterEngineAnalyzer()
        res = analyzer.analyze_package_directory(tmp_dir)

        assert res.is_flutter_app is True
        assert res.libapp_present is True
        assert "https://api.example.com/v1/auth" in res.api_endpoints
        assert "/dashboard" in res.named_routes
        assert res.potential_secrets == [{"name": "embedded credential", "value_redacted": True}]
        assert "synthetic-secret-value-123" not in repr(res.potential_secrets)
        assert res.scan_status == "complete"


def test_flutter_analyzer_reports_bounded_binary_truncation_and_skips_symlinks():
    with tempfile.TemporaryDirectory() as tmp_dir, tempfile.TemporaryDirectory() as outside_dir:
        root = Path(tmp_dir)
        lib = root / "lib" / "arm64-v8a"
        lib.mkdir(parents=True)
        outside = Path(outside_dir) / "libapp.so"
        outside.write_bytes(b"https://external.example.invalid/not-in-tree")
        other_abi = root / "lib" / "x86_64"
        other_abi.mkdir()
        (other_abi / "libapp.so").symlink_to(outside)
        binary = lib / "libapp.so"
        binary.write_bytes(b"x" * 32 + b"https://late.example.invalid/endpoint")
        analyzer = FlutterEngineAnalyzer()
        analyzer.MAX_BINARY_BYTES = 16
        result = analyzer.analyze_package_directory(root)

    assert result.libapp_present is True
    assert result.api_endpoints == []
    assert result.binary_truncated is True
    assert result.binary_bytes_scanned == 16
    assert result.scan_status == "partial"
    assert "symlink_entry_skipped" in result.scan_errors


def test_flutter_analyzer_enforces_aggregate_binary_byte_budget():
    with tempfile.TemporaryDirectory() as tmp_dir:
        root = Path(tmp_dir)
        for abi in ("arm64-v8a", "x86_64"):
            lib = root / "lib" / abi
            lib.mkdir(parents=True)
            (lib / "libapp.so").write_bytes(b"A" * 8)
        analyzer = FlutterEngineAnalyzer()
        analyzer.MAX_BINARY_BYTES = 100
        analyzer.MAX_TOTAL_BINARY_BYTES = 10

        result = analyzer.analyze_package_directory(root)

    assert result.binary_bytes_scanned == 10
    assert result.binary_truncated is True
    assert result.scan_status == "partial"
    assert "total_binary_byte_limit" in result.scan_errors


def test_flutter_inventory_uses_shared_entry_cap_and_rejects_symlinked_asset_parent(tmp_path):
    root = tmp_path / "bounded"
    (root / "lib" / "arm64-v8a").mkdir(parents=True)
    (root / "lib" / "arm64-v8a" / "libapp.so").write_bytes(b"synthetic")
    external = tmp_path / "external-assets" / "flutter_assets"
    external.mkdir(parents=True)
    (external / "AssetManifest.json").write_text("{}", encoding="utf-8")
    (root / "assets").symlink_to(external.parent, target_is_directory=True)
    analyzer = FlutterEngineAnalyzer()
    analyzer.MAX_TREE_ENTRIES = 1

    result = analyzer.analyze_package_directory(root)

    assert result.scan_status == "partial"
    assert result.tree_entries_scanned == 1
    assert "tree_entry_limit" in result.scan_errors
    assert "symlink_asset_directory_skipped" in result.scan_errors


def test_flutter_analyzer_caps_printable_strings_and_candidates_with_partial_status():
    with tempfile.TemporaryDirectory() as tmp_dir:
        lib = Path(tmp_dir) / "lib" / "arm64-v8a"
        lib.mkdir(parents=True)
        binary = lib / "libapp.so"
        binary.write_bytes(
            b"https://one.example.invalid/a\x00https://two.example.invalid/b\x00"
            b"https://three.example.invalid/c\x00"
        )
        analyzer = FlutterEngineAnalyzer()
        analyzer.MAX_PRINTABLE_STRINGS_PER_BINARY = 2
        analyzer.MAX_ENDPOINTS = 1

        result = analyzer.analyze_package_directory(tmp_dir)

    assert result.extracted_strings_count == 2
    assert len(result.api_endpoints) == 1
    assert result.candidate_output_truncated is True
    assert result.scan_status == "partial"
    assert {"endpoint_candidate_limit", "printable_string_limit"} <= set(result.scan_errors)


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
        assert res.overall_score is None
        assert res.grade == "Not validated"
        assert res.vectors["control_flow"].score is None
        assert res.vectors["control_flow"].passed is None
        assert "not implemented" in res.vectors["control_flow"].detected_indicators[0].lower()
        assert all(v.score is None and v.passed is None for v in res.vectors.values())
        assert res.vectors["string_encryption"].detected_indicators[0].endswith("encryption not inferred")
        assert res.coverage["static_status"] == "analyzed_heuristically"
        assert res.coverage["source_files_analyzed"] == 1


def test_rasp_resilience_inventory_bounds_oversized_smali(tmp_path):
    oversized = tmp_path / "Huge.smali"
    oversized.write_bytes(b".class public Lfixture/Huge;\n" + b"x" * (2 * 1024 * 1024))

    result = RaspResilienceAuditor().audit_package(tmp_path)

    assert result.coverage["static_status"] == "partial"
    assert result.coverage["source_files_analyzed"] == 0
    assert result.coverage["source_files_skipped"] == 1
    assert result.coverage["source_file_skip_reasons"]["file_size_limit"] == 1


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

    # A detection alone is not sufficient authority to emit executable guidance.
    assert poc is None


def test_poc_requires_artifact_bound_analyst_attestation():
    from mobileag.reporting.finding import Finding, Severity, FindingStatus
    from mobileag.generators.poc_apk_synthesizer import ExploitPocSynthesizer

    record = {
        "artifact_sha256": "a" * 64, "package_name": "com.target.app",
        "app_version": "1.0", "os_build": "Android synthetic test build",
        "attacker_context": "ordinary_app", "entry_point": "synthetic exported activity",
        "attacker_control": "researcher controlled input", "sensitive_sink": "synthetic canary",
        "security_boundary": "synthetic app boundary", "observed_impact": "canary observed",
        "reproduction_steps": ["launch test app", "observe canary"],
        "positive_control": "positive fixture", "negative_control": "negative fixture",
        "evidence_refs": ["fixture:positive"], "unprivileged_attacker_confirmed": True,
        "unmodified_authorization_confirmed": True, "synthetic_data_confirmed": True,
        "scope_confirmed": True,
    }
    finding = Finding(
        id="INTENT_REDIRECTION_SYNTHETIC", title="Synthetic intent issue", description="test",
        severity=Severity.HIGH, status=FindingStatus.CONFIRMED, cwe_id="CWE-926",
        validation_evidence={"basis": "analyst_attested", "independently_verified": False,
                             "active": True, "record": record},
    )
    poc = ExploitPocSynthesizer().synthesize(finding, "com.target.app")
    assert poc is not None
    assert "analyst" not in poc.explanation.lower()  # output is not itself confirmation
    assert ExploitPocSynthesizer().synthesize(finding, "com.other.app") is None


def test_deeplink_fuzzer_mutations():
    from urllib.parse import parse_qs, urlsplit
    from mobileag.dast.deeplink_intent_fuzzer import DeepLinkIntentFuzzer

    fuzzer = DeepLinkIntentFuzzer()
    mutations = fuzzer.generate_mutations("myapp://oauth/callback?code=123&redirect=home")

    assert len(mutations) > 5
    decoded_values = [value for mutation in mutations[1:]
                      for values in parse_qs(urlsplit(mutation).query).values() for value in values]
    assert "https://attacker.com" in decoded_values
    assert "javascript:alert(document.domain)" in decoded_values
    assert all(set(parse_qs(urlsplit(mutation).query)) == {"code", "redirect"}
               for mutation in mutations[1:])


def test_deeplink_fuzzer_generation_is_bounded_and_rejects_malformed_inputs():
    from mobileag.dast.deeplink_intent_fuzzer import DeepLinkIntentFuzzer

    fuzzer = DeepLinkIntentFuzzer()
    assert fuzzer.generate_mutations("x" * (fuzzer.MAX_URI_LENGTH + 1)) == []
    assert fuzzer.generate_mutations("https://[malformed/path?x=y") == []
    assert fuzzer.generate_mutations("https://api.example.test:70000/path?x=y") == []
    too_many = "&".join(f"q{i}=x" for i in range(fuzzer.MAX_QUERY_FIELDS + 1))
    assert fuzzer.generate_mutations(f"myapp://host/path?{too_many}") == []
    assert len(fuzzer.generate_mutations("myapp://host/path")) <= fuzzer.MAX_MUTATIONS


def test_deeplink_fuzzer_requires_explicit_device_and_scope_guard(monkeypatch):
    import io
    import shlex
    import subprocess
    from mobileag.dast.deeplink_intent_fuzzer import DeepLinkIntentFuzzer

    called = []
    class FakeProcess:
        def __init__(self, *args, **kwargs):
            called.append((args, kwargs))
            self.stdout = io.BytesIO(b"Status: ok synthetic-private-data " + b"x" * 100_000)
            self.stderr = io.BytesIO(b"")
        def wait(self, timeout=None):
            return 0
        def kill(self):
            pass

    monkeypatch.setattr(subprocess, "Popen", FakeProcess)
    fuzzer = DeepLinkIntentFuzzer()
    assert fuzzer.execute_fuzz_case("https://example.test/path").status == "BLOCKED_SCOPE"
    assert fuzzer.execute_fuzz_case(
        "https://example.test/path", serial="device-1", guard=lambda: None
    ).status == "SUCCESS"
    args, _ = called[0]
    assert args[0][:3] == ["adb", "-s", "device-1"]
    result = fuzzer.execute_fuzz_case(
        "https://example.test/path", serial="device-1", guard=lambda: None
    )
    assert result.status == "SUCCESS"
    assert result.output_truncated is True
    assert result.output_bytes_observed > 100_000
    assert result.logcat_errors == []

    injection_shaped_uri = "myapp://host/path?next=x; touch /tmp/mobileag-not-run"
    assert fuzzer.execute_fuzz_case(
        injection_shaped_uri, serial="device-1", guard=lambda: None
    ).status == "SUCCESS"
    args, _ = called[2]
    remote_args = shlex.split(args[0][4])
    assert remote_args[-2:] == ["-d", injection_shaped_uri]

    def deny():
        raise PermissionError("scope revoked")

    assert fuzzer.execute_fuzz_case(
        "https://example.test/path", serial="device-1", guard=deny
    ).status == "BLOCKED_SCOPE"
    assert len(called) == 3


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

