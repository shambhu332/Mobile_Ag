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
    assert current_target[0].metadata == {
        "target_sdk": 35, "review_kind": "compatibility_lead",
        "flags_resolution": "literal_or_constant",
    }
    assert "not evidence that a mutable token was created or exploitable" in current_target[0].description
    assert legacy_target[0].cwe_id == "CWE-927"
    assert legacy_target[0].metadata["target_sdk"] == 30
    assert unknown_target[0].metadata["target_sdk"] is None


def test_pending_intent_auditor_resolves_bounded_flag_aliases_and_withholds_unknowns(tmp_path):
    java = tmp_path / "Flags.java"
    java.write_text('''class Flags {
        private static final int BASE = PendingIntent.FLAG_IMMUTABLE;
        private static final int IMMUTABLE = BASE | 0;
        void create() {
            PendingIntent.getActivity(ctx, 0, intent, IMMUTABLE);
            int dynamic = chooseFlags();
            PendingIntent.getBroadcast(ctx, 0, intent, dynamic);
        }
    }''')
    findings = PendingIntentAuditor().audit_file(java, target_sdk=35)
    assert len(findings) == 1
    assert findings[0].id.startswith("PENDING_INTENT_FLAGS_UNRESOLVED_")
    assert findings[0].metadata["review_kind"] == "flags_unresolved"
    assert findings[0].cwe_id == "CWE-Unknown"

    kotlin = tmp_path / "Flags.kt"
    kotlin.write_text('''class Flags {
        companion object {
            const val IMMUTABLE: Int = PendingIntent.FLAG_IMMUTABLE
        }
        fun create() {
            PendingIntent.getBroadcast(ctx, 0, intent, IMMUTABLE)
        }
    }''')
    assert PendingIntentAuditor().audit_file(kotlin) == []


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
        assert findings[0].metadata["method_scope"] == "bounded_lexical"
        assert findings[0].metadata["method_name"] == "onCreate"
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


def test_intent_redirection_does_not_join_sources_and_sinks_across_methods(tmp_path):
    source = tmp_path / "SeparateMethods.java"
    source.write_text('''class Proxy {
        void extract() {
            Intent target = getIntent().getParcelableExtra("nested");
        }
        void launch() {
            startActivity(target);
        }
    }''')

    assert IntentRedirectionAuditor().audit_file(source) == []


def test_intent_redirection_ignores_comment_and_string_lookalikes(tmp_path):
    source = tmp_path / "LexicalLookalikes.java"
    source.write_text('''class Proxy {
        void open() {
            // Intent next = getIntent().getParcelableExtra("nested");
            String example = "Intent next = getIntent().getParcelableExtra(\\"x\\"); startActivity(next);";
            // startActivity(next);
        }
    }''')

    assert IntentRedirectionAuditor().audit_file(source) == []


def test_intent_redirection_tracks_only_direct_local_alias_copies(tmp_path):
    source = tmp_path / "LocalAlias.java"
    source.write_text('''class Proxy {
        void directAlias() {
            Intent target = getIntent().getParcelableExtra("nested");
            Intent forwarded = target;
            startActivity(forwarded);
        }
        void aliasAfterTrustedOverwrite() {
            Intent target = getIntent().getParcelableExtra("nested");
            target = new Intent();
            Intent forwarded = target;
            startActivity(forwarded);
        }
    }''')

    findings = IntentRedirectionAuditor().audit_file(source)
    assert len(findings) == 1
    assert findings[0].line_number == 5
    assert findings[0].metadata["alias_analysis"] == "direct_local_copy_only"


def test_intent_redirection_candidate_is_invalidated_by_reassignment(tmp_path):
    source = tmp_path / "Reassignment.java"
    source.write_text('''class Proxy {
        void trustedReplacement() {
            Intent next = getIntent().getParcelableExtra("nested");
            next = new Intent();
            startActivity(next);
        }
        void laterUntrustedValue() {
            Intent next = new Intent();
            next = getIntent().getParcelableExtra("nested");
            startActivity(next);
        }
    }''')

    findings = IntentRedirectionAuditor().audit_file(source)
    assert len(findings) == 1
    assert findings[0].line_number == 10
    assert findings[0].metadata["reassignment_analysis"] == "linewise_bounded"


def test_intent_redirection_recognizes_bounded_typed_parcelable_forms(tmp_path):
    source = tmp_path / "TypedParcelable.java"
    source.write_text('''class Proxy {
        void javaCast() {
            Intent target = (Intent) getIntent().getParcelableExtra("nested");
            startActivity(target);
        }
        fun kotlinGeneric() {
            val other: Intent = intent.getParcelableExtra<Intent>("nested")
            startActivity(other)
        }
    }''')

    findings = IntentRedirectionAuditor().audit_file(source)
    assert len(findings) == 2
    assert [finding.metadata["source_line"] for finding in findings] == [3, 7]


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
                         + b"https://api.example.com/v1/auth/token/synthetic-private-token" + b"\x00"
                         + b"/dashboard" + b"\x00" + b'apiKey: "synthetic-secret-value-123"')
        with open(os.path.join(lib_dir, "libapp.so"), "wb") as f:
            f.write(dummy_content)

        analyzer = FlutterEngineAnalyzer()
        res = analyzer.analyze_package_directory(tmp_dir)

        assert res.is_flutter_app is True
        assert res.libapp_present is True
        assert "https://api.example.com/v1/auth" in res.api_endpoints
        assert "https://api.example.com/v1/auth/token/{id}" in res.api_endpoints
        assert "synthetic-private-token" not in repr(res.api_endpoints)
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


def test_rasp_resilience_auditor_ignores_bare_su_substrings(tmp_path):
    smali = tmp_path / "Ordinary.smali"
    smali.write_text(
        ".class public Lfixture/Ordinary;\n"
        ".super Ljava/lang/Object;\n"
        ".method public result()V\n"
        "    const-string v0, \"subscription result\"\n"
        ".end method\n",
        encoding="utf-8",
    )

    result = RaspResilienceAuditor().audit_package(tmp_path)

    assert "su" not in result.vectors["root_detection"].detected_indicators
    assert result.vectors["root_detection"].detected_indicators == [
        "No root-related indicator strings found in scanned Smali"
    ]


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


def test_sbom_rejects_malformed_hash_metadata():
    import pytest
    generator = MobileSbomGenerator()
    with pytest.raises(ValueError, match="Invalid or unsupported SBOM digest"):
        generator.add_component("native", "1", "pkg:generic/native", hashes={"SHA-256": "abc"})
    generator.add_component("native", "1", "pkg:generic/native", hashes={"sha256": "A" * 64})
    assert generator.generate_cyclonedx_json()["components"][0]["hashes"] == [
        {"alg": "SHA-256", "content": "a" * 64}
    ]


def test_sbom_normalizes_and_rejects_advisory_metadata():
    import pytest
    generator = MobileSbomGenerator()
    purl = "pkg:generic/native"
    generator.add_component("native", "1", purl)
    generator.add_vulnerability("OSV-2025-123", purl, "Synthetic advisory", "MODERATE", ["cwe-79"])
    item = generator.generate_cyclonedx_json()["vulnerabilities"][0]
    assert item["ratings"][0]["severity"] == "medium"
    assert item["cwes"] == [79]
    with pytest.raises(ValueError, match="severity"):
        generator.add_vulnerability("OSV-2025-123", purl, severity="severe")
    with pytest.raises(ValueError, match="CWE"):
        generator.add_vulnerability("OSV-2025-123", purl, cwe_ids=["CWE-79<script>"])


def test_sbom_component_metadata_is_bounded_and_typed():
    import pytest
    with pytest.raises(ValueError, match="application name"):
        MobileSbomGenerator("", "1")
    generator = MobileSbomGenerator()
    with pytest.raises(ValueError, match="component type"):
        generator.add_component("native", "1", "pkg:generic/native", component_type="injected")
    with pytest.raises(ValueError, match="package URL"):
        generator.add_component("native", "1", "pkg:generic/bad name")
    generator.add_component("Bank App", "1.0 beta", "pkg:generic/Bank%20App@1.0%20beta")


def test_sbom_purls_are_reference_parsed_canonical_and_unambiguous():
    import pytest
    from mobileag.analysis.sbom_generator import build_package_url, normalize_package_url

    built = build_package_url("maven", namespace="org.example", name="demo app", version="1.0 beta")
    assert built == "pkg:maven/org.example/demo%20app@1.0%20beta"
    assert normalize_package_url("pkg:generic/lib/arm64-v8a/libsample.so") == \
        "pkg:generic/lib/arm64-v8a/libsample.so"
    for malformed in (
        "pkg:", "https://example.invalid/pkg", "pkg:generic/@1", "pkg:generic/name%ZZ",
        "pkg:generic/name?arch=arm64&arch=x86_64", "pkg:generic/name?bad qualifier=value",
    ):
        with pytest.raises(ValueError, match="package URL|Package URL"):
            normalize_package_url(malformed)

    generator = MobileSbomGenerator()
    with pytest.raises(ValueError, match="duplicate qualifier"):
        generator.add_component("bad", "1", "pkg:generic/name?arch=arm64&arch=x86_64")


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
    assert ExploitPocSynthesizer().synthesize(finding, None) is None
    assert ExploitPocSynthesizer().synthesize(finding, "x" * 256) is None
    injected = finding.model_copy(update={"metadata": {"component_name": 'com.target.app.Proxy";id'}})
    assert ExploitPocSynthesizer().synthesize(injected, "com.target.app") is None
    # Kotlin string interpolation syntax must not pass through component validation.
    interpolation = finding.model_copy(update={"metadata": {"component_name": "com.target.app/Proxy$Payload"}})
    assert ExploitPocSynthesizer().synthesize(interpolation, "com.target.app") is None
    injection_cases = [
        ("component_name", 'com.target.app/Proxy";id'),
        ("authority", 'com.target.app.provider";id'),
        ("task_affinity", "com.target.app\n// injected"),
        ("uri_scheme", 'myapp://host/path";id'),
    ]
    for key, value in injection_cases:
        hostile = finding.model_copy(update={"metadata": {key: value}})
        assert ExploitPocSynthesizer().synthesize(hostile, "com.target.app") is None
    hostile_target = finding.model_copy(update={"affected_component": 'com.target.app.Login";id'})
    assert ExploitPocSynthesizer().synthesize(hostile_target, "com.target.app") is None
    hostile_id = finding.model_copy(update={"id": 'INTENT_REDIRECTION\n";id'})
    assert ExploitPocSynthesizer().synthesize(hostile_id, "com.target.app") is None


def test_generated_poc_templates_are_synthetic_canary_only_and_review_only():
    from mobileag.reporting.finding import Finding, Severity, FindingStatus
    from mobileag.generators.poc_apk_synthesizer import ExploitPocSynthesizer

    package = "com.target.app"
    record = {
        "artifact_sha256": "a" * 64, "package_name": package,
        "app_version": "1.0", "os_build": "Android synthetic test build",
        "attacker_context": "ordinary_app", "entry_point": "synthetic fixture",
        "attacker_control": "researcher controlled input", "sensitive_sink": "synthetic canary",
        "security_boundary": "synthetic app boundary", "observed_impact": "canary observed",
        "reproduction_steps": ["run owned fixture", "observe canary"],
        "positive_control": "positive fixture", "negative_control": "negative fixture",
        "evidence_refs": ["fixture:positive"], "unprivileged_attacker_confirmed": True,
        "unmodified_authorization_confirmed": True, "synthetic_data_confirmed": True,
        "scope_confirmed": True,
    }
    evidence = {"basis": "analyst_attested", "independently_verified": False,
                "active": True, "record": record}
    cases = [
        ("INTENT_REDIRECTION_SYNTHETIC", "CWE-926", "intent", {"component_name": f"{package}.Proxy"}),
        ("DEEP_LINK_SYNTHETIC", "CWE-601", "deep link", {}),
        ("PENDING_INTENT_SYNTHETIC", "CWE-927", "pending intent", {}),
        ("FILEPROVIDER_SYNTHETIC", "CWE-22", "file provider", {"authority": f"{package}.files"}),
        ("TASK_AFFINITY_SYNTHETIC", "CWE-1021", "task affinity", {"task_affinity": f"{package}.task"}),
        ("CONTENT_PROVIDER_SQLI_SYNTHETIC", "CWE-89", "content provider", {"authority": f"{package}.provider"}),
    ]
    synth = ExploitPocSynthesizer()
    generated = {}
    for fid, cwe, title, metadata in cases:
        finding = Finding(id=fid, title=title, description="synthetic test", severity=Severity.HIGH,
                          status=FindingStatus.CONFIRMED, cwe_id=cwe, metadata=metadata,
                          validation_evidence=evidence)
        generated[fid] = synth.synthesize(finding, package)
        assert generated[fid] is not None
        assert not generated[fid].adb_command.lstrip().startswith("adb ")

    intent = generated["INTENT_REDIRECTION_SYNTHETIC"].kotlin_exploit_code
    assert "MOBILEAG_SYNTHETIC_CANARY" in intent
    assert "admin_override" not in intent and "PrivateActivity" not in intent
    deep_link = generated["DEEP_LINK_SYNTHETIC"]
    assert "mobileag.invalid" in deep_link.explanation
    pending = generated["PENDING_INTENT_SYNTHETIC"].kotlin_exploit_code
    assert "MOBILEAG_SYNTHETIC_CANARY" in pending
    assert ".send(" not in pending and "GRANT_ALL" not in pending
    file_provider = generated["FILEPROVIDER_SYNTHETIC"].kotlin_exploit_code
    assert "mobileag-fixtures/canary.txt" in file_provider
    assert "ByteArray(64)" in file_provider and "readText()" not in file_provider
    assert "app.db" not in file_provider and "Stolen Database Content" not in file_provider
    task = generated["TASK_AFFINITY_SYNTHETIC"]
    assert "steal credentials" not in task.kotlin_exploit_code.lower()
    assert "No overlay" in task.explanation
    provider = generated["CONTENT_PROVIDER_SQLI_SYNTHETIC"].kotlin_exploit_code
    assert "MOBILEAG_SYNTHETIC_CANARY" in provider
    assert "Leaked Row" not in provider and "SELECT *" not in provider


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

    assert fuzzer.execute_fuzz_case(
        "https://example.test/path", serial="device-1", guard=lambda: False
    ).status == "BLOCKED_SCOPE"
    assert len(called) == 3

    async def async_allow():
        return True

    assert fuzzer.execute_fuzz_case(
        "https://example.test/path", serial="device-1", guard=async_allow
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
    assert spec["x-mobileag-proof-state"] == "not_proven"
    assert "not a complete backend contract" in spec["info"]["description"]
    assert "/v1/users" in spec["paths"]
    assert "get" in spec["paths"]["/v1/users"]
    assert "/v1/auth/login" in spec["paths"]
    assert "post" in spec["paths"]["/v1/auth/login"]


def test_mobile_api_cataloger_exports_graphql_operation_names_only():
    import json
    from mobileag.dast.api_cataloger import CapturedRequest, MobileApiCataloger

    catalog = MobileApiCataloger()
    catalog.ingest_request(CapturedRequest(
        method="POST", url="https://api.example.test/graphql",
        headers={"Content-Type": "application/json"},
        body=json.dumps({
            "query": ('# query HiddenByComment { viewer { id } }\n'
                      '"""query HiddenByDescription { notOperation }"""\n'
                      'query LoadProfile($id: ID!) { profile(id: $id) { id } }\n'
                      'mutation UpdateProfile { updateProfile { id } }'),
            "variables": {"access_token": "synthetic-secret-value"},
        }),
        response_status=200,
    ))

    spec = catalog.export_openapi_json()
    operation = spec["paths"]["/graphql"]["post"]
    candidates = operation["x-mobileag-graphql-operation-candidates"]
    assert [(item["operation_type"], item["operation_name"]) for item in candidates] == [
        ("query", "LoadProfile"), ("mutation", "UpdateProfile"),
    ]
    assert "synthetic-secret-value" not in json.dumps(spec)
    assert "HiddenByComment" not in json.dumps(spec)
    assert "HiddenByDescription" not in json.dumps(spec)
    limits = spec["x-mobileag-capture-limits"]
    assert limits["graphqlOperationCandidates"] == 2


def test_mobile_api_cataloger_rejects_ambiguous_graphql_query_json():
    from mobileag.dast.api_cataloger import CapturedRequest, MobileApiCataloger

    catalog = MobileApiCataloger()
    catalog.ingest_request(CapturedRequest(
        method="POST", url="https://api.example.test/graphql",
        body='{"query":"query First { viewer { id } }","query":"query Second { viewer { id } }"}',
        response_status=200,
    ))
    spec = catalog.export_openapi_json()
    assert "x-mobileag-graphql-operation-candidates" not in spec["paths"]["/graphql"]["post"]
    assert spec["x-mobileag-capture-limits"]["graphqlOperationCoverageGaps"] == 1


def test_mobile_api_cataloger_extracts_graphql_get_query_without_retaining_values():
    import json
    from urllib.parse import urlencode
    from mobileag.dast.api_cataloger import CapturedRequest, MobileApiCataloger

    query = 'query LoadProfile($id: ID!) { profile(id: $id) { id } }'
    url = "https://api.example.test/graphql?" + urlencode({"query": query})
    catalog = MobileApiCataloger()
    catalog.ingest_request(CapturedRequest("GET", url))

    spec = catalog.export_openapi_json()
    operation = spec["paths"]["/graphql"]["get"]
    assert operation["x-mobileag-graphql-operation-candidates"] == [{
        "operation_type": "query", "operation_name": "LoadProfile",
        "evidence_type": "observed_graphql_operation_candidate",
    }]
    serialized = json.dumps(spec)
    assert query not in serialized
    assert "$id" not in serialized


def test_mobile_api_cataloger_marks_repeated_graphql_get_query_ambiguous():
    from urllib.parse import urlencode
    from mobileag.dast.api_cataloger import CapturedRequest, MobileApiCataloger

    query = urlencode([("query", "query First { viewer { id } }"),
                       ("query", "query Second { viewer { id } }")])
    catalog = MobileApiCataloger()
    catalog.ingest_request(CapturedRequest("GET", "https://api.example.test/graphql?" + query))
    spec = catalog.export_openapi_json()
    assert "x-mobileag-graphql-operation-candidates" not in spec["paths"]["/graphql"]["get"]
    assert spec["x-mobileag-capture-limits"]["graphqlOperationCoverageGaps"] == 1


def test_mobile_api_cataloger_marks_oversized_graphql_document_as_coverage_gap():
    from mobileag.dast.api_cataloger import CapturedRequest, MobileApiCataloger

    catalog = MobileApiCataloger()
    catalog.ingest_request(CapturedRequest(
        "POST", "https://api.example.test/graphql",
        body='{"query":"' + (" " * (64 * 1024 + 1)) + '"}',
    ))
    spec = catalog.export_openapi_json()
    assert "x-mobileag-graphql-operation-candidates" not in spec["paths"]["/graphql"]["post"]
    assert spec["x-mobileag-capture-limits"]["graphqlOperationCoverageGaps"] == 1


def test_graphql_operation_candidates_ignore_operation_keyword_fields():
    from mobileag.analysis.graphql_candidates import extract_graphql_operation_candidates

    candidates, malformed, truncated = extract_graphql_operation_candidates(
        "query Load { query { value } mutation { value } subscription { value } }"
    )
    assert candidates == [{"operation_type": "query", "operation_name": "Load"}]
    assert malformed is False
    assert truncated is False


def test_mobile_api_cataloger_caps_graphql_candidates_and_counts_omissions(monkeypatch):
    import json
    from mobileag.dast import api_cataloger
    from mobileag.dast.api_cataloger import CapturedRequest, MobileApiCataloger

    monkeypatch.setattr(api_cataloger, "_MAX_GRAPHQL_OPERATION_CANDIDATES", 1)
    catalog = MobileApiCataloger()
    for path, name in (("first", "First"), ("second", "Second")):
        catalog.ingest_request(CapturedRequest(
            "POST", f"https://api.example.test/{path}",
            body=json.dumps({"query": f"query {name} {{ viewer {{ id }} }}"}),
        ))
    spec = catalog.export_openapi_json()
    assert sum(
        len(operation.get("x-mobileag-graphql-operation-candidates", []))
        for path in spec["paths"].values() for operation in path.values()
    ) == 1
    limits = spec["x-mobileag-capture-limits"]
    assert limits["graphqlOperationCandidates"] == 1
    assert limits["graphqlOperationCandidatesOmitted"] == 1

