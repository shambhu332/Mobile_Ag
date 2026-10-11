"""Unit tests for Advanced DAST & Taint modules:
- FridaRunner (SSL unpinning, crypto telemetry parsing, root bypass)
- DeepLinkFuzzer (bounded redirect, file, and JavaScript-scheme review markers)
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
    return TestClient(app, headers={"Authorization": "Bearer " + app.state.auth_token})


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
    assert res["status"] == "unavailable"  # ADB file writes are not instrumentation.


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
    assert "CWE-79" in cwes  # Inert JavaScript-scheme marker


@pytest.mark.asyncio
async def test_deeplink_fuzzer_runtime_fuzz():
    mock_adb = ADBManager()
    mock_adb.clear_logcat = AsyncMock(return_value=True)
    mock_adb._exec_cmd = AsyncMock(return_value=(0, b"Starting: Intent { act=android.intent.action.VIEW }\n", b""))
    target_logs=[
        "09-21 11:00:00.000 1234 1234 E AndroidRuntime: FATAL EXCEPTION: main",
        "09-21 11:00:00.001 1234 1234 E AndroidRuntime: Process: com.test.app, PID: 1234",
        "java.lang.NullPointerException: Null query parameter in DeepLinkActivity",
    ]
    mock_adb.get_logcat_dump = AsyncMock(side_effect=[[],target_logs]*5)

    fuzzer = DeepLinkFuzzer(adb=mock_adb)
    results, findings = await fuzzer.fuzz_deep_links("emulator-5554", "com.test.app", ["testapp://router"])
    assert len(results) >= 4
    assert len(findings) >= 1
    assert findings[0].cwe_id == "CWE-755"
    assert findings[0].status.value == "UNVERIFIED" and findings[0].cvss_score == 0


# =============================================================================
# 3. TaintEngine Tests (Static Source-to-Sink Dataflow)
# =============================================================================
def test_taint_engine_webview_navigation_uses_untrusted_content_classification():
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
    assert findings[0].cwe_id == "CWE-829"
    assert "Navigation" in findings[0].title
    assert "UXSS" not in findings[0].title
    assert "targetUrl" in findings[0].description


def test_taint_engine_javascript_evaluation_uses_xss_classification():
    source = '''class Handler { void render(Intent intent, WebView web) {
        String script = intent.getStringExtra("script");
        web.evaluateJavascript(script, null);
    } }'''
    findings = TaintEngine().analyze_source_content(source, "Handler.java")
    assert any(item.cwe_id == "CWE-79" and "JavaScript Evaluation" in item.title
               for item in findings)


def test_taint_engine_does_not_treat_arbitrary_json_getstring_as_untrusted_source():
    engine = TaintEngine()
    source_code = '''
    class Model { void render(JSONObject response, WebView web) {
        String value = response.getString("url");
        web.loadUrl("https://safe.invalid/" + value);
    } }
    '''
    assert engine.analyze_source_content(source_code, "Model.java") == []


def test_taint_engine_requires_intent_type_for_intent_extra_source():
    assigned_custom_method = '''class Model { void render(Response response, WebView web) {
        String value = response.getStringExtra("url"); web.loadUrl(value);
    } }'''
    assert not [item for item in TaintEngine().analyze_source_content(assigned_custom_method, "Model.java")
                if item.cwe_id == "CWE-829"]
    inline_custom_method = '''class Model { void render(Response response, WebView web) {
        web.loadUrl(response.getStringExtra("url"));
    } }'''
    assert not [item for item in TaintEngine().analyze_source_content(inline_custom_method, "Model.java")
                if item.cwe_id == "CWE-829"]
    inline_real_intent = '''class Handler { void render(Intent incoming, WebView web) {
        web.loadUrl(incoming.getStringExtra("url"));
    } }'''
    assert any(item.cwe_id == "CWE-829" for item in TaintEngine().analyze_source_content(
        inline_real_intent, "Handler.java"))
    fake_get_intent = '''class Model { void render(Response response, WebView web) {
        String value = response.getIntent().getStringExtra("url"); web.loadUrl(value);
    } }'''
    assert not [item for item in TaintEngine().analyze_source_content(fake_get_intent, "Model.java")
                if item.cwe_id == "CWE-829"]
    fake_get_intent_inline = '''class Model { void render(Response response, WebView web) {
        web.loadUrl(response.getIntent().getStringExtra("url"));
    } }'''
    assert not [item for item in TaintEngine().analyze_source_content(fake_get_intent_inline, "Model.java")
                if item.cwe_id == "CWE-829"]
    activity_get_intent = '''class Handler { void render(WebView web) {
        String value = getIntent().getStringExtra("url"); web.loadUrl(value);
    } }'''
    assert any(item.cwe_id == "CWE-829" for item in TaintEngine().analyze_source_content(
        activity_get_intent, "Handler.java"))
    direct_inline = '''class Handler { void render(WebView web) {
        web.loadUrl(getIntent().getStringExtra("url"));
    } }'''
    direct_inline_findings = TaintEngine().analyze_source_content(direct_inline, "Handler.java")
    assert any(item.cwe_id == "CWE-829" and item.metadata.get("source_kind") == "INTENT_EXTRA"
               for item in direct_inline_findings)
    qualified_activity = '''class Handler { void render(Activity activity, WebView web) {
        web.loadUrl(activity.getIntent().getStringExtra("url"));
    } }'''
    qualified_findings = TaintEngine().analyze_source_content(qualified_activity, "Handler.java")
    assert any(item.cwe_id == "CWE-829" and item.metadata.get("source_kind") == "INTENT_EXTRA"
               for item in qualified_findings)
    direct_intent_sink = '''class Handler { void launch() { startActivity(getIntent()); } }'''
    direct_intent_findings = TaintEngine().analyze_source_content(direct_intent_sink, "Handler.java")
    assert any(item.cwe_id == "CWE-927" and item.metadata.get("source_kind") == "INTENT_SOURCE"
               for item in direct_intent_findings)


def test_taint_engine_does_not_treat_textview_gettext_as_clipboard_input():
    source_code = '''
    class Ui { void render(TextView view, WebView web) {
        String value = view.getText().toString();
        web.loadUrl(value);
    } }
    '''
    assert not [finding for finding in TaintEngine().analyze_source_content(source_code, "Ui.java")
                if finding.cwe_id == "CWE-829"]


def test_taint_engine_retains_clipboard_named_gettext_source():
    source_code = '''
    class Ui { void render(ClipboardManager clipboard, WebView web) {
        CharSequence value = clipboard.getText();
        web.loadUrl(value.toString());
    } }
    '''
    findings = TaintEngine().analyze_source_content(source_code, "Ui.java")
    assert any(finding.cwe_id == "CWE-829" and finding.metadata.get("source_kind") == "CLIPBOARD_SOURCE"
               for finding in findings)


def test_taint_engine_requires_clipboard_type_for_clipboard_source_methods():
    assigned = '''class Model { void render(Response response, WebView web) {
        String value = response.getPrimaryClip().toString(); web.loadUrl(value);
    } }'''
    assert not [item for item in TaintEngine().analyze_source_content(assigned, "Model.java")
                if item.cwe_id == "CWE-829"]
    inline = '''class Model { void render(Response response, WebView web) {
        web.loadUrl(response.getPrimaryClip().toString());
    } }'''
    assert not [item for item in TaintEngine().analyze_source_content(inline, "Model.java")
                if item.cwe_id == "CWE-829"]


def test_taint_engine_recognizes_inline_clipboard_gettext_but_not_generic_gettext():
    clipboard = '''class Ui { void render(ClipboardManager clipManager, WebView web) {
        web.loadUrl(clipManager.getText().toString());
    } }'''
    finding = next(item for item in TaintEngine().analyze_source_content(clipboard, "Ui.java")
                   if item.cwe_id == "CWE-829")
    assert "inline_input_source" in finding.metadata["source_kind"]


def test_taint_engine_requires_intent_receiver_for_getdata_source():
    model = '''class Model { void render(Response response, WebView web) {
        String value = response.getData(); web.loadUrl(value);
    } }'''
    assert not [item for item in TaintEngine().analyze_source_content(model, "Model.java")
                if item.cwe_id == "CWE-829"]
    intent = '''class Handler { void render(Intent incomingIntent, WebView web) {
        Uri value = incomingIntent.getData(); web.loadUrl(value.toString());
    } }'''
    findings = TaintEngine().analyze_source_content(intent, "Handler.java")
    assert any(item.cwe_id == "CWE-829" and item.metadata.get("source_kind") == "INTENT_EXTRA"
               for item in findings)
    neutrally_named = '''class Handler { void render(Intent source, WebView web) {
        Uri value = source.getData();
        String target = value.getQueryParameter("next"); web.loadUrl(target);
    } }'''
    neutral_findings = TaintEngine().analyze_source_content(neutrally_named, "Handler.java")
    assert any(item.cwe_id == "CWE-829" and item.metadata.get("source_kind") == "URI_QUERY_PARAM"
               for item in neutral_findings)


def test_taint_engine_requires_intent_derived_uri_for_query_parameter():
    response = '''class Model { void render(Response response, WebView web) {
        String value = response.getQueryParameter("next"); web.loadUrl(value);
    } }'''
    assert not [item for item in TaintEngine().analyze_source_content(response, "Model.java")
                if item.cwe_id == "CWE-829"]
    uri = '''class Handler { void render(Intent incomingIntent, WebView web) {
        Uri deepLink = incomingIntent.getData();
        String value = deepLink.getQueryParameter("next"); web.loadUrl(value);
    } }'''
    findings = TaintEngine().analyze_source_content(uri, "Handler.java")
    assert any(item.cwe_id == "CWE-829" and item.metadata.get("source_kind") == "URI_QUERY_PARAM"
               for item in findings)
    inline = '''class Handler { void render(Intent intent, WebView web) {
        Uri route = intent.getData(); web.loadUrl(route.getQueryParameter("next"));
    } }'''
    inline_findings = TaintEngine().analyze_source_content(inline, "Handler.java")
    assert any(item.cwe_id == "CWE-829" and item.metadata.get("source_kind") == "URI_QUERY_PARAM"
               for item in inline_findings)

    summarized = '''class Handler {
        String query(Intent incomingIntent) {
            Uri deepLink = incomingIntent.getData(); return deepLink.getQueryParameter("next");
        }
        void render(Intent incomingIntent, WebView web) { web.loadUrl(query(incomingIntent)); }
    }'''
    summary_findings = TaintEngine().analyze_source_content(summarized, "Handler.java")
    assert any(item.metadata.get("source_kind") == "URI_QUERY_PARAM" for item in summary_findings)
    safe_summary = '''class Handler {
        String query(Intent incomingIntent) {
            Uri deepLink = incomingIntent.getData();
            deepLink = Uri.parse("https://safe.invalid/path?next=home");
            return deepLink.getQueryParameter("next");
        }
        void render(Intent incomingIntent, WebView web) { web.loadUrl(query(incomingIntent)); }
    }'''
    assert not [item for item in TaintEngine().analyze_source_content(safe_summary, "Handler.java")
                if item.cwe_id == "CWE-829"]
    shadowed_helper = '''class Handler {
        String query(Intent incomingIntent) {
            Uri deepLink = incomingIntent.getData();
            if (true) { Uri deepLink = Uri.parse("https://safe.invalid/path?next=home"); }
            return deepLink.getQueryParameter("next");
        }
        void render(Intent incomingIntent, WebView web) { web.loadUrl(query(incomingIntent)); }
    }'''
    assert any(item.cwe_id == "CWE-829" and item.metadata.get("source_kind") == "URI_QUERY_PARAM"
               for item in TaintEngine().analyze_source_content(shadowed_helper, "Handler.java"))
    constant = '''class Model { void render(WebView web) {
        Uri fixed = Uri.parse("https://safe.invalid/path?next=home");
        String value = fixed.getQueryParameter("next"); web.loadUrl(value);
    } }'''
    assert not [item for item in TaintEngine().analyze_source_content(constant, "Model.java")
                if item.cwe_id == "CWE-829"]
    parameter = '''class Model { void render(Uri internalRoute, WebView web) {
        String value = internalRoute.getQueryParameter("next"); web.loadUrl(value);
    } }'''
    assert not [item for item in TaintEngine().analyze_source_content(parameter, "Model.java")
                if item.cwe_id == "CWE-829"]


def test_intent_return_summary_requires_a_tainted_intent_argument():
    callback = '''class Handler {
        String read(Intent value) { return value.getStringExtra("url"); }
        void onNewIntent(Intent incoming, WebView web) { web.loadUrl(read(incoming)); }
    }'''
    assert any(item.cwe_id == "CWE-829" and item.metadata.get("source_kind") == "INTENT_EXTRA"
               for item in TaintEngine().analyze_source_content(callback, "Handler.java"))
    arbitrary = '''class Handler {
        String read(Intent value) { return value.getStringExtra("url"); }
        void render(WebView web) { web.loadUrl(read(new Intent())); }
    }'''
    assert not [item for item in TaintEngine().analyze_source_content(arbitrary, "Handler.java")
                if item.cwe_id == "CWE-829"]


def test_taint_does_not_flow_through_unknown_returning_call_but_tracks_identity_helper():
    constant_return = '''class Handler {
        String choose(String ignored) { return "https://safe.invalid/"; }
        void onNewIntent(Intent incoming, WebView web) {
            web.loadUrl(choose(incoming.getStringExtra("url")));
        }
    }'''
    assert not [item for item in TaintEngine().analyze_source_content(constant_return, "Handler.java")
                if item.cwe_id == "CWE-829"]
    identity = '''class Handler {
        String identity(String value) { return value; }
        void onNewIntent(Intent incoming, WebView web) {
            web.loadUrl(identity(incoming.getStringExtra("url")));
        }
    }'''
    assert any(item.cwe_id == "CWE-829" for item in TaintEngine().analyze_source_content(identity, "Handler.java"))
    identity_through_local = '''class Handler {
        String identity(String value) { String local = value; return local; }
        void onNewIntent(Intent incoming, WebView web) {
            web.loadUrl(identity(incoming.getStringExtra("url")));
        }
    }'''
    assert any(item.cwe_id == "CWE-829" for item in TaintEngine().analyze_source_content(
        identity_through_local, "Handler.java"))
    concatenation = '''class Handler {
        String prefix(String value) { return "https://" + value; }
        void onNewIntent(Intent incoming, WebView web) {
            web.loadUrl(prefix(incoming.getStringExtra("host")));
        }
    }'''
    concatenation_findings = TaintEngine().analyze_source_content(concatenation, "Handler.java")
    assert any(item.cwe_id == "CWE-829" and
               item.metadata.get("interprocedural_value_flow") == "same_file_tainted_return_summary"
               for item in concatenation_findings)
    multi_parameter = '''class Handler {
        String join(String prefix, String value) { return prefix + value; }
        void onNewIntent(Intent incoming, WebView web) {
            web.loadUrl(join("https://", incoming.getStringExtra("host")));
        }
    }'''
    assert any(item.cwe_id == "CWE-829" for item in TaintEngine().analyze_source_content(
        multi_parameter, "Handler.java"))
    mixed_alias_parameters = '''class Handler {
        String join(String prefix, String value) {
            String localPrefix = prefix;
            return localPrefix + value;
        }
        void onNewIntent(Intent incoming, WebView web) {
            web.loadUrl(join("https://", incoming.getStringExtra("host")));
        }
    }'''
    assert any(item.cwe_id == "CWE-829" for item in TaintEngine().analyze_source_content(
        mixed_alias_parameters, "Handler.java"))
    conditional_return = '''class Handler {
        String choose(boolean useInput, String fixed, String value) {
            return useInput ? value : fixed;
        }
        void onNewIntent(Intent incoming, WebView web) {
            web.loadUrl(choose(true, "https://safe.invalid/", incoming.getStringExtra("url")));
        }
    }'''
    assert any(item.cwe_id == "CWE-829" for item in TaintEngine().analyze_source_content(
        conditional_return, "Handler.java"))
    constant_arms = '''class Handler {
        String choose(boolean useInput, String value) {
            return useInput ? "https://safe.invalid/a" : "https://safe.invalid/b";
        }
        void onNewIntent(Intent incoming, WebView web) {
            web.loadUrl(choose(incoming.getBooleanExtra("flag", false), incoming.getStringExtra("url")));
        }
    }'''
    assert not [item for item in TaintEngine().analyze_source_content(constant_arms, "Handler.java")
                if item.cwe_id == "CWE-829"]
    transparent_transform = '''class Handler {
        String render(Uri route) { return route.toString(); }
        void onNewIntent(Intent incoming, WebView web) {
            Uri route = incoming.getData(); web.loadUrl(render(route));
        }
    }'''
    assert any(item.cwe_id == "CWE-829" for item in TaintEngine().analyze_source_content(
        transparent_transform, "Handler.java"))
    multiline_identity = '''class Handler {
        String identity(String value) { return value; }
        void onNewIntent(Intent incoming, WebView web) {
            web.loadUrl(identity(incoming.getStringExtra("url")));
        }
    }'''
    identity_finding = next(item for item in TaintEngine().analyze_source_content(
        multiline_identity, "Handler.java") if item.cwe_id == "CWE-829")
    assert "line 3" in identity_finding.description
    assert identity_finding.metadata["interprocedural_value_flow"] == "same_file_tainted_return_summary"


def test_taint_engine_uri_source_binding_dies_on_safe_reassignment():
    reassigned_before_read = '''class Handler { void render(Intent intent, WebView web) {
        Uri route = intent.getData();
        route = Uri.parse("https://safe.invalid/?next=home");
        String next = route.getQueryParameter("next"); web.loadUrl(next);
    } }'''
    assert not [item for item in TaintEngine().analyze_source_content(reassigned_before_read, "Handler.java")
                if item.cwe_id == "CWE-829"]
    extracted_before_reassignment = '''class Handler { void render(Intent intent, WebView web) {
        Uri route = intent.getData();
        String next = route.getQueryParameter("next");
        route = Uri.parse("https://safe.invalid/"); web.loadUrl(next);
    } }'''
    assert any(item.cwe_id == "CWE-829" and item.metadata.get("source_kind") == "URI_QUERY_PARAM"
               for item in TaintEngine().analyze_source_content(extracted_before_reassignment, "Handler.java"))
    reassigned_to_external_uri = '''class Handler { void render(Intent intent, Intent nextIntent, WebView web) {
        Uri route = intent.getData();
        route = nextIntent.getData();
        String next = route.getQueryParameter("next"); web.loadUrl(next);
    } }'''
    assert any(item.cwe_id == "CWE-829" and item.metadata.get("source_kind") == "URI_QUERY_PARAM"
               for item in TaintEngine().analyze_source_content(reassigned_to_external_uri, "Handler.java"))
    shadowed_local = '''class Handler { void render(Intent intent, WebView web) {
        Uri route = intent.getData();
        if (true) { Uri route = Uri.parse("https://safe.invalid/?next=home"); }
        String next = route.getQueryParameter("next"); web.loadUrl(next);
    } }'''
    assert any(item.cwe_id == "CWE-829" and item.metadata.get("source_kind") == "URI_QUERY_PARAM"
               for item in TaintEngine().analyze_source_content(shadowed_local, "Handler.java"))


def test_taint_engine_tracks_uri_path_components_but_not_generic_model_methods():
    uri = '''class Handler { void render(Intent intent, WebView web) {
        Uri incoming = intent.getData();
        String path = incoming.getPath();
        web.loadUrl(path);
    } }'''
    findings = TaintEngine().analyze_source_content(uri, "Handler.java")
    assert any(item.cwe_id == "CWE-829" and item.metadata.get("source_kind") == "URI_COMPONENT"
               for item in findings)
    inline = '''class Handler { void render(Intent intent, WebView web) {
        Uri incoming = intent.getData(); web.loadUrl(incoming.getPath());
    } }'''
    inline_findings = TaintEngine().analyze_source_content(inline, "Handler.java")
    assert any(item.cwe_id == "CWE-829" and item.metadata.get("source_kind") == "URI_COMPONENT"
               for item in inline_findings)
    helper = '''class Handler {
        String readPath(Intent intent) { Uri incoming = intent.getData(); return incoming.getPath(); }
        void render(Intent intent, WebView web) { web.loadUrl(readPath(intent)); }
    }'''
    helper_findings = TaintEngine().analyze_source_content(helper, "Handler.java")
    assert any(item.metadata.get("source_kind") == "URI_COMPONENT" for item in helper_findings)
    parameter_helper = '''class Handler {
        String readPath(Uri route) { return route.getQueryParameter("next"); }
        void render(Intent intent, WebView web) {
            Uri route = intent.getData(); web.loadUrl(readPath(route));
        }
    }'''
    parameter_findings = TaintEngine().analyze_source_content(parameter_helper, "Handler.java")
    assert any(item.cwe_id == "CWE-829" and item.metadata.get("source_kind") == "URI_QUERY_PARAM"
               for item in parameter_findings)
    safe_argument = '''class Handler {
        String readPath(Uri route) { return route.getQueryParameter("next"); }
        void render(WebView web) {
            Uri route = Uri.parse("https://safe.invalid/?next=home");
            web.loadUrl(readPath(route));
        }
    }'''
    assert not [item for item in TaintEngine().analyze_source_content(safe_argument, "Handler.java")
                if item.cwe_id == "CWE-829"]
    overloaded = '''class Handler {
        String read(Uri route) { return route.getQueryParameter("next"); }
        String read(String value) { return "https://safe.invalid"; }
        void render(Intent intent, WebView web) {
            String route = intent.getStringExtra("url");
            web.loadUrl(read(route));
        }
    }'''
    # The summary is name-keyed and cannot resolve Java overloads, so it must
    # abstain rather than attribute the Uri overload's flow to the String call.
    assert not [item for item in TaintEngine().analyze_source_content(overloaded, "Handler.java")
                if item.cwe_id == "CWE-829" and item.metadata.get("source_kind") == "URI_QUERY_PARAM"]
    model = '''class Handler { void render(RouteModel route, WebView web) {
        String path = route.getPath(); web.loadUrl(path);
    } }'''
    assert not [item for item in TaintEngine().analyze_source_content(model, "Handler.java")
                if item.cwe_id == "CWE-829"]
    collision = '''class Handler {
        void inspect(Intent intent) { Uri route = intent.getData(); }
        void render(RouteModel route, WebView web) {
            String path = route.getPath(); web.loadUrl(path);
        }
    }'''
    assert not [item for item in TaintEngine().analyze_source_content(collision, "Handler.java")
                if item.cwe_id == "CWE-829"]
    nested_collision = '''class Handler {
        void render(RouteModel route, WebView web) {
            class Inner { void nested(Uri route) { } }
            String path = route.getPath(); web.loadUrl(path);
        }
    }'''
    assert not [item for item in TaintEngine().analyze_source_content(nested_collision, "Handler.java")
                if item.cwe_id == "CWE-829"]


def test_taint_analysis_respects_shadowed_locals_but_joins_conditional_assignments():
    shadowed = '''class Handler { void render(Intent intent, WebView web, boolean flag) {
        String url = "https://safe.invalid";
        if (flag) { String url = intent.getStringExtra("url"); }
        web.loadUrl(url);
    } }'''
    assert not [item for item in TaintEngine().analyze_source_content(shadowed, "Handler.java")
                if item.cwe_id == "CWE-829"]

    conditional_assignment = '''class Handler { void render(Intent intent, WebView web, boolean flag) {
        String url = "https://safe.invalid";
        if (flag) { url = intent.getStringExtra("url"); }
        web.loadUrl(url);
    } }'''
    findings = TaintEngine().analyze_source_content(conditional_assignment, "Handler.java")
    assert any(item.cwe_id == "CWE-829" for item in findings)


def test_taint_engine_keeps_explicit_preference_getstring_as_review_source():
    engine = TaintEngine()
    source_code = '''
    class Model { void render(SharedPreferences preferences, WebView web) {
        String value = preferences.getString("url", "");
        web.loadUrl(value);
    } }
    '''
    findings = engine.analyze_source_content(source_code, "Model.java")
    finding = next(item for item in findings if item.cwe_id == "CWE-829")
    assert finding.severity.value == "INFO"
    assert finding.cvss_score == 0 and finding.status.value == "UNVERIFIED"
    assert finding.title.startswith("Stored Preference Value Flow Candidate")
    assert finding.metadata["source_control_status"] == "app_persisted_value_origin_not_established"
    assert "attacker control is not proven" in finding.description


@pytest.mark.parametrize("method,signature", [
    ("onNewIntent", "Intent incoming"),
    ("onReceive", "Context context, Intent incoming"),
    ("onActivityResult", "int requestCode, int resultCode, Intent incoming"),
    ("onStartCommand", "Intent incoming, int flags, int startId"),
    ("onHandleIntent", "Intent incoming"),
])
def test_android_callback_intent_parameter_is_candidate_source(method, signature):
    source = f"class Handler {{ void {method}({signature}) {{ startActivity(incoming); }} }}"
    findings = TaintEngine().analyze_source_content(source, "Handler.java")
    finding = next(item for item in findings if item.cwe_id == "CWE-927")
    assert finding.metadata["source_kind"] == "ANDROID_CALLBACK_INTENT_PARAMETER"
    assert finding.metadata["source_reachability"] == "callback_signature_only"
    assert finding.metadata["interprocedural_value_flow"] == "direct_callback_parameter"
    assert finding.status.value == "UNVERIFIED" and finding.cvss_score == 0


def test_non_callback_intent_parameter_is_not_assumed_externally_controlled():
    source = "class Handler { void localHelper(Intent incoming) { startActivity(incoming); } }"
    assert TaintEngine().analyze_source_content(source, "Handler.java") == []


def test_taint_flows_from_callback_through_same_file_sink_helper():
    source = '''
    class Handler {
      void onNewIntent(Intent incoming) { launch(incoming); }
      void launch(Intent target) { startActivity(target); }
    }
    '''
    findings = TaintEngine().analyze_source_content(source, "Handler.java")
    summary = next(item for item in findings if "parameter summary" in item.detection_method)
    assert summary.cwe_id == "CWE-927"
    assert summary.metadata["interprocedural_value_flow"] == "same_file_parameter_to_sink_summary"
    assert summary.status.value == "UNVERIFIED" and summary.cvss_score == 0


def test_java_ast_taint_catches_multiline_source_without_regex_fabrication():
    source = '''class Handler { void open(Intent intent, WebView web) {
        String target = intent
            .getStringExtra("url");
        web.loadUrl(target);
    } }'''
    engine = TaintEngine()
    findings = engine.analyze_source_content(source, "Handler.java")
    # The public combined engine may suppress a duplicate AST candidate when
    # lexical analysis already found the same location. Exercise the AST pass
    # directly as well as verifying the combined result below.
    ast_candidates = engine._java_ast.analyze(source, "Handler.java")
    ast_finding = next(item for item in ast_candidates if item.detection_method.startswith("JavaAstTaintAnalyzer"))
    assert ast_finding.cwe_id == "CWE-829"
    assert ast_finding.metadata["analysis_kind"] == "java_ast_local_flow"
    assert ast_finding.status.value == "UNVERIFIED" and ast_finding.cvss_score == 0
    assert any(item.cwe_id == "CWE-829" for item in findings)
    assert engine.ast_coverage["files_parsed"] == 1


def test_java_ast_ignores_source_tokens_inside_string_literals():
    source = '''class Handler { void open(WebView web) {
        String target = "intent.getStringExtra(\\"url\\")";
        web.loadUrl(target);
    } }'''
    findings = TaintEngine().analyze_source_content(source, "Handler.java")
    assert not [item for item in findings if item.cwe_id == "CWE-829"]


def test_java_ast_preference_flow_does_not_claim_attacker_control():
    from mobileag.analysis.java_ast_taint import JavaAstTaintAnalyzer
    analyzer = JavaAstTaintAnalyzer()
    if not analyzer.available:
        pytest.skip("optional Tree-sitter Java dependency is unavailable")
    findings = analyzer.analyze('''class Model { void render(SharedPreferences preferences, WebView web) {
        String value = preferences.getString("url", ""); web.loadUrl(value);
    } }''', "Model.java")
    finding = next(item for item in findings if item.cwe_id == "CWE-829")
    assert finding.severity.value == "INFO" and finding.status.value == "UNVERIFIED"
    assert finding.metadata["source_control_status"] == "app_persisted_value_origin_not_established"


def test_java_ast_query_parameter_requires_intent_derived_uri():
    from mobileag.analysis.java_ast_taint import JavaAstTaintAnalyzer
    analyzer = JavaAstTaintAnalyzer()
    if not analyzer.available:
        pytest.skip("optional Tree-sitter Java dependency is unavailable")
    model = analyzer.analyze('''class Model { void render(Response response, WebView web) {
        String value = response.getQueryParameter("next"); web.loadUrl(value);
    } }''', "Model.java")
    assert not [item for item in model if item.cwe_id == "CWE-829"]
    uri = analyzer.analyze('''class Handler { void render(Intent intent, WebView web) {
        android.net.Uri link = intent.getData();
        String value = link.getQueryParameter("next"); web.loadUrl(value);
    } }''', "Handler.java")
    assert any(item.cwe_id == "CWE-829" and item.metadata["source_kind"] == "URI_QUERY_PARAM"
               for item in uri)
    constant = analyzer.analyze('''class Model { void render(WebView web) {
        Uri link = Uri.parse("https://safe.invalid/path?next=home");
        String value = link.getQueryParameter("next"); web.loadUrl(value);
    } }''', "Model.java")
    assert not [item for item in constant if item.cwe_id == "CWE-829"]
    internal = analyzer.analyze('''class Model { void render(Uri internalRoute, WebView web) {
        String value = internalRoute.getQueryParameter("next"); web.loadUrl(value);
    } }''', "Model.java")
    assert not [item for item in internal if item.cwe_id == "CWE-829"]


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


@pytest.mark.asyncio
async def test_taint_directory_scan_is_bounded_and_marks_skipped_inputs(tmp_path):
    (tmp_path / "Huge.java").write_text("x" * (2 * 1024 * 1024 + 1))
    engine = TaintEngine()
    await engine.analyze_directory_async(tmp_path)
    assert engine.coverage["static_status"] == "partial"
    assert engine.coverage["source_files_skipped"] == 1
    assert engine.coverage["proof_status"] == "not_proven"


@pytest.mark.asyncio
async def test_taint_directory_scan_marks_source_analysis_exceptions_as_partial(tmp_path):
    source = tmp_path / "Broken.java"
    source.write_text("class Broken {}")
    engine = TaintEngine()

    def fail_analysis(_content, file_path=""):
        raise RuntimeError("synthetic parser failure")

    engine.analyze_source_content = fail_analysis
    await engine.analyze_directory_async(tmp_path)
    assert engine.coverage["static_status"] == "partial"
    assert engine.coverage["analysis_failures"] == 1
    assert engine.coverage["failed_source_files"] == ["Broken.java"]
    assert engine.coverage["exhaustive"] is False


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
    assert res["status"] == "blocked"  # Missing package identity is not safe scope.
    assert res["screens_explored"] == 0
    assert res["buttons_clicked"] == res["dialogs_dismissed"] == res["inputs_filled"] == 0
    assert all('input' not in call.args[0] for call in mock_adb._exec_cmd.call_args_list)


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
            "status": "executed",
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
        assert data["status"] == "executed"
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
    assert data["findings"][0]["cwe_id"] == "CWE-829"


def test_inferred_kotlin_intent_alias_and_exact_java_intent_type():
    engine = TaintEngine()
    kotlin = '''class Route { fun open(input: Intent, view: WebView) {
        val forwarded = input
        val address = forwarded.dataString
        view.loadUrl(address)
    } }'''
    assert 'CWE-829' in {finding.cwe_id for finding in engine.analyze_source_content(kotlin, 'Route.kt')}

    lookalike = '''class Route { void open(FakeIntent input, WebView view) {
        FakeIntent forwarded = input;
        String address = forwarded.getStringExtra("url");
        view.loadUrl(address);
    } }'''
    assert 'CWE-829' not in {finding.cwe_id for finding in engine.analyze_source_content(lookalike, 'Route.java')}
