"""Unit tests for Advanced DAST & Taint modules:
- FridaRunner (SSL unpinning, crypto telemetry parsing, root bypass)
- DeepLinkFuzzer (bounded redirect, file, and JavaScript-scheme review markers)
- TaintEngine (inter-procedural static source-to-sink dataflow tracking)
- UICrawler (UI hierarchy parsing, dialog handling, form filling)
- MemoryForensicsAuditor (category-only memory indicators, CWE-316 review leads)
- Associated FastAPI endpoints
"""

import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient
from mobileag.analysis.android_surface import method_spans
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


@pytest.mark.parametrize("ast_enabled", [False, True])
def test_untrusted_intent_bytes_flow_to_java_object_deserialization(ast_enabled):
    source = '''import android.content.Intent;
import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
class Decoder {
  Object decode(Intent intent) throws Exception {
    byte[] payload = intent.getByteArrayExtra("blob");
    ObjectInputStream input = new ObjectInputStream(new ByteArrayInputStream(payload));
    return input.readObject();
  }
}'''
    engine = TaintEngine()
    if not ast_enabled:
        engine._java_ast.available = False
    findings = engine.analyze_source_content(source, "Decoder.java")
    candidates = [finding for finding in findings
                  if finding.metadata.get("source_sink_trace", {}).get("sink", {}).get("operation")
                  == "UNTRUSTED_DESERIALIZATION"]
    assert candidates
    candidate = candidates[0]
    assert candidate.cwe_id == "CWE-502"
    assert candidate.severity.value == "INFO"
    assert candidate.status.value == "UNVERIFIED"
    assert candidate.metadata["proof_state"] == "not_proven"


def test_local_byte_stream_to_object_deserialization_is_not_external_input_flow():
    source = '''import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
class Decoder {
  Object decode() throws Exception {
    byte[] payload = new byte[] {1, 2, 3};
    ObjectInputStream input = new ObjectInputStream(new ByteArrayInputStream(payload));
    return input.readObject();
  }
}'''
    engine = TaintEngine()
    engine._java_ast.available = False
    findings = engine.analyze_source_content(source, "Decoder.java")
    assert not any(finding.cwe_id == "CWE-502" for finding in findings)


@pytest.mark.parametrize("ast_enabled", [False, True])
@pytest.mark.parametrize("read_code", [
    'InputStream stream = resolver.openInputStream(uri);',
    'android.content.res.AssetFileDescriptor afd = resolver.openAssetFileDescriptor(uri, "r");\n'
    '    InputStream stream = afd.createInputStream();',
    'android.os.ParcelFileDescriptor fd = resolver.openFileDescriptor(uri, "r");\n'
    '    InputStream stream = new java.io.FileInputStream(fd.getFileDescriptor());',
    'android.content.res.AssetFileDescriptor afd = resolver.openTypedAssetFileDescriptor(uri, "*/*", null);\n'
    '    InputStream stream = afd.createInputStream();',
])
def test_intent_uri_content_resolver_reads_flow_to_deserialization(ast_enabled, read_code):
    source = f'''import android.content.ContentResolver;
import android.content.Intent;
import android.net.Uri;
import java.io.InputStream;
import java.io.ObjectInputStream;
class Decoder {{
  Object decode(Intent intent, ContentResolver resolver) throws Exception {{
    Uri uri = intent.getData();
    {read_code}
    ObjectInputStream input = new ObjectInputStream(stream);
    return input.readObject();
  }}
}}'''
    engine = TaintEngine()
    if not ast_enabled:
        engine._java_ast.available = False
    findings = engine.analyze_source_content(source, "Decoder.java")
    candidates = [finding for finding in findings
                  if finding.metadata.get("source_sink_trace", {}).get("source", {}).get("kind")
                  == "CONTENT_RESOLVER_READ"]
    assert len(candidates) == 1
    assert candidates[0].cwe_id == "CWE-502"
    assert candidates[0].metadata["proof_state"] == "not_proven"
    assert candidates[0].metadata["source_sink_trace"]["guards"] == "not_resolved"


def test_static_uri_content_resolver_stream_is_not_treated_as_untrusted_input():
    source = '''import android.content.ContentResolver;
import android.net.Uri;
import java.io.InputStream;
import java.io.ObjectInputStream;
class Decoder {
  Object decode(ContentResolver resolver) throws Exception {
    Uri uri = Uri.parse("content://trusted.example/static");
    InputStream stream = resolver.openInputStream(uri);
    ObjectInputStream input = new ObjectInputStream(stream);
    return input.readObject();
  }
}'''
    engine = TaintEngine()
    engine._java_ast.available = False
    findings = engine.analyze_source_content(source, "Decoder.java")
    assert not any(finding.cwe_id == "CWE-502" for finding in findings)


def test_taint_directory_exports_surface_specific_deserialization_coverage(tmp_path):
    (tmp_path / "Unsafe.java").write_text('''import android.content.ContentResolver;
import android.content.Intent;
import android.net.Uri;
import java.io.InputStream;
import java.io.ObjectInputStream;
class Unsafe {
 Object decode(Intent intent, ContentResolver resolver) throws Exception {
   Uri uri = intent.getData();
   InputStream stream = resolver.openInputStream(uri);
   ObjectInputStream input = new ObjectInputStream(stream);
   return input.readObject();
 }
}''')
    (tmp_path / "Safe.java").write_text('''import java.io.ByteArrayInputStream;
import java.io.ObjectInputStream;
class Safe {
 Object decode() throws Exception {
   ObjectInputStream input = new ObjectInputStream(new ByteArrayInputStream(new byte[] {1}));
   return input.readObject();
 }
}''')
    engine = TaintEngine()
    engine._java_ast.available = False
    findings = engine.analyze_directory(str(tmp_path))
    serialization = engine.coverage["serialization"]
    assert serialization["static_status"] == engine.coverage["static_status"]
    assert serialization["candidate_count"] == 1
    assert serialization["proof_status"] == "not_proven"
    assert sum(finding.cwe_id == "CWE-502" for finding in findings) == 1


@pytest.mark.parametrize("ast_enabled", [False, True])
def test_intent_html_flow_to_webview_load_data_with_base_url(ast_enabled):
    source = '''import android.content.Intent;
import android.webkit.WebView;
class HtmlScreen {
  void show(Intent intent, WebView webView) {
    String html = intent.getStringExtra("html");
    webView.loadDataWithBaseURL("https://app.example", html, "text/html", "UTF-8", null);
  }
}'''
    engine = TaintEngine()
    if not ast_enabled:
        engine._java_ast.available = False
    findings = engine.analyze_source_content(source, "HtmlScreen.java")
    candidate = next(f for f in findings if f.metadata.get("source_sink_trace", {})
                     .get("sink", {}).get("operation") == "WEBVIEW_HTML_LOAD")
    assert candidate.cwe_id == "CWE-79"
    assert candidate.severity.value == "INFO"
    assert candidate.metadata["proof_state"] == "not_proven"


def test_html_webview_history_url_only_is_not_treated_as_untrusted_markup():
    source = '''import android.content.Intent;
import android.webkit.WebView;
class HtmlScreen {
  void show(Intent intent, WebView webView) {
    String url = intent.getStringExtra("history");
    webView.loadDataWithBaseURL("https://app.example", "<p>fixed</p>", "text/html", "UTF-8", url);
  }
}'''
    engine = TaintEngine()
    engine._java_ast.available = False
    findings = engine.analyze_source_content(source, "HtmlScreen.java")
    assert not any(f.metadata.get("source_sink_trace", {}).get("sink", {}).get("operation")
                   == "WEBVIEW_HTML_LOAD" for f in findings)


@pytest.mark.parametrize("annotation", ["  @android.webkit.JavascriptInterface\n", "  @android.webkit.JavascriptInterface ", ""])
@pytest.mark.parametrize("ast_enabled", [False, True])
def test_javascript_interface_parameter_is_only_modeled_when_annotated(annotation, ast_enabled):
    annotated = bool(annotation.strip())
    source = f'''import android.webkit.WebView;
class BridgeScreen {{
  WebView webView;
{annotation}  public void render(String html) {{
    webView.loadDataWithBaseURL("https://app.example", html, "text/html", "UTF-8", null);
  }}
}}'''
    engine = TaintEngine()
    if not ast_enabled:
        engine._java_ast.available = False
    findings = engine.analyze_source_content(source, "BridgeScreen.java")
    candidates = [f for f in findings if f.metadata.get("source_sink_trace", {})
                  .get("sink", {}).get("operation") == "WEBVIEW_HTML_LOAD"]
    assert bool(candidates) is annotated
    if annotated:
        trace = candidates[0].metadata["source_sink_trace"]
        assert trace["source"]["kind"] == "JAVASCRIPT_INTERFACE_PARAMETER"
        assert candidates[0].metadata["proof_state"] == "not_proven"
        assert candidates[0].metadata["source_reachability"] == "not_established"


def test_kotlin_javascript_interface_parameter_name_is_extracted_correctly():
    source = '''class Bridge {
  @android.webkit.JavascriptInterface
  fun render(html: String) { println(html) }
}'''
    spans = list(method_spans(source))
    assert len(spans) == 1
    name, offset, body = spans[0]
    assert TaintEngine._javascript_interface_parameters(source, offset, name, body) == ["html"]


def test_kotlin_javascript_interface_parameter_flows_to_webview_html_sink():
    source = '''import android.webkit.WebView
class Bridge(private val webView: WebView) {
  @android.webkit.JavascriptInterface
  fun render(html: String) {
    webView.loadDataWithBaseURL("https://app.example", html, "text/html", "UTF-8", null)
  }
}'''
    engine = TaintEngine()
    engine._java_ast.available = False
    candidates = [finding for finding in engine.analyze_source_content(source, "Bridge.kt")
                  if finding.metadata.get("source_sink_trace", {}).get("sink", {}).get("operation")
                  == "WEBVIEW_HTML_LOAD"]
    assert len(candidates) == 1
    trace = candidates[0].metadata["source_sink_trace"]
    assert trace["source"]["kind"] == "JAVASCRIPT_INTERFACE_PARAMETER"
    assert trace["sink"]["operation"] == "WEBVIEW_HTML_LOAD"
    assert candidates[0].metadata["proof_state"] == "not_proven"


def test_taint_directory_reports_webview_flow_count_by_surface(tmp_path):
    (tmp_path / "HtmlScreen.java").write_text('''import android.content.Intent;
import android.webkit.WebView;
class HtmlScreen {
  void show(Intent intent, WebView webView) {
    String html = intent.getStringExtra("html");
    webView.loadDataWithBaseURL("https://app.example", html, "text/html", "UTF-8", null);
  }
}''')
    engine = TaintEngine()
    engine._java_ast.available = False
    findings = engine.analyze_directory(str(tmp_path))
    assert engine.coverage["webview"]["candidate_count"] == 1
    assert engine.coverage["webview"]["proof_status"] == "not_proven"
    assert any(f.metadata.get("source_sink_trace", {}).get("sink", {}).get("operation")
               == "WEBVIEW_HTML_LOAD" for f in findings)


# =============================================================================
# 1. FridaRunner safe-profile tests
# =============================================================================
def test_frida_runner_exposes_no_hook_generators():
    runner = FridaRunner()
    assert not any(hasattr(runner, name) for name in (
        "generate_unpinning_script", "generate_crypto_monitor_script",
        "generate_root_bypass_script", "generate_all_in_one_agent_script",
        "generate_stealth_unpinning_script", "generate_stealth_daemon_launcher",
    ))


@pytest.mark.asyncio
async def test_frida_runner_execution():
    mock_adb = ADBManager()
    mock_adb._exec_cmd = AsyncMock(return_value=(0, b"frida-server 1234\n", b""))

    runner = FridaRunner(adb=mock_adb)
    is_running = await runner.is_frida_server_running("emulator-5554")
    assert is_running is None  # Unknown; the helper does not issue root-shell probes.

    res = await runner.execute_script_payload("emulator-5554", "com.test.app", "console.log('test');")
    assert res["status"] == "disabled" and res["executed"] is False
    mock_adb._exec_cmd.assert_not_awaited()


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
    results, findings = await fuzzer.fuzz_deep_links(
        "emulator-5554", "com.test.app", ["testapp://router"], guard=lambda: None,
        synthetic_data_confirmed=True,
    )
    assert len(results) >= 4
    assert len(findings) >= 1
    assert findings[0].cwe_id == "CWE-755"
    assert findings[0].status.value == "UNVERIFIED" and findings[0].cvss_score == 0


@pytest.mark.asyncio
async def test_deeplink_fuzzer_requires_scope_guard_before_device_access():
    mock_adb = ADBManager()
    mock_adb.get_logcat_dump = AsyncMock(return_value=[])
    mock_adb._exec_cmd = AsyncMock(return_value=(0, b"synthetic", b""))
    fuzzer = DeepLinkFuzzer(adb=mock_adb)

    with pytest.raises(PermissionError, match="scope guard is required"):
        await fuzzer.exercise_deep_link(
            "synthetic-serial", "com.example.fixture", "fixture://canary",
            synthetic_data_confirmed=True,
        )

    mock_adb.get_logcat_dump.assert_not_awaited()
    mock_adb._exec_cmd.assert_not_awaited()


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


def test_taint_helper_summary_disambiguates_same_named_methods_by_owner():
    source = '''class Handler {
      WebView view;
      void onNewIntent(Intent incoming) {
        String url = incoming.getStringExtra("url");
        launch(url);
      }
      void launch(String value) { view.loadUrl(value); }
    }
    class Unrelated {
      void launch(String value) { System.out.println(value); }
    }'''
    engine = TaintEngine()
    engine._java_ast.available = False
    findings = engine.analyze_source_content(source, "Handler.java")
    summaries = [item for item in findings if "parameter summary" in item.detection_method]
    assert len(summaries) == 1
    assert summaries[0].metadata["source_sink_trace"]["sink"]["method"] == "launch"
    assert summaries[0].metadata["proof_state"] == "not_proven"


def test_taint_helper_summary_fails_closed_on_same_owner_same_arity_overloads():
    source = '''class Handler {
      WebView view;
      void onNewIntent(Intent incoming) {
        String url = incoming.getStringExtra("url");
        launch(url);
      }
      void launch(String value) { System.out.println(value); }
      void launch(Integer value) { view.loadUrl(String.valueOf(value)); }
    }'''
    engine = TaintEngine()
    engine._java_ast.available = False
    findings = engine.analyze_source_content(source, "Handler.java")
    assert not any("parameter summary" in item.detection_method for item in findings)


@pytest.mark.parametrize("ast_enabled", [False, True])
def test_taint_helper_summary_follows_bounded_same_file_parameter_chain(ast_enabled):
    source = '''class Handler {
      WebView view;
      void onNewIntent(Intent incoming) {
        String url = incoming.getStringExtra("url");
        prepare(url);
      }
      void prepare(String value) { launch(value); }
      void launch(String target) { view.loadUrl(target); }
    }'''
    engine = TaintEngine()
    if not ast_enabled:
        engine._java_ast.available = False
    findings = engine.analyze_source_content(source, "Handler.java")
    summary = next(item for item in findings if "parameter summary" in item.detection_method)
    trace = summary.metadata["source_sink_trace"]
    assert trace["helper_call"]["name"] == "prepare"
    assert trace["sink"]["method"] == "launch"
    assert trace["sink"]["operation"] == "WEBVIEW_NAVIGATION"
    assert summary.metadata["proof_state"] == "not_proven"


@pytest.mark.parametrize("ast_enabled", [False, True])
def test_taint_helper_chain_requires_direct_parameter_forwarding(ast_enabled):
    source = '''class Handler {
      WebView view;
      void onNewIntent(Intent incoming) {
        String url = incoming.getStringExtra("url");
        prepare(url);
      }
      void prepare(String value) { launch(value + "safe"); }
      void launch(String target) { view.loadUrl(target); }
    }'''
    engine = TaintEngine()
    if not ast_enabled:
        engine._java_ast.available = False
    findings = engine.analyze_source_content(source, "Handler.java")
    assert not any("parameter summary" in item.detection_method for item in findings)


def test_taint_coverage_counts_transitive_same_file_summaries(tmp_path):
    (tmp_path / "Handler.java").write_text('''class Handler {
      WebView view;
      void onNewIntent(Intent incoming) {
        String url = incoming.getStringExtra("url");
        prepare(url);
      }
      void prepare(String value) { launch(value); }
      void launch(String target) { view.loadUrl(target); }
    }''')
    engine = TaintEngine()
    engine._java_ast.available = False
    findings = engine.analyze_directory(str(tmp_path))
    summary = engine.coverage["same_file_parameter_summary"]
    assert summary["source_files_analyzed"] == 1
    assert summary["direct_summaries"] >= 1
    assert summary["transitive_summaries"] >= 1
    assert summary["files_with_transitive_summaries"] == 1
    assert summary["proof_status"] == "not_proven"
    assert any("same-file parameter summary" in item.detection_method for item in findings)
    from mobileag.reporting.capability_inventory import capability_inventory
    reported = capability_inventory({"taint": engine.coverage})["formats"]["java_kotlin"]
    assert reported["same_file_parameter_summary"]["transitive_summaries"] >= 1


def test_taint_symbol_resolver_propagates_partial_inventory_coverage(tmp_path):
    source=tmp_path/'Handler.java'
    source.write_text('package synthetic; class Handler {}',encoding='utf-8')
    outside=tmp_path.parent/(tmp_path.name+'-Outside.java')
    outside.write_text('package hidden; class Outside {}',encoding='utf-8')
    (tmp_path/'Linked.java').symlink_to(outside)
    engine=TaintEngine();engine._java_ast.available=False
    engine.analyze_directory(str(tmp_path))
    symbols=engine.coverage['symbol_resolver']
    assert symbols['indexed_classes']==1
    assert symbols['indexed_files']==1
    assert symbols['static_status']=='partial'
    assert symbols['coverage']['source_file_skip_reasons']['symlink_entry']==1


def test_taint_symbol_resolver_never_calls_heuristic_indexing_completed(tmp_path):
    (tmp_path/'Handler.java').write_text('package synthetic; class Handler {}',encoding='utf-8')
    engine=TaintEngine();engine._java_ast.available=False
    engine.analyze_directory(str(tmp_path))
    assert engine.coverage['symbol_resolver']['static_status']=='analyzed_heuristically'
    assert engine.coverage['symbol_resolver']['coverage']['exhaustive'] is False


def test_taint_parameter_summary_budget_is_reported_as_partial(tmp_path, monkeypatch):
    import mobileag.analysis.taint_engine as taint_module
    monkeypatch.setattr(taint_module, "MAX_PARAMETER_SINK_SUMMARIES", 1)
    (tmp_path / "Handler.java").write_text('''class Handler {
      void launch(Intent value) {
        startActivity(value);
        startActivity(value);
      }
    }''')
    engine = TaintEngine()
    engine._java_ast.available = False
    engine.analyze_directory(str(tmp_path))
    summary = engine.coverage["same_file_parameter_summary"]
    assert summary["candidate_limit_files"] == 1
    assert engine.coverage["static_status"] == "partial"
    assert engine.coverage["limits_reached"] is True
    assert engine.coverage["limit_reasons"]["taint_parameter_summary_count"] == 1


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


def test_java_ast_parser_failures_are_counted_separately_from_unavailable_parser():
    engine = TaintEngine()
    if not engine._java_ast.available:
        pytest.skip("Tree-sitter Java is required for syntax-error accounting")
    malformed = "class Broken { void f( {"
    assert engine._java_ast.analyze(malformed, "Broken.java") is None
    assert engine._java_ast.last_failure_reason == "syntax_error"
    engine.analyze_source_content(malformed, "Broken.java")
    assert engine.ast_coverage["parse_fallbacks"] == 1
    assert engine.ast_coverage["syntax_error_fallbacks"] == 1
    assert engine.ast_coverage["syntax_error_nodes_observed"] > 0
    assert engine.ast_coverage["syntax_error_node_count_incomplete_files"] == 0

    unavailable = TaintEngine()
    unavailable._java_ast.available = False
    unavailable.analyze_source_content("class Plain { void f() {} }", "Plain.java")
    assert unavailable.ast_coverage["parser_unavailable_fallbacks"] == 1
    assert unavailable.ast_coverage["syntax_error_fallbacks"] == 0


def test_java_ast_parse_error_node_count_fails_closed_at_visit_budget(monkeypatch):
    import mobileag.analysis.java_ast_taint as module
    analyzer = module.JavaAstTaintAnalyzer()
    if not analyzer.available:
        pytest.skip("Tree-sitter Java is required for syntax-error accounting")
    monkeypatch.setattr(module, "MAX_PARSE_ERROR_NODE_VISITS", 1)
    assert analyzer.analyze("class Broken { void f( {", "Broken.java") is None
    assert analyzer.last_failure_reason == "syntax_error"
    assert analyzer.last_parse_error_node_count is not None
    assert analyzer.last_parse_error_count_status == "incomplete_visit_limit"


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


def test_ui_crawler_parser_rejects_oversized_entity_and_node_bomb_inputs():
    crawler = UICrawler()
    assert crawler.parse_ui_elements('<!DOCTYPE hierarchy [<!ENTITY x "expanded">]><hierarchy><node text="&x;"/></hierarchy>') == []
    assert crawler.parse_ui_elements('<hierarchy>' + (' ' * (2 * 1024 * 1024)) + '</hierarchy>') == []
    nodes = ''.join('<node package="com.example" clickable="true"/>' for _ in range(5001))
    assert crawler.parse_ui_elements('<hierarchy>' + nodes + '</hierarchy>') == []


@pytest.mark.asyncio
async def test_ui_crawler_crawl_flow():
    mock_adb = ADBManager()
    mock_adb._exec_cmd = AsyncMock(return_value=(0, b"""<?xml version="1.0" encoding="utf-8"?>
    <hierarchy rotation="0">
      <node text="OK" class="android.widget.Button" clickable="true" bounds="[100,200][300,400]" />
    </hierarchy>""", b""))

    crawler = UICrawler(adb=mock_adb)
    res = await crawler.crawl_app("emulator-5554", "com.test.app", max_steps=2, guard=lambda: None)
    assert res["status"] == "blocked"  # Missing package identity is not safe scope.
    assert res["screens_explored"] == 0
    assert res["buttons_clicked"] == res["dialogs_dismissed"] == res["inputs_filled"] == 0
    assert all('input' not in call.args[0] for call in mock_adb._exec_cmd.call_args_list)


# =============================================================================
# 5. MemoryForensicsAuditor Tests
# =============================================================================
@pytest.mark.asyncio
async def test_memory_forensics_secret_detection():
    from mobileag.reporting.finding import Severity

    mock_adb = ADBManager()

    async def mock_exec(cmd, timeout=3.0, output_limit=None):
        cmd_str = " ".join(cmd)
        if "pidof" in cmd_str:
            return (0, b"4567\n", b"")
        if "strings" in cmd_str and "awk" in cmd_str:
            return (0, b"JWT Bearer Token\nPlaintext Password Parameter\n", b"")
        return (0, b"", b"")

    mock_adb._exec_cmd = mock_exec
    auditor = MemoryForensicsAuditor(adb=mock_adb)

    pid, findings = await auditor.audit_process_memory(
        "emulator-5554", "com.test.app", guard=lambda: None,
    )
    assert pid == 4567
    assert len(findings) >= 2
    cwes = {f.cwe_id for f in findings}
    assert "CWE-316" in cwes
    serialized = str([finding.to_dict() for finding in findings])
    assert "SuperSecretPass!" not in serialized
    assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in serialized
    assert all(f.severity == Severity.INFO and f.confidence == 0.4 for f in findings)
    assert all(f.metadata["raw_value_collected"] is False for f in findings)


@pytest.mark.asyncio
async def test_memory_forensics_rejects_raw_output_and_never_reads_environment():
    mock_adb = ADBManager()
    commands = []

    async def mock_exec(cmd, timeout=3.0, output_limit=None):
        commands.append(" ".join(cmd))
        # Simulate unexpected raw output; only fixed labels are accepted.
        return (0, b"JWT Bearer Token\nBearer synthetic-raw-value\n", b"")

    mock_adb._exec_cmd = mock_exec
    auditor = MemoryForensicsAuditor(adb=mock_adb)
    indicators = await auditor.extract_memory_indicators(
        "synthetic-device", 1234, guard=lambda: None,
    )
    assert indicators == ["JWT Bearer Token"]
    assert len(commands) == 1
    assert "awk" in commands[0]
    assert "/proc/1234/mem" in commands[0]
    assert "/proc/1234/environ" not in commands[0]
    assert "cat " not in commands[0]


@pytest.mark.asyncio
async def test_memory_forensics_scope_denial_and_revocation_block_shell_commands():
    mock_adb = ADBManager()
    calls = []

    async def mock_exec(cmd, timeout=3.0, output_limit=None):
        calls.append(" ".join(cmd))
        return (1, b"", b"")

    mock_adb._exec_cmd = mock_exec
    auditor = MemoryForensicsAuditor(adb=mock_adb)
    with pytest.raises(PermissionError, match="required"):
        await auditor.get_process_pid("synthetic-device", "com.test.app")
    assert calls == []

    async def async_allow():
        return True

    with pytest.raises(PermissionError, match="synchronous"):
        await auditor.get_process_pid("synthetic-device", "com.test.app", guard=async_allow)
    assert calls == []

    with pytest.raises(PermissionError):
        await auditor.get_process_pid("synthetic-device", "com.test.app", guard=lambda: False)
    assert calls == []

    approvals = iter((True, False))
    with pytest.raises(PermissionError):
        await auditor.get_process_pid(
            "synthetic-device", "com.test.app", guard=lambda: next(approvals),
        )
    assert len(calls) == 1


# =============================================================================
# 6. Web API Endpoints Tests
# =============================================================================
def test_web_deeplinks_endpoint(client):
    with patch("mobileag.web.app.deeplink_fuzzer.fuzz_deep_links") as mock_fuzz:
        mock_fuzz.return_value = (
            [{"scheme_uri": "testapp://", "status_code": 0}],
            [],
        )
        rejected = client.post("/api/dast/deeplinks", json={
            "serial": "emulator-5554", "package_name": "com.test.app",
            "deep_links": ["testapp://"],
        })
        assert rejected.status_code == 403
        mock_fuzz.assert_not_called()
        response = client.post("/api/dast/deeplinks", json={
            "serial": "emulator-5554",
            "package_name": "com.test.app",
            "deep_links": ["testapp://"],
            "synthetic_data_confirmed": True,
        })
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "success"
        assert len(data["results"]) == 1


def test_web_deeplink_dispatch_requires_synthetic_data_confirmation(client):
    with patch("mobileag.web.app.intent_fuzzer.exercise_component") as dispatch:
        response = client.post("/api/dast/deeplink", json={
            "serial": "emulator-5554", "package_name": "com.test.app",
            "uri": "testapp://synthetic",
        })
        assert response.status_code == 403
        dispatch.assert_not_awaited()


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
        response = client.post("/api/dast/frida", json={
            "serial": "emulator-5554",
            "package_name": "com.test.app",
            "script_type": "crypto",
        })
        assert response.status_code == 403
        mock_frida.assert_not_called()


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

    reassigned = '''class Route { fun open(input: Intent, fake: FakeIntent, view: WebView) {
        var forwarded = input
        forwarded = fake
        val address = forwarded.getStringExtra("url")
        view.loadUrl(address)
    } }'''
    assert 'CWE-829' not in {finding.cwe_id for finding in engine.analyze_source_content(reassigned, 'Route.kt')}
