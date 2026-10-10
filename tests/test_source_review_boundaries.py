"""Synthetic lexical-review regression controls; no Android runtime is exercised."""
from pathlib import Path

import pytest

from mobileag.analysis.code_reviewer import CodeReviewer
from mobileag.analysis.source_syntax import call_sites, literal_flag_bits
from mobileag.analysis.taint_engine import TaintEngine
from mobileag.reporting.finding import FindingStatus


def test_kotlin_nullable_intent_safe_call_is_modeled_but_fake_type_is_not():
    engine = TaintEngine()
    safe_call = '''class Handler { fun open(incoming: Intent?, web: WebView) {
        val target = incoming?.getStringExtra("url")
        web.loadUrl(target)
    } }'''
    fake_model = safe_call.replace("Intent?", "FakeIntent?")
    findings = engine.analyze_source_content(safe_call, "Handler.kt")
    assert any(f.cwe_id == "CWE-829" and f.status == FindingStatus.UNVERIFIED for f in findings)
    assert not engine.analyze_source_content(fake_model, "Handler.kt")


def test_balanced_calls_keep_nested_commas_and_ignore_comments_strings():
    source = '''// PendingIntent.getActivity(a,0,i,0)
String text = "PendingIntent.getActivity(a,0,i,0)";
PendingIntent.getActivity(
  ctx, request(2, 4), new Intent(ctx, Target.class),
  0, options(1, new int[] {2, 4}));'''
    calls = list(call_sites(source, r"\bPendingIntent\.getActivity"))
    assert len(calls) == 1
    assert len(calls[0].args) == 5
    assert calls[0].args[1] == "request(2, 4)"
    assert calls[0].args[3] == "0"


@pytest.mark.parametrize("expression,bits,complete", [
    ("0x04000000 | 134217728", 0x0C000000, True),
    ("PendingIntent.FLAG_MUTABLE | flags", 0x02000000, False),
    ("Context.RECEIVER_NOT_EXPORTED | 1", 5, True),
    ("getFlags(2, 4)", 0, False),
    ("4 + 2", 0, False),
    ("040000000", 0, False),  # Ambiguous Java octal is not treated as decimal.
    ("__import__('os').system('false')", 0, False),
])
def test_flag_resolution_is_literal_only(expression, bits, complete):
    assert literal_flag_bits(expression, {
        "FLAG_MUTABLE": 0x02000000, "RECEIVER_NOT_EXPORTED": 4,
    }) == (bits, complete)


def test_one_line_and_multiline_methods_are_scoped():
    code = '''class Handler {
public void first(Intent in) { Intent next = in.getParcelableExtra("x"); startActivity(next); }
public void second(
  Intent in
) { Intent clean = new Intent(); startActivity(clean); }
}'''
    findings = CodeReviewer()._audit_intent_redirection(code, "Handler.java", "Handler")
    assert len(findings) == 1
    assert "first" in findings[0]["title"]
    assert "no proxy access was demonstrated" in findings[0]["description"]


def test_pending_intent_multiline_nested_and_fourth_arg_with_options():
    code = '''PendingIntent.getActivity(ctx, request(2, 4), new Intent(ctx, Target.class),
0, options(PendingIntent.FLAG_IMMUTABLE));
PendingIntent.getActivities(ctx, 0, new Intent[] {i, j}, PendingIntent.FLAG_MUTABLE);
PendingIntent.getBroadcast(ctx, 0, i, flags);
PendingIntent.getService(ctx, 0, i, PendingIntent.FLAG_IMMUTABLE | 134217728);
PendingIntent.getForegroundService(ctx, 0, i, 67108864);'''
    results = CodeReviewer()._audit_pending_intent_mutability(code, "F.java", "F")
    assert len(results) == 3
    assert "missing" in results[0]["title"]
    assert "mutable" in results[1]["title"]
    assert "unresolved" in results[2]["title"]
    assert "API 31" in results[0]["description"]


def test_receiver_incidental_digits_do_not_hide_missing_flags():
    reviewer = CodeReviewer()
    code = '''ctx.registerReceiver(receiver2, new IntentFilter("ACTION4"));
ctx.registerReceiver(receiver, filter, "permission2", handler4);
ContextCompat.registerReceiver(ctx, receiver, filter,
  ContextCompat.RECEIVER_EXPORTED);
ctx.registerReceiver(receiver, filter, flags);'''
    results = reviewer._audit_dynamic_receivers(code, "F.java", "F")
    assert len(results) == 4
    assert all("Review" in item["title"] for item in results)
    assert "exported runtime" in results[2]["title"]
    assert "unresolved" in results[3]["title"]
    assert "API 34" in results[0]["description"]
    assert "system-only" in results[0]["description"]


def test_receiver_literal_private_flags_and_sticky_queries_not_reported():
    code = '''ctx.registerReceiver(receiver, filter, 4 | 1);
ContextCompat.registerReceiver(ctx, receiver, filter, ContextCompat.RECEIVER_NOT_EXPORTED);
ctx.registerReceiver(null, filter);
ctx.registerReceiver(receiver, filter, permission, handler, 0x4);'''
    assert not CodeReviewer()._audit_dynamic_receivers(code, "F.java", "F")


@pytest.mark.asyncio
async def test_whole_reviewer_ignores_comments_strings_and_has_no_fabricated_cvss(tmp_path):
    fake = '''class Fake {
// PendingIntent.getActivity(ctx, 0, i, 0);
// registerReceiver(receiver, filter);
// webView.addJavascriptInterface(bridge, "name");
String demo = "webView.setAllowFileAccess(true)";
String trust = "void checkServerTrusted(Object a) {}";
}'''
    (tmp_path / "Fake.java").write_text(fake)
    reviewer = CodeReviewer()
    assert not await reviewer.review(str(tmp_path), {})
    (tmp_path / "Real.java").write_text('class Real { void work() { PendingIntent.getActivity(ctx,0,i,0); } }')
    findings = await reviewer.review(str(tmp_path), {})
    assert len(findings) == 1
    assert findings[0].status is FindingStatus.UNVERIFIED
    assert findings[0].cvss_score == 0
    assert findings[0].cvss_vector == ""
    assert findings[0].metadata["proof_state"] == "not_proven"


@pytest.mark.asyncio
async def test_webview_configuration_candidates_do_not_claim_exposure_or_file_disclosure(tmp_path):
    (tmp_path / "Web.java").write_text('''class Web {
        void setup(WebSettings settings, WebView web) {
            settings.setAllowFileAccess(true);
            web.addJavascriptInterface(new Bridge(), "bridge");
        }
    }''')
    findings = await CodeReviewer().review(str(tmp_path), {})
    file_access = next(item for item in findings if "AllowFileAccess" in item.title)
    bridge = next(item for item in findings if "JavascriptInterface" in item.title)
    assert file_access.cwe_id == "CWE-669"
    assert bridge.cwe_id == "CWE-749"
    assert all(item.severity.value == "INFO" and item.cvss_score == 0
               and item.status is FindingStatus.UNVERIFIED for item in (file_access, bridge))
    assert "does not demonstrate disclosure" in file_access.description
    assert "Registration alone is not proof" in bridge.description


@pytest.mark.asyncio
async def test_openfile_pattern_is_not_misreported_as_proven_path_traversal(tmp_path):
    (tmp_path / "ProviderClient.java").write_text('''class ProviderClient {
        void read(ContentResolver resolver, Uri fixedUri) throws Exception {
            resolver.openFile(fixedUri, "r");
        }
    }''')
    findings = await CodeReviewer().review(str(tmp_path), {})
    candidate = next(item for item in findings if "File-Open Path Review" in item.title)
    assert candidate.cwe_id == "CWE-Unknown"
    assert candidate.severity.value == "INFO"
    assert candidate.cvss_score == 0 and candidate.status is FindingStatus.UNVERIFIED
    assert "does not establish attacker-controlled paths" in candidate.description


def test_comment_in_trust_manager_does_not_hide_real_validation():
    source = '''void checkServerTrusted(Object c, String a) {
// A comment, then actual validation.
delegate.checkServerTrusted(c,a);
}'''
    assert not CodeReviewer()._audit_trust_managers_and_verifiers(source, "F.java", "F")


def test_taint_literals_comments_and_bound_sql_arguments_are_not_query_syntax():
    source = '''class Handler { void run(Intent in) {
String input = in.getStringExtra("name");
// web.loadUrl(input);
String doc = "web.loadUrl(input)";
db.rawQuery("SELECT name FROM synthetic WHERE name = ?", new String[] { input });
web.loadUrl("https://synthetic.invalid/constant", headers(input));
startActivity(cleanIntent, options(input));
} }'''
    assert not TaintEngine().analyze_source_content(source)


def test_taint_multiline_inline_sources_and_same_line_scopes():
    source = '''class Handler {
void first() { String name = in.getStringExtra("name"); }
void second() { db.rawQuery(name, null); }
void third(Intent in) {
web.loadUrl(
  in.getStringExtra("url")
);
}
}'''
    results = TaintEngine().analyze_source_content(source, "Handler.java")
    assert len(results) == 1
    assert results[0].cwe_id == "CWE-829"
    assert results[0].metadata["interprocedural_value_flow"] == "intra_method_lexical_flow"
    assert results[0].cvss_score == 0 and results[0].cvss_vector == ""


def test_tainted_ternary_condition_does_not_taint_constant_result_arms():
    source = '''class Handler {
void render(Intent incoming, WebView web) {
  String flag = incoming.getStringExtra("flag");
  String fixed = flag.equals("yes")
      ? "https://safe-a.invalid/" : "https://safe-b.invalid/";
  web.loadUrl(fixed);
  String selected = incoming.getStringExtra("flag").equals("yes")
      ? "https://safe.invalid/" : incoming.getStringExtra("url");
  web.loadUrl(selected);
}
}'''
    results = TaintEngine().analyze_source_content(source, "Handler.java")
    assert len(results) == 1
    assert results[0].cwe_id == "CWE-829"


def test_kotlin_safe_call_does_not_join_following_lines_into_same_statement():
    source = '''class Handler {
fun render(incoming: Intent, web: WebView) {
  val optional = incoming?.getStringExtra("optional")
  val target = incoming.getStringExtra("url")
  web.loadUrl(target)
}
}'''
    results = TaintEngine().analyze_source_content(source, "Handler.kt")
    assert len(results) == 1
    assert results[0].cwe_id == "CWE-829"
    assert "target" in results[0].description


def test_webview_sink_name_on_unrelated_local_class_is_not_a_webview_finding():
    source = '''class Dummy { void loadUrl(String value) {} }
class Handler {
  void render(Intent incoming, Dummy web) {
    String target = incoming.getStringExtra("url");
    web.loadUrl(target);
  }
}'''
    results = TaintEngine().analyze_source_content(source, "Handler.java")
    assert not any(item.cwe_id == "CWE-829" for item in results)

    subclass_source = '''class SafeWebView extends WebView {}
class Handler {
  void render(Intent incoming, SafeWebView web) {
    String target = incoming.getStringExtra("url");
    web.loadUrl(target);
  }
}'''
    subclass_results = TaintEngine().analyze_source_content(subclass_source, "Handler.java")
    assert any(item.cwe_id == "CWE-829" for item in subclass_results)


def test_rawquery_name_on_unrelated_local_class_is_not_sql_injection():
    source = '''class DummyStore { void rawQuery(String sql) {} }
class Handler {
  void query(Intent incoming, DummyStore store) {
    String sql = incoming.getStringExtra("query");
    store.rawQuery(sql);
  }
}'''
    results = TaintEngine().analyze_source_content(source, "Handler.java")
    assert not any(item.cwe_id == "CWE-89" for item in results)

    sqlite_compatible = '''interface SupportSQLiteDatabase { void rawQuery(String sql); }
class WrappedStore implements SupportSQLiteDatabase {
  public void rawQuery(String sql) {}
}
class Handler {
  void query(Intent incoming, WrappedStore store) {
    String sql = incoming.getStringExtra("query");
    store.rawQuery(sql);
  }
}'''
    compatible_results = TaintEngine().analyze_source_content(sqlite_compatible, "Handler.java")
    assert any(item.cwe_id == "CWE-89" for item in compatible_results)


def test_startactivity_name_collision_does_not_create_intent_redirection_candidate():
    source = '''class FakeLauncher { void startActivity(Intent value) {} }
class Handler {
  void onNewIntent(Intent incoming, FakeLauncher launcher) {
    Intent next = incoming.getParcelableExtra("next");
    launcher.startActivity(next);
  }
}'''
    results = TaintEngine().analyze_source_content(source, "Handler.java")
    assert not any(item.cwe_id == "CWE-927" for item in results)

    actual_context_sink = '''class Handler {
  void onNewIntent(Intent incoming, Activity activity) {
    Intent next = incoming.getParcelableExtra("next");
    activity.startActivity(next);
  }
}'''
    context_results = TaintEngine().analyze_source_content(actual_context_sink, "Handler.java")
    assert any(item.cwe_id == "CWE-927" for item in context_results)


def test_same_named_helpers_do_not_share_parameter_sink_summaries():
    source = '''class RealLauncher {
  void open(Intent next) { context.startActivity(next); }
}
class PlainHandler { void open(String value) {} }
class Handler {
  void onNewIntent(Intent incoming, PlainHandler helper) {
    helper.open(incoming.getStringExtra("url"));
  }
}'''
    results = TaintEngine().analyze_source_content(source, "Handler.java")
    assert not any(item.cwe_id == "CWE-927" for item in results)


def test_helper_sink_summary_does_not_match_different_typed_receiver():
    source = '''class RealLauncher {
  void open(Intent next) { context.startActivity(next); }
}
class Handler {
  void onNewIntent(Intent incoming, ExternalHelper helper) {
    helper.open(incoming.getParcelableExtra("next"));
  }
}'''
    results = TaintEngine().analyze_source_content(source, "Handler.java")
    assert not any(item.cwe_id == "CWE-927" for item in results)

    field_receiver_source = '''class RealLauncher {
  void open(Intent next) { context.startActivity(next); }
}
class Handler {
  ExternalHelper helper;
  void onNewIntent(Intent incoming) {
    helper.open(incoming.getParcelableExtra("next"));
  }
}'''
    field_results = TaintEngine().analyze_source_content(field_receiver_source, "Handler.java")
    assert not any(item.cwe_id == "CWE-927" for item in field_results)


def test_helper_return_summary_does_not_match_different_typed_receiver():
    source = '''class LocalParser {
  String parse(Intent input) { return input.getStringExtra("url"); }
}
class Handler {
  void onNewIntent(Intent incoming, ExternalParser parser, WebView web) {
    web.loadUrl(parser.parse(incoming.getStringExtra("url")));
  }
}'''
    results = TaintEngine().analyze_source_content(source, "Handler.java")
    assert not any(item.cwe_id == "CWE-829" for item in results)

    matching_receiver = source.replace("ExternalParser parser", "LocalParser parser")
    matching_results = TaintEngine().analyze_source_content(matching_receiver, "Handler.java")
    assert any(item.cwe_id == "CWE-829" for item in matching_results)


def test_reflection_arguments_are_not_mistaken_for_dynamic_target_selection():
    invoke_arguments = '''class Handler {
  void onNewIntent(Intent incoming, Method method) {
    String value = incoming.getStringExtra("value");
    method.invoke(this, value);
  }
}'''
    assert not any(item.cwe_id == "CWE-470" for item in
                   TaintEngine().analyze_source_content(invoke_arguments, "Handler.java"))

    class_lookup = '''class Handler {
  void onNewIntent(Intent incoming) {
    String className = incoming.getStringExtra("className");
    Class<?> selected = Class.forName(className);
  }
}'''
    assert any(item.cwe_id == "CWE-470" for item in
               TaintEngine().analyze_source_content(class_lookup, "Handler.java"))

    method_lookup = '''class Handler {
  void onNewIntent(Intent incoming, Class<?> type) {
    String methodName = incoming.getStringExtra("methodName");
    type.getMethod(methodName);
  }
}'''
    assert any(item.cwe_id == "CWE-470" for item in
               TaintEngine().analyze_source_content(method_lookup, "Handler.java"))
