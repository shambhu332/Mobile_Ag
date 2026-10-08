"""Synthetic lexical-review regression controls; no Android runtime is exercised."""
from pathlib import Path

import pytest

from mobileag.analysis.code_reviewer import CodeReviewer
from mobileag.analysis.source_syntax import call_sites, literal_flag_bits
from mobileag.analysis.taint_engine import TaintEngine
from mobileag.reporting.finding import FindingStatus


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
void third() {
web.loadUrl(
  in.getStringExtra("url")
);
}
}'''
    results = TaintEngine().analyze_source_content(source, "Handler.java")
    assert len(results) == 1
    assert results[0].cwe_id == "CWE-749"
    assert results[0].metadata["interprocedural_value_flow"] == "not_implemented"
    assert results[0].cvss_score == 0 and results[0].cvss_vector == ""
