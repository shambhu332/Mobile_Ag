"""Unit tests for Smali Call Graph & Reachability Engine."""

import tempfile
from pathlib import Path
import pytest
from mobileag.analysis.call_graph import (
    SmaliCallGraphEngine,
    _parameter_argument_registers,
)


def test_smali_argument_mapper_accounts_for_receiver_and_wide_parameters():
    assert _parameter_argument_registers("(JLjava/lang/String;)V", True,
                                         ["v0", "v1", "v2"]) == [("p0", "v0"), ("p2", "v2")]
    assert _parameter_argument_registers("(JLjava/lang/String;)V", False,
                                         ["v0", "v1", "v2", "v3"]) == [("p1", "v1"), ("p3", "v3")]
    assert _parameter_argument_registers("(Ljava/lang/String;)V", True, ["v0", "v1"]) == []


def test_smali_call_graph_parsing_and_reachability():
    engine = SmaliCallGraphEngine()

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        # Create simulated MainActivity.smali: calls getIntent().getStringExtra() -> Router.navigate()
        main_activity_smali = """
.class public Lcom/target/app/MainActivity;
.super Landroid/app/Activity;

.method public onCreate(Landroid/os/Bundle;)V
    .registers 3
    invoke-virtual {p0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;
    move-result-object v0
    const-string v1, "deep_url"
    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v2
    invoke-static {v2}, Lcom/target/app/Router;->navigate(Ljava/lang/String;)V
    return-void
.end method
"""

        # Create simulated Router.smali: calls WebView.loadUrl()
        router_smali = """
.class public Lcom/target/app/Router;
.super Ljava/lang/Object;

.method public static navigate(Ljava/lang/String;)V
    .registers 2
    sget-object v0, Lcom/target/app/Router;->webView:Landroid/webkit/WebView;
    invoke-virtual {v0, p0}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
"""

        (tmp_path / "MainActivity.smali").write_text(main_activity_smali)
        (tmp_path / "Router.smali").write_text(router_smali)

        # Build graph and audit directory
        findings = engine.audit_smali_directory(tmp_path)

        assert len(findings) >= 1
        finding = findings[0]
        assert finding.cwe_id == "CWE-829"
        # Syntactic call reachability is not proven register dataflow or UXSS.
        assert "call-path candidate" in finding.title
        assert "MainActivity" in finding.code_snippet
        assert "loadUrl" in finding.code_snippet
        assert finding.confidence <= 0.5
        assert finding.cvss_score == 0
        assert finding.status.value == "UNVERIFIED"
        assert finding.metadata["register_dataflow"] == "not_implemented"
        assert finding.metadata["proof_state"] == "not_proven"


def test_smali_same_method_register_flow_is_reported_separately_from_call_path(tmp_path):
    (tmp_path / "Local.smali").write_text("""
.class public Lcom/example/Local;
.super Landroid/app/Activity;
.method public onCreate(Landroid/os/Bundle;)V
    .registers 4
    invoke-virtual {p0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;
    move-result-object v0
    const-string v1, "url"
    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    # assembler comment between invoke and move-result should not drop source taint
    move-result-object v2
    move-object v3, v2
    sget-object v0, Lcom/example/Local;->web:Landroid/webkit/WebView;
    invoke-virtual/range {v0 .. v3}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
""")
    findings = SmaliCallGraphEngine().audit_smali_directory(tmp_path)
    local = [f for f in findings if f.metadata.get("analysis_kind") == "smali_local_register_flow"]
    assert len(local) == 1
    assert local[0].cwe_id == "CWE-829"
    assert local[0].line_number == 14
    assert local[0].status.value == "UNVERIFIED"
    assert local[0].cvss_score == 0
    assert local[0].metadata["register_dataflow"] == "same_method_moves_plus_exact_signature_parameter_arguments"


def test_smali_interprocedural_argument_flow_reports_both_source_and_sink_files(tmp_path):
    source_file = tmp_path / "Entry.smali"
    sink_file = tmp_path / "Helper.smali"
    source_file.write_text("""
.class public Lcom/example/Entry;
.super Landroid/app/Activity;
.method public onCreate(Landroid/os/Bundle;)V
    .registers 3
    invoke-virtual {p0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;
    move-result-object v0
    const-string v1, "target"
    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v2
    invoke-static {v2}, Lcom/example/Helper;->load(Ljava/lang/String;)V
    return-void
.end method
""", encoding="utf-8")
    sink_file.write_text("""
.class public Lcom/example/Helper;
.super Ljava/lang/Object;
.method public static load(Ljava/lang/String;)V
    .registers 2
    sget-object v0, Lcom/example/Helper;->web:Landroid/webkit/WebView;
    invoke-virtual {v0, p0}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
""", encoding="utf-8")

    engine = SmaliCallGraphEngine()
    findings = engine.audit_smali_directory(tmp_path)
    cross_method = [finding for finding in findings
                    if finding.metadata.get("analysis_kind") == "smali_interprocedural_argument_flow"]

    assert len(cross_method) == 1
    finding = cross_method[0]
    assert finding.cwe_id == "CWE-829"
    assert finding.status.value == "UNVERIFIED"
    assert finding.file_path == str(sink_file)
    assert finding.metadata["source_file"] == str(source_file)
    assert finding.metadata["source_method"].startswith("Lcom/example/Entry;->onCreate")
    assert "dynamic dispatch" in finding.description
    assert engine.coverage["interprocedural_flow_status"] == "bounded_parameter_arguments"


@pytest.mark.parametrize("annotated,visibility,expected", [
    (True, "public", True),
    (False, "public", False),
    (True, "private", False),
])
def test_javascript_interface_parameters_are_only_candidate_sources(
        tmp_path, annotated, visibility, expected):
    annotation = (
        ".annotation runtime Landroid/webkit/JavascriptInterface;\n    .end annotation"
        if annotated else ""
    )
    (tmp_path / "Bridge.smali").write_text(f"""
.class public Lcom/example/Bridge;
.super Ljava/lang/Object;
.method {visibility} bridge(Ljava/lang/String;)V
    .registers 3
    {annotation}
    sget-object v0, Lcom/example/Bridge;->web:Landroid/webkit/WebView;
    invoke-virtual {{v0, p1}}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
""", encoding="utf-8")

    engine = SmaliCallGraphEngine()
    findings = engine.audit_smali_directory(tmp_path)
    bridge_flows = [finding for finding in findings
                    if finding.metadata.get("source_kind") == "WEBVIEW_JAVASCRIPT_INTERFACE_PARAMETER"]

    assert bool(bridge_flows) is expected
    if expected:
        finding = bridge_flows[0]
        assert finding.cwe_id == "CWE-829"
        assert finding.metadata["proof_state"] == "not_proven"
        assert finding.line_number == 9
        assert "does not prove the object is registered" in finding.description


@pytest.mark.parametrize(("source_method", "sink_method"), [
    ("getStringExtraCompat", "loadUrl"),
    ("getStringExtra", "loadUrlCompat"),
])
def test_framework_method_lookalike_names_do_not_match_source_or_sink_prefixes(
        tmp_path, source_method, sink_method):
    (tmp_path / "Lookalike.smali").write_text(f"""
.class public Lcom/example/Lookalike;
.super Landroid/app/Activity;
.method public inspect(Landroid/content/Intent;Landroid/webkit/WebView;)V
    .registers 4
    const-string v0, "url"
    invoke-virtual {{p1, v0}}, Landroid/content/Intent;->{source_method}(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v1
    invoke-virtual {{p2, v1}}, Landroid/webkit/WebView;->{sink_method}(Ljava/lang/String;)V
    return-void
.end method
""", encoding="utf-8")

    engine = SmaliCallGraphEngine()
    findings = engine.audit_smali_directory(tmp_path)
    assert findings == []


@pytest.mark.parametrize("overwrite", [
    'const-string v2, "https://example.invalid"',
    "aget-object v2, v4, v5",
    "move-exception v2",
])
def test_smali_overwritten_source_register_does_not_create_local_flow_candidate(tmp_path, overwrite):
    (tmp_path / "NoFlow.smali").write_text("""
.class public Lcom/example/NoFlow;
.super Landroid/app/Activity;
.method public onCreate(Landroid/os/Bundle;)V
    .registers 4
    invoke-virtual {p0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;
    move-result-object v0
    const-string v1, "unused"
    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v2
    {overwrite}
    sget-object v0, Lcom/example/NoFlow;->web:Landroid/webkit/WebView;
    invoke-virtual {v0, v2}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
""".replace("    {overwrite}", f"    {overwrite}"))
    findings = SmaliCallGraphEngine().audit_smali_directory(tmp_path)
    assert not any(f.metadata.get("analysis_kind") == "smali_local_register_flow" for f in findings)


def test_smali_unreachable_sink_after_return_is_not_local_flow(tmp_path):
    (tmp_path / "DeadCode.smali").write_text("""
.class public Lcom/example/DeadCode;
.super Landroid/app/Activity;
.method public open()V
    .registers 3
    invoke-virtual {p0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;
    move-result-object v0
    const-string v1, "url"
    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v2
    return-void
    sget-object v0, Lcom/example/DeadCode;->web:Landroid/webkit/WebView;
    invoke-virtual {v0, v2}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
.end method
""")
    findings = SmaliCallGraphEngine().audit_smali_directory(tmp_path)
    assert not any(f.metadata.get("analysis_kind") == "smali_local_register_flow" for f in findings)


def test_smali_conditional_branch_keeps_possible_tainted_path(tmp_path):
    (tmp_path / "Branch.smali").write_text("""
.class public Lcom/example/Branch;
.super Landroid/app/Activity;
.method public open()V
    .registers 4
    invoke-virtual {p0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;
    move-result-object v0
    const-string v1, "url"
    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v2
    if-eqz v1, :load
    const-string v2, "https://safe.invalid"
    :load
    sget-object v0, Lcom/example/Branch;->web:Landroid/webkit/WebView;
    invoke-virtual {v0, v2}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
""")
    findings = SmaliCallGraphEngine().audit_smali_directory(tmp_path)
    assert any(f.metadata.get("analysis_kind") == "smali_local_register_flow" and f.cwe_id == "CWE-829"
               for f in findings)


def test_smali_unmodeled_switch_marks_register_flow_coverage_partial(tmp_path):
    (tmp_path / "Switch.smali").write_text("""
.class public Lcom/example/Switch;
.super Ljava/lang/Object;
.method public route(I)V
    .registers 2
    packed-switch p1, :pswitch_data
    return-void
    :case_0
    return-void
    :pswitch_data
    .packed-switch 0x0
        :case_0
    .end packed-switch
.end method
""")
    engine = SmaliCallGraphEngine()
    engine.audit_smali_directory(tmp_path)
    assert engine.coverage["static_status"] == "partial"
    assert "unresolved switch targets" in " ".join(engine.coverage["register_dataflow_warnings"])


def test_smali_call_graph_reflection_resolution():
    engine = SmaliCallGraphEngine()

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        reflective_smali = """
.class public Lcom/target/app/ReflectiveLoader;
.super Landroid/app/Activity;

.method public onCreate(Landroid/os/Bundle;)V
    .registers 5
    invoke-virtual {p0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;
    move-result-object v0
    const-string v1, "cmd"
    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v2
    invoke-static {v2}, Lcom/target/app/ReflectiveLoader;->executeReflective(Ljava/lang/String;)V
    return-void
.end method

.method public static executeReflective(Ljava/lang/String;)V
    .registers 4
    const-class v0, Ljava/lang/Runtime;
    const-string v1, "exec"
    invoke-virtual {v0, v1}, Ljava/lang/Class;->getMethod(Ljava/lang/String;)Ljava/lang/reflect/Method;
    move-result-object v2
    invoke-virtual {v2, v0, p0}, Ljava/lang/reflect/Method;->invoke(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;
    return-void
.end method
"""
        (tmp_path / "ReflectiveLoader.smali").write_text(reflective_smali)
        findings = engine.audit_smali_directory(tmp_path)
        assert len(findings) >= 1
        cwes = {f.cwe_id for f in findings}
        assert "CWE-78" in cwes or "CWE-470" in cwes


def test_smali_call_graph_synthetic_bridge_resolution():
    engine = SmaliCallGraphEngine()

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)

        outer_smali = """
.class public Lcom/target/app/PluginManager;
.super Ljava/lang/Object;

.method private static loadPluginInternal(Ljava/lang/String;)V
    .registers 3
    new-instance v0, Ldalvik/system/DexClassLoader;
    invoke-direct {v0, p0}, Ldalvik/system/DexClassLoader;-><init>(Ljava/lang/String;)V
    return-void
.end method

.method static synthetic access$000(Ljava/lang/String;)V
    .registers 1
    invoke-static {p0}, Lcom/target/app/PluginManager;->loadPluginInternal(Ljava/lang/String;)V
    return-void
.end method
"""

        caller_smali = """
.class public Lcom/target/app/ReceiverActivity;
.super Landroid/app/Activity;

.method public onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    .registers 4
    invoke-virtual {p2}, Landroid/content/Intent;->getDataString()Ljava/lang/String;
    move-result-object v0
    invoke-static {v0}, Lcom/target/app/PluginManager;->access$000(Ljava/lang/String;)V
    return-void
.end method
"""
        (tmp_path / "PluginManager.smali").write_text(outer_smali)
        (tmp_path / "ReceiverActivity.smali").write_text(caller_smali)

        findings = engine.audit_smali_directory(tmp_path)
        assert len(findings) >= 1
        assert any(f.cwe_id == "CWE-470" for f in findings)
