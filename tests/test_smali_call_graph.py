"""Unit tests for Smali Call Graph & Reachability Engine."""

import tempfile
from pathlib import Path
import pytest
from mobileag.analysis.call_graph import SmaliCallGraphEngine


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
    assert local[0].metadata["register_dataflow"] == "same_method_move_result_and_move_object_only"


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
