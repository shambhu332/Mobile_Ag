"""Unit tests for Smali Call Graph & Reachability Engine."""

import tempfile
from pathlib import Path
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
        assert finding.cwe_id == "CWE-749"
        assert "UXSS" in finding.title
        assert "MainActivity" in finding.code_snippet
        assert "loadUrl" in finding.code_snippet
        assert finding.confidence >= 0.9


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

