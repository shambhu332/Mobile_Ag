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
