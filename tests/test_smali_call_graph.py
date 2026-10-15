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
    assert local[0].metadata["register_dataflow"] == (
        "same_method_moves_arithmetic_string_transforms_builder_mutations_array_elements_static_fields_exact_signature_arguments_and_returns"
    )


def test_smali_interprocedural_register_flow_reports_both_source_and_sink_files(tmp_path):
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
                    if finding.metadata.get("analysis_kind") == "smali_interprocedural_register_flow"]

    assert len(cross_method) == 1
    finding = cross_method[0]
    assert finding.cwe_id == "CWE-829"
    assert finding.status.value == "UNVERIFIED"
    assert finding.file_path == str(sink_file)
    assert finding.metadata["source_file"] == str(source_file)
    assert finding.metadata["source_method"].startswith("Lcom/example/Entry;->onCreate")
    assert "dynamic dispatch" in finding.description
    assert engine.coverage["interprocedural_flow_status"] == "bounded_arguments_static_fields_and_returns"


def test_smali_static_field_taint_flows_between_methods(tmp_path):
    source_file = tmp_path / "Entry.smali"
    sink_file = tmp_path / "Reader.smali"
    source_file.write_text("""
.class public Lcom/example/Entry;
.super Landroid/app/Activity;
.method public onCreate(Landroid/os/Bundle;)V
    .registers 3
    invoke-virtual {p0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;
    move-result-object v0
    const-string v1, "url"
    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v2
    sput-object v2, Lcom/example/Shared;->target:Ljava/lang/String;
    return-void
.end method
""", encoding="utf-8")
    sink_file.write_text("""
.class public Lcom/example/Reader;
.super Ljava/lang/Object;
.method public static load()V
    .registers 2
    sget-object v0, Lcom/example/Shared;->target:Ljava/lang/String;
    sget-object v1, Lcom/example/Reader;->web:Landroid/webkit/WebView;
    invoke-virtual {v1, v0}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
""", encoding="utf-8")

    engine = SmaliCallGraphEngine()
    findings = engine.audit_smali_directory(tmp_path)
    field_flows = [finding for finding in findings
                   if finding.metadata.get("analysis_kind") == "smali_interprocedural_register_flow"]

    assert len(field_flows) == 1
    assert field_flows[0].file_path == str(sink_file)
    assert field_flows[0].metadata["source_file"] == str(source_file)
    assert engine.coverage["interprocedural_static_field_taint_facts"] == 1


def test_internal_static_field_value_is_not_assumed_untrusted(tmp_path):
    (tmp_path / "InternalField.smali").write_text("""
.class public Lcom/example/InternalField;
.super Ljava/lang/Object;
.method public static load()V
    .registers 3
    const-string v0, "constant"
    sput-object v0, Lcom/example/InternalField;->target:Ljava/lang/String;
    sget-object v1, Lcom/example/InternalField;->target:Ljava/lang/String;
    sget-object v2, Lcom/example/InternalField;->web:Landroid/webkit/WebView;
    invoke-virtual {v2, v1}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
""", encoding="utf-8")

    engine = SmaliCallGraphEngine()
    findings = engine.audit_smali_directory(tmp_path)
    assert not any(finding.metadata.get("analysis_kind") in {
        "smali_local_register_flow", "smali_interprocedural_register_flow",
    } for finding in findings)


def test_smali_taint_flows_through_exact_method_return_summary(tmp_path):
    source_file = tmp_path / "Entry.smali"
    helper_file = tmp_path / "Helper.smali"
    source_file.write_text("""
.class public Lcom/example/Entry;
.super Landroid/app/Activity;
.method public onCreate(Landroid/os/Bundle;)V
    .registers 4
    invoke-virtual {p0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;
    move-result-object v0
    const-string v1, "url"
    invoke-virtual {v0, v1}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v2
    invoke-static {v2}, Lcom/example/Helper;->identity(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v3
    sget-object v0, Lcom/example/Entry;->web:Landroid/webkit/WebView;
    invoke-virtual {v0, v3}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
""", encoding="utf-8")
    helper_file.write_text("""
.class public Lcom/example/Helper;
.super Ljava/lang/Object;
.method public static identity(Ljava/lang/String;)Ljava/lang/String;
    .registers 1
    return-object p0
.end method
""", encoding="utf-8")

    engine = SmaliCallGraphEngine()
    findings = engine.audit_smali_directory(tmp_path)
    return_flows = [finding for finding in findings
                    if finding.metadata.get("analysis_kind") == "smali_interprocedural_register_flow"]

    assert len(return_flows) == 1
    assert return_flows[0].file_path == str(source_file)
    assert return_flows[0].metadata["source_file"] == str(source_file)
    assert engine.coverage["interprocedural_return_taint_facts"] == 1
    assert engine.coverage["interprocedural_flow_status"] == (
        "bounded_arguments_static_fields_and_returns"
    )


def test_smali_untainted_return_value_does_not_inherit_tainted_arguments(tmp_path):
    (tmp_path / "ReturnConstant.smali").write_text("""
.class public Lcom/example/ReturnConstant;
.super Landroid/app/Activity;
.method public inspect(Landroid/content/Intent;Landroid/webkit/WebView;)V
    .registers 4
    const-string v0, "url"
    invoke-virtual {p1, v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v1
    invoke-static {v1}, Lcom/example/Helper;->constant(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v2
    invoke-virtual {p2, v2}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
""", encoding="utf-8")
    (tmp_path / "Helper.smali").write_text("""
.class public Lcom/example/Helper;
.super Ljava/lang/Object;
.method public static constant(Ljava/lang/String;)Ljava/lang/String;
    .registers 2
    const-string v0, "constant"
    return-object v0
.end method
""", encoding="utf-8")

    findings = SmaliCallGraphEngine().audit_smali_directory(tmp_path)
    assert not any(finding.metadata.get("analysis_kind") in {
        "smali_local_register_flow", "smali_interprocedural_register_flow",
    } for finding in findings)


def test_smali_primitive_moves_and_arithmetic_preserve_taint(tmp_path):
    (tmp_path / "PrimitiveFlow.smali").write_text("""
.class public Lcom/example/PrimitiveFlow;
.super Ljava/lang/Object;
.method public static adjust(I)I
    .registers 5
    move v0, p0
    add-int/lit8 v1, v0, 0x1
    neg-int v2, v1
    add-int/2addr v2, v0
    return v2
.end method
""", encoding="utf-8")

    engine = SmaliCallGraphEngine()
    engine.build_graph(tmp_path)
    method = next(iter(engine.methods.values()))
    trace = ("SYNTHETIC_PRIMITIVE", method.line_number, method.key, method.file_path)
    _flows, _arguments, _field_writes, _field_reads, return_flows, _called = (
        engine._analyze_local_register_flows(method, {"p0": frozenset({trace})})
    )

    assert return_flows == {trace}


@pytest.mark.parametrize("construction", [
    "string_concat", "string_value_of", "string_substring", "string_builder_chain",
    "builder_constructor", "builder_insert_chain",
])
def test_smali_string_construction_preserves_tainted_input(construction, tmp_path):
    if construction == "string_concat":
        body = """
    const-string v0, "prefix:"
    invoke-virtual {p0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;
    move-result-object v1
    const-string v2, "url"
    invoke-virtual {v1, v2}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v3
    invoke-virtual {v0, v3}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v4
    sget-object v0, Lcom/example/Compose;->web:Landroid/webkit/WebView;
    invoke-virtual {v0, v4}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
"""
    elif construction == "string_value_of":
        body = """
    invoke-virtual {p0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;
    move-result-object v1
    const-string v2, "url"
    invoke-virtual {v1, v2}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v3
    invoke-static {v3}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;
    move-result-object v4
    sget-object v0, Lcom/example/Compose;->web:Landroid/webkit/WebView;
    invoke-virtual {v0, v4}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
"""
    else:
        if construction == "string_substring":
            body = """
    invoke-virtual {p0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;
    move-result-object v1
    const-string v2, "url"
    invoke-virtual {v1, v2}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v3
    const/4 v4, 0x0
    const/4 v5, 0x1
    invoke-virtual {v3, v4, v5}, Ljava/lang/String;->substring(II)Ljava/lang/String;
    move-result-object v6
    sget-object v0, Lcom/example/Compose;->web:Landroid/webkit/WebView;
    invoke-virtual {v0, v6}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
"""
        elif construction == "builder_constructor":
            body = """
    new-instance v0, Ljava/lang/StringBuilder;
    invoke-virtual {p0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;
    move-result-object v1
    const-string v2, "url"
    invoke-virtual {v1, v2}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v3
    invoke-direct {v0, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v4
    sget-object v0, Lcom/example/Compose;->web:Landroid/webkit/WebView;
    invoke-virtual {v0, v4}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
"""
        elif construction == "builder_insert_chain":
            body = """
    new-instance v0, Ljava/lang/StringBuilder;
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V
    invoke-virtual {p0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;
    move-result-object v1
    const-string v2, "url"
    invoke-virtual {v1, v2}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v3
    const/4 v1, 0x0
    invoke-virtual {v0, v1, v3}, Ljava/lang/StringBuilder;->insert(ILjava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v4
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v5
    sget-object v0, Lcom/example/Compose;->web:Landroid/webkit/WebView;
    invoke-virtual {v0, v5}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
"""
        else:
            body = """
    new-instance v0, Ljava/lang/StringBuilder;
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V
    invoke-virtual {p0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;
    move-result-object v1
    const-string v2, "url"
    invoke-virtual {v1, v2}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v3
    invoke-virtual {v0, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v4
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v5
    sget-object v0, Lcom/example/Compose;->web:Landroid/webkit/WebView;
    invoke-virtual {v0, v5}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
"""
    (tmp_path / "Compose.smali").write_text(f"""
.class public Lcom/example/Compose;
.super Landroid/app/Activity;
.method public inspect()V
    .registers 7
{body}
    return-void
.end method
""", encoding="utf-8")

    findings = SmaliCallGraphEngine().audit_smali_directory(tmp_path)
    flows = [finding for finding in findings
             if finding.metadata.get("analysis_kind") == "smali_local_register_flow"]
    assert len(flows) == 1
    assert flows[0].metadata["source_kind"] == "INTENT_EXTRA"


def test_internal_string_builder_is_not_unconditionally_treated_as_tainted(tmp_path):
    (tmp_path / "InternalBuilder.smali").write_text("""
.class public Lcom/example/InternalBuilder;
.super Ljava/lang/Object;
.method public static load()V
    .registers 4
    new-instance v0, Ljava/lang/StringBuilder;
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V
    const-string v1, "constant"
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;
    move-result-object v2
    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v3
    sget-object v0, Lcom/example/InternalBuilder;->web:Landroid/webkit/WebView;
    invoke-virtual {v0, v3}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
""", encoding="utf-8")

    findings = SmaliCallGraphEngine().audit_smali_directory(tmp_path)
    assert not any(finding.metadata.get("analysis_kind") in {
        "smali_local_register_flow", "smali_interprocedural_register_flow",
    } for finding in findings)


@pytest.mark.parametrize("webview_sink", ["loadData", "loadDataWithBaseURL", "postUrl"])
def test_smali_webview_content_and_post_sinks_trace_intent_input(webview_sink, tmp_path):
    if webview_sink == "loadData":
        get_extra = "getStringExtra(Ljava/lang/String;)Ljava/lang/String;"
        load_call = "invoke-virtual {p1, v1, v2, v3}, Landroid/webkit/WebView;->loadData(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V"
    elif webview_sink == "loadDataWithBaseURL":
        get_extra = "getStringExtra(Ljava/lang/String;)Ljava/lang/String;"
        load_call = "invoke-virtual {p1, v2, v1, v3, v4, v5}, Landroid/webkit/WebView;->loadDataWithBaseURL(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)V"
    else:
        get_extra = "getByteArrayExtra(Ljava/lang/String;)[B"
        load_call = "invoke-virtual {p1, v2, v1}, Landroid/webkit/WebView;->postUrl(Ljava/lang/String;[B)Z"

    (tmp_path / "WebViewSink.smali").write_text(f"""
.class public Lcom/example/WebViewSink;
.super Landroid/app/Activity;
.method public inspect(Landroid/webkit/WebView;)V
    .registers 8
    const-string v0, "data"
    invoke-virtual {{p0}}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;
    move-result-object v6
    const-string v0, "payload"
    invoke-virtual {{v6, v0}}, Landroid/content/Intent;->{get_extra}
    move-result-object v1
    const-string v2, "https://example.invalid/"
    const-string v3, "text/html"
    const-string v4, "UTF-8"
    const-string v5, ""
    {load_call}
    return-void
.end method
""", encoding="utf-8")

    findings = SmaliCallGraphEngine().audit_smali_directory(tmp_path)
    flows = [finding for finding in findings
             if finding.metadata.get("analysis_kind") == "smali_local_register_flow"]
    assert len(flows) == 1
    assert flows[0].metadata["source_kind"] == "INTENT_EXTRA"
    assert f"Landroid/webkit/WebView;->{webview_sink}" in flows[0].description


@pytest.mark.parametrize("getter", ["getAction()Ljava/lang/String;", "getType()Ljava/lang/String;"])
def test_smali_intent_metadata_getters_derive_taint_from_external_intent(getter, tmp_path):
    (tmp_path / "IntentMetadata.smali").write_text(f"""
.class public Lcom/example/IntentMetadata;
.super Landroid/app/Activity;
.method public inspect(Landroid/webkit/WebView;)V
    .registers 4
    invoke-virtual {{p0}}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;
    move-result-object v0
    invoke-virtual {{v0}}, Landroid/content/Intent;->{getter}
    move-result-object v1
    invoke-virtual {{p1, v1}}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
""", encoding="utf-8")

    findings = SmaliCallGraphEngine().audit_smali_directory(tmp_path)
    flows = [finding for finding in findings
             if finding.metadata.get("analysis_kind") == "smali_local_register_flow"]
    assert len(flows) == 1
    assert flows[0].metadata["source_kind"] == "ACTIVITY_INTENT"
    assert flows[0].metadata["source_line"] < flows[0].line_number


def test_smali_lifecycle_intent_parameters_seed_derived_accessors_only_at_callbacks(tmp_path):
    (tmp_path / "LifecycleIntent.smali").write_text("""
.class public Lcom/example/LifecycleIntent;
.super Landroid/app/Activity;
.method public onNewIntent(Landroid/content/Intent;)V
    .registers 4
    invoke-virtual {p1}, Landroid/content/Intent;->getAction()Ljava/lang/String;
    move-result-object v0
    sget-object v1, Lcom/example/LifecycleIntent;->web:Landroid/webkit/WebView;
    invoke-virtual {v1, v0}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
.method protected onActivityResult(IILandroid/content/Intent;)V
    .registers 6
    invoke-virtual {p3}, Landroid/content/Intent;->getAction()Ljava/lang/String;
    move-result-object v0
    sget-object v1, Lcom/example/LifecycleIntent;->web:Landroid/webkit/WebView;
    invoke-virtual {v1, v0}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
.method public ordinaryHelper(Landroid/content/Intent;Landroid/webkit/WebView;)V
    .registers 4
    invoke-virtual {p1}, Landroid/content/Intent;->getAction()Ljava/lang/String;
    move-result-object v0
    invoke-virtual {p2, v0}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
""", encoding="utf-8")

    (tmp_path / "LifecycleReceiver.smali").write_text("""
.class public Lcom/example/LifecycleReceiver;
.super Landroid/content/BroadcastReceiver;
.method public onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    .registers 5
    invoke-virtual {p2}, Landroid/content/Intent;->getAction()Ljava/lang/String;
    move-result-object v0
    sget-object v1, Lcom/example/LifecycleReceiver;->web:Landroid/webkit/WebView;
    invoke-virtual {v1, v0}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
""", encoding="utf-8")

    (tmp_path / "LifecycleLookalike.smali").write_text("""
.class public Lcom/example/LifecycleLookalike;
.super Ljava/lang/Object;
.method public onNewIntent(Landroid/content/Intent;)V
    .registers 4
    invoke-virtual {p1}, Landroid/content/Intent;->getAction()Ljava/lang/String;
    move-result-object v0
    sget-object v1, Lcom/example/LifecycleLookalike;->web:Landroid/webkit/WebView;
    invoke-virtual {v1, v0}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
""", encoding="utf-8")

    engine = SmaliCallGraphEngine()
    findings = engine.audit_smali_directory(tmp_path)
    flows = [finding for finding in findings
             if finding.metadata.get("analysis_kind") == "smali_local_register_flow"]
    assert len(flows) == 3
    assert {flow.metadata["source_kind"] for flow in flows} == {"LIFECYCLE_INTENT_PARAMETER"}
    assert engine.coverage["lifecycle_intent_parameter_seed_methods"] == 3


@pytest.mark.parametrize("class_name,parent,method_signature,return_code,registers", [
    ("StartCommandService", "Landroid/app/Service;",
     "onStartCommand(Landroid/content/Intent;II)I", "const/4 v0, 0\n    return v0", 6),
    ("IntentWorker", "Landroid/app/IntentService;",
     "onHandleIntent(Landroid/content/Intent;)V", "return-void", 4),
    ("BoundService", "Landroid/app/Service;",
     "onBind(Landroid/content/Intent;)Landroid/os/IBinder;", "const/4 v0, 0\n    return-object v0", 4),
    ("UnboundService", "Landroid/app/Service;",
     "onUnbind(Landroid/content/Intent;)Z", "const/4 v0, 0\n    return v0", 4),
])
def test_smali_service_lifecycle_intent_parameters_are_seeded(
        class_name, parent, method_signature, return_code, registers, tmp_path):
    owner = f"Lcom/example/{class_name};"
    (tmp_path / f"{class_name}.smali").write_text(f"""
.class public {owner}
.super {parent}
.method public {method_signature}
    .registers {registers}
    invoke-virtual {{p1}}, Landroid/content/Intent;->getAction()Ljava/lang/String;
    move-result-object v0
    sget-object p0, {owner}->web:Landroid/webkit/WebView;
    invoke-virtual {{p0, v0}}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    {return_code}
.end method
""", encoding="utf-8")

    engine = SmaliCallGraphEngine()
    findings = engine.audit_smali_directory(tmp_path)
    flows = [finding for finding in findings
             if finding.metadata.get("analysis_kind") == "smali_local_register_flow"]
    assert len(flows) == 1
    assert flows[0].metadata["source_kind"] == "LIFECYCLE_INTENT_PARAMETER"
    assert engine.coverage["lifecycle_intent_parameter_seed_methods"] == 1


def test_smali_clipdata_uri_flows_from_external_intent_to_webview_navigation(tmp_path):
    (tmp_path / "ClipDataFlow.smali").write_text("""
.class public Lcom/example/ClipDataFlow;
.super Landroid/app/Activity;
.method public inspect(Landroid/webkit/WebView;)V
    .registers 5
    invoke-virtual {p0}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;
    move-result-object v0
    invoke-virtual {v0}, Landroid/content/Intent;->getClipData()Landroid/content/ClipData;
    move-result-object v1
    const/4 v2, 0x0
    invoke-virtual {v1, v2}, Landroid/content/ClipData;->getItemAt(I)Landroid/content/ClipData$Item;
    move-result-object v3
    invoke-virtual {v3}, Landroid/content/ClipData$Item;->getUri()Landroid/net/Uri;
    move-result-object v3
    invoke-virtual {v3}, Landroid/net/Uri;->toString()Ljava/lang/String;
    move-result-object v4
    invoke-virtual {p1, v4}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
""", encoding="utf-8")

    findings = SmaliCallGraphEngine().audit_smali_directory(tmp_path)
    flows = [finding for finding in findings
             if finding.metadata.get("analysis_kind") == "smali_local_register_flow"]
    assert len(flows) == 1
    assert flows[0].metadata["source_kind"] == "ACTIVITY_INTENT"
    assert flows[0].metadata["source_line"] < flows[0].line_number


def test_smali_clipdata_accessors_are_not_unconditional_sources(tmp_path):
    (tmp_path / "InternalClipData.smali").write_text("""
.class public Lcom/example/InternalClipData;
.super Ljava/lang/Object;
.method public inspect(Landroid/content/Intent;Landroid/webkit/WebView;)V
    .registers 5
    invoke-virtual {p1}, Landroid/content/Intent;->getClipData()Landroid/content/ClipData;
    move-result-object v0
    const/4 v1, 0x0
    invoke-virtual {v0, v1}, Landroid/content/ClipData;->getItemAt(I)Landroid/content/ClipData$Item;
    move-result-object v2
    invoke-virtual {v2}, Landroid/content/ClipData$Item;->getUri()Landroid/net/Uri;
    move-result-object v2
    invoke-virtual {v2}, Landroid/net/Uri;->toString()Ljava/lang/String;
    move-result-object v3
    invoke-virtual {p2, v3}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
""", encoding="utf-8")

    findings = SmaliCallGraphEngine().audit_smali_directory(tmp_path)
    assert not any(finding.metadata.get("analysis_kind") == "smali_local_register_flow"
                   for finding in findings)


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


@pytest.mark.parametrize(("container_call", "container_sig", "accessor_call", "accessor_sig", "source_kind"), [
    ("getExtras", "()Landroid/os/Bundle;", "Landroid/os/Bundle;->getString", "(Ljava/lang/String;)Ljava/lang/String;", "INTENT_BUNDLE"),
    ("getData", "()Landroid/net/Uri;", "Landroid/net/Uri;->getQueryParameter", "(Ljava/lang/String;)Ljava/lang/String;", "INTENT_DATA_URI"),
])
def test_bundle_and_uri_accessors_only_derive_existing_intent_taint(
        tmp_path, container_call, container_sig, accessor_call, accessor_sig, source_kind):
    (tmp_path / "Derived.smali").write_text(f"""
.class public Lcom/example/Derived;
.super Landroid/app/Activity;
.method public onCreate(Landroid/os/Bundle;)V
    .registers 5
    invoke-virtual {{p0}}, Landroid/app/Activity;->getIntent()Landroid/content/Intent;
    move-result-object v0
    invoke-virtual {{v0}}, Landroid/content/Intent;->{container_call}{container_sig}
    move-result-object v1
    const-string v2, "key"
    invoke-virtual {{v1, v2}}, {accessor_call}{accessor_sig}
    move-result-object v3
    sget-object v4, Lcom/example/Derived;->web:Landroid/webkit/WebView;
    invoke-virtual {{v4, v3}}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
""", encoding="utf-8")

    findings = SmaliCallGraphEngine().audit_smali_directory(tmp_path)
    derived = [finding for finding in findings
               if finding.metadata.get("analysis_kind") == "smali_local_register_flow"
               and finding.metadata.get("source_kind") == source_kind]
    assert len(derived) == 1
    assert derived[0].cwe_id == "CWE-829"
    assert derived[0].status.value == "UNVERIFIED"


def test_internal_bundle_getter_is_not_unconditionally_treated_as_external_input(tmp_path):
    (tmp_path / "InternalBundle.smali").write_text("""
.class public Lcom/example/InternalBundle;
.super Ljava/lang/Object;
.method public load()V
    .registers 4
    new-instance v0, Landroid/os/Bundle;
    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V
    const-string v1, "key"
    invoke-virtual {v0, v1}, Landroid/os/Bundle;->getString(Ljava/lang/String;)Ljava/lang/String;
    move-result-object v2
    sget-object v3, Lcom/example/InternalBundle;->web:Landroid/webkit/WebView;
    invoke-virtual {v3, v2}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
""", encoding="utf-8")

    findings = SmaliCallGraphEngine().audit_smali_directory(tmp_path)
    assert not any(finding.metadata.get("analysis_kind") in {
        "smali_local_register_flow", "smali_interprocedural_register_flow",
    } for finding in findings)


@pytest.mark.parametrize("array_flow", ["intent_extra", "tainted_store"])
def test_smali_array_element_taint_reaches_sink(array_flow, tmp_path):
    source = (
        "invoke-virtual {p0, v0}, Landroid/content/Intent;->getStringArrayExtra(Ljava/lang/String;)[Ljava/lang/String;\n"
        "move-result-object v1\n"
        "aget-object v2, v1, v0"
        if array_flow == "intent_extra" else
        "invoke-virtual {p0, v0}, Landroid/content/Intent;->getStringExtra(Ljava/lang/String;)Ljava/lang/String;\n"
        "move-result-object v1\n"
        "new-array v2, v0, [Ljava/lang/String;\n"
        "aput-object v1, v2, v0\n"
        "move-object v4, v2\n"
        "aget-object v3, v4, v0"
    )
    value_register = "v2" if array_flow == "intent_extra" else "v3"
    (tmp_path / "ArrayFlow.smali").write_text(f"""
.class public Lcom/example/ArrayFlow;
.super Landroid/app/Activity;
.method public inspect(Landroid/content/Intent;Landroid/webkit/WebView;)V
    .registers 6
    const/4 v0, 0x0
    {source}
    invoke-virtual {{p1, {value_register}}}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
""", encoding="utf-8")

    findings = SmaliCallGraphEngine().audit_smali_directory(tmp_path)
    array_flows = [finding for finding in findings
                   if finding.metadata.get("analysis_kind") == "smali_local_register_flow"]
    assert len(array_flows) == 1
    assert array_flows[0].metadata["source_kind"] == "INTENT_EXTRA"
    assert array_flows[0].metadata["proof_state"] == "not_proven"


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


def test_smali_external_content_flows_through_reader_and_file_path_to_webview(tmp_path):
    (tmp_path / "ExternalContent.smali").write_text("""
.class public Lcom/example/ExternalContent;
.super Landroid/app/Activity;
.method public onNewIntent(Landroid/content/Intent;Landroid/webkit/WebView;)V
    .registers 8
    invoke-virtual {p1}, Landroid/content/Intent;->getData()Landroid/net/Uri;
    move-result-object v0
    invoke-virtual {p0}, Landroid/app/Activity;->getContentResolver()Landroid/content/ContentResolver;
    move-result-object v1
    invoke-virtual {v1, v0}, Landroid/content/ContentResolver;->openInputStream(Landroid/net/Uri;)Ljava/io/InputStream;
    move-result-object v2
    new-instance v3, Ljava/io/InputStreamReader;
    invoke-direct {v3, v2}, Ljava/io/InputStreamReader;-><init>(Ljava/io/InputStream;)V
    new-instance v4, Ljava/io/BufferedReader;
    invoke-direct {v4, v3}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V
    invoke-virtual {v4}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;
    move-result-object v5
    invoke-virtual {p2, v5}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
.method public onNewIntentViaPath(Landroid/content/Intent;Landroid/webkit/WebView;)V
    .registers 8
    invoke-virtual {p1}, Landroid/content/Intent;->getData()Landroid/net/Uri;
    move-result-object v0
    invoke-virtual {v0}, Landroid/net/Uri;->getPath()Ljava/lang/String;
    move-result-object v1
    new-instance v2, Ljava/io/File;
    invoke-direct {v2, v1}, Ljava/io/File;-><init>(Ljava/lang/String;)V
    invoke-virtual {v2}, Ljava/io/File;->toPath()Ljava/nio/file/Path;
    move-result-object v3
    invoke-static {v3}, Ljava/nio/file/Files;->readString(Ljava/nio/file/Path;)Ljava/lang/String;
    move-result-object v4
    invoke-virtual {p2, v4}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
""", encoding="utf-8")

    findings = SmaliCallGraphEngine().audit_smali_directory(tmp_path)
    flows = [finding for finding in findings
             if finding.metadata.get("analysis_kind") == "smali_local_register_flow"
             and finding.metadata.get("source_kind") == "EXTERNAL_FILE_CONTENT_CANDIDATE"]
    assert len(flows) == 2
    assert all(flow.metadata["source_line"] < flow.line_number for flow in flows)


def test_smali_external_stream_read_buffer_taint_flows_through_array_and_builder(tmp_path):
    (tmp_path / "ExternalBuffer.smali").write_text("""
.class public Lcom/example/ExternalBuffer;
.super Landroid/app/Activity;
.method public onNewIntent(Landroid/content/Intent;Landroid/webkit/WebView;)V
    .registers 9
    invoke-virtual {p1}, Landroid/content/Intent;->getData()Landroid/net/Uri;
    move-result-object v0
    invoke-virtual {p0}, Landroid/app/Activity;->getContentResolver()Landroid/content/ContentResolver;
    move-result-object v1
    invoke-virtual {v1, v0}, Landroid/content/ContentResolver;->openInputStream(Landroid/net/Uri;)Ljava/io/InputStream;
    move-result-object v2
    new-instance v3, Ljava/io/InputStreamReader;
    invoke-direct {v3, v2}, Ljava/io/InputStreamReader;-><init>(Ljava/io/InputStream;)V
    const/4 v4, 1
    new-array v5, v4, [C
    invoke-virtual {v3, v5, v4, v4}, Ljava/io/InputStreamReader;->read([CII)I
    const/4 v6, 0
    aget-char v7, v5, v6
    new-instance v8, Ljava/lang/StringBuilder;
    invoke-direct {v8}, Ljava/lang/StringBuilder;-><init>()V
    invoke-virtual {v8, v7}, Ljava/lang/StringBuilder;->append(C)Ljava/lang/StringBuilder;
    move-result-object v8
    invoke-virtual {v8}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v8
    invoke-virtual {p2, v8}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
""", encoding="utf-8")

    findings = SmaliCallGraphEngine().audit_smali_directory(tmp_path)
    flows = [finding for finding in findings
             if finding.metadata.get("analysis_kind") == "smali_local_register_flow"]
    assert len(flows) == 1
    assert flows[0].metadata["source_kind"] == "EXTERNAL_FILE_CONTENT_CANDIDATE"


def test_smali_external_stream_single_value_read_flows_to_webview(tmp_path):
    (tmp_path / "ExternalSingleRead.smali").write_text("""
.class public Lcom/example/ExternalSingleRead;
.super Landroid/app/Activity;
.method public onNewIntent(Landroid/content/Intent;Landroid/webkit/WebView;)V
    .registers 8
    invoke-virtual {p1}, Landroid/content/Intent;->getData()Landroid/net/Uri;
    move-result-object v0
    invoke-virtual {p0}, Landroid/app/Activity;->getContentResolver()Landroid/content/ContentResolver;
    move-result-object v1
    invoke-virtual {v1, v0}, Landroid/content/ContentResolver;->openInputStream(Landroid/net/Uri;)Ljava/io/InputStream;
    move-result-object v2
    invoke-virtual {v2}, Ljava/io/InputStream;->read()I
    move-result v3
    new-instance v4, Ljava/lang/StringBuilder;
    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V
    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;
    move-result-object v4
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v5
    invoke-virtual {p2, v5}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
""", encoding="utf-8")

    findings = SmaliCallGraphEngine().audit_smali_directory(tmp_path)
    flows = [finding for finding in findings
             if finding.metadata.get("analysis_kind") == "smali_local_register_flow"]
    assert len(flows) == 1
    assert flows[0].metadata["source_kind"] == "EXTERNAL_FILE_CONTENT_CANDIDATE"


def test_smali_tainted_path_files_read_flows_to_webview(tmp_path):
    (tmp_path / "ExternalNioRead.smali").write_text("""
.class public Lcom/example/ExternalNioRead;
.super Landroid/app/Activity;
.method public onNewIntent(Landroid/content/Intent;Landroid/webkit/WebView;)V
    .registers 8
    invoke-virtual {p1}, Landroid/content/Intent;->getData()Landroid/net/Uri;
    move-result-object v0
    invoke-virtual {v0}, Landroid/net/Uri;->getPath()Ljava/lang/String;
    move-result-object v1
    const/4 v2, 0
    new-array v2, v2, [Ljava/lang/String;
    invoke-static {v1, v2}, Ljava/nio/file/Paths;->get(Ljava/lang/String;[Ljava/lang/String;)Ljava/nio/file/Path;
    move-result-object v3
    invoke-static {v3}, Ljava/nio/file/Files;->readString(Ljava/nio/file/Path;)Ljava/lang/String;
    move-result-object v4
    invoke-virtual {p2, v4}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
""", encoding="utf-8")

    findings = SmaliCallGraphEngine().audit_smali_directory(tmp_path)
    flows = [finding for finding in findings
             if finding.metadata.get("analysis_kind") == "smali_local_register_flow"]
    assert len(flows) == 1
    assert flows[0].metadata["source_kind"] == "EXTERNAL_FILE_CONTENT_CANDIDATE"


def test_smali_files_read_all_bytes_taints_loaded_array_elements(tmp_path):
    (tmp_path / "ExternalNioBytes.smali").write_text("""
.class public Lcom/example/ExternalNioBytes;
.super Landroid/app/Activity;
.method public onNewIntent(Landroid/content/Intent;Landroid/webkit/WebView;)V
    .registers 12
    invoke-virtual {p1}, Landroid/content/Intent;->getData()Landroid/net/Uri;
    move-result-object v0
    invoke-virtual {v0}, Landroid/net/Uri;->getPath()Ljava/lang/String;
    move-result-object v1
    const/4 v2, 0
    new-array v2, v2, [Ljava/lang/String;
    invoke-static {v1, v2}, Ljava/nio/file/Paths;->get(Ljava/lang/String;[Ljava/lang/String;)Ljava/nio/file/Path;
    move-result-object v3
    invoke-static {v3}, Ljava/nio/file/Files;->readAllBytes(Ljava/nio/file/Path;)[B
    move-result-object v4
    const/4 v5, 0
    aget-byte v6, v4, v5
    new-instance v7, Ljava/lang/StringBuilder;
    invoke-direct {v7}, Ljava/lang/StringBuilder;-><init>()V
    invoke-virtual {v7, v6}, Ljava/lang/StringBuilder;->append(B)Ljava/lang/StringBuilder;
    move-result-object v7
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v8
    invoke-virtual {p2, v8}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
""", encoding="utf-8")

    findings = SmaliCallGraphEngine().audit_smali_directory(tmp_path)
    flows = [finding for finding in findings
             if finding.metadata.get("analysis_kind") == "smali_local_register_flow"]
    assert len(flows) == 1
    assert flows[0].metadata["source_kind"] == "EXTERNAL_FILE_CONTENT_CANDIDATE"


def test_smali_files_new_buffered_reader_path_flows_to_webview(tmp_path):
    (tmp_path / "ExternalNioReader.smali").write_text("""
.class public Lcom/example/ExternalNioReader;
.super Landroid/app/Activity;
.method public onNewIntent(Landroid/content/Intent;Landroid/webkit/WebView;)V
    .registers 9
    invoke-virtual {p1}, Landroid/content/Intent;->getData()Landroid/net/Uri;
    move-result-object v0
    invoke-virtual {v0}, Landroid/net/Uri;->getPath()Ljava/lang/String;
    move-result-object v1
    const/4 v2, 0
    new-array v2, v2, [Ljava/lang/String;
    invoke-static {v1, v2}, Ljava/nio/file/Paths;->get(Ljava/lang/String;[Ljava/lang/String;)Ljava/nio/file/Path;
    move-result-object v3
    invoke-static {v3}, Ljava/nio/file/Files;->newBufferedReader(Ljava/nio/file/Path;)Ljava/io/BufferedReader;
    move-result-object v4
    invoke-virtual {v4}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;
    move-result-object v5
    invoke-virtual {p2, v5}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
""", encoding="utf-8")

    findings = SmaliCallGraphEngine().audit_smali_directory(tmp_path)
    flows = [finding for finding in findings
             if finding.metadata.get("analysis_kind") == "smali_local_register_flow"]
    assert len(flows) == 1
    assert flows[0].metadata["source_kind"] == "EXTERNAL_FILE_CONTENT_CANDIDATE"


def test_smali_files_new_input_stream_path_flows_to_webview(tmp_path):
    (tmp_path / "ExternalNioStream.smali").write_text("""
.class public Lcom/example/ExternalNioStream;
.super Landroid/app/Activity;
.method public onNewIntent(Landroid/content/Intent;Landroid/webkit/WebView;)V
    .registers 12
    invoke-virtual {p1}, Landroid/content/Intent;->getData()Landroid/net/Uri;
    move-result-object v0
    invoke-virtual {v0}, Landroid/net/Uri;->getPath()Ljava/lang/String;
    move-result-object v1
    const/4 v2, 0
    new-array v2, v2, [Ljava/lang/String;
    invoke-static {v1, v2}, Ljava/nio/file/Paths;->get(Ljava/lang/String;[Ljava/lang/String;)Ljava/nio/file/Path;
    move-result-object v3
    const/4 v4, 0
    new-array v4, v4, [Ljava/nio/file/OpenOption;
    invoke-static {v3, v4}, Ljava/nio/file/Files;->newInputStream(Ljava/nio/file/Path;[Ljava/nio/file/OpenOption;)Ljava/io/InputStream;
    move-result-object v5
    invoke-virtual {v5}, Ljava/io/InputStream;->read()I
    move-result v6
    new-instance v7, Ljava/lang/StringBuilder;
    invoke-direct {v7}, Ljava/lang/StringBuilder;-><init>()V
    invoke-virtual {v7, v6}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;
    move-result-object v7
    invoke-virtual {v7}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v8
    invoke-virtual {p2, v8}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
""", encoding="utf-8")

    findings = SmaliCallGraphEngine().audit_smali_directory(tmp_path)
    flows = [finding for finding in findings
             if finding.metadata.get("analysis_kind") == "smali_local_register_flow"]
    assert len(flows) == 1
    assert flows[0].metadata["source_kind"] == "EXTERNAL_FILE_CONTENT_CANDIDATE"


def test_smali_content_resolver_cursor_values_flow_only_from_tainted_cursor(tmp_path):
    (tmp_path / "ProviderCursor.smali").write_text("""
.class public Lcom/example/ProviderCursor;
.super Landroid/app/Activity;
.method public queryProvider(Landroid/webkit/WebView;)V
    .registers 9
    invoke-virtual {p0}, Landroid/app/Activity;->getContentResolver()Landroid/content/ContentResolver;
    move-result-object v0
    const-string v1, "content://com.example.provider/items"
    invoke-static {v1}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;
    move-result-object v1
    const/4 v2, 0
    invoke-virtual {v0, v1, v2, v2, v2, v2}, Landroid/content/ContentResolver;->query(Landroid/net/Uri;[Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;Ljava/lang/String;)Landroid/database/Cursor;
    move-result-object v3
    const/4 v4, 0
    invoke-interface {v3, v4}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;
    move-result-object v5
    invoke-virtual {p1, v5}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
.method public readInternalCursor(Landroid/database/Cursor;Landroid/webkit/WebView;)V
    .registers 4
    const/4 v0, 0
    invoke-interface {p1, v0}, Landroid/database/Cursor;->getString(I)Ljava/lang/String;
    move-result-object v1
    invoke-virtual {p2, v1}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
""", encoding="utf-8")

    findings = SmaliCallGraphEngine().audit_smali_directory(tmp_path)
    flows = [finding for finding in findings
             if finding.metadata.get("analysis_kind") == "smali_local_register_flow"]
    assert len(flows) == 1
    assert flows[0].metadata["source_kind"] == "CONTENT_RESOLVER_QUERY"


def test_smali_tainted_file_object_flows_through_file_input_stream(tmp_path):
    (tmp_path / "ExternalFileObject.smali").write_text("""
.class public Lcom/example/ExternalFileObject;
.super Landroid/app/Activity;
.method public onNewIntent(Landroid/content/Intent;Landroid/webkit/WebView;)V
    .registers 12
    invoke-virtual {p1}, Landroid/content/Intent;->getData()Landroid/net/Uri;
    move-result-object v0
    invoke-virtual {v0}, Landroid/net/Uri;->getPath()Ljava/lang/String;
    move-result-object v1
    new-instance v2, Ljava/io/File;
    invoke-direct {v2, v1}, Ljava/io/File;-><init>(Ljava/lang/String;)V
    new-instance v3, Ljava/io/FileInputStream;
    invoke-direct {v3, v2}, Ljava/io/FileInputStream;-><init>(Ljava/io/File;)V
    invoke-virtual {v3}, Ljava/io/FileInputStream;->read()I
    move-result v4
    new-instance v5, Ljava/lang/StringBuilder;
    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V
    invoke-virtual {v5, v4}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;
    move-result-object v5
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v6
    invoke-virtual {p2, v6}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
""", encoding="utf-8")

    findings = SmaliCallGraphEngine().audit_smali_directory(tmp_path)
    flows = [finding for finding in findings
             if finding.metadata.get("analysis_kind") == "smali_local_register_flow"
             and finding.metadata.get("source_kind") == "EXTERNAL_FILE_CONTENT_CANDIDATE"]
    assert len(flows) == 1


def test_smali_external_content_is_not_seeded_from_untainted_uri_or_path(tmp_path):
    (tmp_path / "InternalReads.smali").write_text("""
.class public Lcom/example/InternalReads;
.super Landroid/app/Activity;
.method public readInternalUri(Landroid/webkit/WebView;)V
    .registers 7
    const-string v0, "content://com.example.internal/settings"
    invoke-static {v0}, Landroid/net/Uri;->parse(Ljava/lang/String;)Landroid/net/Uri;
    move-result-object v1
    invoke-virtual {p0}, Landroid/app/Activity;->getContentResolver()Landroid/content/ContentResolver;
    move-result-object v2
    invoke-virtual {v2, v1}, Landroid/content/ContentResolver;->openInputStream(Landroid/net/Uri;)Ljava/io/InputStream;
    move-result-object v3
    new-instance v4, Ljava/io/InputStreamReader;
    invoke-direct {v4, v3}, Ljava/io/InputStreamReader;-><init>(Ljava/io/InputStream;)V
    new-instance v5, Ljava/io/BufferedReader;
    invoke-direct {v5, v4}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V
    invoke-virtual {v5}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;
    move-result-object v6
    invoke-virtual {p1, v6}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
.method public readInternalPath(Landroid/webkit/WebView;)V
    .registers 7
    const-string v0, "/data/user/0/com.example.app/files/config"
    new-instance v1, Ljava/io/FileInputStream;
    invoke-direct {v1, v0}, Ljava/io/FileInputStream;-><init>(Ljava/lang/String;)V
    new-instance v2, Ljava/io/InputStreamReader;
    invoke-direct {v2, v1}, Ljava/io/InputStreamReader;-><init>(Ljava/io/InputStream;)V
    new-instance v3, Ljava/io/BufferedReader;
    invoke-direct {v3, v2}, Ljava/io/BufferedReader;-><init>(Ljava/io/Reader;)V
    invoke-virtual {v3}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;
    move-result-object v4
    invoke-virtual {p1, v4}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
.method public readInternalNio(Landroid/webkit/WebView;)V
    .registers 5
    const-string v0, "/data/user/0/com.example.app/files/config"
    const/4 v1, 0
    new-array v1, v1, [Ljava/lang/String;
    invoke-static {v0, v1}, Ljava/nio/file/Paths;->get(Ljava/lang/String;[Ljava/lang/String;)Ljava/nio/file/Path;
    move-result-object v2
    invoke-static {v2}, Ljava/nio/file/Files;->readString(Ljava/nio/file/Path;)Ljava/lang/String;
    move-result-object v3
    invoke-virtual {p1, v3}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
.method public readInternalNioBytes(Landroid/webkit/WebView;)V
    .registers 10
    const-string v0, "/data/user/0/com.example.app/files/config"
    const/4 v1, 0
    new-array v1, v1, [Ljava/lang/String;
    invoke-static {v0, v1}, Ljava/nio/file/Paths;->get(Ljava/lang/String;[Ljava/lang/String;)Ljava/nio/file/Path;
    move-result-object v2
    invoke-static {v2}, Ljava/nio/file/Files;->readAllBytes(Ljava/nio/file/Path;)[B
    move-result-object v3
    const/4 v4, 0
    aget-byte v5, v3, v4
    new-instance v6, Ljava/lang/StringBuilder;
    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V
    invoke-virtual {v6, v5}, Ljava/lang/StringBuilder;->append(B)Ljava/lang/StringBuilder;
    move-result-object v6
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v7
    invoke-virtual {p1, v7}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
.method public readInternalNioReader(Landroid/webkit/WebView;)V
    .registers 8
    const-string v0, "/data/user/0/com.example.app/files/config"
    const/4 v1, 0
    new-array v1, v1, [Ljava/lang/String;
    invoke-static {v0, v1}, Ljava/nio/file/Paths;->get(Ljava/lang/String;[Ljava/lang/String;)Ljava/nio/file/Path;
    move-result-object v2
    invoke-static {v2}, Ljava/nio/file/Files;->newBufferedReader(Ljava/nio/file/Path;)Ljava/io/BufferedReader;
    move-result-object v3
    invoke-virtual {v3}, Ljava/io/BufferedReader;->readLine()Ljava/lang/String;
    move-result-object v4
    invoke-virtual {p1, v4}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
.method public readInternalFileObject(Landroid/webkit/WebView;)V
    .registers 8
    const-string v0, "/data/user/0/com.example.app/files/config"
    new-instance v1, Ljava/io/File;
    invoke-direct {v1, v0}, Ljava/io/File;-><init>(Ljava/lang/String;)V
    new-instance v2, Ljava/io/FileInputStream;
    invoke-direct {v2, v1}, Ljava/io/FileInputStream;-><init>(Ljava/io/File;)V
    invoke-virtual {v2}, Ljava/io/FileInputStream;->read()I
    move-result v3
    new-instance v4, Ljava/lang/StringBuilder;
    invoke-direct {v4}, Ljava/lang/StringBuilder;-><init>()V
    invoke-virtual {v4, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;
    move-result-object v4
    invoke-virtual {v4}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v5
    invoke-virtual {p1, v5}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
.method public readInternalNioStream(Landroid/webkit/WebView;)V
    .registers 10
    const-string v0, "/data/user/0/com.example.app/files/config"
    const/4 v1, 0
    new-array v1, v1, [Ljava/lang/String;
    invoke-static {v0, v1}, Ljava/nio/file/Paths;->get(Ljava/lang/String;[Ljava/lang/String;)Ljava/nio/file/Path;
    move-result-object v2
    const/4 v3, 0
    new-array v3, v3, [Ljava/nio/file/OpenOption;
    invoke-static {v2, v3}, Ljava/nio/file/Files;->newInputStream(Ljava/nio/file/Path;[Ljava/nio/file/OpenOption;)Ljava/io/InputStream;
    move-result-object v4
    invoke-virtual {v4}, Ljava/io/InputStream;->read()I
    move-result v5
    new-instance v6, Ljava/lang/StringBuilder;
    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V
    invoke-virtual {v6, v5}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;
    move-result-object v6
    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;
    move-result-object v7
    invoke-virtual {p1, v7}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
    return-void
.end method
""", encoding="utf-8")

    findings = SmaliCallGraphEngine().audit_smali_directory(tmp_path)
    assert not [finding for finding in findings
                if finding.metadata.get("analysis_kind") == "smali_local_register_flow"]
