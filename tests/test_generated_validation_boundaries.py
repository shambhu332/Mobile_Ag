"""Generation creates review plans, never observations or privileged proof."""
from types import SimpleNamespace

import pytest

from mobileag.analysis.call_graph import SmaliCallGraphEngine
from mobileag.analysis.native_analyzer import NativeAnalyzer
from mobileag.generators.frida_generator import FridaGenerator
from mobileag.generators.poc_generator import PoCGenerator
from mobileag.reporting.finding import Finding, FindingStatus, Severity


class Router:
    async def route(self, **kwargs):
        return SimpleNamespace(success=False, error="offline fixture", content="")


@pytest.mark.asyncio
@pytest.mark.parametrize("cwe", ["CWE-926", "CWE-927", "CWE-22", "CWE-89", "CWE-601", "CWE-749", "CWE-285", "CWE-306", "CWE-798"])
async def test_plans_do_not_invent_targets_or_execute_destructive_operations(cwe):
    finding = Finding(title="Synthetic candidate", description="Unverified lexical observation", cwe_id=cwe,
                      severity=Severity.HIGH, file_path="Synthetic.java", line_number=8,
                      affected_component="com.example.Synthetic")
    guide = await PoCGenerator(Router()).generate(finding, {"package_name": "com.example.owned"})
    assert "NOT EXECUTED" in guide
    assert "controls" in guide
    assert "ordinary-app" in guide
    assert "attacker.com" not in guide and "api.target.com" not in guide
    assert "delete_account" not in guide and "content delete" not in guide
    assert "curl -X DELETE" not in guide and "curl -X PUT" not in guide
    assert "com.example.owned://" not in guide
    assert "content://com.example.owned.provider" not in guide
    assert finding.status is FindingStatus.UNVERIFIED


@pytest.mark.asyncio
async def test_model_and_frida_generation_are_never_execution_attestations():
    class SuccessRouter:
        async def route(self, **kwargs):
            return SimpleNamespace(success=True, error="", content="Generated draft")
    finding = Finding(title="Synthetic", description="Unverified", cwe_id="CWE-Unknown")
    guide = await PoCGenerator(SuccessRouter()).generate(finding, {})
    assert guide.startswith("**Generated validation plan - NOT EXECUTED")
    script = await FridaGenerator(Router()).generate(finding, {})
    assert "NOT EXECUTED OR VERIFIED" in script
    assert "no hook was installed" in script
    assert "Hook installed successfully" not in script
    assert finding.status is FindingStatus.UNVERIFIED


def test_smali_reused_engine_cannot_report_previous_artifact(tmp_path):
    first = tmp_path / "first"
    first.mkdir()
    (first / "Entry.smali").write_text('''.class public Lcom/example/Entry;
.super Landroid/app/Activity;
.method public onCreate()V
 .locals 3
 invoke-virtual {v0}, Landroid/content/Intent;->getDataString()Ljava/lang/String;
 move-result-object v1
 const-string v2, "https://synthetic.invalid/constant"
 invoke-virtual {v0, v2}, Landroid/webkit/WebView;->loadUrl(Ljava/lang/String;)V
 return-void
.end method
''')
    engine = SmaliCallGraphEngine()
    candidates = engine.audit_smali_directory(first)
    assert len(candidates) == 1  # Co-occurrence is retained, not claimed dataflow.
    assert candidates[0].metadata["register_dataflow"] == "not_implemented"
    assert candidates[0].status is FindingStatus.UNVERIFIED
    assert candidates[0].severity is Severity.INFO
    assert candidates[0].cvss_score == 0 and candidates[0].confidence == .5
    second = tmp_path / "second"
    second.mkdir()
    assert not engine.audit_smali_directory(second)
    assert not engine.methods and not engine.class_hierarchy
    assert not engine.audit_smali_directory(tmp_path / "missing")


@pytest.mark.asyncio
async def test_native_string_presence_not_import_call_or_memory_corruption_proof(tmp_path):
    lib = tmp_path / "lib" / "arm64-v8a"
    lib.mkdir(parents=True)
    (lib / "libsynthetic.so").write_bytes(b"not-even-ELF: documentation strcpy system ptrace")
    findings = await NativeAnalyzer(Router()).analyze(str(tmp_path))
    assert len(findings) == 3
    for finding in findings:
        assert finding.severity is Severity.INFO
        assert finding.cvss_score == 0
        assert finding.status is FindingStatus.UNVERIFIED
        assert finding.metadata["ghidra_executed"] is False
        assert "does not establish an ELF import" in finding.description
