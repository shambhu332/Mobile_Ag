"""Missing analyzer roots must never resolve to the process working directory."""
from pathlib import Path

import pytest

from mobileag.analysis.bounded_sources import SourceInventory, explicit_scan_root
from mobileag.analysis.code_reviewer import CodeReviewer
from mobileag.analysis.dependency_scanner import DependencyScanner
from mobileag.analysis.fileprovider_auditor import FileProviderAuditor
from mobileag.analysis.native_analyzer import NativeAnalyzer
from mobileag.analysis.secret_scanner import SecretScanner
from mobileag.analysis.taint_engine import TaintEngine
from mobileag.analysis.symbol_resolver import SymbolResolver
from mobileag.analysis.flutter_engine import FlutterEngineAnalyzer
from mobileag.analysis.hermes_analyzer import HermesBytecodeAnalyzer
from mobileag.analysis.il2cpp_auditor import Il2CppAuditor
from mobileag.analysis.network_security_config_auditor import NetworkSecurityConfigAuditor
from mobileag.analysis.privacy_manifest_auditor import PrivacyManifestAuditor
from mobileag.analysis.react_native_scanner import ReactNativeScanner
from mobileag.analysis.binary_protection_auditor import BinaryProtectionAuditor


@pytest.mark.parametrize("missing", [None, "", "   "])
def test_explicit_scan_root_rejects_missing_roots(missing):
    assert explicit_scan_root(missing) is None


def test_explicit_scan_root_preserves_explicit_current_directory():
    assert explicit_scan_root(".") == Path(".")


@pytest.mark.asyncio
@pytest.mark.parametrize("missing", [None, "", "   "])
async def test_source_analyzers_fail_closed_on_missing_root(monkeypatch, missing):
    def unexpected(*_args, **_kwargs):
        raise AssertionError("analyzer attempted a filesystem scan without an explicit root")

    code = CodeReviewer()
    monkeypatch.setattr(code, "_sync_scan_source", unexpected)
    assert await code.review(missing, {}) == []
    assert code.coverage["static_status"] == "not_analyzed"

    secret = SecretScanner(None)
    monkeypatch.setattr(secret, "_sync_scan_files", unexpected)
    assert await secret.scan(missing) == []
    assert secret.coverage["static_status"] == "not_analyzed"

    native = NativeAnalyzer(None)
    monkeypatch.setattr(native, "_sync_analyze", unexpected)
    assert await native.analyze(missing) == []
    assert native.coverage["static_status"] == "not_analyzed"

    dependencies = DependencyScanner(None)
    monkeypatch.setattr(dependencies, "_sync_find_dependencies", unexpected)
    monkeypatch.setattr(dependencies, "_sync_find_native_libraries", unexpected)
    assert await dependencies.scan(missing, allow_advisory_lookup=True) == []
    assert dependencies.coverage["static_status"] == "not_analyzed"
    assert dependencies.coverage["lookup_status"] == "not_started"

    fileprovider = FileProviderAuditor()
    monkeypatch.setattr(SourceInventory, "read", unexpected)
    assert fileprovider.audit_resource_directory(missing) == []
    assert fileprovider.coverage["static_status"] == "not_analyzed"


@pytest.mark.parametrize("missing", [None, "", "   "])
def test_taint_engine_passes_missing_root_as_none_not_dot(monkeypatch, missing):
    roots = []
    reads = []

    def record_index(_self, root):
        roots.append(root)
        return 0

    def record_read(_self, root, *_args, **_kwargs):
        reads.append(root)
        return iter(())

    monkeypatch.setattr(SymbolResolver, "index_directory", record_index)
    monkeypatch.setattr(SourceInventory, "read", record_read)
    engine = TaintEngine()

    assert engine.analyze_directory(missing) == []
    assert roots == [None]
    assert reads == [None]
    assert engine.coverage["static_status"] == "not_analyzed"
    assert engine.coverage["proof_status"] == "not_proven"


@pytest.mark.parametrize("missing", [None, "", "   "])
def test_framework_and_resource_auditors_reject_missing_roots(monkeypatch, missing):
    def unexpected(*_args, **_kwargs):
        raise AssertionError("filesystem scan attempted without an explicit root")

    # os.walk-based auditors must return before touching the process directory.
    monkeypatch.setattr("mobileag.analysis.flutter_engine.os.walk", unexpected)
    monkeypatch.setattr("mobileag.analysis.il2cpp_auditor.os.walk", unexpected)
    monkeypatch.setattr("mobileag.analysis.privacy_manifest_auditor.os.walk", unexpected)
    assert FlutterEngineAnalyzer().analyze_package_directory(missing).scan_status == "invalid"
    assert Il2CppAuditor().audit_package(missing).scan_status == "invalid"
    assert PrivacyManifestAuditor().audit_ios_privacy_manifest(missing).parse_status == "invalid"

    network = NetworkSecurityConfigAuditor()
    monkeypatch.setattr(SourceInventory, "read", unexpected)
    assert network.locate_config_path(missing) is None
    assert network.coverage["static_status"] == "not_analyzed"

    react = ReactNativeScanner()
    assert react.locate_bundle(missing) is None
    assert react.coverage["static_status"] == "not_analyzed"

    binary = BinaryProtectionAuditor()
    assert binary.find_native_libraries(missing) == []
    assert binary.audit_directory(missing) == []
    assert binary.coverage["static_status"] == "not_analyzed"

    hermes = HermesBytecodeAnalyzer()
    assert hermes.audit_package_bundles(missing) == []
