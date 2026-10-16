"""Test suite for accuracy improvements: Native JNI analyzer, path-sensitive sanitizers, and dynamic verification loop."""
import os
import shutil
import subprocess
import tempfile
from unittest.mock import MagicMock, patch
import pytest

from mobileag.analysis.native_jni_bridge import NativeJniAnalyzer
from mobileag.filters.sanitizer_check import SanitizerFilter
from mobileag.dast.verification_loop import DynamicVerificationLoop, DynamicVerificationOutcome
from mobileag.reporting.finding import Finding, FindingStatus, Severity


def test_native_jni_analyzer():
    with tempfile.TemporaryDirectory() as tmp_dir:
        arm_dir = os.path.join(tmp_dir, "lib", "arm64-v8a")
        os.makedirs(arm_dir)

        # Create mock ELF binary with JNI exported symbols and libc dangerous calls
        mock_elf = (
            b"\x7fELF"
            + b"\x00" * 40
            + b"Java_com_example_app_NativeSecurity_executeCommand"
            + b"\x00" * 20
            + b"system"
            + b"\x00" * 10
            + b"sqlite3_exec"
            + b"\x00" * 50
        )

        so_path = os.path.join(arm_dir, "libsecurity.so")
        with open(so_path, "wb") as f:
            f.write(mock_elf)

        analyzer = NativeJniAnalyzer()
        res = analyzer.audit_library(so_path)

        assert res.library_name == "libsecurity.so"
        assert res.architecture == "arm64-v8a"
        assert res.exported_jni_functions == []  # The malformed fixture has no parsed dynamic symbols.
        assert "Java_com_example_app_NativeSecurity_executeCommand" in res.jni_export_name_candidates
        assert "system" in res.dangerous_symbol_string_candidates
        assert "sqlite3_exec" in res.dangerous_symbol_string_candidates
        assert res.imported_dangerous_symbols == []
        assert len(res.findings) >= 2
        for finding in res.findings:
            assert finding.cwe_id == "CWE-Unknown"
            assert finding.severity == Severity.INFO
            assert finding.metadata["call_reachability"] == "not_analyzed"
            assert "does not establish an ELF dynamic import" in finding.description


@pytest.mark.parametrize("symbol, expected", [
    ("Java_com_example_Native_run__I", ("com.example.Native", "run")),
    ("Java_com_example_Native_do_1Thing", ("com.example.Native", "do_Thing")),
    ("Java_com_example_Native_text_2value", ("com.example.Native", "text;value")),
    ("Java_com_example_Native_array_3value", ("com.example.Native", "array[value")),
    ("Java_com_example_Native_name_00041", ("com.example.Native", "nameA")),
])
def test_jni_export_name_decoder_handles_overload_and_escape_forms(symbol, expected):
    assert NativeJniAnalyzer().demangle_jni_name(symbol) == expected


@pytest.mark.skipif(shutil.which("gcc") is None, reason="gcc required for synthetic ELF fixture")
def test_native_jni_analyzer_parses_import_and_export_symbols_without_call_path(tmp_path):
    source = tmp_path / "native.c"
    library = tmp_path / "libnative.so"
    source.write_text(
        "#include <stdlib.h>\n"
        "void Java_com_example_Native_run(void) { system(\"true\"); }\n",
        encoding="utf-8",
    )
    subprocess.run(
        [shutil.which("gcc"), "-shared", "-fPIC", "-fno-builtin", "-o", str(library), str(source)],
        check=True, capture_output=True, text=True, timeout=30,
    )

    result = NativeJniAnalyzer().audit_library(library)

    assert result.elf_parse_status == "parsed"
    assert result.dynamic_symbols_seen > 0
    assert "system" in result.imported_dangerous_symbols
    assert any(item.java_method == "run" for item in result.exported_jni_functions)
    assert result.exported_jni_functions[0].dangerous_calls_referenced == []
    system_finding = next(item for item in result.findings if item.title.endswith(": system"))
    assert system_finding.metadata["analysis_kind"] == "elf_dynamic_symbol_import"
    assert system_finding.metadata["call_reachability"] == "not_analyzed"
    assert system_finding.severity == Severity.INFO
    assert system_finding.cwe_id == "CWE-Unknown"

    object_file = tmp_path / "native.o"
    subprocess.run(
        [shutil.which("gcc"), "-c", "-fno-builtin", "-o", str(object_file), str(source)],
        check=True, capture_output=True, text=True, timeout=30,
    )
    object_result = NativeJniAnalyzer().audit_library(object_file)
    assert object_result.elf_parse_status == "not_present"
    assert object_result.scan_status == "partial"
    assert object_result.imported_dangerous_symbols == []
    assert "dynamic_symbol_table_missing" in object_result.scan_errors


def test_native_jni_analyzer_does_not_follow_direct_library_symlink(tmp_path):
    target = tmp_path / "synthetic.elf"
    target.write_bytes(b"\x7fELF" + b"\x00" * 40 + b"system\x00")
    link = tmp_path / "libcandidate.so"
    link.symlink_to(target)

    result = NativeJniAnalyzer().audit_library(link)

    assert result.imported_dangerous_symbols == []
    assert result.findings == []
    assert result.scan_status == "invalid"
    assert result.scan_errors == ["library_read_error"]


def test_native_jni_analyzer_reports_bounded_prefix_as_partial(tmp_path):
    library = tmp_path / "liblarge.so"
    library.write_bytes(b"\x7fELF\x00system\x00" + b"\x00" * (5 * 1024 * 1024))

    result = NativeJniAnalyzer().audit_library(library)

    assert result.scan_status == "partial"
    assert result.scan_truncated is True
    assert result.bytes_scanned == 5 * 1024 * 1024
    assert "library_byte_limit" in result.scan_errors
    assert result.imported_dangerous_symbols == []
    candidate = next(item for item in result.findings if "system" in item.title)
    assert candidate.metadata["scan_status"] == "partial"
    assert candidate.metadata["elf_parse_status"] == "partial"
    assert candidate.metadata["scan_truncated"] is True


def test_native_jni_analyzer_reports_missing_elf_parser_as_partial(tmp_path, monkeypatch):
    import mobileag.analysis.native_jni_bridge as native_jni

    library = tmp_path / "libcandidate.so"
    library.write_bytes(b"\x7fELF\x00system\x00")
    monkeypatch.setattr(native_jni, "ELFFile", None)

    result = NativeJniAnalyzer().audit_library(library)

    assert result.elf_parse_status == "unsupported"
    assert result.scan_status == "partial"
    assert result.imported_dangerous_symbols == []
    assert result.dangerous_symbol_string_candidates == ["system"]
    assert "elf_parser_unavailable" in result.scan_errors


def test_native_jni_analyzer_caps_and_deduplicates_dynamic_symbols(tmp_path, monkeypatch):
    from types import SimpleNamespace
    import mobileag.analysis.native_jni_bridge as native_jni

    class FakeSymbol:
        name = "system"
        entry = SimpleNamespace(
            st_info=SimpleNamespace(type="STT_FUNC"), st_shndx="SHN_UNDEF",
        )

    class FakeDynamicSymbols:
        def iter_symbols(self):
            for _ in range(5001):
                yield FakeSymbol()

    class FakeElf:
        def __init__(self, _stream):
            pass

        def get_section_by_name(self, name):
            return FakeDynamicSymbols() if name == ".dynsym" else None

    library = tmp_path / "libbounded.so"
    library.write_bytes(b"\x7fELF\x00system\x00")
    monkeypatch.setattr(native_jni, "ELFFile", FakeElf)

    result = NativeJniAnalyzer().audit_library(library)

    assert result.elf_parse_status == "partial"
    assert result.scan_status == "partial"
    assert result.dynamic_symbols_seen == 5000
    assert result.imported_dangerous_symbols == ["system"]
    assert "dynamic_symbol_limit" in result.scan_errors


def test_sanitizer_filter_path_sensitive_guards():
    mock_router = MagicMock()
    filter_engine = SanitizerFilter(router=mock_router)

    # 1. Path traversal with canonicalization guard
    safe_path_code = """
    File f = new File(baseDir, userInput);
    if (!f.getCanonicalPath().startsWith(baseDir.getCanonicalPath())) {
        throw new SecurityException("Traversal attempt");
    }
    FileInputStream fis = new FileInputStream(f);
    """
    score, reason = filter_engine._pattern_check(safe_path_code, "CWE-22")
    assert score <= 0.2
    assert "Canonical path" in reason

    # 2. XSS / Open redirect with host allowlist guard
    safe_url_code = """
    Uri uri = Uri.parse(targetUrl);
    if (!uri.getHost().equals("trusted.bank.com")) {
        finish();
        return;
    }
    webView.loadUrl(targetUrl);
    """
    score, reason = filter_engine._pattern_check(safe_url_code, "CWE-79")
    assert score <= 0.2
    assert "Host/Origin allowlist guard" in reason

    # 3. SQL injection with parameterized arguments
    safe_sql_code = """
    String query = "SELECT * FROM users WHERE id = ?";
    String[] selectionArgs = new String[]{ userId };
    db.rawQuery(query, selectionArgs);
    """
    score, reason = filter_engine._pattern_check(safe_sql_code, "CWE-89")
    assert score <= 0.2
    assert "Parameterized SQL arguments" in reason


def test_dynamic_verification_loop():
    finding = Finding(
        id="DEEP_LINK_VULN_01",
        title="Deep Link Arbitrary Redirection",
        description="Deep link scheme accepts untrusted redirect param",
        severity=Severity.HIGH,
        status=FindingStatus.UNVERIFIED,
        cwe_id="CWE-601",
        file_path="RouterActivity.java",
        metadata={"uri_scheme": "bankapp://auth?redirect=https://attacker.com"},
    )

    verifier = DynamicVerificationLoop()

    # Case 1: Verification probe succeeds on device
    mock_success = MagicMock()
    mock_success.returncode = 0
    mock_success.stdout = "Starting: Intent { act=android.intent.action.VIEW dat=bankapp://auth... }\nStatus: ok\n"
    mock_success.stderr = ""

    with patch("subprocess.run", return_value=mock_success):
        outcome = verifier.verify_finding(finding, target_package="com.example.bank")
        assert outcome.verified is True
        assert outcome.verdict == "CONFIRMED"

        updated = verifier.apply_verification_to_finding(finding, outcome)
        assert updated.status == FindingStatus.CONFIRMED
        assert "dynamic_verification" in updated.metadata

    # Case 2: Verification probe blocked by Android OS permission gate
    mock_blocked = MagicMock()
    mock_blocked.returncode = 1
    mock_blocked.stdout = ""
    mock_blocked.stderr = "java.lang.SecurityException: Permission Denial: starting Intent not exported from uid 1000\n"

    finding2 = Finding(
        id="INTENT_RED_02",
        title="Intent Redirection",
        description="Unexported component call",
        severity=Severity.HIGH,
        status=FindingStatus.UNVERIFIED,
        cwe_id="CWE-926",
        file_path="VulnerableActivity.java",
    )

    with patch("subprocess.run", return_value=mock_blocked):
        outcome2 = verifier.verify_finding(finding2, target_package="com.example.bank")
        assert outcome2.verified is False
        assert outcome2.verdict == "BLOCKED_BY_OS"

        updated2 = verifier.apply_verification_to_finding(finding2, outcome2)
        assert len(updated2.false_positive_reasons) > 0
        assert "Android OS enforced permission denial" in updated2.false_positive_reasons[0]
